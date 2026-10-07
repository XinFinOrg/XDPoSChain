---
status: accepted
---

# Bound the executed marker to the lifetime of the state it guards

## Context

PR #2566 (`fix-issue-2534-2535`, merged 2026-10-06) introduced `blockReceiptsExecutedSuffix` (`core/rawdb/schema.go`): a per-block key recording "this node executed this block", read by `BlockChain.HasExecutedBlock` as the authority for "known" (`core/block_validator.go:73-76`, `core/blockchain.go`). It exists because `HasBlockAndFullState` is keyed by the state root rather than by the block, so a block this node never ran - a side entry written by `writeBlockWithoutState`, or a fast sync range completed by `InsertReceiptChain` - could be adopted as the head without `Process` or `ValidateState` ever running on it.

The record is written for every block this node executes and nothing evicted it: one key per executed block, ~0.9 GB on a chain of 107.5 M blocks (#2566), growing with the chain.

## Decision

Evict the marker exactly where the write path evicts the state, and only on the nodes that evict state:

- on a node whose `CacheConfig.TrieDirtyDisabled` is false - `--gcmode full`, which is also the `--gcmode` flag default (`cmd/utils/flags.go:211-216`) - delete the marker at `chosen = current - TriesInMemory`, which on the forward path is `head - TriesInMemory`;
- on an archive node (`--gcmode archive`), delete nothing.

There is no window constant and nothing new to tune. The rule is:

> a marker goes exactly when the state it vouches for is gone, and the state is gone when the root its header names no longer resolves: the eviction takes the marker of every height the write path carries past whose state is not readable by then, and leaves the rest.

The eviction rides the trie garbage collector `writeBlockWithState` already runs in its non-archive branch, inside the same non-archive gate that keeps every marker of an archive node. The queue's second exit, the drain `saveData` runs at shutdown, takes no markers while the head sits at the last block the write path executed: everything still queued then sits inside the state window, above the line, where the marker still decides and where the drain has just committed the states to disk. Taking those markers would make a restarted node execute a re-delivery it recognises today, so the drain is bounded at the cursor and leaves them. What that costs is one window of markers per clean shutdown, recorded under Consequences. The write path is the arm a fixture can pin; the drain's other arm, the delete below its line, is recorded here rather than pinned, because reaching it takes a head pointer lowered below the deepest executed block with those blocks left in place and the stored range above the hole re-delivered.

## Why the boundary is the state window and not a value of `M`

`HasExecutedBlock` is a conjunction (`core/blockchain.go:1286-1291`):

```go
func (bc *BlockChain) HasExecutedBlock(hash common.Hash, number uint64) bool {
	if !rawdb.HasExecutedMarker(bc.db, hash, number) {
		return false
	}
	return bc.HasBlockAndFullState(hash, number)
}
```

Below `head - TriesInMemory` on a pruning node the second conjunct is false for every height whose state the write path dropped from memory instead of writing, and the eviction asks exactly that question of the trie database before it takes a marker. An absent marker therefore cannot change any answer, for any caller: not the classifier in `ValidateBody`, not `writeKnownBlock`'s assertion, not `insertSideChain`'s prefix scan, not `blockAlreadyImported`. The eviction is behaviour-preserving **by construction**, not by measurement - and the construction is the predicate `HasExecutedBlock` itself applies to that half, rather than a height the rule assumes the state behind.

The heights the probe leaves alone are not one per call. The flush above the loop commits the state of the height it picks, which is `chosen` itself; a height whose header names that same root - a block without transactions and without rewards, the shape `makeSharedStateChain` builds - is readable for the same reason, and on a different call, and `Cap` writes roots of its own. Dereferencing a committed root takes nothing off disk, so on all of those the marker is the half that decides.

What it rests on is `HasBlockAndFullState` answering false for a state whose root is not on disk - which is what the eviction asks, so a root `Cap` wrote while the rest of that state was still in memory keeps its marker with it, and that earlier cost is gone with it. Behind both is the root-only check, which is older than this change: `HasFullState` resolves a root without walking it, so a height whose root node resolves over nodes that are not all there still answers true. That weakness is unchanged and recorded under Consequences, and the eviction now shares it rather than working around it - both sides ask the same question of the same database, so they cannot disagree about one height.

The repository already pins the pruning side of that statement in its own fixtures: `newPrunedCanonicalChain` describes what it imports as "their blocks are stored and canonical, their state is gone" (`core/blockchain_testfixture_test.go:117-140`), and `TestProcFutureBlocksKeepsPrunedAncestorParkedBlock` asserts `HasBlockAndFullState` is false for such a block (`core/blockchain_sidechain_pruned_test.go:30-33`).

`MaxForkAncestry` (90 000) is how far the downloader may look back for a fork point (`eth/downloader/downloader.go`), and it is 88 times further from the head than this line. Nothing about the eviction has to be reasoned about against the downloader, no constant has to move into `params` for `core` to reach it, and the strictness of the comparison at the downloader's floor is immaterial.

## Why archive nodes are left alone

An archive node never dereferences state, so `HasBlockAndFullState` stays true across its whole history and the marker decides all the way down. Evicting there would need the window, a background evictor, a persisted cursor and a one-time pass over the receipts key range - and it would change what a re-delivered range costs. `HasExecutedBlock` has no fallback, so a range whose marker is gone is executed again rather than recognised; on an archive node its state is still present, so that re-execution is the shape the file importers meet - `FirstMissingImportedBlock` decides the start of a batch on bodies below the head, while `insertBlock`'s `blockAlreadyImported` still asks the marker for every block.

Against that: a marker costs ~8.4 bytes per executed block (0.9 GB / 107.5 M), about 0.13 GB a year at XDC's block time, against an archive database whose state is measured in hundreds of gigabytes. Archive eviction is left to its own issue, with those costs measured first.

## How it rides the garbage collector

`writeBlockWithState` runs this loop once the chain is taller than `TriesInMemory`, on a node that prunes (`core/blockchain.go:2372-2390`):

```go
for !bc.triegc.Empty() {
	entry, number := bc.triegc.Pop()
	height := uint64(-number)
	if height > chosen {
		bc.triegc.Push(entry, number)
		break
	}
	bc.triedb.Dereference(entry.root)
	if !bc.HasState(entry.root) {
		if err := rawdb.DeleteExecutedMarker(bc.db, entry.hash, height); err != nil {
			log.Error("Failed to delete the executed-block marker", "number", height, "err", err)
		}
	}
}
```

The dereference comes first, so the question is asked about the state as the eviction is leaving it: a root the flush above committed - or an earlier flush, or `Cap` - is still readable on disk, and a root another queued entry still references is still readable in memory. `HasState` is the second conjunct of `HasExecutedBlock` with the block dropped (`core/blockchain_reader.go:255`), and it answers for the same root the block's header names, so the marker and the state half are decided by one predicate. The drain's delete arm in `saveData` is the one place that does not ask it, cutting by its own cursor instead; see Consequences.

Three properties make it the right place:

1. It is a child of `if current := block.NumberU64(); current > TriesInMemory` (`core/blockchain.go:2304-2400`) and a sibling of the flush gating (`core/blockchain.go:2323-2357`), not a child of it: a trie being flushed is not what triggers it. Upstream gates this same loop the same way, as an early return (`if current <= state.TriesInMemory { return nil }` in geth's `writeBlockWithState`). Below `TriesInMemory` there is nothing outside the state window to take; above it the loop runs on every written block.
2. `bc.triegc` pops by ascending height - entries are pushed with priority `-int64(block.NumberU64())` and the queue returns the highest priority - and the `break` re-pushes the first entry above `chosen`. With `chosen = current - TriesInMemory` advancing with the head, every height is visited exactly once, so the eviction cannot lag the head. That single visit is what makes the probe a decision rather than a guess: a height is popped on the call whose `chosen` is that height, and what the probe sees when that entry's root is dereferenced is never revisited - a height whose state survives that moment keeps its marker for good, and one whose state does not has nothing left to name.
3. It already holds the height, and it already writes to the database, under the chain mutex.

So the eviction needs no sweep, no cursor, no throttle, no one-time pass over the database, no background goroutine and no new lifecycle. It is one point delete per height, at a height the loop is already standing on. The queue has a second exit: `saveData` drains what the write path had not reached yet when the node stops (`core/blockchain.go:1373-1386`), dereferences those roots, and takes no markers with it while the head sits at the last block the write path executed. The loop breaks on the first entry above its cursor, so the heights still queued are then exactly the ones inside the state window, and the ones a restart does not enqueue again. They are also the heights `saveData` has just committed the state of (`core/blockchain.go:1336-1363`): their markers still decide, and taking them would turn "this node ran the block" into an execution for every height whose state outlives the restart. The drain therefore carries the cursor as a guard rather than a cut it makes: on that line the write path cannot leave an entry at or below it, so the drain takes no marker, and the markers of the window stay behind - one window at most, never taken later, taken the normal way if those heights are ever rewritten. A head adopted past the last written block - `writeKnownBlock` moves the head without a write - can leave queued entries at or below the drain's line, and the markers there go with the roots the drain dereferences in the same loop: below the eviction line, where the state they vouch for is gone, which is the fail-closed direction the rule asks for.

Three details were decided by the change that implemented this:

- the loop held the trie `root` and the height but not the block hash, and the marker key is `blockReceiptsPrefix || num || hash || suffix`. The block hash now travels in the `bc.triegc` entry, so the delete names the key without a read, and the marker taken at a height belongs to the block that was enqueued there.
- a sidechain block whose parent state is missing never reaches this: `insertSideChain` writes it through `writeBlockWithoutState` (`core/blockchain.go:3170`), which enqueues nothing. One that was executed through the batch path is enqueued with its own hash like any other block, which is the marker the delete names - so the hazard of a canonical hash naming a different block at an enqueued height does not arise, whatever the queue holds.
- `DeleteExecutedMarker` returns its refusal rather than logging it there, because the callers differ: the write-path ones keep it fatal, and the eviction reports the key it lost and carries on, so a refusal costs a key rather than the block.

## Considered options

- **A fixed window `M` below the head.** Rejected. `M` exists to keep an archive node's re-delivered ranges from being executed again - but archive eviction is what creates that problem, and keeping the markers is the simpler answer to it. Once the line is the state window, the downloader's bound is 88 times away and needs no reasoning; the fixed form instead brings a constant to move into `params`, a janitor, a persisted cursor, a one-time scan and a file-importer regression.
- **Evicting on archive nodes too.** Rejected for this change; see above.
- **Making `HasExecutedBlock` head-aware** (below the head, answer by state alone). Rejected here. Its appeal is real - it is the rule `FirstMissingImportedBlock` already applies - but `insertSideChain`'s prefix scan (`core/blockchain.go:3229-3231`) is an **adoption** site, not a classifier: it adopts the last block of the prefix it found through `writeKnownBlock`, and it refuses to adopt anything lower when the prefix comes out empty. Relaxing it below the head would let a block this node never ran, whose root merely resolves, be adopted as the head - the #2534 shape, on the path #2535 was reported from. Splitting the classifier from the adoption sites is a change to the #2534 guard and belongs in its own issue.
- **Giving the marker its own key prefix.** Rejected. It would make an empty marker range free to walk and a dense one ~1 GB, at the cost of dropping the prefix compression the marker shares with its receipts (roughly four times the transient marker storage during a full sync) and orphaning the markers a database already carries. With the eviction tied to the state window there is no scan to optimise in the first place.

## Consequences

- One root resolution per executed block on a pruning node's write path, to decide whether there is a state to leave the marker with - `HasState`, the same predicate `HasExecutedBlock` applies to its state half - and no lookup to name the key: the block hash travels in the trie GC entry. A refusing database costs the key rather than the block - the delete is reported and skipped, because the height is behind the cursor and will not be asked about again.
- What stays below the line is proportional to the states the node kept rather than to the chain, and it is no longer one height per call. With the default commit time limit - 5 minutes (`ethconfig.Defaults.TrieTimeout`, put on `CacheConfig.TrieTimeLimit` at `eth/backend.go:217` and again in the nil-cache fallback at `core/blockchain.go:472-478`, with no flag wired to either) - the bound trips first, because `chosen > lastWrite+TriesInMemory` forces a flush every `TriesInMemory` blocks on its own; a synced node then keeps roughly one marker per `TriesInMemory` blocks, about 0.88 MB over 107.5 M, plus the markers of the heights naming those same roots and of the heights whose root a queued entry still referenced when the cursor reached them. A node that spends the whole limit inside fewer than `TriesInMemory` blocks flushes more often and keeps more, and at a limit of zero every height is a flush boundary, every marker is kept, and the eviction reclaims nothing. The two goals are in tension - a marker that follows its state onto disk cannot also stop growing with a chain whose state never changes - so that is the shape to measure first if the limit is ever lowered.
- The root-only check behind both `HasFullState` and the eviction's probe is older than this change: a root node that resolves over nodes that are not all present still answers true, and `Cap` writes a root while the rest of its state is still in memory. The eviction now shares that answer rather than working around it, so the two ends cannot disagree about one height - and the marker is kept there, which is the fail-closed side.
- The converse is new and bounded: a height whose root another queued entry still references when the cursor reaches it keeps its marker, even if that root goes when the later entry is popped and nothing writes it to disk. The marker then outlives its state, where the second conjunct of `HasExecutedBlock` is false anyway, so the key is the cost and not an answer.
- At most one window of markers is left behind per clean shutdown. `saveData` dereferences the heights the write path had not reached and takes no markers while the head sits at the last block the write path executed: the loop that fills the queue breaks on the first entry above its cursor, so every height still queued is then above the bound the drain computes from that same head, inside the state window, and one whose state the drain has just committed. The bound is a guard rather than a cut, and it is written down rather than assumed: above `TriesInMemory` the write path has already popped and deleted everything up to its own cursor, which is the same line the drain computes while the head has not moved, and at or below it the drain's cursor is zero while the only height zero is genesis, which is never enqueued - so no queued height reaches the delete on that line. A head adopted past the last written block - `writeKnownBlock` moves the head without a write - puts queued entries at or below the drain's line, and the markers there go with the roots the drain dereferences in the same loop. That arm cuts by its cursor instead of asking the state, and it is the one place in this change where the two lifetimes are not decided by the same question: a height at or below its line whose root another queued entry still references, or one the three commits above it wrote, would lose its marker with the state still readable. Reaching it takes the head-adopted shape, which nothing pins, and it is recorded here rather than solved. Those window markers are not stale answers - they are the deciding half of an answer that is true where the state survived the restart - so they are left, and nothing later takes them (a restart does not enqueue those heights again). The residue is bounded by `TriesInMemory` keys, roughly 43 KB, once per shutdown; a `SetHead` or a re-import that rewrites those heights removes them the normal way. The cases pinned by tests are the write path's eviction, the heights whose state outlives the cursor, and this drain's leave-behind behaviour; the delete on the drain's line is not pinned, because the head has to be adopted past the last written block through `writeKnownBlock` first, and no fixture in the package lowers the head pointer without deleting the blocks it leaves behind.
- Markers a database already carries are not swept, because the eviction only names heights the queue still holds. The queue is filled by `writeBlockWithState` (`core/blockchain.go:2291`) and emptied by the write path and the shutdown drain, so a marker whose height was popped before this change - when the pop deleted nothing - sits below the line with nothing left to name it, and nothing later does: a restart does not enqueue those heights again, and `SetHead` deletes only the range it rewinds. The marker is inert there (below the line the second conjunct of `HasExecutedBlock` is already false), but it is not reclaimed, so an upgraded node's marker set does not shrink; what the change bounds is its growth from the upgrade point on, and the bounded growth is what a fresh full sync ends up with from genesis.
- `InspectDatabase` counts marker keys as receipts (`core/rawdb/database.go:163-167`), so the numbers it reports change meaning, and the 0.9 GB figure is not separately measurable with the existing tools.
- A rewind below the window puts already-evicted heights back inside it, and they cannot be re-marked, so re-importing them re-executes. Fail-closed. `SetHead` deletes the bodies, receipts and markers of the rewound range, so a re-import recreates them; `repair` only lowers the head pointer and leaves the blocks in place.
- Archive nodes keep every marker, so their marker set still grows with the chain. Recorded, not solved.

## Out of scope

- Archive eviction. Own issue.
- `HasExecutedBlock` keeps its strict meaning: marker and state, no fallback and no head test.
- No change to the key layout of `blockReceiptsExecutedSuffix`.
