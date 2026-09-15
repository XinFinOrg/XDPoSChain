# Runbook: proposed-block stall alert (skipped-proposed-block/state)

## Symptom

Either of:

- An `Error` log from the fetcher proposed-block handler:

  ```text
  [fetcher] skipped proposed block handler: canonical block state not executed, voting stalled
  ```

- Sustained growth of the `skipped-proposed-block/state` metrics counter
  (a handful of increments per hour is normal noise; more than ~10 within
  a 10-minute window warrants investigation).

- A `Warn` log naming the other cause of the same check, which is *not*
  this alert:

  ```text
  [fetcher] skipped proposed block handler: block body not stored
  ```

  `HasBlockAndExecutedState` answers false both when the body is missing and
  when the state trie does not open. This line means the body, so the state
  triage below does not apply; it stays at `Warn` because a missing body is a
  different defect from unexecuted state.

## What it means

The fetcher proposed-block gate (`eth/proposed_block.go`,
`newFetcherProposedBlockHandler`) judged the state of a **canonical block
within `proposedBlockStallWindow` (64) blocks of the head** as not openable
(`HasBlockAndExecutedState` == false: the block exists but
`stateCache.OpenTrie(root)` fails, or its body is missing — the latter is
logged separately and is not this stall). The gate runs once per propagated
block and the block will never be re-executed, so QC processing and
voting for that block on this path stay gated **until manual
intervention**. QC convergence itself is not lost: the two quorum-signed
entries (`SyncInfoHandler` and the vote-threshold path) are deliberately
ungated, but the block cannot join the PBOR proposal path locally.

There is no automatic fallback — degrading the gate to `HasBlock` would
re-admit unexecuted blocks into the judging path, which is exactly what
the gate protects against.

## Triage

Identify the affected height from the log's `number` field, then walk the
three known causes in order.

**Retransmission does not self-heal.** A re-announced block is imported
first (`fetcher.insertBlock` → `core.BlockChain.insertBlock` →
`getResultBlock`), and for a canonical block at or below the head height
`getResultBlock` returns `ErrKnownBlock` immediately — the fetcher logs
"Propagated block import failed" and returns, so the proposed-block gate
is never reached again. Re-announce loops cannot re-execute the state;
only the recovery actions below can.

### 1. Expected no-state zone (no action needed)

Old canonical blocks legitimately have no state on GC nodes and below a
fast-sync pivot:

- **Pruning / GC node** (`--gcmode full`, the default): states older than
  `TriesInMemory` (128) blocks behind the head are garbage-collected. The
  64-block escalation window keeps the `Error` inside the range where a
  full node should still have state, so an `Error` here is *not* explained
  by pruning alone — but verify `head number - block number` before
  concluding: if the head has raced far ahead between the announce and the
  log, the skip was expected noise (it logs `Warn` in that case, not
  `Error`).
- **Fast-sync pivot** (`--syncmode fast`): all canonical blocks below the
  pivot store headers and bodies only. Right after fast sync completes,
  the head is still near the pivot; a grace window in the gate suppresses
  the escalation for this transition. If the `Error` names a height below
  the pivot the node last fast-synced at, treat it as expected.

If the height falls in one of these zones, no recovery is required;
re-tune alerting to exclude them.

### 2. SetHead / manual rewind

Check for recent `SetHead` operations or rewind logs (`Rewound state
missing`, `Rolled back`): a rewind can land the head on a block whose
state was never executed, and the gate for that block stays false
forever.

Recovery: re-run a fast sync (`--syncmode fast`) or `SetHead` to a height
whose state is known-good, then let the node re-sync forward.

### 3. Trie corruption

If neither of the above applies, the state trie node for the block root
may be missing or damaged. Look for trie-level errors in the logs
(`missing trie node`, `Failed to ...`, unexpected `OpenTrie` failures).

Recovery: stop the node and either restore the chain/state data from a
known-good backup or re-sync from scratch (fast sync from the latest
pivot). Do not delete only the affected block — the chain markers will
not heal by themselves.

## Related counters

| Counter | Meaning |
| --- | --- |
| `proposed-block-skip-total` | Engine-side gate skips (before processQC and before the vote). Named outside the `skipped-proposed-block/` prefix so the aggregate regex below cannot double-count it — read-only cross-check, not a second alert term |
| `skipped-proposed-block/state` | Fetcher-gate skips: state not openable (this runbook), or a canonical block with no stored body; only the former logs at `Error` |
| `skipped-proposed-block/non-canonical` | Non-canonical block skips (expected on forks) |
| `skipped-proposed-block/no-canonical-header` | Skips when no canonical header exists at the block's height |
| `skipped-proposed-block/body-not-stored` | Canonical block whose body is not stored (see the downloader pre-filter) |
| `skipped-proposed-block/prefilter` | Downloader pre-filter skips |
| `skipped-proposed-block/snap-sync` | Skips during fast sync (expected while `snapSync` is set; sustained growth after the pivot commit means a sync-failure loop) |

Aggregate alert: one regex, `^skipped-proposed-block/`, sums every counter in
this table except the engine total — that is the intended single alert term.
`proposed-block-skip-total` is the same quantity viewed from the engine gates
and must not be added to the aggregate.
