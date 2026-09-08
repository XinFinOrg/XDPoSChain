# Plan: Port go-ethereum v1.17.5 Ancient DB (Freezer) + Add "Minimal Mode"

Branch: `feature-ancientdb-v1.14` (consider renaming to `feature-ancientdb-v1.17`)
Author: gerui@xinfin.org
Status: **Phase 1 implemented** (see §8 for what landed and what is outstanding).
Decisions in §7 resolved.

---

## 0. Executive summary

Two phases, strictly sequential. Phase 1 must be merged/stable and pass its full
test harness (including a 3-node local subnet soak) before Phase 2 starts.

| Phase | Goal | Rough size |
|---|---|---|
| 1 | Port the v1.17.5 chain freezer into `core/rawdb` + `ethdb`, wire into `node`/`eth`/`core`, add `--datadir.ancient` | ~6k LOC added, ~40 files touched |
| 2 | Add `--history.mode minimal`: continuously prune the `blockdata` tail group down to the newest data file, keep `headers`/`hashes` intact | ~500 LOC, ~12 files touched |

**Locked decisions** (see §7): pin **v1.17.5**; flag is **`--history.mode full|minimal`**;
total difficulty **stays in leveldb, never frozen**; tx-lookup index pruning is
**deferred to a follow-up**; subnet testing uses a **hand-rolled docker-compose
over `cicd/local`**; existing datadirs migrate via **background freeze** with no
startup stall; minimal mode **writes then prunes** during initial sync; there is
**no role-based guardrail**, only a loud warning; the soak runs **nightly in CI**,
not per-PR.

---

## 1. Current state of this codebase (verified)

**Already present (v1.9/v1.10.3-era scaffolding, no implementation):**

- `ethdb/database.go` declares the *old* ancient interfaces:
  `AppendAncient(number uint64, hash, header, body, receipt, td []byte) error`,
  `TruncateAncients(n uint64) error`, `HasAncient`, `Ancient`, `Ancients`,
  `AncientSize`, `Sync`. **No** `Tail`, `AncientRange`, `ReadAncients`,
  `ModifyAncients`, `TruncateHead`, `TruncateTail`, `MigrateTable`.
- `core/rawdb/database.go` — `nofreezedb` stub returning `errNotSupported` for
  every ancient call. `NewDatabase`/`NewMemoryDatabase`/`NewLevelDBDatabase`
  all wrap in `nofreezedb`. There is **no** `NewDatabaseWithFreezer`.
- `core/rawdb/freezer_table.go` — a 34-line file containing only
  `errClosed`, `errOutOfBounds`, `errNotSupported`. No implementation.
- `core/rawdb/schema.go:96-109` — table names already defined, matching upstream
  on-disk names: `headers`, `hashes`, `bodies`, `receipts`, and `diffs`
  (the last one is being dropped — see §3.4).
- `core/rawdb/table.go` — passthroughs for the old ancient methods.
- `core/rawdb/accessors_chain.go` — read paths already try the freezer first
  (lines 37, 250, 337, 468, …) and fall back to leveldb. These work today only
  because `Ancient` always errors out.
- `core/rawdb/database.go:202` — `InspectDatabase` already tallies ancient sizes.
- `core/blockchain.go:827-833` — `SetHead` already calls `bc.db.Ancients()` /
  `bc.db.TruncateAncients(num+1)`.
- `XDCxDAO/interfaces.go:36-41` and `XDCxDAO/leveldb.go:113+` — a second
  implementation of the ancient interface (XDCx order/lending DB) that must be
  kept compiling.

**Verified favourable finding:** `ReadTdRLP` (`core/rawdb/accessors_chain.go`)
is **already leveldb-only** — it does a plain `db.Get(headerTDKey(...))` and
never consults the ancient store. The "TD stays in leveldb" decision therefore
requires **no accessor changes at all**.

**Missing entirely:**

- `freezer.go`, `freezer_batch.go`, `freezer_meta.go`, `freezer_utils.go`,
  `chain_freezer.go`, `ancient_scheme.go`, `ancient_utils.go`,
  `key_length_iterator.go` — none exist.
- `params.FullImmutabilityThreshold` — not defined anywhere.
- `--datadir.ancient` flag — `grep -ri ancient cmd/` returns nothing.
- `node.OpenDatabaseWithFreezer` — not present; `eth/backend.go:129` and
  `cmd/utils/flags.go:1817` both call plain `stack.OpenDatabase("chaindata", …)`.
- `BlockChain.InsertReceiptChain(blocks, receipts)` has **no** `ancientLimit`
  parameter (`core/blockchain.go:1363`); the downloader
  (`eth/downloader/downloader.go:1887,1897`) calls the 2-arg form and contains
  zero ancient-related logic.
- `core/rawdb/chain_iterator.go` does not exist and there are **zero** hits for
  `TxLookupLimit` anywhere — the tx-lookup index is never unwound today.
- No `les`/`light` packages (deleted in this fork) — one less consumer to fix.
- Trie is hash-scheme-centric (`PathScheme` const exists in
  `core/rawdb/accessors_trie.go:45` but no pathdb backend under `trie/triedb/`).

**Consequence:** the *state* freezer, the *trienode* freezer, verkle variants
and the BAL table are all **out of scope**. Only the **chain freezer** is
ported.

---

## 2. Reference version: go-ethereum v1.17.5

Pin **v1.17.5** (latest release at time of writing). Record the exact tag in
each ported file header as `// ported from go-ethereum v1.17.5 <path>`.

### 2.1 Why the newest tag, not v1.14

Because **v1.17 already implements the core of minimal mode.** `Freezer` no
longer has a single scalar tail; it has per-group tails, and each table declares
its group in `freezerTableConfig`:

```go
type freezerTableConfig struct {
    noSnappy  bool   // disable item compression
    tailGroup string // logical group of tables sharing a tail position
}
```

Chain freezer assignments upstream:

| Table | Tail group | Prunable |
|---|---|---|
| `headers` | *(none)* | **no** |
| `hashes` | *(none)* | **no** |
| `bodies` | `ChainFreezerBlockDataGroup` = `"blockdata"` | yes |
| `receipts` | `ChainFreezerBlockDataGroup` = `"blockdata"` | yes |
| `bals` | `ChainFreezerBALGroup` = `"bal"` | yes (out of scope) |

That is essentially the exact retention policy this project wants: headers and
hashes unprunable, bodies and receipts pruned together. The interface reflects
it: `Tail(group string) (uint64, error)` and
`TruncateTail(group string, tail uint64) (uint64, error)`.

Had we pinned v1.14, Phase 2 would have required surgery on `Freezer.repair()`
to relax its single-global-tail invariant, a custom `tails map`, and a bespoke
`TruncateTableTail`. All of that is now upstream, maintained, and tested.

### 2.2 What must be stripped from the v1.17 port

- State freezer (`stateHistoryMeta`, `account.index`, `storage.index`,
  `account.data`, `storage.data`) and `MerkleStateFreezerName` /
  `VerkleStateFreezerName` — no pathdb in this fork.
- Trienode freezer (`trienode.header`, `trienode.key`, `trienode.value`,
  `MerkleTrienodeFreezerName` / `VerkleTrienodeFreezerName`).
- `ChainFreezerBALTable` / `ChainFreezerBALGroup` (EIP-7928 block access lists).
- Era / era1 history export and `--history.chain` — not needed, and the name
  would collide confusingly with our `--history.mode`.

### 2.3 What must be added back

Nothing schema-wise. Upstream dropped the `diffs` table post-merge and we are
**not** re-adding it — see §3.4.

---

## 3. Phase 1 — Port the ancient DB

### 3.1 New interfaces (`ethdb/database.go`)

Adopt the v1.17 shape verbatim. This is a **breaking interface change**; every
implementation must be updated in the same commit.

```go
type AncientReaderOp interface {
    Ancient(kind string, number uint64) ([]byte, error)
    AncientRange(kind string, start, count, maxBytes uint64) ([][]byte, error)
    AncientBytes(kind string, id, offset, length uint64) ([]byte, error)
    Ancients() (uint64, error)
    Tail(group string) (uint64, error)
    AncientSize(kind string) (uint64, error)
}

type AncientReader interface {
    AncientReaderOp
    ReadAncients(fn func(AncientReaderOp) error) error
}

type AncientWriter interface {
    ModifyAncients(func(AncientWriteOp) error) (int64, error)
    SyncAncient() error
    TruncateHead(n uint64) (uint64, error)
    TruncateTail(group string, n uint64) (uint64, error)
}

type AncientWriteOp interface {
    Append(kind string, number uint64, item interface{}) error
    AppendRaw(kind string, number uint64, item []byte) error
}

type AncientStore interface { AncientReader; AncientWriter; Stater; io.Closer }

type ResettableAncientStore interface { AncientStore; Reset() error }
```

Notes:
- `HasAncient` is gone upstream; callers use `Ancient` + error check or
  `Ancients()` bounds. Audit `core/rawdb/table.go` and `XDCxDAO` accordingly.
- `Sync()` was renamed `SyncAncient()`; do not confuse it with
  `KeyValueStore.Sync` if this fork has one.
- Keep `XDCxDatabase` untouched.

### 3.2 New files in `core/rawdb`

Ported near-verbatim (module path rewritten `github.com/ethereum/go-ethereum` →
`github.com/XinFinOrg/XDPoSChain`, `log`/`metrics` imports repointed):

| File | Contents |
|---|---|
| `freezer.go` | `Freezer` struct (`head atomic.Uint64`, `tails map[string]*atomic.Uint64`, `tables`, `instanceLock`), `NewFreezer`, `repair()`, all read/write/truncate methods |
| `freezer_table.go` | **replaces** the current stub: `freezerTable`, index file, data files, `repair`, `truncateHead`, `truncateTail`, `releaseFilesBefore`, snappy handling |
| `freezer_batch.go` | `freezerBatch` / `freezerTableBatch`, `Append`, `AppendRaw`, `commit` |
| `freezer_meta.go` | `freezerTableMeta` (version + `virtualTail`), rlp-encoded in `*.meta` |
| `freezer_utils.go` | `copyFrom`, `openFreezerFileForAppend`, `truncateFreezerFile`, `openFreezerFileTruncated` |
| `chain_freezer.go` | `chainFreezer` + the background `freeze(db)` loop, `freezeRange`, threshold handling |
| `ancient_scheme.go` | `ChainFreezerName = "chain"`, the four table consts, `chainFreezerTableConfigs` with `noSnappy` + `tailGroup`, `ChainFreezerBlockDataGroup = "blockdata"` |
| `ancient_utils.go` | `inspectFreezers`, `freezerInfo` — feeds `InspectDatabase` |
| `key_length_iterator.go` | needed by the ancient-aware iteration in `InspectDatabase` |

**Snappy policy** (from upstream, keeps on-disk layout geth-compatible):
`hashes` uncompressed; `headers`, `bodies`, `receipts` snappy-compressed.

### 3.3 Modified files in `core/rawdb`

- `database.go`
  - Replace the `nofreezedb` ancient methods with the v1.17 stub set
    (`errNotSupported` everywhere, plus a `ReadAncients` that runs `fn(db)` so
    callers work uniformly, and `Tail(group)` / `TruncateTail(group, n)`).
  - Add `freezerdb` wrapper (`ethdb.KeyValueStore` + `ethdb.AncientStore`,
    `Close` closes both, `Freeze`/`AncientDatadir` accessors).
  - Add `NewDatabaseWithFreezer(db ethdb.KeyValueStore, ancient, namespace string, readonly bool) (ethdb.Database, error)` with all upstream consistency
    checks:
    - genesis-in-freezer vs genesis-in-leveldb mismatch → refuse to start;
    - freezer non-empty but leveldb has no ancient marker → refuse;
    - leveldb head < freezer head → truncate freezer head;
    - `ReadAncientDatadir` / `WriteAncientDatadir` marker so a relocated ancient
      dir is detected.
  - Add `resolveChainFreezerDir` (`<ancient>/chain`).
  - **Line 201:** drop `freezerDifficultyTable` from the inspected category
    list, leaving `headers`, `bodies`, `receipts`, `hashes`.
- `table.go` — forward all new reader/writer methods; drop `HasAncient`.
- `accessors_chain.go` — switch batched read paths to
  `db.ReadAncients(func(reader ethdb.AncientReaderOp) error { … })` for
  `ReadCanonicalHash`, `ReadHeaderRLP`, `ReadBodyRLP`, `ReadReceiptsRLP`,
  `HasBody`, `HasReceipts`. Add `WriteAncientBlocks` (the `ModifyAncients`
  writer used by fast sync and the freeze loop). **`ReadTdRLP` / `ReadTd` are
  left exactly as they are.**
- `schema.go` — **delete** `freezerDifficultyTable` (line 108-109); add
  `ancientKey` / `ancientDatadirKey` metadata keys.

### 3.4 Total difficulty: stays in leveldb (decision)

Upstream removed the `diffs` freezer table in v1.15 because TD is meaningless
post-merge. XDPoSChain still uses TD across 13 non-test files
(`core/blockchain.go`, `core/blockchain_reader.go`, `core/genesis.go`,
`core/headerchain.go`, `eth/downloader/downloader.go`, `eth/handler.go`,
`eth/sync.go`, `eth/api_backend.go`, `ethstats/ethstats.go`,
`internal/ethapi/{api,backend,simulate}.go`).

**Decision: never freeze TD.** It remains a leveldb key
(`headerTDKey(number, hash)`), exactly as today.

- Read path cost: **zero** — `ReadTdRLP` already reads only from leveldb.
- Cleanup: remove the now-unused `freezerDifficultyTable` const and its entry in
  `InspectDatabase`.
- **CORRECTION (found during Phase 1 implementation).** This section previously
  claimed the decision had *zero* implementation cost. That was wrong, and the
  error was load-bearing. The chain freezer's post-freeze cleanup wipes the
  key-value copies of every frozen block via `deleteBlockWithoutNumber`, which
  calls `DeleteTd`. Upstream can do that because it has copied TD into the
  `diffs` ancient table first. With that table removed, the freeze loop was
  **permanently destroying total difficulty for every frozen block** — silently,
  with no error. Fixed by `deleteFrozenCanonicalBlock` in `chain_freezer.go`,
  which deletes receipts, header and body but deliberately preserves TD.
  Regression-locked by `TestTotalDifficultyNeverFrozen`.
  Lesson for Phase 2: "we simply do not use table X" is never free in a codebase
  that also *deletes* on the assumption table X exists.
- **SECOND CORRECTION (found when a fast-synced node was measured).** The same
  decision has a second consequence in the other direction: nothing *writes* TD
  either, once the phase that used to write it stops. When `InsertReceiptChain`
  became the sole writer of fast-synced data (see the correction in §3.5), TD
  had to be derived there — parent TD plus each block's difficulty — and stored
  by both `writeAncient` and `writeLive`. Upstream has no equivalent code to
  copy because upstream has no TD at all. Locked by the TD assertions in
  `TestInsertReceiptChainWritesAncients`.
- **Accepted trade-off:** leveldb retains one TD entry (~40 bytes + key
  overhead) per block forever. At 2s blocks that is roughly 16M blocks/year,
  order ~1 GB/year of leveldb that the freezer will not relieve. This is a known
  limitation, not an oversight; revisit alongside the deferred tx-lookup
  unindexer (§4.5), which has the same shape of problem and should be solved by
  the same follow-up work.

### 3.5 Wiring outside `core/rawdb`

- `params/network_params.go` — add `FullImmutabilityThreshold = 90000`.
- `node/node.go` — add `OpenDatabaseWithFreezer(name string, cache, handles int, ancient, namespace string, readonly bool)`; resolve a relative `ancient`
  against the instance dir, keep absolute paths as-is; register in
  `n.databases` so `Close` shuts the freezer down.
- `eth/ethconfig/config.go` + `gen_config.go` — add `DatabaseFreezer string`
  and regenerate `gen_config.go`.
- `eth/backend.go:129` — call
  `OpenDatabaseWithFreezer(..., config.DatabaseFreezer, ...)`.
- `cmd/utils/flags.go` — add `AncientFlag` (`--datadir.ancient`), set
  `cfg.DatabaseFreezer` in `SetEthConfig`, update `MakeChainDatabase`
  (line ~1817). Register in `cmd/XDC/main.go` flag groups and `cmd/XDC/usage.go`.
- `core/blockchain.go`
  - `SetHead` (lines 827-833): `TruncateAncients` → `TruncateHead`.
  - `InsertReceiptChain(blockChain, receiptChain, ancientLimit uint64, checkFreq int)` — add the
    parameter and the upstream ancient write path (`writeAncient` / `writeLive`
    split, `rawdb.WriteAncientBlocks`, head-fast-block update, tx-lookup
    indexing of the ancient range).
  - Start/stop the chain freezer goroutine with the blockchain lifecycle;
    `Stop()` must wait for the freeze loop to exit.
- `eth/downloader/downloader.go`
  - `BlockChain` interface (line 218): `InsertReceiptChain` gains `uint64, int`.
  - Compute `d.ancientLimit` as upstream does (pivot − `fsMinFullBlocks`,
    clamped by `FullImmutabilityThreshold`); pass it at lines 1887 and 1897.
  - On fast-sync failure, `TruncateHead(frozen)` rollback.

- **CORRECTION (found when a fast-synced mainnet node was measured).** Porting
  only `writeAncient` from v1.17.5 was not enough, and the gap was expensive:
  `db inspect` reported **190 GB of key-value `Headers` alongside 163 GB of
  ancient `Headers`** — the entire header chain stored twice, permanently.

  Cause: v1.17.5's `writeAncient` correctly writes no header to leveldb, but it
  is only correct *in combination with v1.17.5's downloader*, which never calls
  `InsertHeaderChain` at all (grep it: no caller). This fork still runs the
  legacy header phase, which wrote the whole header chain into leveldb before
  the bodies arrived. Nothing ever removed those copies: the background freezer
  only cleans the range it freezes itself, starting at the ancient head, so it
  never revisits the pre-pivot range.

  Two upstream fixes exist and only one applies. v1.10.x, the era of the legacy
  downloader this fork still has, deleted the copies at the end of
  `writeAncient` (`DeleteCanonicalHash` + `DeleteBlockWithoutNumber`, plus a
  `ReadAllHashesInRange` sweep for side forks). v1.17.5 instead removed the
  duplicate *write*. **Decision: adopt the v1.17.5 model** — writing 190 GB only
  to delete it again is pure write amplification.

  What that means concretely:
  - `processHeaders` no longer inserts headers in `FastSync`; the branch is now
    `mode == LightSync` only, which is test-only code in this fork (see the
    deviations list). The downloader diff is two guard changes and nothing else.
  - `InsertReceiptChain` becomes the sole writer of fast-synced data. It
    validates the headers up front (`hc.ValidateHeaderChain`), derives TD
    (§3.4), and `writeLive` now writes `WriteCanonicalHash` + `WriteBlock` +
    TD rather than just the body. Its `HasHeader` precondition and `HasBlock`
    skip are gone, as upstream's are.
  - The head *header* marker now moves with the content, since no header phase
    advances it any more.
  - Fast sync's `errStallingPeer` check against the header head is dropped, as
    upstream dropped it. `testHighTDStarvationAttack` still passes via the
    existing `!gotHeaders` check; `testHeaderHeadLag` is now light-sync only.

  Regression-locked by the key-value assertions in
  `TestInsertReceiptChainWritesAncients`, by
  `TestInsertReceiptChainValidatesHeaders`, and by the "no header without block
  content" invariant added to `assertOwnForkedChain`, which every downloader
  sync test now enforces.

  Note this does **not** reclaim space on an already-synced node — it removes
  the second write, so an affected database has to be resynced.

  Lesson, and it is the same shape as the TD one above: a function copied from
  upstream is only correct together with its callers. Check what upstream
  *removed* around it, not just what it kept.
- `XDCxDAO/interfaces.go`, `XDCxDAO/leveldb.go`, `XDCxDAO/mongodb.go` — update
  stub ancient methods to the new signatures. These stay `errNotSupported`;
  XDCx does not get a freezer.

### 3.6 Commands / tooling

- `cmd/XDC/dbcmd.go` (create) or extend `chaincmd.go`: `XDC db inspect`,
  `XDC db freezer-index <table> <start> <end>`. Cheap to port, essential for
  Phase 2 verification.
- `XDC removedb` must prompt separately for state data vs ancient data.
- `XDC import` / `export` / `init` must open the DB with the freezer.

### 3.7 Testability hooks (do these in Phase 1)

`FullImmutabilityThreshold = 90000` at ~2s blocks means ~2 days before the first
block freezes. Add two **hidden/dev** overrides:

```
--history.immutabilitythreshold <n>    (hidden, default 90000, HARD FLOOR 10000)
XDC_FREEZER_TABLE_SIZE=<bytes>         (env, default upstream 2 GiB)
```

Both log a loud `log.Warn` when set. Every integration test in §5 depends on the
first; Phase 2 depends on the second to produce ≥3 data files per table within a
soak window.

> **The floor is not optional.** The audit in §3.10 establishes that XDPoS
> consensus reads block bodies and receipts up to **1800 blocks** back
> (2 × `RewardCheckpoint`, which is 900 on every network). An earlier draft of
> this plan proposed `--history.immutabilitythreshold 200` for the soak tests;
> that value places the freeze boundary *inside* the consensus lookback window.
> Harmless in Phase 1 (frozen reads still resolve), but **fatal in Phase 2**,
> where it would prune bodies that the reward hooks then dereference without a
> nil check. The flag rejects any value below `params.MinFullImmutabilityThreshold`,
> which is set to **10000** — deliberately far above the known 1800-block depth,
> so that a future consensus change with a deeper lookback does not silently
> outgrow the floor. Use **10000** in all tests.

> **Soak-duration consequence of the 10000 floor.** At the local subnet's 2s
> block period, a node must reach ~10000 blocks — roughly **5.5 hours** — before
> the first freeze cycle can fire. The ">= 2 hours / >= 3000 blocks" target in
> §5.4 is therefore *no longer sufficient to exercise the freezer at all*. Either
> run the soak for >= 7 hours, or drop the subnet's block period (XDPoS
> `period`/`minePeriod`) for test genesis so 10000 blocks arrive sooner. Decide
> this before writing the compose harness; a soak that never freezes is worse
> than no soak, because it looks green.

### 3.10 XDPoS per-block data audit (completed)

This was the blocking item from earlier drafts. Result: **Phase 1 is safe;
Phase 2 has a hard retention floor and needs five defensive fixes.**

#### Clean — nothing number-keyed, nothing orphaned by freezing

`core/rawdb/accessors_xdc.go` holds no number-keyed per-block data:

- `ReadXdposV1Snapshot` / `ReadXdposV2Snapshot` / `WriteXdpos*` /
  `DeleteXdposSnapshot` are all keyed by **block hash** (`xdposV1Key(hash)`,
  `xdposV2Key(hash)`).
- Every one of them is typed `ethdb.KeyValueReader` / `ethdb.KeyValueWriter`,
  **not** `ethdb.Reader` — so they physically cannot reach the ancient store.
  Snapshots stay in leveldb regardless of what the freezer does.
- `ReadSectionHead` / `WriteSectionHead` are section-keyed (bloom-bits), and
  `randomizeKey` / `validSectionsKey` are singletons. None interact with the
  freezer.

Also confirmed: **`Penalties` is a header field**, not body data
(`core/types/block.go:84`; `Block.Penalties()` at :455 returns
`b.header.Penalties`). Epoch penalty extraction is therefore header-only in
substance, even where the code fetches a whole block to get at it.

And the engine holds the freezer-aware handle: `eth/backend.go:148` passes
`chainDb` into `CreateConsensusEngine`, so `XDPoS.GetDb()` → `ReadRawReceipts`
resolves frozen receipts transparently. No change needed for Phase 1.

#### Consensus reads into old blocks — depth and guard status

| Site | Reads | Lookback depth | Nil guard |
|---|---|---|---|
| `contracts/utils.go:340-343` (`GetRewardForCheckpoint`) | bodies (`block.Transactions()`) **and receipts** (`rawdb.ReadRawReceipts`) | **~1800** (2 × `RewardCheckpoint`) | **none** |
| `eth/hooks/engine_v1_hooks.go:45` | whole block → `GetSignersFromContract` → `statedb.GetSigners(block)` | **900** (one epoch) | **none** |
| `eth/hooks/engine_v1_hooks.go:147-148` | `block.Transactions()` | **150** (`RangeReturnSigner`) | **none** |
| `eth/hooks/engine_v2_hooks.go:176-179` | `block.Transactions()` | 150 | `if block != nil` ✅ |
| `eth/hooks/engine_v2_hooks.go:247-249` | `block.Transactions()` | 150 | `if block != nil` ✅ |
| `eth/hooks/engine_v2_hooks.go:525-528` | `block.Transactions()` | ~1800 | `if block != nil` ✅ |
| `consensus/XDPoS/engines/engine_v1/engine.go:1028-1029` (`removePenaltiesFromBlock`) | `GetBlock(...)` then `.Penalties()` — **header data only** | epoch boundary | **none** |
| `eth/api_backend.go:584` (`GetVotersCap`) | `GetBlockByNumber(checkpoint).Root()` | **RPC-supplied, unbounded** | **none** |

Constants confirmed: `RewardCheckpoint = 900` on mainnet, testnet and devnet
(`params/config_networks.go:305,413,474,540`) and in the local `genesis.json`;
`common.RangeReturnSigner = 150`, `common.MergeSignRange = 15`,
`common.LimitPenaltyEpoch = 4` (`common/constants.go:16,20,21`).

**Maximum consensus lookback into block bodies/receipts: 1800 blocks.**

#### Conclusions

1. **Phase 1 is safe by a wide margin.** 1800 ≪ 90000, so with the default
   threshold every consensus lookback is served from leveldb; and where it does
   reach the freezer, reads resolve normally. No freezing-related breakage.
2. **Phase 2 has a hard retention floor.** Minimal mode's tail must never rise
   above `head - 2*RewardCheckpoint` (1800 blocks). This is a **consensus
   correctness requirement, not a tuning preference** — encode it as a constant
   with a comment pointing at `GetRewardForCheckpoint`, and clamp the pruner
   against it in addition to the data-file boundary rule from §4.2. In practice
   the file-boundary rule will usually dominate, but the clamp must exist so a
   small `XDC_FREEZER_TABLE_SIZE` in testing cannot prune into the window.
3. **Five missing nil guards** should be fixed defensively regardless of mode —
   the v2 hooks already show the intended pattern. The v1 paths and
   `removePenaltiesFromBlock` predate it.
4. **`removePenaltiesFromBlock` should not fetch a block at all.** It reads only
   `block.Penalties()`, which is header data. Rewrite as
   `chain.GetHeaderByNumber(epochNumber).Penalties` — removes a body read from
   the epoch-switch path entirely, which is both a small performance win and one
   less pruning hazard. Note it also dereferences `header` without a nil check.
5. **`GetVotersCap` is an RPC-reachable panic vector** under minimal mode: the
   caller supplies an arbitrary checkpoint number, and a pruned block yields
   `nil` before `.Root()`. Guard it and return a clear error (this folds into
   the §4.4 ethapi work).

### 3.8 Phase 1 risks

| Risk | Mitigation |
|---|---|
| XDPoS stores extra per-block data (snapshots, masternode sets); freezing bodies must not orphan it | Audit `core/rawdb/accessors_xdc.go` + `consensus/XDPoS/engines/*/snapshot.go` for number-keyed data. XDPoS snapshots appear hash-keyed and should survive — **confirm before merging**. |
| `InsertReceiptChain` signature change ripples into `core/blockchain_test.go`, `eth/downloader/*_test.go` and XDC chain wrappers | Compile-wide `go build ./...` + `go vet ./...` gate |
| v1.17 interfaces (`AncientBytes`, `Tail(group)`, `SyncAncient`) are far from this fork's; large mechanical diff in `table.go` and `XDCxDAO` | Do the interface swap as one isolated commit (§6 step 3) so review is tractable |
| Reorgs deeper than the freeze threshold become unrecoverable | Same as upstream — accepted; XDPoS v2 finality makes deep reorgs a non-issue |
| Windows: file-handle release on delete is stricter | Ported `releaseFile` must `Close()` before `Remove()`; run `go test ./core/rawdb/...` on Windows |

### 3.9 Upgrading an existing datadir: background freeze (decision)

When a node that already has a large `chaindata` starts with `--datadir.ancient`
for the first time, **the node opens for business immediately** and the chain
freezer's background goroutine works through the backlog while the node syncs
and serves RPC. This is upstream's behaviour; no blocking migration, no separate
`db migrate-ancient` command.

Implications that must be handled, not just accepted:

- **Sustained heavy I/O for a long time.** On a mainnet-height datadir the
  backlog is millions of blocks. The freeze loop must stay rate-limited and must
  never starve block processing. Verify the ported loop keeps upstream's batch
  size and its `backoff` behaviour on error.
- **leveldb does not shrink until compaction.** Operators will see the ancient
  directory grow while `chaindata` stays large for a while. This is the single
  most likely support question — it belongs in the release notes, not just the
  code.
- **Progress must be observable.** Log `log.Info("Freezing legacy chain data", "frozen", …, "remaining", …)` at a sane interval, and expose a
  `rawdb/chainfreezer/backlog` gauge. Without this an operator cannot tell a
  working migration from a stuck one.
- **Interruptible and resumable.** Killing the node mid-backlog must be safe:
  `repair()` on restart aligns the tables and the loop resumes from the current
  head. This is covered by §5.3 step 4, but exercise it specifically against a
  large backlog, not just a fresh chain.
- **Release-note requirement:** state plainly that the first start after upgrade
  causes extended background I/O, that `--datadir.ancient` should point at
  spinning-rust-friendly storage if the operator is separating devices, and that
  the ancient directory must be backed up alongside `chaindata` from then on —
  they are no longer independently useful.

---

## 4. Phase 2 — Minimal mode

**Only start after Phase 1 has passed §5 in full.**

Thanks to v1.17's tail groups, this phase is now small.

### 4.1 Semantics

New flag: `--history.mode <full|minimal>` (default `full`).

In `minimal` mode, while the node runs:

- `headers` and `hashes`: no tail group → **never** pruned. Full header chain is
  retained, so the node still validates, serves headers, and answers
  header-only queries for all of history.
- `bodies` and `receipts` (`blockdata` group): after each freeze cycle,
  `TruncateTail("blockdata", n)` where `n` is chosen so that **only the newest
  data file per table remains**. Older `.cdat` files are deleted from disk.
- Live (non-frozen) blocks in leveldb are untouched — the last
  `FullImmutabilityThreshold` blocks always have full bodies and receipts.

This mirrors reth's minimal-mode intent: keep the header chain and a recent
window of bodies/receipts, drop the rest.

**Initial sync behaviour (decision): write then prune.** A node syncing from
scratch in minimal mode writes bodies and receipts to the freezer exactly as a
full node does; the pruner then deletes older data files as it goes. There is
**no** second code path that skips writes below the tail.

- Upside: minimal mode is one mechanism, not two. The downloader's
  `ancientLimit` logic, `WriteAncientBlocks`, and the pruner are all the same
  code that full mode exercises, so §5.4's full-mode soak covers most of it.
- Accepted cost: **transient peak disk exceeds the steady state.** Between one
  pruner pass and the next, the node holds up to a full data file more than it
  will settle at. Sizing guidance in the release notes must quote the peak, not
  the steady state, or operators will provision too small a disk and fail
  mid-sync.
- Test hook: §5.5 must assert peak ancient-dir size during sync, not only the
  post-soak size, so this cost stays visible if the pruner interval regresses.

### 4.2 Choosing the truncation point

`TruncateTail(group, n)` takes an *item number*, and upstream's
`freezerTable.truncateTail` only frees disk when the new tail crosses a data
file boundary (`releaseFilesBefore` deletes whole `.cdat` files; a mid-file tail
merely hides items via `virtualTail`).

So add one small helper on `freezerTable`:

```go
// tailFileBoundary returns the item number of the first item stored in the
// newest data file, i.e. the largest tail that still deletes whole files.
func (t *freezerTable) tailFileBoundary() (uint64, error)
```

It reads `t.headId` and the index entry at that file's start. The pruner then
calls `TruncateTail(ChainFreezerBlockDataGroup, tail)` where

```go
tail = min(
    min(tailFileBoundary() over the group's tables),   // only delete whole files
    head - xdposConsensusLookback,                     // §3.10 floor, MANDATORY
)
```

The first `min` keeps the group's tables consistent — exactly the invariant the
group abstraction exists to protect — and guarantees pruning only ever deletes
whole files, never rewrites one.

The second term is the **consensus retention floor** established by the §3.10
audit:

```go
// xdposConsensusLookback is the deepest a consensus code path reaches back
// into block bodies and receipts. GetRewardForCheckpoint (contracts/utils.go)
// walks 2*RewardCheckpoint blocks back reading Transactions() and raw
// receipts. Pruning above this line breaks reward and penalty calculation.
xdposConsensusLookback = 2 * chainConfig.XDPoS.RewardCheckpoint // 1800 on all networks
```

Do not treat this as belt-and-braces. The file-boundary term usually dominates
at production `freezerTableSize`, which means a bug in the floor would stay
invisible until someone shrinks `XDC_FREEZER_TABLE_SIZE` — i.e. exactly during
the soak tests, or on a small subnet. Assert it directly in a unit test rather
than relying on the boundary term to mask it.

### 4.3 The pruner

New file `core/rawdb/minimal_pruner.go` (or extend `chain_freezer.go`):

- Runs inside the existing chain-freezer goroutine, immediately after each
  successful `freezeRange` commit — no second goroutine, no extra locking.
- Computes the group boundary per §4.2 and calls `TruncateTail`.
- Skips if nothing new was frozen.
- Logs `log.Info("Pruned ancient block data", "tail", …, "files_deleted", …)`
  and exposes metrics `rawdb/minimal/pruned/{bodies,receipts}`.

### 4.4 Consumers that must tolerate a pruned tail

| Site | Required behaviour |
|---|---|
| `core/rawdb/accessors_chain.go` `ReadBodyRLP` / `ReadReceiptsRLP` | Already returns `nil` on freezer error → OK, but add a tail check first so we don't log-spam `errOutOfBounds` |
| `core/blockchain.go` `GetBlock`, `GetReceiptsByHash` | Return `nil` cleanly; must not panic when the header exists but the body doesn't |
| `eth/handler.go` `GetBlockBodies` / `GetReceipts` | Skip pruned entries (the protocol permits short responses) |
| `internal/ethapi/api.go` | `eth_getBlockByNumber(fullTx=true)`, `eth_getTransactionByHash`, `eth_getTransactionReceipt`, `eth_getLogs` over pruned ranges → return a clear `"block body pruned; node runs in minimal history mode"` error. `fullTx=false` still works from headers. **This guard is mandatory, not optional — see §4.5.** |
| `consensus/XDPoS/api.go` `GetV2BlockByNumber` etc. | Uses headers + snapshots; snapshots are hash-keyed in leveldb (§3.10) so they survive pruning |
| `eth/hooks/engine_v1_hooks.go:45,147` | **Add nil guards** — currently dereference `chain.GetBlock(...)` unchecked. Mirror the `if block != nil` pattern already used in `engine_v2_hooks.go:177,248,526` |
| `consensus/XDPoS/engines/engine_v1/engine.go:1028` `removePenaltiesFromBlock` | **Rewrite to read the header only** — `Penalties` is header data (§3.10), so the `GetBlock` call is unnecessary. Also add the missing nil check on `GetHeaderByNumber` |
| `eth/api_backend.go:584` `GetVotersCap` | **RPC-reachable panic vector**: arbitrary caller-supplied checkpoint → `nil` block → `.Root()`. Guard and return the "pruned" error |
| `contracts/utils.go:340-343` `GetRewardForCheckpoint` | Protected by the §4.2 retention floor, but add a nil guard + explicit error anyway; a silent wrong reward is worse than a loud failure |
| snap/fast sync serving | A minimal node cannot serve receipts for old pivots. Log a startup warning; do not advertise as an archive peer. |

### 4.5 Deferred: tx-lookup index pruning (decision)

**Not in Phase 2.** This fork has no `chain_iterator.go` and no `TxLookupLimit`,
so the tx-lookup index is never unwound. Consequences we knowingly ship:

1. leveldb keeps growing with one tx-lookup entry per transaction, forever.
   Combined with the TD entries (§3.4), minimal mode shrinks the ancient
   directory but does **not** bound total disk usage.
2. `eth_getTransactionByHash` for a pruned transaction will resolve the hash to
   a block number whose body has been deleted. **Without the §4.4 ethapi guard
   this returns a wrong/misleading answer rather than an error** — which is why
   that guard is listed as mandatory.

Follow-up ticket to file: port `core/rawdb/chain_iterator.go` + a
`--txlookuplimit` equivalent, and revisit freezing or pruning TD at the same
time.

### 4.6 Mode persistence + safety

- Persist the mode in leveldb (`rawdb.ReadHistoryMode` / `WriteHistoryMode`).
- Startup checks:
  - stored `minimal`, flag says `full` → **fatal**: "this datadir has pruned
    history and cannot be run in full mode; resync required".
  - stored `full`, flag says `minimal` → allowed; first freeze cycle prunes. Log
    a loud one-time warning that this is irreversible.
- `XDC db inspect` reports the mode and each group's tail.

**No role-based guardrail (decision).** Minimal mode is *not* refused for
validators, masternodes, or `--mine` nodes. Operators decide, the same way they
decide `--gcmode`. The only hard refusal is `--history.mode minimal` together
with `--gcmode archive`, which is a self-contradictory configuration rather than
a policy judgement.

Instead, emit a prominent startup banner (once, at `log.Warn`), along the lines
of:

```
WARN Node running in minimal history mode
     This node has pruned block bodies and receipts and CANNOT serve
     historical chain data to syncing peers. A network needs at least one
     full-history node to bootstrap new members. Pruning is irreversible
     for this datadir.
```

- **Accepted risk, stated plainly:** a subnet whose validators *all* enable
  minimal mode silently loses the ability to bootstrap any new node, and the
  failure surfaces only when someone tries to join. The warning is the entire
  mitigation. This trade-off was chosen deliberately over a hard `--mine`
  refusal, partly because `--mine` lives in `cmd/utils/flags_legacy.go` and
  would not reliably detect every masternode deployment anyway.
- **Documentation requirement:** operator docs must state the "keep at least one
  full node per network" rule explicitly. §5.5's mixed-mode control run (two
  minimal + one full) is the tested reference topology.

---

## 5. Test & verification harness

Run all of §5.1–§5.4 at the end of Phase 1, then again (plus §5.5) at the end of
Phase 2.

### 5.1 Unit tests (ported + adapted)

From geth v1.17.5, adapted to this package path:

- `core/rawdb/freezer_test.go` — append/read/truncate, concurrent read/write,
  per-group tail behaviour.
- `core/rawdb/freezer_table_test.go` — the big one: corrupt index, corrupt data
  file, truncated head, truncated tail, offset repair, snappy/no-snappy, file
  boundary edges, `TestFreezerReadonly`.
- `core/rawdb/freezer_batch_test.go`, `freezer_utils_test.go`,
  `ancient_utils_test.go`.
- Extend `core/rawdb/accessors_chain_test.go` with ancient variants
  (`TestAncientStorage`, `TestBlockReceiptStorage` on a freezer-backed db).
- Update `core/rawdb/table_test.go` for the new passthroughs.
- New `TestNewDatabaseWithFreezerMismatch` — genesis mismatch, head mismatch,
  relocated ancient dir. These prevent silent corruption.
- New `TestTdNotFrozen` — assert TD round-trips through leveldb only and that no
  `diffs` table is created on disk.

Gate: `go test ./core/rawdb/... ./ethdb/... -count=1 -race`

### 5.2 Package-level regression

```
go build ./...
go vet ./...
go test ./core/... ./eth/... ./node/... ./consensus/... ./internal/... -count=1
go test ./core/... ./eth/downloader/... -race -count=1
```

Confirm `core/blockchain_test.go` fast-sync tests and `eth/downloader` tests
pass with the new `ancientLimit` parameter.

### 5.3 Single-node smoke test

Using `cicd/Dockerfile` + `cicd/local/start.sh` and a puppeth-generated
`genesis.json` (one already exists untracked at the repo root, along with
`puppeth.exe`):

1. `docker build -f cicd/Dockerfile -t xdc-ancient:test .`
2. Run one node with `NETWORK=local`, `--datadir.ancient /work/ancient`,
   `--history.immutabilitythreshold 10000`.
3. Mine past block 400. Assert:
   - `/work/ancient/chain/` contains `headers.*.cdat`, `bodies.*.cdat`,
     `receipts.*.cdat`, `hashes.*.rdat` with matching `.cidx`/`.ridx`;
   - **no `diffs.*` files exist** (TD stayed in leveldb);
   - `XDC db inspect` shows non-zero ancient counts;
   - `eth_getBlockByNumber("0x1", true)` returns a full block from the freezer
     (confirm the leveldb body key is gone via `XDC db get`).
4. **Crash recovery:** `docker kill -s KILL` mid-freeze, restart, assert the node
   reaches the same head and `repair()` lost nothing beyond the last partial item.
5. **Restart idempotence:** clean stop/start 3×; head must be monotonic.

### 5.4 3-node local subnet soak (primary acceptance gate)

**Harness: hand-rolled `docker-compose.yml` over three `cicd/local` containers.**
This repo already provides everything needed — `cicd/Dockerfile`,
`cicd/local/start.sh` (reads `PRIVATE_KEY`, `PORT`, `RPC_PORT`, `WS_PORT`,
`INSTANCE_IP`, `LOG_LEVEL`), and `cicd/local/README.md` documenting the
`genesis.json` + `bootnodes.list` injection contract (note: `bootnodes.list`
**requires a trailing newline**). Deliverable: `cicd/local/compose-3node/`
containing the compose file, three key files, a shared `bootnodes.list`, and a
`healthcheck.sh` assertion script.

The official Subnet-Deployment wizard is deliberately not used: its docs don't
cover pinning a locally built image or health endpoints, and we need scripted
assertions rather than a UI.

Procedure:

1. Build the image from this branch; compose pins it directly.
2. Launch 3 validators, all with `--datadir.ancient` and
   `--history.immutabilitythreshold 10000`, plus `XDC_FREEZER_TABLE_SIZE` small
   enough to force ≥3 data-file rollovers.
3. Soak **≥ 2 hours** (target ≥ 3000 blocks).
4. Assertions, scripted every 30s in `healthcheck.sh`:
   - `eth_blockNumber` on all 3 nodes within 2 blocks of each other, strictly
     increasing;
   - `net_peerCount` == 2 on each node;
   - `XDPoS_getV2BlockByNumber("latest")` shows a committed block advancing;
   - `XDPoS_getMasternodesByNumber` stable;
   - for 20 random block numbers in `[1, head-300]`,
     `eth_getBlockByNumber(n, true)` returns identical hashes on all 3 nodes;
   - a tx sent at soak start still resolves via `eth_getTransactionReceipt` at
     soak end (i.e. after its block was frozen);
   - no `ERROR`/`CRIT` lines in any log; no `errOutOfBounds` spam;
   - ancient dir grows; leveldb does not grow proportionally.
5. **Restart under load:** restart node 3 at the 1h mark; it must catch up and
   re-agree on all spot-check blocks.
6. **New-node join:** at 1.5h, add a 4th node syncing from scratch. It must
   reach head. This exercises serving frozen bodies/receipts to a syncing peer —
   the most likely place for a Phase 1 bug.

### 5.5 Phase 2 additional tests

Unit:
- `TestTailFileBoundary` — table with 5 data files → exactly 4 deleted, tail
  lands on the first item of file 5, all remaining items readable.
- `TestBlockDataGroupTailIndependent` — `Tail("blockdata") == 3000` while
  `headers`/`hashes` remain at 0; reopen and assert `repair()` accepts it and
  group tails are restored from `.meta`.
- `TestMinimalModeReadPruned` — `ReadBody`/`ReadReceipts` below the group tail
  return `nil`; `ReadHeader` below the tail still returns the header.
- `TestHistoryModeDowngradeRefused` — minimal datadir + `--history.mode full`
  → startup error.

Integration (repeat §5.3 and §5.4 with `--history.mode minimal`):
- Per node after the soak:
  - `ls ancient/chain/bodies.*.cdat | wc -l` == 1 (plus the open head file);
  - same for `receipts.*`;
  - `headers.*.cdat` count **unchanged** vs the full-mode control run;
  - total ancient dir size dramatically smaller than the control.
- **Peak disk during sync**, sampled every 30s throughout the run, not just at
  the end (§4.1). Record the peak-to-steady-state ratio; a regression in the
  pruner interval shows up here and nowhere else. This number is what the
  release-note sizing guidance must quote.
- Node still produces blocks, still finalises, still has 2 peers.
- `eth_getBlockByNumber(n, false)` works for **all** n.
- `eth_getBlockByNumber(n, true)` for pruned n returns the documented
  "body pruned" error — not a panic, not `null`, not a wrong answer.
- `eth_getTransactionByHash` for a pruned tx returns the same clear error
  (this is the §4.5 sharp edge — test it explicitly).
- Recent blocks still return full bodies and receipts.
- Restart a minimal node → tails preserved, no re-download of pruned ranges.
- **Mixed-mode control:** one full-mode node in a subnet with two minimal nodes;
  confirm consensus holds.

### 5.6 CI integration (decision)

The existing `.github/workflows/ci.yml` has a sharded unit-test matrix
(`A-B` … `T-Z` on `ubuntu-latest`), Docker build/push jobs, and k8s deploy jobs.
Slot the new work in as follows:

**Per-PR (existing `Run tests` matrix, no new job):**
- §5.1 and §5.2 land in the existing shards automatically — `core/rawdb` falls in
  the `C-[a-m]` shard. Confirm the new freezer tests do not blow that shard's
  runtime; if they do, split `core/rawdb` out rather than letting one shard
  become the critical path.
- The `-race` runs in §5.2 are the expensive part; keep them scoped to
  `./core/rawdb/... ./ethdb/... ./eth/downloader/...` rather than `./core/...`
  wholesale on PRs.

**Nightly scheduled job (new):**
- Add a `schedule:` trigger running a **shortened soak** — roughly 20 minutes,
  `--history.immutabilitythreshold 10000`, small `XDC_FREEZER_TABLE_SIZE` — over
  the §5.4 compose harness. Runs both `full` and `minimal` modes.
- Reuses the image built by the existing Docker job, so no duplicated build.
- Needs a failure destination: wire it to the existing
  `pr-notify-slack.yml` mechanism, or the nightly will fail unnoticed and the
  harness rots anyway — which is precisely the outcome the nightly is meant to
  prevent.
- `timeout-minutes` must be set explicitly; a hung node otherwise burns a full
  runner slot.

**Manual, at each phase gate:**
- The full ≥2h soak (§5.4) and the complete §5.5 minimal-mode battery, run by
  hand before declaring a phase done. The nightly is a regression net, not a
  substitute for the acceptance gate.

**Known flakiness risk:** `docker compose` multi-container networking on
`ubuntu-latest` runners is not always reliable. Build in a bounded retry for
peer discovery (`net_peerCount` reaching 2) before failing the job, and make the
healthcheck script distinguish "never formed a network" from "network formed
then broke" — only the second is a real regression.

### 5.7 Definition of done

**Phase 1:** §5.1–§5.4 green, `go build ./...` clean on Linux and Windows, and a
full-history node's `eth_getBlockByNumber` answers byte-identical to a pre-port
node on the same chain.

**Phase 2:** §5.5 green **and** §5.4 re-run in full mode still green (no
regression to the default path).

---

## 6. Suggested commit sequence

Phase 1:
1. `core/rawdb: add freezer table implementation` (+ tests)
2. `core/rawdb: add freezer, batch, meta, utils with per-group tails` (+ tests)
3. `ethdb, core/rawdb, XDCxDAO: switch to v1.17 ancient interface`
4. `core/rawdb: add chain freezer and NewDatabaseWithFreezer`
5. `core/rawdb: drop unused diffs freezer table, keep TD in leveldb`
6. `params: add FullImmutabilityThreshold`
7. `node, eth, cmd/utils: wire --datadir.ancient`
8. `core, eth/downloader: thread ancientLimit through InsertReceiptChain`
8b. `core, eth/downloader: make InsertReceiptChain the sole writer of fast-sync
    data` (the §3.5 correction — stops the header chain being stored twice)
9. `cmd/XDC: add db inspect / freezer-index, teach removedb about ancients`
10. `core/rawdb: add hidden immutability-threshold and table-size test overrides`
11. `core/rawdb: add freeze backlog progress logging and metrics`
12. `cicd/local: add 3-node compose harness and healthcheck script`
13. `ci: add nightly ancient-db soak job`

Phase 2:
14. `core/rawdb: add tailFileBoundary helper`
15. `core/rawdb: add minimal-mode ancient pruner`
16. `eth, internal/ethapi: guard pruned bodies/receipts and tx lookups`
17. `cmd/utils, eth: add --history.mode flag, persistence and warning banner`
18. `core/rawdb, eth: tests for minimal mode`
19. `ci: extend nightly soak to cover minimal mode`

---

## 7. Decisions (resolved)

| # | Question | Decision |
|---|---|---|
| 1 | Reference version | **v1.17.5** (latest). Chosen over v1.14 because per-group tails — `bodies`+`receipts` in `blockdata`, `headers`+`hashes` unprunable — are already upstream, which is precisely minimal mode's retention policy. |
| 2 | Minimal-mode flag | **`--history.mode full\|minimal`**. Namespaced, extensible, avoids collision with `--syncmode full` and with upstream's `--history.chain`. |
| 3 | Total difficulty | **Keep in leveldb, never freeze.** Zero implementation cost (`ReadTdRLP` is already leveldb-only). Accepted cost: unbounded leveldb TD growth (§3.4). |
| 4 | Tx-lookup index pruning | **Deferred** to a follow-up. Makes the §4.4 ethapi guard mandatory so pruned lookups error out instead of returning wrong answers (§4.5). |
| 5 | Subnet test harness | **Hand-rolled docker-compose over `cicd/local`**, committed to `cicd/local/compose-3node/`. Official wizard not used. |
| 6 | Existing-datadir migration | **Background freeze, node serves immediately** (§3.9). No blocking migration, no offline command. Requires progress logging, a backlog metric, and explicit release notes about sustained I/O and delayed leveldb shrinkage. |
| 7 | Minimal mode during initial sync | **Write then prune** (§4.1). One mechanism instead of two. Accepted cost: transient peak disk exceeds steady state, so sizing guidance must quote the peak. |
| 8 | Role-based guardrail | **None** (§4.6). Loud startup warning only; the sole hard refusal is `minimal` + `--gcmode archive`. Accepted risk: an all-minimal network silently cannot bootstrap new nodes. |
| 9 | CI integration | **Nightly scheduled shortened soak**, not per-PR (§5.6). Unit tests ride the existing shard matrix. Nightly needs a wired-up failure notification or it rots. |

### Previously-blocking item: now resolved

**XDPoS per-block data audit — completed, see §3.10.** Verdict: XDPoS snapshots
are hash-keyed and leveldb-only, so nothing is orphaned by freezing; Phase 1 is
safe with the default threshold. Phase 2 inherits a hard **1800-block retention
floor** (2 × `RewardCheckpoint`) plus five defensive nil-guard fixes, all folded
into §3.7, §4.2 and §4.4. The audit also invalidated the earlier proposed test
threshold of 200; the flag is now floored at 10000.

---

## 8. Phase 1 implementation status

`go build ./...` clean. `core/rawdb` 69 tests pass (upstream freezer suite plus
XDC-specific), `core`, `eth/downloader`, `node` and `params` all green.

### Landed

- Freezer ported from v1.17.5: `freezer.go`, `freezer_table.go`,
  `freezer_batch.go`, `freezer_meta.go`, `freezer_utils{,_unix,_windows}.go`,
  `freezer_memory.go`, `freezer_resettable.go`, `ancient_scheme.go`,
  `ancient_utils.go`, `chain_freezer.go`, `key_length_iterator.go`, plus the
  `ancienttest` helpers and the full upstream test suite.
- `ethdb` interfaces swapped to the v1.17 shape; `core/rawdb/table.go` and
  `XDCxDAO` updated to match.
- `NewDatabaseWithFreezer` / `Open` with all upstream consistency guards.
- Accessors converted to batched `ReadAncients`; `WriteAncientBlocks` added.
- `node.OpenDatabaseWithFreezer` + `ResolveAncient`; `--datadir.ancient` wired
  through `SetEthConfig` -> `eth/backend.go` and `MakeChainDatabase`.
- `SetHead` uses `TruncateHead`.
- `params.FullImmutabilityThreshold` is now a var with
  `--history.immutabilitythreshold` (hidden, floored at
  `MinFullImmutabilityThreshold` = 10000).
- **Fast-sync direct-to-ancient path**: `InsertReceiptChain` takes
  `ancientLimit`, splitting into `writeAncient` / `writeLive`;
  `eth/downloader` computes `d.ancientLimit`, disables it when live data already
  exists below the freezer head, and rewinds via `SetHead` on deep reorg.
  `BlockChain` interface gained `SetHead`.
- **Single-writer fast sync (v1.17.5 model)**: the fast-sync header phase writes
  nothing; `InsertReceiptChain` stores the header, body and receipts together
  and is the only place downloaded headers are validated. See the correction in
  §3.5 for why, and for the 190 GB it saves.

### Deviations from upstream (all deliberate)

- No state / trienode / verkle freezers, no BAL table, no era layer.
- No `diffs` table: TD is never frozen (§3.4).
- `chainFreezer.freezeThreshold` drops upstream's `max(finality, headLimit)`
  term — `ReadFinalizedBlockHash` is a post-merge beacon marker XDPoS does not
  store. Only the immutability depth is used, which is strictly more conservative.
- `d.ancientLimit` likewise derives from the advertised remote height only
  (upstream's non-merged fallback path); no finality and no chain cutoff.
- `chainFreezer.Ancient` returns `errOutOfBounds` for pruned items instead of
  falling back to an Era store. This is the hook Phase 2 builds on.
- `InsertReceiptChain` does not hold `chainmu` for its body. Upstream v1.17.5
  takes it at the top — `if !bc.chainmu.TryLock()` immediately after the
  unlocked `ValidateHeaderChain` — and holds it for the whole function; this
  fork keeps the pre-port shape and locks only the tail section that moves the
  head markers (`core/blockchain.go:1568`).

  **Which writes are now unlocked.** Before the §3.5 correction the receipt
  phase only wrote content hanging off already-committed headers (body,
  receipts, tx-lookup), and everything canonicality-affecting was written by the
  header phase under `chainmu` (`InsertHeaderChain` → `hc.WriteHeader`).
  `writeLive` now also writes, with no lock held:

  - `rawdb.WriteCanonicalHash` — the canonical marker itself,
  - `rawdb.WriteBlock` — header (and body),
  - `rawdb.WriteTd` — the TD that head selection compares against.

  `writeAncient` similarly writes `WriteHeaderNumber` / `WriteTd` /
  `WriteTxLookupEntriesByBlock` unlocked, after the freezer append. So the
  invariant "canonical markers are only mutated under `chainmu`" no longer
  holds. `writeHeadBlock` (`core/blockchain.go:1059`) is the only other writer
  of `CanonicalHash` / `HeadHeaderHash` that can run in production and is
  reached exclusively under `chainmu`; `writeLive` is not.

  **Why that is safe today.** Nothing imports blocks concurrently with a snap
  sync: `processFastSyncContent` is a single goroutine, so `InsertReceiptChain`
  never overlaps itself, and the block fetcher is barred while snap sync runs,
  so `writeBlockWithState` cannot interleave. That is a property of the callers,
  not a lock. Any future path that runs `InsertReceiptChain` concurrently with
  block import would race on the canonical marker, and since both sides write
  through separate batches with no compare-and-set, the loser would win silently
  for its subset of heights — a canonical mapping mixed from two chains, which
  survives restart. This is a database race, not a Go data race: `-race` cannot
  see it.

  **Why the lock was not simply added.** Not for the reason first recorded here
  (a contended `TryLock` aborting the sync): `syncx.ClosableMutex.TryLock`
  blocks on contention and returns `false` only after `chainmu.Close()`, i.e.
  only during `Stop()` (`internal/syncx/mutex.go:34`). The real costs are
  fork-specific:

  - While parked on the lock the function cannot observe `insertStopped()`.
    `spawnSync` ends every sync with `d.Cancel()` → `InterruptInsert(true)` →
    `cancelWg.Wait()` (`eth/downloader/downloader.go:654`), and
    `processFastSyncContent` is one of the fetchers waited on. Today it bails
    out at once; with the acquire at the top, teardown would wait out whoever
    holds `chainmu` — including fork-only long holders such as `ExportN`
    (`core/blockchain.go:1024`, held across an entire RPC-driven export) and
    XDPoS's `insertBlock` masternode / trading-state work. Stalls, not deadlock:
    no cycle exists, every holder does finish.
  - The locked region would be much heavier than upstream's. Upstream receives
    pre-encoded receipts (`[]rlp.RawValue`) and has no TD at all; this fork runs
    `DeriveFields` plus `encodeStorageReceipts` per block and a `GetTd` per
    block, on top of the same `WriteAncientBlocks` and `SyncAncient()` fsync.
  - `procInterrupt` is dual-owned here. Upstream's flag is monotonic (set once
    at shutdown), which is what licenses its long critical section — see the
    `Stop()` comment, "since we also called StopInsert, the mutex should become
    available quickly". This fork's `Stop()` sets it (`core/blockchain.go:1235`)
    but `Downloader.Cancel()` clears it at the end of every sync
    (`eth/downloader/downloader.go:657`), so a `Cancel()` finishing just after
    `Stop()` begins wipes the shutdown interrupt and `chainmu.Close()` then
    waits out the full batch. Pre-existing, but a longer critical section makes
    it bite harder.

  **Consequences.** The head-header write is pushed forward only (upstream
  writes it unconditionally, safe under its whole-function lock), and the head
  update stays in the existing tail section.

  **Follow-up (out of scope for this port).** Adopting upstream's whole-function
  lock restores the invariant and is the right end state: acquire after
  `ValidateHeaderChain`, delete the tail re-lock (`ClosableMutex` is not
  reentrant — a second acquire on the same goroutine blocks forever), restore
  the unconditional head update, remap `errChainStopped` at the two downloader
  call sites so shutdown does not surface as `errInvalidChain` and drop a peer,
  and split `procInterrupt` into a monotonic shutdown flag plus a
  downloader-scoped one. Held back because it changes cancel and shutdown
  semantics on a path XDPoS consensus shares, and deserves its own testing.
- `ValidateHeaderChain` is called with a caller-supplied `checkFreq` rather than
  upstream's verify-every-header. The downloader passes `fsHeaderCheckFrequency`
  (0), exactly what its header phase used to pass to `InsertHeaderChain`, so
  pre-pivot seal checking is unchanged from before the port. XDPoS/ethash seals
  are not free, and post-pivot blocks are still fully verified by `InsertChain`.
- `InsertReceiptChain` early-returns on an empty chain: this fork's
  `ValidateHeaderChain` panics on an empty slice (`seals[len(seals)-1]`),
  upstream's has no seals logic.
- The `LightSync` branch of `processHeaders` is retained, with its
  `InsertHeaderChain` call and header rollback. Note this is **test-only** code:
  `eth/backend.go:114` rejects `LightSync` at startup ("light mode has been
  deprecated") and the fork has no `les`/`light` packages. It is kept because
  the downloader test suite exercises the mode, not because it can run.
  Consequence worth recording: after the §3.5 correction `bc.InsertHeaderChain`
  has **no production caller left**, which is exactly upstream v1.17.5's
  property. `writeHeadBlock` is the only other head-header writer that can
  actually run.

### Bugs found and fixed during implementation

1. **TD was being silently destroyed.** See the correction in §3.4. Fixed by
   `deleteFrozenCanonicalBlock`; locked by `TestTotalDifficultyNeverFrozen`.
2. **Freezer handle leaked on `Open`'s rejection paths.** Upstream returns
   without closing the freezer when a consistency guard fires; harmless for geth
   (it exits) but it locks the ancient files, and on Windows the caller cannot
   even delete the directory afterwards. Fixed with a deferred close.
3. **The whole header chain was stored twice after a fast sync** — 190 GB of
   key-value `Headers` next to 163 GB of ancient `Headers` on mainnet, and
   permanent, because the freezer never revisits the pre-pivot range. See the
   correction in §3.5. Fixed by adopting v1.17.5's single-writer model rather
   than v1.10.x's delete-after-freeze. Requires a resync to benefit.

### Outstanding for Phase 1

- `XDC db inspect` / `db freezer-index` commands; `removedb` ancient prompt
  (§3.6). `InspectFreezerTable` is ported and ready to be exposed.
- `XDC_FREEZER_TABLE_SIZE` dev override (§3.7) — needed before Phase 2 can
  demonstrate multi-file pruning.
- `cicd/local/compose-3node/` harness and the nightly CI job (§5.4, §5.6), so
  the single-node smoke test (§5.3) and the 3-node soak (§5.4) have **not run**.
- **Not verified: the CLI end to end.** The binary compiles and the flags are
  registered, but this sandbox refuses to execute freshly built binaries, so no
  node has actually been started with `--datadir.ancient`. Do this manually
  before trusting the wiring.

### Known unrelated failure

`TestStoreLoadSnapshot` (`consensus/XDPoS/engines/engine_v2`) fails on Windows
with a TempDir cleanup error. Verified to fail identically on a clean tree — a
pre-existing leveldb handle leak in that test, not caused by this work.
