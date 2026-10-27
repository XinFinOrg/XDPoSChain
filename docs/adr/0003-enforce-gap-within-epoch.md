---
status: accepted
---

# Enforce `0 < gap < epoch` inside `core`

## Context

`params.XDPoSConfig` carries the two fields every XDPoS engine derives its checkpoint and snapshot heights from - `Epoch` and `Gap` (`params/config_xdpos.go:46,49`). Nothing enforced a relation between them. `CheckConfigForkOrder`'s only `Epoch`-related check is the `SwitchBlock % Epoch` alignment, and it is skipped when `Epoch == 0` (`params/config.go:738`). Both engine constructors paper over a missing `epoch`: `consensus/XDPoS/XDPoS.go:92-94` rewrites `Epoch == 0` to `900` in place, mutating the caller's config, and `consensus/XDPoS/engines/engine_v1/engine.go:94-97` does the same on a copy.

A schedule outside the range the engines were written for reaches runtime and changes what a historical block verifies against. Core's two gap predicates disagree on `Gap == Epoch`: `isGapBlockNumber` accepts it (`core/blockchain.go:1825`, `gap <= epoch`) while `isNextEpochGapBlock` refuses it (`core/blockchain.go:4495`, `gap >= epoch`). For `Gap > Epoch`, `isGapBlockNumber`'s `gap <= epoch` guard makes it report no gap block at all, while the v1 engine still walks `Gap` blocks back from an epoch checkpoint (`consensus/XDPoS/engines/engine_v1/engine.go:1048-1058`) and looks for a snapshot at a height core no longer reports.

## Decision

A chain config that declares an XDPoS section must satisfy

```
0 < gap < epoch
```

rejecting `Gap == 0`, `Gap == Epoch`, `Gap > Epoch` and `Epoch == 0` alike. `Epoch == 0` is subsumed: no `gap` satisfies `0 < gap < 0`.

### Enforcement points

All four are in `core`, and all reach the same unexported helper:

- `Genesis.commit` (`core/genesis.go`), immediately after `CheckConfigForkOrder` - covers `Genesis.Commit`/`MustCommit`, empty-database startup and `geth init` (which resolves through `SetupGenesisBlock`, `cmd/XDC/chaincmd.go:200`).
- `setupGenesisBlock`'s two resolution points (`core/genesis_setup.go:79`, `:272`), each immediately after `CheckConfigForkOrder` and before the branch can persist a config: `resolveSetupStoredConfigResult` for the stored-config path, and the missing-config repair branch ahead of its `rawdb.WriteChainConfig` - covers the stored-config and missing-config branches that return without committing a genesis.
- `loadChainConfigInternal` (`core/genesis_load.go:215`), in its existing defer - covers the read-only resolvers `LoadChainConfig` and `LoadChainConfigWithCompat{,WithOverride}`.
- `newBlockChain` (`core/blockchain.go:468`), after the nil-config check - covers the `NewBlockChain*Resolved` opens that take a caller-supplied config and skip the resolvers.

The first three run before `XDPoS.New` is called, so `Epoch == 0` is still visible. `newBlockChain` alone would not be enough: on node startup the engine is built before the chain is opened (`cmd/utils/flags.go:1986` -> `:1993` -> `:2017`, `eth/backend.go:135` -> `:148` -> `:265`), and `XDPoS.New` has already rewritten the same config pointer to `900`. Consequently the `newBlockChain` gate only rejects a caller-supplied `Gap` outside the bound; a missing epoch is covered by the three earlier points.

The rule is a startup invariant, not a runtime guard: a violating config is not warned about and then served, it does not start.

### Error contract

`core.ErrInvalidEpochGap = errors.New("invalid XDPoS schedule")` is declared in `core/xdpos_schedule.go` next to `checkXDPoSSchedule`, which returns it. One message prints both values and the required relation:

```
invalid XDPoS schedule: XDPoS.Epoch 0, XDPoS.Gap 0 (want 0 < gap < epoch)
```

Callers and tests match with `errors.Is`; the exact string is asserted once. `cmd/utils.FormatChainConfigError` appends the operator-facing recovery hint to this error, so the fatal messages at startup point at the same remedy as the Migration section below.

### What core-only leaves uncovered

`params` and `consensus` are untouched by decision:

- `params/config.go:738` keeps its `Epoch != 0` short-circuit and `CheckConfigForkOrder` keeps accepting `Epoch == 0`.
- `consensus/XDPoS/XDPoS.go:92-94` and `engine_v1/engine.go:94-97` keep rewriting a missing epoch to `900`. A caller that builds an engine directly from a config, without opening a core chain, is still not validated.
- Core's two gap predicates keep their current shape. Inside the bound they denote the same heights; outside it they still diverge, but only configs installed after startup (`BlockChain.SetChainConfig`, struct-literal engines, `XDPoS.NewFaker`) can reach them.
- `eth/downloader` and `cmd/puppeth` keep their own schedule handling.

Node startup paths that open a chain (`cmd/utils.MakeChain`, `eth.New`) resolve the config before building the engine and reach the gate there, so the uncovered surface is direct engine consumers.

## Consequences

### Migration

A chain config that violates the bound - including a non-Localnet custom chain that declares `XDPoS` but omits `epoch`/`gap` and keeps `0/0` - now fails at startup instead of having `epoch` defaulted to `900`.

A stored config is validated again on the next start: an already-running non-compliant private chain keeps running until then, and then refuses to start. `geth init` cannot repair it: with a head above genesis, `SetupGenesisBlock` returns the `ConfigCompatError` for the `Epoch`/`Gap` drift instead of persisting the corrected config (`core/genesis_setup.go:87-93`), and `cmd/XDC/chaincmd.go:204-205` exits on that error.

The in-place alternative is to hand the node the corrected config through the config file's `Eth.Genesis` (`eth/ethconfig/config.go:68`) and start with `--chain-config-mismatch-policy=update-config-only`, which persists the corrected config without moving the head (`core/blockchain.go:643-648`). `rewind-and-update` instead rewinds to `ConfigCompatError.RewindTo`, which for an XDPoS schedule drift is `XDPoS.V2.SwitchBlock - 1`, or height 0 when the chain has no `XDPoS.V2` (`params/config_compat.go:325-330`, `:366-378`). `docs/upgrade.md` documents the policies in full. A node that takes neither path has to be initialised from genesis again.

Read-only commands hit the same gate: the read-only resolvers call it as well, so an `XDC db`-style tool refuses a database whose stored schedule violates the bound instead of opening it. The repair is a writable operation - supply the corrected config and start a node once, after which the read-only tools work again.

### Test fixtures

All changed fixtures are synthetic setups whose subject is not the schedule:

- `core/blockchain_epochswitch_test.go`, `core/blockchain_reorg_checkpoint_test.go`, `core/blockchain_knownblock_test.go`: open on the mock `900/450` schedule and call `SetChainConfig` with the `Epoch=3, Gap=0` config before the blocks under test (the notify-only fixture inserts none); the engine keeps the out-of-bound config.
- `eth/api_backend_test.go`, `ethclient/simulated/backend_finalized_test.go`: `Epoch=2, Gap=1, SwitchBlock=-2` instead of `Epoch=1, SwitchBlock=-1`. `uint64(-2) % 2 == 0` satisfies the alignment check and block 0 is still above the switch.
- `miner/worker_test.go`: declares `900/450`.
- `core/genesis_load_test.go`, `core/genesis_compat_test.go`: `Epoch=2, Gap=1` (`2 % 2 == 0`); the inherited testnet gap of `450` would still violate the bound at `Epoch=2`, so `Gap` changes too. `V2.SwitchEpoch` keeps the `SwitchBlock / Epoch` relation and becomes `1`.

## Considered options

- **Enforce in `params.CheckConfigForkOrder`.** Rejected for this change: `params` also evaluates candidate configs during backfill and droppable-slot checks, and `XDPoS.New` repairs `Epoch == 0` before calling it, so the missing-epoch case would still pass.
- **Enforce in `newBlockChain` only.** Rejected: every node startup path builds the engine first, so the bound would only see the rewritten `900`.
- **Warn and continue.** Rejected: the schedule is consensus-critical, and a chain with `Gap == Epoch` cannot verify its history consistently.
- **`0 < gap <= epoch` (admit `Gap == Epoch`).** Rejected: that is exactly the input where core's gap predicates disagree.
- **Add a test-only bypass instead of migrating fixtures.** Rejected: it would leave a production field that exists only for tests.

## Supersedes PR #2560

Branch `reject-invalid-gap-schedule` = PR #2560 (closed unmerged, 2026-09-13) implemented "reject an unusable gap schedule at every entry point" in `params`, with `CheckConfigForkOrderWithEpochDefault(defaultEpoch)` validating a filled-in clone. This change keeps the hard-reject answer but places the gate in `core`, where it runs before the engine rewrites `epoch`. None of #2560's symbols (`GapOffset`, `GapBlockNumber`, `CheckGapSchedule`, `DefaultXDPoSEpoch`) exist on `dev-upgrade`.

## Out of scope

- Deleting the `Epoch == 0` hydration in `consensus/XDPoS`.
- Narrowing core's gap predicates, in particular the `Gap == Epoch` acceptance of `isGapBlockNumber`.
- `engine_v1`'s unguarded `% Epoch` sites.
