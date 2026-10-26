---
status: accepted
---

# Enforce `0 < gap < epoch` in `params` and `core`

## Context

`params.XDPoSConfig` carries the two fields every XDPoS engine derives its checkpoint and snapshot heights from - `Epoch` and `Gap` (`params/config_xdpos.go:46,49`). `params` itself enforced no relation between them. `CheckConfigForkOrder`'s only `Epoch`-related check was the inline `SwitchBlock % Epoch` alignment, skipped when `Epoch == 0` (`params/config.go:783` before this change; it now lives in `CheckSwitchBlockAlignment`, `params/config.go:795`). Both engine constructors paper over a missing `epoch`: `consensus/XDPoS/XDPoS.go:86-88` rewrites `Epoch == 0` to `900` in place, mutating the caller's config, and `consensus/XDPoS/engines/engine_v1/engine.go:94-97` does the same on a copy.

A schedule outside the range the engines were written for reaches runtime and changes what a historical block verifies against. Core's two gap predicates disagree on `Gap == Epoch`: `isGapBlockNumber` accepts it (`core/blockchain.go:1766`, `num%Epoch == Epoch-Gap`, which is zero there) while `isNextEpochGapBlock` refuses it (`core/blockchain.go:4438`, `Gap >= Epoch`). For `Gap > Epoch`, `Epoch-Gap` wraps to a value the modulo cannot reach, so `isGapBlockNumber` reports no gap block at all, while the v1 engine still walks `Gap` blocks back from an epoch checkpoint (`consensus/XDPoS/engines/engine_v1/engine.go:1048-1058`) and looks for a snapshot at a height core no longer reports. Inside the bound the two predicates cannot disagree: for `0 < Gap < Epoch`, `(number+Gap)%Epoch == 0` holds exactly when `number%Epoch == Epoch-Gap`, which is why the `gap != 0` and `gap <= epoch` conjuncts core's predicates carried before this change could not have matched a schedule a node can hold.

#2822 put a core-side gate in front of the four places a config enters a chain. `params` owns the fields the bound talks about, so the rule is declared there as well: `CheckConfigForkOrder` now validates the schedule, which reaches every caller of that function, while core keeps its earlier gate for the paths that see `Epoch == 0` before `XDPoS.New` rewrites it.

## Decision

A chain config that declares an XDPoS section must satisfy

```
0 < gap < epoch
```

rejecting `Gap == 0`, `Gap == Epoch`, `Gap > Epoch` and `Epoch == 0` alike. `Epoch == 0` is subsumed: no `gap` satisfies `0 < gap < 0`.

The rule is one method, `(*XDPoSConfig).CheckSchedule()` in `params`, called at the end of the `XDPoS` block of `ChainConfig.checkConfigForkOrder` (`params/config.go:792`) just before the `SwitchBlock % Epoch` alignment check. The order is load-bearing: the bound proves `Epoch >= 2`, so the alignment check divides by an epoch that cannot be zero and drops the `Epoch != 0` short-circuit it used to carry. The trade is precedence - the `ErrMissingForkSwitch` checks for the `V2` section still run first, but a config that is both out of bound and misaligned now reports the schedule instead of `ErrWrongForkSwitchOrder`. A nil receiver is a config without an XDPoS section, which is not an XDPoS chain, and is accepted.

### Enforcement points

All four are in `core`, and all reach the same unexported helper, which now delegates to `params.XDPoSConfig.CheckSchedule`:

- `Genesis.commit` (`core/genesis.go`), immediately after `CheckConfigForkOrder` - covers `Genesis.Commit`/`MustCommit`, empty-database startup and `geth init` (which resolves through `SetupGenesisBlock`, `cmd/XDC/chaincmd.go:200`).
- `setupGenesisBlock`'s two resolution points (`core/genesis_setup.go:79`, `:272`), each immediately after `CheckConfigForkOrder` and before the branch can persist a config: `resolveSetupStoredConfigResult` for the stored-config path, and the missing-config repair branch ahead of its `rawdb.WriteChainConfig` - covers the stored-config and missing-config branches that return without committing a genesis.
- `loadChainConfigInternal` (`core/genesis_load.go:215`), in its existing defer - covers the read-only resolvers `LoadChainConfig` and `LoadChainConfigWithCompat{,WithOverride}`.
- `newBlockChain` (`core/blockchain.go:460`), after the nil-config check - covers the `NewBlockChain*Resolved` opens that take a caller-supplied config and skip the resolvers.

The fifth gate is the `params` one itself, inside `CheckConfigForkOrder`, and it reaches every caller of that function in addition to core's four:

- `XDPoS.New` (`consensus/XDPoS/XDPoS.go:89`) calls it after repairing a missing epoch and `XDPoS.NewFaker` (`:135`) calls it directly, so an XDPoS config with `Gap == 0` no longer builds an engine even when a caller skips core entirely.
- The backfill path (`params/config_backfill.go:1188`) validates candidate configs by calling `checkConfigForkOrder` with the schedule judgement on, and now judges their schedule too. The droppable-slot probe behind the fork-order hint (`params/config.go:593`) calls the same function with `skipXDPoSSchedule` set: an invalid schedule is independent of the fork slots, so it must not erase the repair a fork-order error names.
- Any other caller that validates a chain config directly.

The first three core points run before `XDPoS.New` is called, so `Epoch == 0` is still visible. `newBlockChain` alone would not be enough: on node startup the engine is built before the chain is opened (`cmd/utils/flags.go:1986` -> `:1993` -> `:2017`, `eth/backend.go:136` -> `:149` -> `:266`), and `XDPoS.New` has already rewritten the same config pointer to `900`. Consequently the `newBlockChain` gate only rejects a caller-supplied `Gap` outside the bound; a missing epoch is covered by the three earlier points.

Those three points also run immediately after `CheckConfigForkOrder`, whose `params` gate now judges the same schedule, so on those paths they cannot reject anything that call accepts; they stay as the gate position, not as a second rule. `newBlockChain` is the one that no other check covers: `NewBlockChain*Resolved` opens take a caller-supplied config and skip `CheckConfigForkOrder`.

The rule is a startup invariant, not a runtime guard: a violating config is not warned about and then served, it does not start.

### Error contract

`params.ErrInvalidEpochGap = errors.New("invalid XDPoS schedule")` is declared next to `CheckSchedule`, which returns it; `core.ErrInvalidEpochGap` is an alias of the same value. Every message starts with the sentinel text and then names the shape it found, because the rejected shapes need different answers - an unset epoch has to be supplied, an epoch of one cannot satisfy `1 <= gap < epoch` at all, and `Gap == Epoch` is the only rejected shape whose trigger still matches a height:

```
invalid XDPoS schedule: XDPoS.Epoch is unset, so no gap block fits (want 1 <= Gap < Epoch)
invalid XDPoS schedule: XDPoS.Epoch 1 leaves no gap block (want Epoch >= 2 so that 1 <= Gap < Epoch is satisfiable)
invalid XDPoS schedule: XDPoS.Gap 900 puts the gap trigger on the epoch switch block, which would have to consume the candidate set it samples (want 1 <= Gap < Epoch)
invalid XDPoS schedule: XDPoS.Gap 901 designates no gap block inside XDPoS.Epoch 900 (want 1 <= Gap < Epoch)
```

This is a deliberate departure from the single generic message `#2742` proposed (`ErrInvalidEpochGap = errors.New("invalid epoch/gap")`, one message printing both values): the four shapes need four different operator answers, and knowing which shape was hit is worth more than one sentence. The sentinel value itself is unchanged from what `#2822` put in `core`, so this change widens where it is produced rather than renaming it.
Callers and tests match with `errors.Is`; each tier's string is asserted in `params`, so the tiers cannot collapse back into one message unnoticed. `cmd/utils.FormatChainConfigError` appends the operator-facing recovery hint to this error, so the fatal messages at startup point at the same remedy as the Migration section below, whichever gate produced it.

### What stays outside the gates

`consensus` is untouched by decision, and a few callers keep their own handling outside the gates:

- `consensus` keeps its engine guards, the `repairGapCandidates` guards and `XDPoS.NewFaker`'s `CheckConfigForkOrder` call, which `#2743` would have removed. `consensus/XDPoS/XDPoS.go:86-88` and `engine_v1/engine.go:94-97` still rewrite a missing epoch to `900`; `XDPoS.New` and `XDPoS.NewFaker` then call `CheckConfigForkOrder` and reject an out-of-bound schedule, and only a caller that builds an engine (`engine_v1.New`, `engine_v2.New`) directly, without the wrapper, skips validation. That is the one decision `#2742`/`#2743` took that this change leaves out: it lives in `consensus`, and the repair is entangled with the validation that follows it, so dropping it changes which error every caller sees.
- Core's two gap predicates drop the conjuncts the bound makes arithmetically redundant - `gap != 0` and `gap <= epoch` in `isGapBlockNumber`, and `Gap == 0` in `isNextEpochGapBlock` - and keep the two guards that still do work: `Epoch != 0` before the modulo and `Gap >= Epoch` before `Epoch - Gap`. Both predicates reach the same verdict on every input as before (`number % Epoch` is never `Epoch`, so `Gap == 0` could not have matched either, and with `Gap > Epoch` the subtraction wraps to a value at or above `Epoch+1`, out of the modulo's range), which is what makes the removal a cleanup rather than a rule change.
- `cmd/puppeth` judges the gap bound and the switch-block rule through `CheckSchedule` and `CheckSwitchBlockAlignment` and returns their errors verbatim, so a node starting on the generated genesis reports the same message for those two rules. The prompt keeps its own floors only where the bound cannot be judged yet: a negative gap, which has no uint64 spelling, and an epoch below 2, which has to be refused before a gap is chosen because the template's gap is still in place. A typed zero is read as unspecified and replaced with the epoch's default (`interactiveGapDefault`), so the interactive path never hands the bound a zero gap: that shape is reported only for a config built elsewhere. `CheckSwitchBlockAlignment` is the one statement of the v2 switch-block rule - `checkConfigForkOrder` reaches it too - which is what lets the wizard judge the answer at the prompt instead of after the genesis contracts have been deployed. The wizard refuses a negative switch block as well: `V2.SwitchEpoch` is a uint64 and `SwitchEpochFor` cannot represent the derived epoch, so that spelling survives only in a hand-written genesis, where the alignment rule judges the block by its absolute value. Nothing validates that pair - `CheckConfigForkOrder` aligns the block to the epoch and compares no switch epoch - so the wizard stores the quotient `SwitchEpochFor` derives from the final switch block rather than a second copy of the division: a block typed at the prompt and the epoch that has to divide it cannot describe different schedules, and a hand-written `switchEpoch` that disagrees is corrected rather than refused.
- `eth/downloader`'s gap-block cut (`splitBlocksForVerification`) drops the same two redundant range conjuncts; its `Epoch == 0` early return stays, because the two `% Epoch` uses below depend on it. The cut behaves as before for every schedule a node can hold; the one that would cut differently, `Gap == Epoch`, is refused at startup.
- `eth/downloader`'s `gapPivotNumbers` already returns nil for `Epoch == 0` (`eth/downloader/downloader.go:308`). `#2743` recorded that site as unguarded, which the code contradicts, so the guard stays and that premise is outdated.
- `eth/downloader`'s `processFullSyncContent` reads `% Epoch` with no `Epoch != 0` guard (`eth/downloader/downloader.go:1625`; the comparison on the next line reads the wrapped offset). No production path can install such a config - `BlockChain.SetChainConfig` has no production caller, and the startup gate refuses the shape - so the omission is recorded here rather than patched; only a test that constructs the config directly can reach it.
- `setHeadBeyondRoot`'s warning (`core/blockchain.go:791-792`) fires for exactly the schedules `isGapBlockNumber` cannot match - `Epoch == 0`, which guards its division, `Gap == 0`, which compares against `Epoch` that the modulo never yields, and `Gap > Epoch`, whose wrapped offset is out of the modulo's range - because in all three the rewind deletes no snapshot and the leftovers leak. All three are refused at startup, so only a config installed after startup reaches the warning; the leftovers are keyed by block hash, so they are never loaded again - a leak, not a wrong answer.

Node startup paths that open a chain (`cmd/utils.MakeChain`, `eth.New`) resolve the config before building the engine and reach the gates there.

## Consequences

### Migration

A chain config that violates the bound - including a non-Localnet custom chain that declares `XDPoS` but omits `epoch`/`gap` and keeps `0/0` - now fails at startup instead of having `epoch` defaulted to `900`. The rejection comes from whichever gate runs first: core's earlier one on the chain-open paths, the `params` one inside `CheckConfigForkOrder` everywhere else.

`XDPoS.New` has the same side effect. It repairs a missing `Epoch` and then calls `CheckConfigForkOrder` (`consensus/XDPoS/XDPoS.go:86-89`), so an XDPoS config with `Gap == 0` no longer builds an engine where it built one before: the `900` repair rescues a missing epoch, never a missing gap. `engine_v1.New` (`engine_v1/engine.go:92-97`) does not call `CheckConfigForkOrder` and stays unaffected.

A stored config is validated again on the next start: an already-running non-compliant private chain keeps running until then, and then refuses to start. `geth init` cannot repair it: with a head above genesis, `SetupGenesisBlock` returns the `ConfigCompatError` for the `Epoch`/`Gap` drift instead of persisting the corrected config (`core/genesis_setup.go:87-93`), and `cmd/XDC/chaincmd.go:204-205` exits on that error.

The in-place alternative is to hand the node the corrected config through the config file's `Eth.Genesis` (`eth/ethconfig/config.go:68`) and start with `--chain-config-mismatch-policy=update-config-only`, which persists the corrected config without moving the head (`core/blockchain.go:630-635`). `rewind-and-update` instead rewinds to `ConfigCompatError.RewindTo`, which for an XDPoS schedule drift is `XDPoS.V2.SwitchBlock - 1`, or height 0 when the chain has no `XDPoS.V2` (`params/config_compat.go:325-330`, `:366-378`). `docs/upgrade.md` documents the policies in full. A node that takes neither path has to be initialised from genesis again.

Read-only commands hit the same gate: the read-only resolvers call it as well, so an `XDC db`-style tool refuses a database whose stored schedule violates the bound instead of opening it. The repair is a writable operation - supply the corrected config and start a node once, after which the read-only tools work again.

### Test fixtures

The fixtures this change had to migrate are synthetic setups whose subject is not the schedule:

- `core/blockchain_epochswitch_test.go`, `core/blockchain_reorg_checkpoint_test.go`, `core/blockchain_knownblock_test.go`: `Epoch=3, Gap=1`, shared through one fixture, so the config is inside the bound from construction to teardown - the faker, the genesis and the chain are all built from it and nothing is rewritten afterwards. The short epoch puts the epoch switch blocks inside the chain, which puts gap blocks there too, so the genesis seeds the voting contract with the fixture's masternode set: the refresh a gap block owes then runs on that set instead of stopping the node on an empty one.

The fixtures the bound also touched were migrated by #2822 (`a333026be4`) and are unchanged here: `eth/api_backend_test.go` and `ethclient/simulated/backend_finalized_test.go` open their chain on `Epoch=2, Gap=1, SwitchBlock=-2` (`-2` is a multiple of `2`, and the alignment check takes the remainder on the `big.Int`, so the sign does not matter; block 0 is still above the switch), `miner/worker_test.go` declares `900/450`, and `core/genesis_load_test.go` / `core/genesis_compat_test.go` use `Epoch=2, Gap=1` with `V2.SwitchEpoch` keeping the `SwitchBlock / Epoch` relation. The ethclient file also installs `Epoch=10, Gap=5, SwitchBlock=-1` through `SetChainConfig` in one test; that path validates nothing, so neither the bound nor the alignment applies to it.

## Considered options

- **Enforce in `params.CheckConfigForkOrder`.** Rejected then, adopted now. The original objection was that `params` also evaluates candidate configs during backfill and droppable-slot checks, and that `XDPoS.New` repairs `Epoch == 0` before calling it, so the missing-epoch case would pass. Both remain true, but they no longer decide the outcome: core's #2822 gate rejects `Epoch == 0` before `XDPoS.New` runs, so the `params` rule is a second gate rather than the only one. A backfill candidate that fails the schedule check is a config core refuses at startup anyway, and the hint path only affects diagnostics: the droppable-slot probe runs with `skipXDPoSSchedule` set, so the schedule judgement never blocks a fork-order repair.
- **Enforce in `newBlockChain` only.** Rejected: every node startup path builds the engine first, so the bound would only see the rewritten `900`.
- **Warn and continue.** Rejected: the schedule is consensus-critical, and a chain with `Gap == Epoch` cannot verify its history consistently.
- **`0 < gap <= epoch` (admit `Gap == Epoch`).** Rejected: that is exactly the input where core's gap predicates disagree.
- **Add a test-only bypass instead of migrating fixtures.** Rejected: it would leave a production field that exists only for tests.

## Supersedes PR #2560

Branch `reject-invalid-gap-schedule` = PR #2560 (closed unmerged, 2026-09-13) implemented "reject an unusable gap schedule at every entry point" in `params`, with `CheckConfigForkOrderWithEpochDefault(defaultEpoch)` validating a filled-in clone. This change keeps the hard-reject answer but places the gate in `params` and `core`, where it runs both inside `CheckConfigForkOrder` and before the engine rewrites `epoch`. None of #2560's symbols (`GapOffset`, `GapBlockNumber`, `CheckGapSchedule`, `DefaultXDPoSEpoch`) exist on `dev-upgrade`.

## Out of scope

- Deleting the `Epoch == 0` hydration in `consensus/XDPoS`.
- Narrowing core's gap predicates beyond dropping the conjuncts the bound makes redundant, in particular the `Gap == Epoch` acceptance of `isGapBlockNumber`.
- Dropping `XDPoS.NewFaker`'s `CheckConfigForkOrder` call and the engine-side guards `#2743` listed, which all live in `consensus`.
- `engine_v1`'s unguarded `% Epoch` sites.
- Comparing `XDPoS.V2.SwitchEpoch` with `SwitchBlock / Epoch` on the node side. The puppeth wizard derives the pair with `SwitchEpochFor` into the genesis it writes, and `CheckSwitchBlockAlignment` now refuses a positive block whose quotient no uint64 can hold, but nothing verifies a stored `SwitchEpoch` that a hand-written genesis or a template replacing `SwitchBlock` left stale.

The deferred items above, and the per-site keep/delete table `#2743` asked for, are tracked in #2940.

`XDPoS.New` and `XDPoS.NewFaker` now reject a `Gap == 0` config as a side effect of the `params` gate; the epoch repair rescues a missing epoch, never a missing gap. `engine_v1.New` does not call `CheckConfigForkOrder` and stays outside both gates.
