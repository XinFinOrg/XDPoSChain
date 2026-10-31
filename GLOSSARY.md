# XDPoS domain

Vocabulary for the XDPoS chain: the block schedule its validators run to, the block processing steps applied before the first transaction, the chain data those blocks are stored in, and the wire protocol its nodes speak.

## Language

### Schedule

**gap block**:
The block inside every epoch at which the next epoch's masternode set is prepared.
_Avoid_: checkpoint block, gap height

**gap trigger**:
The height inside each epoch at which the gap block falls, `Epoch - Gap`.
_Avoid_: gap height, checkpoint trigger

**XDPoS schedule**:
The rule that places one gap block inside each epoch, fixed by the epoch length and the gap offset. `(*params.XDPoSConfig).CheckSchedule` is the judgement, reached through `CheckConfigForkOrder`; `core` keeps the earlier gate.
_Avoid_: gap schedule, gap config, checkpoint schedule, epoch/gap pair, checkpoint spacing
_See_: [ADR-0003](docs/adr/0003-enforce-gap-within-epoch.md)

**reward checkpoint**:
The block at which the v1 engine pays out masternode rewards, every `RewardCheckpoint` blocks. The interval is configured independently of the epoch, so a reward checkpoint is not necessarily an epoch boundary and can coincide with a gap block.

### Block schedule

**epoch**:
The unit the validator schedule runs on, `Epoch` in the chain config (900 on mainnet), counted in blocks under the v1 engine and in rounds under the v2 engine; at each epoch switch block the masternode set is re-taken.
_Avoid_: cycle, term
_See_: [params/config_xdpos.go:46](params/config_xdpos.go), [consensus/XDPoS/engines/engine_v2/epochSwitch.go:162](consensus/XDPoS/engines/engine_v2/epochSwitch.go)

**epoch switch block**:
The block that opens a new epoch — under v1 the block whose number is a multiple of `Epoch`, under v2 the first block whose round falls in a new epoch of rounds.
_Avoid_: epoch boundary, checkpoint block
_See_: [consensus/XDPoS/engines/engine_v1/engine.go:1084](consensus/XDPoS/engines/engine_v1/engine.go), [consensus/XDPoS/engines/engine_v2/epochSwitch.go:162](consensus/XDPoS/engines/engine_v2/epochSwitch.go)

**round**:
The attempt counter inside an epoch, `types.Round`; a validator's turn is decided per round, and a timeout moves the chain to the next one and resets the timeout pools.
_Avoid_: step, attempt
_See_: [core/types/consensus_v2.go:12](core/types/consensus_v2.go), [consensus/XDPoS/engines/engine_v2/engine.go:1061](consensus/XDPoS/engines/engine_v2/engine.go)

**masternode**:
A node in the validator set that signs blocks and votes, capped by `MaxMasternodes`; the set is snapshotted at each epoch's gap block.
_Avoid_: master node, witness
_See_: [consensus/XDPoS/utils/types.go:17](consensus/XDPoS/utils/types.go), [params/config_xdpos.go:128](params/config_xdpos.go)

### Chain data

**executed marker**:
A per-block record that this node ran the block itself, written when the block is executed and read together with the state its header names.
_Avoid_: execution flag, sync marker
_See_: [ADR-0001](docs/adr/0001-bound-executed-marker-to-state-lifetime.md)

**state window**:
The recent span of a chain whose state a pruning node still holds; it ends `TriesInMemory` blocks below the head.
_Avoid_: pruning window, retention window
_See_: [ADR-0001](docs/adr/0001-bound-executed-marker-to-state-lifetime.md)

**fork ancestry**:
The depth below the head that the downloader treats as still reorganisable, `MaxForkAncestry` blocks; below it a chain segment is immutable.
_Avoid_: reorg depth, rollback limit
_See_: [ADR-0001](docs/adr/0001-bound-executed-marker-to-state-lifetime.md)

### Block processing

**block level hooks**:
The state changes block processing applies before the first transaction of a block: the TIPSigning removal of the legacy block signers account, the Multicall3 install after Prague whenever the account has no code and the EIP-2935 parent hash write. The DAO fork change is not one of them: only the paths that process or generate a block apply it, each on its own at `DAOForkBlock`, the way upstream `core.PreExecution` leaves it out.
_Avoid_: pre-execution calls, system calls
_See_: [ApplyBlockLevelHooks](core/state_processor.go)

### Wire protocol

**eth capability**:
The devp2p capability XDPoSChain advertises under the name "eth"; the label names the wire protocol, not compatibility with Ethereum's wire format.
_Avoid_: xdc capability
_See_: [ADR-0004](docs/adr/0004-split-eth-wire-layer-into-protocols-eth.md)

**xdc version**:
A wire-protocol version of the eth capability — `xdc166`, `xdc165`, `xdc164`, `xdc100` — numbered apart from geth's eth6x series on purpose.
_Avoid_: eth version, protocol version
_See_: [ADR-0004](docs/adr/0004-split-eth-wire-layer-into-protocols-eth.md)

**BFT message**:
One of the three consensus messages the eth capability carries: vote, timeout, and sync info.
_Avoid_: consensus message
_See_: [ADR-0004](docs/adr/0004-split-eth-wire-layer-into-protocols-eth.md)
