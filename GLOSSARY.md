# XDPoS consensus

Vocabulary for the XDPoS chain: the block schedule its validators run to, the block processing steps applied before the first transaction, and the chain data those blocks are stored in.

## Language

### Block schedule

**XDPoS schedule**:
The epoch and gap of an XDPoS chain config, the pair every XDPoS engine derives its checkpoint and snapshot heights from; core only starts a chain whose config satisfies `0 < gap < epoch`.
_Avoid_: epoch/gap pair, checkpoint spacing
_See_: [ADR-0003](docs/adr/0003-enforce-gap-within-epoch.md)

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
