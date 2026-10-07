# XDPoS consensus

Vocabulary for the XDPoS chain: the block schedule its validators run to, and the chain data those blocks are stored in.

## Language

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
