---
status: proposed
---

# Run XDC subnets on the v2 engine behind `XDPoS.isSubnet`

## Context

XDC subnets ran on XinFinOrg/XDC-Subnet, a fork of this client taken in March
2024 that has since drifted by thousands of commits. Nethermind has since added
a subnet engine (`XDPoSSubnet`, `src/Nethermind/Nethermind.Xdc/*Subnet*`), and
subnet deployments mix the two clients. Running subnets from this repository
removes the fork, provided this client follows the subnet rules closely enough
to share a subnet with Nethermind nodes and to feed the subnet checkpoint
contracts, which parse subnet headers by position.

Only new subnets are in scope: there is no existing subnet chain to replay.

## Decision

**A chain config flag selects the rules.** `XDPoS.isSubnet` makes the v2
engine apply the subnet rules from genesis; `BlockConsensusVersion` reports v2
for every block of a subnet, the genesis included, so the v1 engine never sees
one. The flag is part of the stored config: the semantic equality, the config
digest (version 5) and the compatibility check cover it, so a stored chain
cannot change it. Subnet configs are not backfilled from the built-in networks.
`params.checkSubnetConfig` rejects the configs the rules cannot run on: v2 not
from genesis, `gap < 2`, EIP-1559 on, halving or tiered rewards, no masternode
cap.

**The subnet rules branch inside `engine_v2`.** They live in
`engine_v2/subnet.go` and are reached from a few branch points: epoch
detection and numbering, the masternode calculation, `Prepare`, `verifyHeader`
and the epoch switch info. A separate engine package would have duplicated
some 5000 lines that change upstream every week. Mainnet code paths are
unchanged when the flag is off, which the existing engine tests check.

**Nethermind's subnet engine is the reference.** Where XDC-Subnet and Nethermind
disagree, this client follows Nethermind, because that is what a mixed subnet
needs:

- the epoch switch `validators` must match the computed masternodes in order
  (XDC-Subnet accepts any order);
- equal-stake candidates are ordered by `utils.SortMasternodesByStakeDesc`, of
  which Nethermind's `XdcSort` is a port (XDC-Subnet's standard library sort
  orders seven or more equal stakes differently);
- the masternode cap is the v2 config's `maxMasternodes` (XDC-Subnet hardcodes
  108).

Branch `subnet-consensus-xdc-subnet-rules` implements the XDC-Subnet choices
for comparison.

**The header layout is chosen per header.** Subnet headers must hash and travel
in the subnet RLP layout (address lists, `nextValidators`, no base fee), while
the rest of the client keeps the legacy layout. `types.Header` gains
`NextValidators` and a non-serialized `Subnet` flag; its `EncodeRLP` picks the
layout from the flag, and `DecodeRLP` recognizes a subnet header by its 17th
item being a list, so headers from peers and from the database carry their
layout with them. The engine sets the flag on the headers it prepares and
rejects headers whose layout does not match the chain. A process-wide switch
would have been simpler but untestable alongside mainnet code in one process.

**Penalties are computed at the gap block, through the engine.** Core derives
the snapshot of every gap block through `XDPoS_v2.BuildGapSnapshot`, which on a
subnet reads the subnet validator contract (candidates at slot 7) and runs the
subnet penalty hook over the blocks before the gap block. Every path that
derives a snapshot goes through it: block import, reorg, head adoption and the
startup repair. Fast sync, which has no bodies for that epoch yet, takes the
penalties from the block after the gap block.

**Snapshots are looked up by the gap block hash.** The block after a gap block
is checked against the snapshot of its parent by hash, as Nethermind does, so a
fork at the gap block verifies against its own gap block. A gap block that is
not canonical has no stored snapshot; it is derived from its state, which the
header verification reader now opens through the chain it wraps.

## Consequences

- A node importing a gap block and the block after it in one batch stops at the
  latter with the local `ErrGapSnapshotUnavailable` and resumes in the next
  sync cycle, once per epoch, like the epoch switch of an XDPoS chain.
- The subnet fields of the block after a gap block are only compared with the
  local snapshot on a full verification, like the epoch switch masternodes.
- The penalty constants (one block, MergeSignRange 15, RangeReturnSigner 150)
  are fixed on a subnet, as in the other subnet clients.
- The image starts a subnet node from the environment of the XDC-Subnet image,
  so the subnet generator can deploy this client as is.
