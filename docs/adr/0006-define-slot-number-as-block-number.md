---
status: proposed
---

# Define the slot number as the block number

Symbols are referenced rather than lines, which drift as the tree moves.

## Context

EIP-7843 adds the `SLOTNUM` opcode (`0x4b`, 2 gas) that returns the slot number of the block being executed. Upstream go-ethereum gets the value from the consensus layer through the engine API and stores it in a `SlotNumber` execution header field, which is what makes the block self-contained for proving.

XDPoSChain has neither a beacon chain nor an engine API. Before this decision the Amsterdam instruction set (`newAmsterdamInstructionSet` in `core/vm/jump_table.go`) omitted the opcode, because the chain had no source for the value (#2760). Solidity 0.8.37 exposes `block.slotnum` for `--evm-version amsterdam`, so bytecode compiled for that target could not run here while the opcode was missing.

ADR-0005 requires each Amsterdam EIP to be ported verbatim from the upstream commit that introduced it. EIP-7843 is the deliberate exception: the opcode itself is ported as-is, but its value is the block number rather than a header field, because this chain has no consensus layer to supply one.

## Decision

The slot number of a block is its block number. One block occupies one slot, and there are no empty slots.

`SLOTNUM` returns `vm.BlockContext.SlotNum`, which `core.NewEVMBlockContext` fills from `header.Number`. No header field is added.

## Considered options

- **Derive the slot from time** (elapsed time divided by a slot duration). Rejected: XDC only enforces `parent.Time + Period <= header.Time` (v1, `verifyHeader` in `consensus/XDPoS/engines/engine_v1/engine.go`; v2, `verifyHeader` in `consensus/XDPoS/engines/engine_v2/verifyHeader.go`), and v2 takes `MinePeriod` from `V2.Config(round)`. The value would therefore not be a function of the header the EVM sees, and a block that arrives late would have no on-chain way to say which slot it was for.
- **Use the v2 round from the extra data.** Rejected: the round is the consensus attempt counter, not a block counter. A timeout certificate advances it without producing a block (`processTC` calls `setNewRound(timeoutCert.Round+1)`, `consensus/XDPoS/engines/engine_v2/timeout.go`), so a block's round can exceed the previous block's round by more than one and `SLOTNUM` would stop matching the block number. It is also cumulative rather than epoch-local: `IsEpochSwitch` derives the epoch from `round / Epoch` (`consensus/XDPoS/engines/engine_v2/epochSwitch.go`), so the round keeps increasing across epoch switches instead of resetting.
- **Add the header field anyway, carrying the block number.** Rejected: the value is already a pure function of the header, so the field would be consensus-critical duplication, and any disagreement between the field and the derivation is a fork rather than a local error. `PREVRANDAO` is handled the same way on this chain, derived from the block number in `NewEVMBlockContext` (`core/evm.go`) instead of stored.
- **Leave the opcode out.** Rejected: executions of `SLOTNUM` would keep failing on any chain that activates Amsterdam, so bytecode that uses `block.slotnum` would stay unservable. This decision adds the opcode for Amsterdam.

## Consequences

- `block.slotnum == block.number` wherever `SLOTNUM` executes, i.e. on any XDC chain that schedules Amsterdam.
- An RPC block-number override moves the slot number with it: when the overridden number activates Amsterdam and within the `uint64` range described next, `eth_call` and `debug_traceCall` with `blockOverrides.number` report the overridden number from both `NUMBER` and `SLOTNUM`.
- The slot number is a `uint64`, so a block number beyond that range truncates — the same limit `NewEVMBlockContext` applies to a header number.
- The block hash, the genesis, the two sealing hashes and the RPC header outputs are untouched, so there is nothing to validate on import and no historical block changes.
- If XDC ever defines slots independently of block numbers, a header field becomes unavoidable. This ADR records why none exists today.
- Amsterdam is still not a sound compiler target: EIP-8037 and EIP-8038 are absent, so gas metering and state access pricing stay at their Osaka values. `docs/solidity.md` keeps advising against `--evm-version amsterdam`.

## Out of scope

EIP-8037 and EIP-8038 (#2764) and the Amsterdam activation schedule (#2730).

## References

#2760 · ethereum/go-ethereum#33589 · EIP-7843 <https://eips.ethereum.org/EIPS/eip-7843>
