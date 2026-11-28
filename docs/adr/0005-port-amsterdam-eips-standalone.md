---
status: proposed
---

# Port Amsterdam EIPs one at a time, verbatim from upstream

File:line references are against `dev-upgrade` @ `1ac4fb4e49` (2026-10-29).

## Context

Amsterdam is tracked as one umbrella (#2730) plus one issue per EIP: #2759 (EIP-2780), #2762 (EIP-7976), #2763 (EIP-7981), #2764 (EIP-8037). Upstream geth did not land them on the base we have. EIP-7976 (`ac406c2fe`, #34748) and EIP-7981 (`aaa2b66285`, #34755) landed while `IntrinsicGas` still took its fork flags as booleans and `FloorDataGas` still took the calldata alone; EIP-2780 (`1ef0ffb98c`, #35318) then rewrote both into the `params.Rules`-carrying shape with `intrinsicBaseGasEIP2780` that master has today.

Our `core/state_transition.go` at `1ac4fb4e49` is that pre-2780 shape: `IntrinsicGas(..., isHomestead, isEIP2028, isEIP3860 bool)` (`:68`) and `FloorDataGas(data []byte)` (`:117`). It is not a coincidence — the file has not diverged since the import — so each of the two smaller EIPs ports with a diff that invents nothing.

## Decision

Implement each Amsterdam EIP on its own branch, commit and PR, porting the upstream commit that introduced it against the base that commit was written on. Reach upstream master's restructured shape only when EIP-2780 itself lands.

- `IntrinsicGas` keeps its boolean signature until #2759. That change is the one that must reconcile upstream's `rules.IsIstanbul` check with XDC scheduling EIP-2028 at Prague (`:425`), so it cannot ride along with a calldata-pricing change.
- `FloorDataGas` takes `params.Rules` from the first port (#2762), as upstream already had it, so #2763 only appends the access-list branch instead of also moving the signature.

## Considered options

- **Jump straight to upstream master's shape.** Rejected: it folds #2759, #2762, #2763 and #2764 into one unreviewable change, and the XDC-specific `IntrinsicGas` fork mapping would be re-derived by hand rather than reviewed on its own.
- **Keep booleans in `FloorDataGas` too.** Rejected: it invents a signature upstream never had, turning every later port into a manual rewrite instead of a diff.

## Consequences

- The intermediate state has `IntrinsicGas` boolean-driven and `FloorDataGas` rules-driven — exactly upstream's state between #34748 and #35318. A reader comparing against geth master sees a deliberate lag, not drift.
- `FloorDataGas`'s signature changes twice more: #2763 adds `accessList`, #2759 adds `from`, `to`, `value` and swaps its base to `intrinsicBaseGasEIP2780`. Each change touches the call sites in `core/state_transition.go`, `core/txpool/validation.go` and the core tests.
- #2759 landed the restructure: `IntrinsicGas` now takes the resolved `params.Rules` and derives this chain's EIP-2028 and EIP-3860 mapping inside, from `IsPrague` and `IsEIP1559`, while `eth/gasestimator` takes the caller's gas cap from the same base (12,000 after Amsterdam) and the miner's packing floor does too (the `minTxGas` half of geth #35773). The remaining gap to geth master is the `vm.GasCosts` wrapper, the EIP-8037 runtime charge, the 7,816 per-authorization base and the 2D gas-ledger half of #35773 (`gasPool.Available` and the `ethapi` exclusions; all #2764), plus the rest of the EIP-8038 repricing — the Amsterdam access-list prices (2,900/2,000) — under #2765; `CREATE_ACCESS` and `COLD_ACCOUNT_ACCESS` take their values from geth #35497. The estimator's base-aware caller cap is local to this tree — upstream still measures the cap against the flat 21,000, so there is no upstream patch to port — and it keeps a 12,000–20,999 cap effective under Amsterdam, matching `ethclient/simulated`. It lacks upstream's plain-value-transfer short circuit (#28618, now returning the used gas after #35592), which is an optimisation — the binary search reaches the same lower estimates. The Osaka gas-cap exemption after Amsterdam (#34841) landed with T16-a (#3136): under Amsterdam `eth/gasestimator` no longer clamps its search ceiling to `MaxTxGas`, the txpool validation and the execution precheck apply `params.MaxTxTotalGas` (2^32-1) instead, and the legacypool boundary discard keys the cap off the head the pool lands on. The two-dimensional pool that splits the total into execution and state dimensions is still missing (T16-b).
- Amsterdam and Prague are separate switches in this tree, while the calldata floor only runs under Prague: a network that schedules Amsterdam without it would charge the EIP-7981 access-list tokens with no EIP-7623/EIP-7976 floor and no EIP-2028 calldata price. The Amsterdam activation has to schedule Prague at or before Amsterdam.

## Out of scope

EIP-7981 (#2763), EIP-2780 (#2759), EIP-8037 (#2764) and the Amsterdam activation schedule (#2730): each is tracked and ported on its own branch under the same rule.

## References

#2730 · #2759 · #2762 · #2763 · #2764 · ethereum/go-ethereum#34748 · ethereum/go-ethereum#34755 · ethereum/go-ethereum#35318
