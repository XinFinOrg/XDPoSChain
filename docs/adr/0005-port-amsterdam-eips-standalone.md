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

## References

#2730 · #2759 · #2762 · #2763 · #2764 · ethereum/go-ethereum#34748 · ethereum/go-ethereum#34755 · ethereum/go-ethereum#35318
