# GitHub Copilot Instructions – XDC Network client

- This repository is a fork of `go-ethereum` (geth). When reviewing code, prefer patterns and APIs used in upstream geth where possible, and call out unnecessary divergence from upstream.

- The codebase is mostly Go. Follow standard Go best practices: idiomatic Go style, `gofmt` formatting, clear error handling (no ignored errors), no unused imports or variables, avoid global state where not necessary, and keep functions small and focused.

## Branch & PR policy

- Treat `dev-upgrade` as the main staging branch for protocol / infra upgrades.  
- **Always review PRs whose base branch is `dev-upgrade`** and:
  - Check that the PR description clearly explains the change, scope, and any compatibility impact.
  - Verify that tests are added/updated and relevant CI checks are enabled.
  - Flag missing labels (e.g., `consensus`, `rpc`, `db`, `refactor`) when helpful for maintainers.
  - Call out any change that might require a migration guide, release note, or coordination with node operators.

## Code review focus

- **Consensus & protocol safety:** Changes under `consensus/`, `core/`, `eth/`, `params/` or wire protocol code must not break block validation, fork choice, or network compatibility. Flag any change that alters block structure, receipts, or state transition rules without clear rationale and migration notes.

- **Performance & allocations:** For hot paths (e.g., block processing, tx pool, EVM execution, database access), check for unnecessary allocations, blocking I/O, or quadratic loops. Prefer reuse of buffers and efficient iteration.

- **Security:** Treat all RPC, P2P, and transaction inputs as untrusted. Ensure bounds checks, nil checks, and validation of user-supplied data. Avoid introducing custom cryptography; reuse existing primitives and helpers from upstream or audited libraries.

- **EVM & JSON-RPC compatibility:** Maintain compatibility with standard Ethereum JSON-RPC methods unless the project docs explicitly state a deviation. Call out breaking RPC changes or inconsistent behavior vs. Ethereum where not documented.

- **Database & state:** Be careful with changes in `core/rawdb`, `trie`, and state handling. Flag anything that might corrupt state, change database schema without migration code, or break fast-sync/snap-sync logic.

## General expectations

- For every non-trivial change, check that:
  - There are unit and/or integration tests covering the new behavior.
  - Existing tests still pass logically (not just compile).
  - Logging is informative but not excessively noisy on hot paths.

- When suggesting changes, prefer small, incremental refactors over large rewrites, and always preserve backward compatibility for network peers unless the PR is clearly marked as a consensus or protocol upgrade.

- In review comments, be concise and concrete: point to specific lines, explain the impact on consensus, performance, or security, and propose idiomatic Go alternatives where appropriate.
