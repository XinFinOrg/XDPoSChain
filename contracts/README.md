# contracts

Solidity sources and checked-in `abigen` bindings of the built-in system
contracts, plus a few fixtures. The sources here are a historical record of what
was deployed, not the recommended way to write or build contracts today.

## Historical system contract sources

These contracts are already deployed on mainnet and Apothem. Their addresses come
either from the constants in `common/types.go` (for example the validator voting
contract at `0x…0088`, the block signer at `0x…0089`, the randomize contract at
`0x…0090`) or from each network's `ChainConfig` in `params/config_networks.go`
(for example `XDCXListingSMC`). The code running at those addresses is shipped in
the genesis allocations (`core/genesis_alloc_mainnet.go`,
`core/genesis_alloc_testnet.go`, `core/genesis_alloc_devnet.go`), not compiled
from these sources, which are kept to document what was deployed:

| Source | Contract | pragma |
| --- | --- | --- |
| `validator/contract/XDCValidator.sol` | XDCValidator | `^0.4.21` |
| `blocksigner/contract/BlockSigner.sol` | BlockSigner | `^0.4.21` |
| `randomize/contract/XDCRandomize.sol` | XDCRandomize | `^0.4.21` |
| `multisigwallet/contract/MultiSigWallet.sol` | MultiSigWallet | `^0.4.21` |
| `trc21issuer/contract/TRC21.sol`, `TRC21Issuer.sol` | TRC21, TRC21Issuer | `^0.4.24` |
| `XDCx/contract/*.sol` | Registration, LendingRegistration, XDCXListing, … | `0.4.24` / `^0.4.24` |

The `libs/SafeMath.sol` files beside them belong to the same deployments and are
pinned to the same compiler versions.

Do not modernise them. Raising the pragma or recompiling with a current `solc`
changes the metadata hash and therefore the bytecode, which then no longer
matches what those addresses hold on chain. Nothing in the build compiles these
files; `Makefile` mentions `solc` only in its `devtools` target.

## Bindings

The `*.go` files in the same directories are generated bindings, carrying both the
ABI and the `…Bin` bytecode. The node uses the ABI at runtime
(`contracts/validator`, `contracts/blocksigner`, `internal/ethapi`), and the
bytecode is used to deploy fresh copies of the contracts in the engine tests
(`consensus/tests/engine_v1_tests`, `consensus/tests/engine_v2_tests`). They were
produced by an old `abigen` and match the sources above exactly, so regenerate
them only when the deployed contract itself changes.

## Other Solidity here

- `solidity_0.6/` holds small samples of the syntax changes introduced by
  Solidity 0.6; its own `README.md` describes them. Illustrations, not templates.
- `tests/contract/` holds the `Inherited` fixture used by `contracts/tests`. Not a
  system contract.

## Writing new contracts

For anything new, follow `docs/solidity.md`: use a current 0.8.x compiler and pin
`evmVersion` explicitly to the fork your target network has activated.
