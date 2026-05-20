# Upgrade Notes

This document summarizes the current startup rules for `genesis` and
`ChainConfig` in XDPoSChain:

- how single-binary startup now selects the target network at runtime
- how the node distinguishes built-in networks, Localnet, and custom networks
- which missing fields can be backfilled for each class
- when a resolved `ChainConfig` is written back to the database
- how to upgrade `ChainConfig` to add a future fork without changing the canonical genesis block

## Operator Migration: Single Binary, Runtime Network Selection

The network-specific constant files `constants.mainnet.go`,
`constants.testnet.go`, `constants.devnet.go`, and `constants.local.go` have
been removed from the startup path. Operators should now assume a single `XDC`
binary and select the target network at runtime.

Impact for existing automation:

- Do not keep separate service definitions, container entrypoints, or wrapper scripts that select a different binary or compile-time constant set per network.
- Update each startup command so the network choice is explicit in the CLI flags or in the `genesis.json` used for initialization.
- Treat this as an operator-visible migration, not an internal refactor. A restart on the new binary must still select the same effective network as before.

Built-in network selection now maps to the following runtime choices:

- Mainnet: `XDC --mainnet ...`
- Mainnet notes: equivalent alias `--xinfin`. If `--networkid` is omitted, startup uses chain ID `50` and the built-in mainnet genesis.
- Testnet: `XDC --testnet ...`
- Testnet notes: equivalent alias `--apothem`. If `--networkid` is omitted, startup uses chain ID `51` and the built-in testnet genesis.
- Devnet: `XDC --devnet ...`
- Devnet notes: if `--networkid` is omitted, startup uses chain ID `5551` and the built-in devnet genesis.
- Localnet: explicit `genesis.json` plus `XDC --datadir <datadir> init /path/to/genesis.json`, then `XDC --datadir <datadir> --networkid 5151 ...`
- Localnet notes: there is no dedicated `--localnet` flag. Localnet is identified from the resolved config by `ChainID == 5151`.

Practical migration rules:

1. For built-in Mainnet, Testnet, and Devnet, replace any old per-network binary selection with the matching runtime flag on `XDC`.
2. For Localnet, custom, and private deployments, keep the authoritative `genesis.json` under operator control and initialize the data directory explicitly before normal startup.
3. `--networkid 50`, `--networkid 51`, and `--networkid 5551` still map to the built-in network profiles at runtime, but using `--mainnet`, `--testnet`, or `--devnet` is clearer for operational scripts and service files.
4. `--networkid 5151` does not create a built-in Localnet genesis on an empty data directory. On first initialization, or whenever metadata must be repaired, you still need an explicit writable path with the matching `genesis.json`.

Minimal command migration examples:

```bash
# Mainnet
XDC --datadir <datadir> --mainnet <other flags>

# Testnet
XDC --datadir <datadir> --testnet <other flags>

# Devnet
XDC --datadir <datadir> --devnet <other flags>

# Localnet or any custom/private network
XDC --datadir <datadir> init /path/to/genesis.json
XDC --datadir <datadir> --networkid 5151 <other flags>
```

If an operator script previously inferred the network only from which constant
file or binary variant was present, that script now needs an explicit runtime
branch. The required branch point is:

- built-in networks: add the matching built-in flag
- Localnet/custom networks: pass the authoritative `genesis.json` on writable initialization and use the intended chain ID on normal startup

## Network Classification

The node classifies the effective startup config in the following order:

| Class                     | How it is identified                                                                                | Notes                                                                                                                                                     |
| ------------------------- | --------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Built-in network          | Genesis hash matches mainnet, testnet, or devnet                                                    | Bundled config remains the canonical source for that hash unless the data directory was explicitly initialized as a trusted same-hash custom override.    |
| Localnet                  | `ChainID == 5151`                                                                                   | Localnet uses `params.LocalnetChainConfig` as its full backfill source even when the genesis hash is not a built-in hash.                                 |
| Custom network            | Genesis hash is not built-in and `ChainID` is not Localnet                                          | Custom configs keep explicit values authoritative and only receive the narrow custom compatibility backfill.                                              |
| Same-hash custom override | Genesis hash matches a built-in network, but the data directory carries a persisted override marker | This is still a custom chain for that data directory. The override marker is what distinguishes it from an ordinary built-in network using the same hash. |

## Backfill Rules

Backfill only applies to fields that are actually missing. Explicit `0`,
`false`, `null`, or zero-address values remain authoritative and are not
overwritten. However, a zero address is only treated as an explicit override
for backfill purposes. If validation requires a system-contract address to be
set, the config may still be rejected instead of accepting the zero address as
a usable value.

`BackfillMissingFieldsFrom` uses strict JSON-key presence when the config came
from `UnmarshalJSON`. In that case, an explicit value such as
`"berlinBlock": 0` or `"pragueBlock": null` is preserved because the key is
present in the original JSON. If a `ChainConfig` is constructed directly in Go
code, or through a helper that never populated JSON presence metadata, the
compatibility fallback degrades to treating `nil` pointers and zero values as
missing. That fallback is intentional for legacy callers, but it means `nil`
on a fork-block pointer is interpreted as "missing", not as "this fork is
intentionally absent".

| Class                     | Backfill source                                                          | What is backfilled                                                                                                                                                                                                                                                                                                                                                                |
| ------------------------- | ------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Built-in network          | Matching bundled config for that genesis hash                            | Full missing-field backfill through `BackfillMissingFieldsFrom`. This includes all supported built-in fork fields, system-contract addresses, and XDPoS fields.                                                                                                                                                                                                                   |
| Localnet                  | `params.LocalnetChainConfig`                                             | Full missing-field backfill through `BackfillMissingFieldsFrom`.                                                                                                                                                                                                                                                                                                                  |
| Custom network            | `params.LocalnetChainConfig`                                             | Narrow compatibility backfill through `BackfillCustomMigratedFieldsFrom`. Only the historical migrated custom-network fields are backfilled, plus `XDPoS.MaxMasternodesV2`.                                                                                                                                                                                                       |
| Same-hash custom override | Stored custom config for that data directory, using custom-network rules | The chain remains custom for restart purposes. It only receives the same narrow custom compatibility backfill as an ordinary custom network: the historical migrated custom-network fields, migrated system-contract addresses, and `XDPoS.MaxMasternodesV2`. It does not inherit new built-in fork flags automatically just because the genesis hash matches a built-in network. |

For ordinary custom XDPoS networks and same-hash custom override networks, the narrow backfill covers:

- migrated top-level XDC fork fields moved into `ChainConfig`
- migrated system-contract addresses
- `XDPoS.MaxMasternodesV2`

It does not backfill later-added fork switches or other nested XDPoS fields.

Operational note for custom/private networks:

- The default compatibility source for custom-network hydration is still `params.LocalnetChainConfig`.
- Startup keeps the custom path narrow, but any caller that directly runs `BackfillMissingFieldsFrom(params.LocalnetChainConfig)` on an incomplete custom config will inherit whatever Localnet defaults were omitted from that config.
- The node now emits a `WARN` listing the auto-filled fields when this custom-Localnet fallback happens through `BackfillMissingFieldsFrom`.
- To disable this behavior, declare every fork field explicitly in your custom chain config instead of relying on omission. Use `null` to disable a pointer-based fork, and `0` or another block number only when that activation is intentional.

Prague declaration requirement:

- Every chain config should now declare `pragueBlock` explicitly.
- Use `"pragueBlock": null` to keep Prague disabled, or a positive integer to schedule activation.
- Do not rely on omission as a long-term configuration strategy. Legacy built-in and Localnet configs can still have a missing `pragueBlock` hydrated from their bundled backfill source through `BackfillMissingFieldsFrom`, but custom-network hydration does not inherit later-added fork switches automatically.

## When a New ChainConfig Is Written to the Database

The node does not rewrite the database on every startup.

1. On an empty database, first initialization writes the resolved
  `ChainConfig` after startup hydration and validation.
2. On an existing database, ordinary startup compares the stored config and the
  new effective config after clearing JSON field-presence metadata.
3. If the two effective configs are semantically identical, startup does not
  rewrite the stored chain-config blob just because runtime backfill filled
  omitted fields in memory.
4. If the new effective config is semantically different and compatibility
  checks pass, the node writes the new resolved `ChainConfig` to the database.

In this context, “semantically different” means the two configs differ after
ignoring JSON field-presence tracking. In other words, field omission alone is
not treated as a meaningful change if the resolved values are the same.

Additional notes:

- For built-in networks, adding a new future fork in `params/config.go` does
 not automatically rewrite an existing stored built-in `ChainConfig` during an
 ordinary restart if runtime hydration already makes the effective config match
 the bundled config.
- For same-hash custom chains, first explicit initialization can also persist a
 chain-config override marker for that data directory.

## Startup API Semantics

The startup helpers now have distinct writable vs. readonly roles:

| Helper                      | Intended use                                               | Side effects                                                                              | Return shape                                                           | Operational meaning                                                                                                                                                |
| --------------------------- | ---------------------------------------------------------- | ----------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `SetupGenesisBlock`         | Writable startup and repair                                | May write the resolved `ChainConfig` and may persist the same-hash custom override marker | `(*params.ChainConfig, common.Hash, *params.ConfigCompatError, error)` | `compatErr` means the caller must decide whether to rewind/repair before continuing. The helper does not perform the rewind itself.                                |
| `LoadChainConfigWithCompat` | Readonly startup checks                                    | No database writes                                                                        | `(*params.ChainConfig, common.Hash, *params.ConfigCompatError, error)` | Mirrors writable normalization rules, but only reports what writable startup would need to repair or rewind.                                                       |
| `LoadChainConfig`           | Legacy readonly callers that only need the resolved config | No database writes                                                                        | `(*params.ChainConfig, common.Hash, error)`                            | Compatibility rewind metadata is intentionally discarded. Callers that need to distinguish hard failure from required repair must use `LoadChainConfigWithCompat`. |

Important behavior changes relative to older startup logic:

- `SetupGenesisBlock` no longer relies on a broad `params.AllEthashProtocolChanges` fallback for ambiguous stored metadata. Classification now follows the network classes and same-hash override rules described in this document.
- `SetupGenesisBlock` and `LoadChainConfigWithCompat` preserve `ConfigCompatError` values even when `compatErr.RewindTo == 0`. A rewind-to-zero compatibility error still means the stored chain metadata and the requested config disagree in a way the caller must handle explicitly.
- Because both helpers now return `compatErr` separately from `error`, callers should treat `compatErr != nil` as a required operator decision, not as a successful startup.

## Schema Change: `chainConfigOverride`

Same-hash custom chains now persist a dedicated metadata marker under the rawdb
key prefix:

```text
ethereum-cfgoverride-<genesisHash>
```

The value is a versioned payload written by `WriteChainConfigOverride` when a
data directory is intentionally using a custom `ChainConfig` for a genesis hash
that also matches a bundled built-in network. The current format is two bytes:

```text
{version=1, flags=1}
```

This change does not bump `core.BlockChainVersion`. The marker is additive
metadata under a new rawdb key prefix; it does not rewrite existing block,
receipt, trie, or chain-config encodings, and it does not change the meaning of
`databaseVersionKey`. Older binaries that do not know this key simply leave it
unread.

The override prefix intentionally no longer shares the `ethereum-config-`
prefix namespace, so future rawdb prefix iteration over chain-config blobs does
not accidentally scan override metadata.

This marker is used to distinguish:

- an ordinary built-in chain using the bundled config for chain IDs `50`, `51`, or `5551`
- a custom chain that intentionally reuses the same genesis block contents/hash

Forward-compatibility rules:

- New binaries treat a missing marker as "not explicitly override-backed".
- Writable startup can still recognize some legacy pre-marker same-hash custom chains from the stored config and then persist the marker as a one-way metadata repair.
- Once the versioned marker has been written, the data directory should be considered migrated to the new schema.

Downgrade warning:

- Older binaries do not know about the versioned `chainConfigOverride` metadata.
- At the rawdb layer they ignore the additional key, but because they never
  consult the marker they cannot preserve the upgraded same-hash custom-chain
  classification rules.
- If you start a new binary and allow it to persist the new marker, then roll back to an older binary on the same data directory, the old binary may misclassify the chain instead of refusing startup.
- For a same-hash custom chain, that downgrade can surface `errGenesisConfigConflict` or cause the node to ignore the intended custom classification because the old code cannot see the override marker.

Operational guidance:

- Do not downgrade an override-backed same-hash custom chain to an older binary after the marker has been written unless you also restore a pre-migration data-directory backup.
- If you must test an older binary, use a snapshot taken before the marker existed, not the already-migrated live database.

## Compatibility Matrix For Existing Mainnet/Testnet/Devnet Databases

This matrix applies to data directories whose canonical genesis hash is one of
the bundled built-in networks:

- Mainnet (`ChainID == 50`)
- Testnet (`ChainID == 51`)
- Devnet (`ChainID == 5551`)

Use the matching runtime flag on the upgraded binary:

- Mainnet: `XDC --mainnet ...`
- Testnet: `XDC --testnet ...`
- Devnet: `XDC --devnet ...`

Ordinary built-in Mainnet, Testnet, or Devnet database using the bundled config

  First startup on the current binary:
  Supported as a direct restart with the matching built-in runtime flag. No explicit `genesis.json` is required for ordinary built-in data directories.

  State after successful upgrade or repair:
  Remains a built-in network database. Ordinary startup does not need to persist `chainConfigOverride` metadata for this path.

  Can the same post-upgrade database be reopened by an older binary?
  Usually yes. The additive override-marker schema is not required for an ordinary built-in database, so rollback risk is much lower. Still take a backup before any downgrade.

  Operator guidance:
  A normal rolling upgrade is acceptable. Keep the network selection explicit with `--mainnet`, `--testnet`, or `--devnet`.

Legacy pre-marker same-hash custom database on a built-in genesis hash or chain ID, with no persisted override marker yet

  First startup on the current binary:
  Not safe as a plain restart. Readonly checks and restart attempts without the authoritative custom `genesis.json` can fail with `errGenesisConfigConflict`. The current binary does not implicitly migrate this case on a readonly path.

  State after successful upgrade or repair:
  After a writable repair, typically `XDC --allow-builtin-config-override init --datadir <datadir> /path/to/genesis.json` or another writable startup with the matching authoritative genesis, the node persists the repaired chain-config metadata and the `chainConfigOverride` marker. Later restarts on the current binary are then supported when the operator again supplies `--allow-builtin-config-override`.

  Can the same post-upgrade database be reopened by an older binary?
  No, not safely after the repair has written the marker. Older binaries ignore the marker and may misclassify the chain or surface a config conflict.

  Operator guidance:
  Treat the first upgraded start as a migration. Back up the data directory, run the writable repair with the exact matching custom genesis and `--allow-builtin-config-override`, then restart on the current binary with `--allow-builtin-config-override` whenever that data directory must continue to use the custom override instead of the bundled built-in config.

Already-migrated same-hash custom database on a built-in genesis hash or chain ID, with `chainConfigOverride` already present

  First startup on the current binary:
  Supported on the current binary when the operator starts the node with `--allow-builtin-config-override`. The marker preserves same-hash custom classification for that data directory, but the override is not applied implicitly.

  State after successful upgrade or repair:
  Remains an override-backed same-hash custom database. Current binaries continue to honor the stored custom classification and repaired metadata.

  Can the same post-upgrade database be reopened by an older binary?
  No, not safely. This is the downgrade case called out above: older binaries do not understand `chainConfigOverride` and cannot preserve the upgraded classification rules.

  Operator guidance:
  Do not downgrade on the same live database. If an older binary must be tested, restore a backup or snapshot taken before the marker existed.

Operational summary:

- For ordinary built-in Mainnet, Testnet, and Devnet databases, upgrade is a direct binary replacement plus the matching runtime flag.
- For same-hash custom databases that reuse a built-in identity surface, compatibility depends on whether the directory has already been migrated to the explicit override-marker schema.
- The one-way compatibility boundary is the first successful writable migration that persists `chainConfigOverride`.

## Operator Impact and Repair Workflow

Readonly checks can now tell you that the database is logically repairable but
not safe to continue with as-is.

Typical cases:

- `LoadChainConfigWithCompat` returns a non-nil `compatErr`
- a same-hash custom chain is missing its stored config blob and must be reopened with an explicit genesis on a writable path
- writable startup needs to persist the new override marker for a legacy pre-marker same-hash custom chain

In those cases, the correct response is to reopen the data directory in a
writable mode using the current binary and repair the metadata, rather than to
keep retrying readonly startup.

For a legacy pre-marker same-hash custom database, do not expect an ordinary
restart or a readonly command to perform that migration implicitly. The repair
must be done on a writable path with the authoritative matching `genesis.json`
and explicit `--allow-builtin-config-override`.

Recommended operator workflow:

1. Stop the node and back up the data directory.
2. Run the current binary in a writable startup path. For same-hash custom chains on built-in IDs, include `--allow-builtin-config-override` and the explicit matching `genesis.json`.
3. Allow writable startup or `XDC init` to persist the repaired chain-config metadata and, when applicable, the override marker.
4. Restart and confirm the resolved chain config matches expectations. For same-hash custom chains on built-in IDs, continue to include `--allow-builtin-config-override` on later startups and maintenance commands that rely on the override-backed classification.

## Minimal Upgrade Checklist For Strict XDC Fork Config Validation

Nodes now reject any chain config that enables XDPoS or any XDC-specific fork
field unless the following strict required fields are resolved to non-zero
usable values.

Operator checklist before the first restart on the upgraded binary:

- Confirm which authoritative source you will trust for the repair:
  the persisted chain-config blob in the data directory, or the external
  `genesis.json` used for `XDC init` or writable repair.
- Confirm that source explicitly declares every required field below.

Top-level XDC fork and system-contract fields:

- [ ] `TIPTRC21FeeBlock`
- [ ] `Gas50xBlock`
- [ ] `TRC21IssuerSMC`
- [ ] `XDCXListingSMC`
- [ ] `RelayerRegistrationSMC`
- [ ] `LendingRegistrationSMC`

XDPoS root fields:

- [ ] `XDPoS`
- [ ] `XDPoS.FoundationWalletAddr`
- [ ] `XDPoS.MaxMasternodesV2`
- [ ] `XDPoS.V2`

XDPoS v2 fields:

- [ ] `XDPoS.V2.SwitchBlock`
- [ ] `XDPoS.V2.CurrentConfig`
- [ ] `XDPoS.V2.AllConfigs`
- [ ] `XDPoS.V2.AllConfigs[0]`

Recommended operator check while filling the list:

- Treat every blank, omitted key, `null`, `0`, or zero-address value as a stop
  signal until you have confirmed that the current validation path really
  allows it.
- If startup is expected to run with XDPoS enabled, verify that the
  authoritative source contains the full `XDPoS` object, not only selected
  nested fields.

For custom or private networks, do not rely on omission as an upgrade strategy.
If the persisted config is incomplete, update the `config` section in the
authoritative `genesis.json` so the writable repair path can persist the full
strict-validation field set.

For legacy custom XDPoS networks, older sparse genesis files can still pass
startup migration when those keys were omitted entirely. In that case
`hydrateLegacyCompatibleCustomChainConfig` backfills the historical migrated
fields from `params.LocalnetChainConfig` before strict validation runs.

Important caveat:

- Auto-hydration only applies to omitted fields.
- Explicit `0`, `null`, or zero-address values remain authoritative and will
  still fail strict validation if the field is required.
- The narrow custom-network backfill only runs when the config already has an
  `XDPoS` section. If `config.XDPoS` is missing entirely, writable startup
  cannot synthesize the missing nested XDPoS fields for you; the
  authoritative `genesis.json` must declare them explicitly.

Minimal `genesis.json` example for a custom XDPoS chain:

- Use this as a shape reference for the strict-validation fields, not as a
  production template.
- Replace the addresses, `chainId`, fork heights, and reward values with the
  authoritative values for your network.
- The fork block values shown as `0` only demonstrate that the field must be
  declared. They are not universally valid defaults for an existing private
  chain.
- If the chain is already initialized, merge these `config` fields into your
  existing `genesis.json`; do not change other genesis fields unless you
  intentionally want a different genesis hash.

```json
{
  "config": {
    "chainId": 1337,
    "homesteadBlock": 0,
    "eip150Block": 0,
    "eip155Block": 0,
    "eip158Block": 0,
    "byzantiumBlock": 0,
    "constantinopleBlock": 0,
    "petersburgBlock": 0,
    "istanbulBlock": 0,
    "tip2019Block": 0,
    "tipSigningBlock": 0,
    "tipRandomizeBlock": 0,
    "tipIncreaseMasternodesBlock": 0,
    "tipNoHalvingMNRewardBlock": 0,
    "tipXDCXBlock": 0,
    "tipXDCXLendingBlock": 0,
    "tipXDCXCancellationFeeBlock": 0,
    "tipTRC21FeeBlock": 0,
    "gas50xBlock": 0,
    "trc21IssuerSMC": "0x0000000000000000000000000000000000000101",
    "xdcxListingSMC": "0x0000000000000000000000000000000000000102",
    "relayerRegistrationSMC": "0x0000000000000000000000000000000000000103",
    "lendingRegistrationSMC": "0x0000000000000000000000000000000000000104",
    "XDPoS": {
      "period": 2,
      "epoch": 900,
      "reward": 5000,
      "rewardCheckpoint": 900,
      "gap": 450,
      "foundationWalletAddr": "0x0000000000000000000000000000000000000068",
      "maxMasternodesV2": 108,
      "v2": {
        "switchEpoch": 1,
        "switchBlock": 900,
        "config": {
          "maxMasternodes": 108,
          "switchRound": 0,
          "minePeriod": 2,
          "timeoutSyncThreshold": 3,
          "timeoutPeriod": 10,
          "certificateThreshold": 0.667,
          "expTimeoutConfig": {
            "base": 1,
            "maxExponent": 0
          }
        },
        "allConfigs": {
          "0": {
            "maxMasternodes": 108,
            "switchRound": 0,
            "minePeriod": 2,
            "timeoutSyncThreshold": 3,
            "timeoutPeriod": 10,
            "certificateThreshold": 0.667,
            "expTimeoutConfig": {
              "base": 1,
              "maxExponent": 0
            }
          }
        }
      }
    }
  },
  "alloc": {},
  "coinbase": "0x0000000000000000000000000000000000000000",
  "difficulty": "0x20000",
  "extraData": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "gasLimit": "0x2fefd8",
  "mixhash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "nonce": "0x0000000000000042",
  "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "timestamp": "0x00"
}
```

If the first upgraded startup fails with `missing fork switch` for one of the
fields above, treat it as a migration task rather than a transient startup
error. Reopen the data directory through a writable path and ensure the
persisted config or external `genesis.json` carries the required values.

Do not treat a readonly compatibility warning as a harmless cosmetic diff. It
means the writable path would need to repair metadata or require an explicit
rewind decision before startup should proceed.

## Same-Hash Custom Chains on Built-In IDs (`50` / `51` / `5551`)

The most error-prone migration path is a custom genesis that intentionally
reuses the same block contents and built-in identity surface as:

- Mainnet (`ChainID == 50`)
- Testnet (`ChainID == 51`)
- Devnet (`ChainID == 5551`)

For these chains, classification now depends on more than the genesis hash
alone.

Practical rules:

1. If the data directory already carries the override marker, the chain is treated as a same-hash custom chain for that directory.
2. If the marker is absent, writable startup may still recognize a legacy stored custom config and migrate the directory by writing the marker.
3. If both the marker and the custom stored config are missing, the node falls back to bundled built-in classification for that hash.

Migration guidance for operators:

1. Keep the exact custom `genesis.json` used to initialize the chain. You need it for repair and restart if the stored chain-config metadata is missing.
2. Run a writable startup with the current binary and `--allow-builtin-config-override` at least once so legacy pre-marker databases can be migrated and the override marker can be persisted.
3. After migration, avoid downgrading to older binaries on the same database.
4. If readonly startup reports a conflict on a chain that should be same-hash custom, assume the directory is missing the marker or stored config and repair it with a writable startup using `--allow-builtin-config-override` and the matching explicit genesis.

For same-hash custom chains on built-in IDs, `--allow-builtin-config-override` is an explicit operator acknowledgement. Without it, the current binary rejects the override instead of silently treating a matching built-in hash as custom. When the override is accepted, startup logs `YOU ARE OVERRIDING BUILTIN CHAIN CONFIG`.

Minimal repair sequence for a legacy pre-marker same-hash custom database:

1. Back up the data directory.
2. Run `XDC --allow-builtin-config-override --datadir <datadir> init /path/to/genesis.json` or another writable startup path with `--allow-builtin-config-override` and the same authoritative genesis file.
3. Let the current binary persist the repaired chain-config metadata and override marker.
4. Restart with `--allow-builtin-config-override`. Only use readonly commands after that writable migration has completed.

The helper logic behind `isLegacyStoredCustomBuiltInConfig` and
`shouldAllowCustomBuiltInConfig` is intentionally conservative. Its purpose is
to preserve legitimate legacy custom deployments, not to guess operator intent
from incomplete metadata. When in doubt, prefer an explicit writable repair
with the authoritative custom genesis file.

## Upgrading ChainConfig

Use this procedure when the chain is already running and you want to add a new
future fork or otherwise change `ChainConfig` without changing the canonical
genesis block.

### Prerequisites

- Back up the data directory and record the current head block number.
- Start from the current effective custom or built-in config, not from an old
 template.
- Keep the genesis block contents unchanged. Do not modify alloc, nonce,
 timestamp, extra data, gas limit, difficulty, or any other field that would
 change the genesis hash.
- Change only future-compatible values in the `config` section.
- For same-hash custom chains, the data directory must already be an
 override-backed same-hash custom chain. Otherwise the node still treats that
 hash as a bundled network.

### Steps

a. Update the `config` section in your `genesis.json` with the new future fork
  switch or other future-only config value.
b. Make sure all required migrated fields, system-contract addresses, and
  XDPoS settings remain explicitly declared, including
  `XDPoS.FoundationWalletAddr`, `XDPoS.MaxMasternodesV2`,
  `XDPoS.V2.SwitchBlock`, `XDPoS.V2.CurrentConfig`, and
  `XDPoS.V2.AllConfigs`.
c. Verify that each new or modified fork switch is still in the future and
  that fork ordering remains valid.
d. Apply the update with:

  ```bash
  XDC --datadir <datadir> init /path/to/genesis.json
  ```

  For same-hash custom chains on built-in IDs, use:

  ```bash
  XDC --allow-builtin-config-override --datadir <datadir> init /path/to/genesis.json
  ```

e. Restart the node normally.
  For same-hash custom chains on built-in IDs, restart with `--allow-builtin-config-override`.
f. Verify that the node is now using the expected updated chain config.

### Important Notes

- Running `XDC init` on a non-empty data directory does not recreate the
 canonical genesis block when the genesis hash is unchanged. It re-runs
 startup chain-config validation with the explicit genesis/config you provide.
- If the proposed config change would alter the genesis hash, treat it as a
 different chain and use a fresh data directory instead of trying to mutate
 the existing one in place.
- If a new fork point is no longer entirely in the future, compatibility checks
 may return a `ConfigCompatError` and require a rewind or another migration
 workflow instead of an in-place update.

## Prague / EIP-2935

- The history storage contract is predeployed only in the developer genesis.
- For other networks, the contract is deployed at Prague activation by the
 system call during block processing and state access.
- Nodes upgrading after Prague will perform a one-time backfill of recent
 parent hashes into the ring buffer. If historical headers are pruned or
 unavailable, missing slots are skipped and only available hashes are filled.
- If you maintain a custom genesis and want predeployment, add an account entry
 for `HistoryStorageAddress` with `Nonce: 1` and `Code: HistoryStorageCode`.
