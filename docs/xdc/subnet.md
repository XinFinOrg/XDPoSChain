# XDC subnets

An XDC subnet is a permissioned XDPoS 2.0 chain whose block headers are
checkpointed on a parent chain (XDC mainnet, Apothem or devnet) by the subnet
relayer and the checkpoint contract (CSC). Setting `isSubnet` in the XDPoS
section of the chain config makes this client run a subnet: the v2 engine then
follows the subnet consensus rules of the other subnet clients, Nethermind's
`XDPoSSubnet` engine and the Go XDC-Subnet client, and the two can validate the
same subnet side by side.

The design is recorded in [ADR 0005](../adr/0005-subnet-consensus.md).

## Consensus rules

A subnet runs the XDPoS 2.0 HotStuff flow unchanged: the same rounds, votes,
timeouts, sync messages, quorum and timeout certificates (`certificateThreshold`
is the fraction of masternodes that must sign) and the same leader rotation,
`masternodes[round % epoch % len(masternodes)]`. What differs:

| | XDPoS chain | Subnet |
|---|---|---|
| v2 engine | from `v2.switchBlock` | from genesis, the genesis included |
| Epoch switch | first block of a new round epoch | block `n` with `n % epoch == 0` |
| Epoch number | `switchEpoch + round / epoch` | `n / epoch` |
| Validator contract | XDCValidator, candidates at slot 8 | subnet XDCValidator (grandmasters), candidates at slot 7 |
| Penalties computed | at the epoch switch | at the gap block, stored in its snapshot |
| Penalties published | `penalties` of the epoch switch header | `penalties` of the block after the gap block |
| Next-epoch candidates published | nowhere | `nextValidators` of the block after the gap block |
| Epoch switch `validators` | candidates minus penalties, compared as a set | candidates minus penalties, compared as a set |
| Header layout | legacy | subnet (see below) |
| EIP-1559 | optional | off |
| Reward | per fork schedule | flat, no halving, masternodes of the epoch switch header |

With `E = epoch` and `G = gap`:

- **Gap block** `n % E == E - G`. The node snapshots the candidates of the
  subnet validator contract, sorted by stake, and computes the penalties of the
  next epoch (below). Both are stored with the block.
- **Block after the gap block** `n % E == E - G + 1`, and block 1 for the
  genesis snapshot. Its header publishes the snapshot: `nextValidators` holds
  the candidates, `penalties` the penalties. Every other block leaves both
  empty. Peers compare them with their own snapshot of the parent block.
- **Epoch switch** `n % E == 0`. `validators` holds the masternodes of the new
  epoch: the snapshot candidates of gap block `n - G` without its penalties, in
  candidate order, capped at `maxMasternodes`. Peers compare the list with
  their own as a set, as on mainnet; the order written in the header then
  decides the leader of each round of the epoch.

**Penalties.** At gap block `g`, the node walks back from `g - 1` to the
previous gap block (block 1 for the first epochs), counting the blocks each
miner produced. At every epoch switch on the way, and at the end of the walk,
each masternode of that epoch that produced fewer than one block of the segment
just counted is penalized. The penalties the previous block after a gap block
published carry over. A penalized node comes back once it has sent a signing
transaction for one of the MergeSignRange (15) blocks among the last
RangeReturnSigner (150) blocks before the gap block. The list is deduplicated
and sorted by EIP-55 address.

**Rewards.** At each epoch switch the reward of the epoch that started two epoch
switches before is paid: `reward` ether split among the masternodes listed in
that epoch switch header, in proportion to the MergeSignRange blocks each signed,
90% to the masternode owner and 10% to the foundation wallet. The genesis header
lists no masternodes, so the genesis epoch pays nothing.

**Header layout.** A subnet header is the RLP list

```
parentHash, uncleHash, coinbase, root, txHash, receiptHash, bloom, difficulty,
number, gasLimit, time, extra, mixDigest, nonce,
validator (bytes), validators ([]address), nextValidators ([]address), penalties ([]address)
```

with no base fee. The seal (`validator`) signs the keccak256 of the same list
without `validator` and `nextValidators`. The subnet checkpoint contracts parse
this layout, and the header hash is the hash of this encoding. In memory the
address fields are kept packed, like those of the legacy layout, and
`Header.Subnet` selects the encoding; decoding recognizes the layout by its
17th item, a list.

## Chain config

A subnet config is taken as written: unlike other custom chains it is never
backfilled with the defaults of the built-in networks. Besides the usual XDPoS
requirements (`foundationWalletAddr`, `maxMasternodesV2`, a v2 config at round
0, `tipTRC21FeeBlock`, `gas50xBlock` and the four XDC system contract
addresses), the config check enforces:

- `v2.switchBlock` and `v2.switchEpoch` are 0;
- `2 <= gap < epoch`, so the block after the gap block is never an epoch switch;
- `eip1559Block` is unset, and so are the forks that require it (Cancun on);
- `tipNoHalvingMNRewardBlock` is 0 and the tiered reward forks
  (`tipFixedRewardBlock`, `tipProportionalRewardBlock`, `tipEpochHalvingBlock`)
  are unset;
- every v2 config has a positive `maxMasternodes`.

`networkName` and `denom` are optional and only reported by
`XDPoS_networkInformation`.

Example (the v2 config is abridged; the genesis block, extra data and alloc come
from the subnet genesis tool):

```json
"config": {
  "chainId": 18448,
  "homesteadBlock": 0, "eip150Block": 0, "eip155Block": 0, "eip158Block": 0,
  "byzantiumBlock": 0, "constantinopleBlock": 0, "petersburgBlock": 0,
  "istanbulBlock": 0, "berlinBlock": 0, "londonBlock": 0, "mergeBlock": 0,
  "shanghaiBlock": 0,
  "eip1559Block": null, "cancunBlock": null, "pragueBlock": null, "osakaBlock": null,
  "tip2019Block": 0, "tipSigningBlock": 0, "tipIncreaseMasternodesBlock": 0,
  "tipNoHalvingMNRewardBlock": 0, "tipTRC21FeeBlock": 0, "gas50xBlock": 0,
  "trc21IssuerSMC": "0x8c0faeb5C6bEd2129b8674F262Fd45c4e9468bee",
  "xdcxListingSMC": "0xDE34dD0f536170993E8CFF639DdFfCF1A85D3E53",
  "relayerRegistrationSMC": "0x16c63b79f9C8784168103C0b74E6A59EC2de4a02",
  "lendingRegistrationSMC": "0x7d761afd7ff65a79e4173897594a194e3c506e57",
  "XDPoS": {
    "isSubnet": true,
    "networkName": "mysubnet",
    "denom": "sdc",
    "period": 2,
    "epoch": 900,
    "gap": 450,
    "reward": 2,
    "rewardCheckpoint": 900,
    "foundationWalletAddr": "0x...",
    "maxMasternodesV2": 108,
    "v2": {
      "switchEpoch": 0,
      "switchBlock": 0,
      "config": { "switchRound": 0, "maxMasternodes": 108, "minePeriod": 2, "timeoutPeriod": 10,
                  "timeoutSyncThreshold": 3, "certificateThreshold": 0.667,
                  "expTimeoutConfig": { "base": 1.0, "maxExponent": 0 } },
      "allConfigs": { "0": { "...": "the same as config" } }
    }
  }
}
```

The fork schedule decides the EVM. With the schedule above the EVM is the one
existing subnets run; the subnet generator's chainspec converter derives the
matching Nethermind chainspec from it (`genesis-to-chainspec.js --subnet`).

### Genesis

The genesis block lists the genesis masternodes in its extra data, in the v1
layout (32 bytes of vanity, the addresses, 65 zero bytes), and allocates the
subnet validator contract at `0x0000000000000000000000000000000000000088` with
the same masternodes as candidates. The puppeth of the XDC-Subnet image writes
such a genesis (`puppeth --file genesis_input.yml`); replacing its chain config
with a subnet config as above keeps the genesis hash, so the same genesis serves
XDC-Subnet, Nethermind and this client.

## Running a node

The Docker image starts a subnet node when a genesis is mounted at
`/work/genesis.json` and `NETWORK` is unset (or `NETWORK=subnet`). It takes the
environment of the XDC-Subnet image, so the files the subnet generator writes
work unchanged: set the generator's node image (`VERSION_SUBNET_IMAGE`) to this
image.

| Variable | Flag | Default |
|---|---|---|
| `PRIVATE_KEY` | imported and unlocked as the miner | required on first start |
| `NETWORK_ID` | `--networkid` | 102 |
| `BOOTNODES` | `--bootnodes` | |
| `PORT`, `RPCPORT`, `WSPORT` | `--port`, `--http-port`, `--ws-port` | 30303, 8545, 8555 |
| `RPC_API` | `--http-api`, `--ws-api` | `db,eth,net,txpool,web3,XDPoS` |
| `STATS_SERVICE_ADDRESS`, `STATS_SECRET`, `INSTANCE_NAME` | `--ethstats` | |
| `SYNC_MODE`, `GC_MODE`, `LOG_LEVEL` | `--syncmode`, `--gcmode`, `--verbosity` | full, full, 3 |
| `GASPRICE`, `GASLIMIT` | `--miner-gasprice`, `--miner-gaslimit` | 1, 420000000 |
| `EXTIP` | `--nat extip:` | |

Without Docker: `XDC init genesis.json`, then start `XDC` with `--mine` and the
masternode account unlocked as for any XDPoS network.

## RPC

- `eth_getBlockBy*` and `eth_getHeaderBy*` report `validators`,
  `nextValidators` and `penalties` as address lists, as Nethermind does.
- `XDPoS_getV2BlockBy*` return the subnet header RLP in `EncodedRLP`, which the
  relayer posts to the checkpoint contract.
- `XDPoS_networkInformation` adds `NetworkName` and `Denom`.
- `XDPoS_getMasternodesByNumber` and `eth_getCandidates` report the penalties of
  the epoch from the gap block snapshot; the candidates come from the subnet
  validator contract.
- `XDPoS_getBlockInfoByEpochNum` and the other epoch lookups number epochs by
  block.

## Things to know

- **Syncing stops once per epoch.** A node importing a batch that holds both a
  gap block and the block after it cannot check the latter until the gap block
  is processed and its snapshot stored. The import keeps the blocks before it
  and reports a local condition; the next sync cycle resumes from there. The
  epoch switch of an XDPoS chain behaves the same way.
- **Fast sync** takes the penalties of a gap block snapshot from the block
  after it rather than recomputing them, since it has not imported the bodies of
  that epoch yet. Full sync recomputes them.
- **Only full verification checks the published fields.** Like the epoch switch
  masternodes, `nextValidators` and `penalties` are compared with the local
  snapshot only when a header is fully verified.
- **The penalty constants are fixed**: one block per epoch segment,
  MergeSignRange 15 and RangeReturnSigner 150, as in the other subnet clients.
  The `minimumMinerBlockPerEpoch`, `limitPenaltyEpoch` and `minimumSigningTx` v2
  config fields are not read on a subnet.
- **Exponential timeouts.** Nethermind has no counterpart for
  `expTimeoutConfig`; in a mixed subnet set it to `base 1, maxExponent 0` so all
  clients time out after `timeoutPeriod`.
- **Equal stakes.** Equal-stake candidates are ordered by the XDPoS sort, the
  frozen pre-1.19 `sort.Slice`, which XDC-Subnet and Nethermind (`XdcSort`) use
  too, so every client derives the same masternode order.
- **Nethermind's order check.** Nethermind's subnet engine requires the epoch
  switch `validators` in exactly the computed order, while this client, like
  XDPoS mainnet and XDC-Subnet, compares them as a set. Blocks from honest
  producers pass both; a block listing the masternodes in another order would
  be accepted by this client and rejected by Nethermind nodes.
- **Masternode cap.** Set `maxMasternodes` to 108 to match XDC-Subnet, which
  ignores the config and always caps at 108.
- **Nodes and threshold.** A quorum certificate needs
  `ceil(masternodes * certificateThreshold)` signatures; with the default 0.667
  a subnet of three masternodes stops whenever one is down, while four or more
  tolerate one.
