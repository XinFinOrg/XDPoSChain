
# Module XDPoS

## Method XDPoS_getBlockInfoByEpochNum

Parameters:

- epochNumber: integer, required, epoch number

Returns:

result: object EpochNumInfo:

- hash: hash of first block in this epoch
- round: round of epoch
- firstBlock: number of first block in this epoch
- lastBlock: number of last block in this epoch

Example:

```shell
epoch=89300

curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "XDPoS_getBlockInfoByEpochNum",
  "params": [
    '"${epoch}"'
  ]
}' | jq
```

## Method XDPoS_getEpochNumbersBetween

Parameters:

- begin: string, required, block number
- end: string, required, block number

Returns:

result: array of uint64

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "XDPoS_getEpochNumbersBetween",
  "params": [
    "0x5439860",
    "0x5439c48"
  ]
}' | jq
```

## Method XDPoS_getLatestPoolStatus

The `XDPoS_getLatestPoolStatus` method retrieves current vote pool and timeout pool content and missing messages.

Parameters:

None

Returns:

result: object MessageStatus

- vote:    object
- timeout: object

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "XDPoS_getLatestPoolStatus"
}' | jq
```

## Method XDPoS_getMasternodesByNumber

Parameters:

- number: string, required, BlockNumber

Returns:

result: object MasternodesStatus:

- Number:          uint64
- Round:           uint64
- MasternodesLen:  int
- Masternodes:     array of address
- PenaltyLen:      int
- Penalty:         array of address
- StandbynodesLen: int
- Standbynodes:    array of address
- Error:           string

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "XDPoS_getMasternodesByNumber",
  "params": [
    "latest"
  ]
}' | jq
```

## Method XDPoS_getMissedRoundsInEpochByBlockNum

Parameters:

- number: string, required, BlockNumber

Returns:

result: object PublicApiMissedRoundsMetadata:

- EpochRound:       uint64
- EpochBlockNumber: big.Int
- MissedRounds:     array of MissedRoundInfo

MissedRoundInfo:

- Round:            uint64
- Miner:            address
- CurrentBlockHash: hash
- CurrentBlockNum:  big.Int
- ParentBlockHash:  hash
- ParentBlockNum:   big.Int

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "XDPoS_getMissedRoundsInEpochByBlockNum",
  "params": [
    "latest"
  ]
}' | jq
```

## Method XDPoS_getSigners

The `getSigners` method retrieves the list of authorized signers at the specified block.

Parameters:

- number: string, required, BlockNumber

Returns:

result: array of address

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "XDPoS_getSigners",
  "params": [
    "latest"
  ]
}' | jq
```

## Method XDPoS_getSignersAtHash

The `getSignersAtHash` method retrieves the state snapshot at a given block.

Parameters:

- hash: string, required, block hash

Returns:

same as `XDPoS_getSigners`

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "XDPoS_getSignersAtHash",
  "params": [
    "'"${hash}"'"
  ]
}' | jq
```

## Method XDPoS_getSnapshot

The `getSnapshot` method retrieves the state snapshot at a given block.

Parameters:

- number: string, required, BlockNumber

Returns:

result: object PublicApiSnapshot:

- number:  block number where the snapshot was created
- hash:    block hash where the snapshot was created
- signers: array of authorized signers at this moment
- recents: array of recent signers for spam protections
- votes:   list of votes cast in chronological order
- tally:   current vote tally to avoid recalculating

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "XDPoS_getSnapshot",
  "params": [
    "latest"
  ]
}' | jq
```

## Method XDPoS_getSnapshotAtHash

The `getSnapshotAtHash` method retrieves the state snapshot at a given block.

Parameters:

- hash: string, required, block hash

Returns:

same as `XDPoS_getSnapshot`

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "XDPoS_getSnapshotAtHash",
  "params": [
    "latest"
  ]
}' | jq
```

## Method XDPoS_getV2BlockByHash

Parameters:

- hash: string, required, block hash

Returns:

same as `XDPoS_getV2BlockByNumber`

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "XDPoS_getV2BlockByHash",
  "params": [
    "'"${hash}"'"
  ]
}' | jq
```

## Method XDPoS_getV2BlockByNumber

Parameters:

- number: string, required, BlockNumber

Returns:

result: object V2BlockInfo:

- Hash:       hash
- Round:      uint64
- Number:     big.Int
- ParentHash: hash
- Committed:  bool
- Miner:      common.Hash
- Timestamp:  big.Int
- EncodedRLP: string
- Error:      string

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "XDPoS_getV2BlockByNumber",
  "params": [
    "latest"
  ]
}' | jq
```

## Method XDPoS_networkInformation

Parameters:

None

Returns:

result: object NetworkInformation:

- NetworkId:                  big.Int
- XDCValidatorAddress:        address
- RelayerRegistrationAddress: address
- XDCXListingAddress:         address
- XDCZAddress:                address
- LendingAddress:             address
- ConsensusConfigs:           object of XDPoSConfig

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "XDPoS_networkInformation"
}' | jq
```
