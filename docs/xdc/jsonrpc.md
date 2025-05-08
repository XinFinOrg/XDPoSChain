# XDC blockchain JSONRPC API

Notice: type `BlockNumber` is the block number in hexadecimal format or the string `latest`, `earliest`, `pending` or `finalized`.

## module XDPoS

### XDPoS_getBlockInfoByEpochNum

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

### XDPoS_getEpochNumbersBetween

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

### XDPoS_getLatestPoolStatus

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

### XDPoS_getMasternodesByNumber

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

### XDPoS_getMissedRoundsInEpochByBlockNum

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

### XDPoS_getSigners

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

### XDPoS_getSignersAtHash

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

### XDPoS_getSnapshot

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

### XDPoS_getSnapshotAtHash

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

### XDPoS_getV2BlockByHash

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

### XDPoS_getV2BlockByNumber

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

### XDPoS_networkInformation

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

## module admin

The `admin` API gives you access to several non-standard RPC methods, which will allow you to have a fine grained control over your Geth instance, including but not limited to network peer and RPC endpoint management.

### admin_addPeer

The `addPeer` administrative method requests adding a new remote node to the list of tracked static nodes. The node will try to maintain connectivity to these nodes at all times, reconnecting every once in a while if the remote connection goes down.

Parameters:

- url: string, required, the enode URL of the remote peer to start tracking

Returns:

result: bool, indicating whether the peer was accepted for tracking or some error occurred.

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "admin_addPeer",
  "params": [
    "enode://1f5a9bd8bd4abb4ecec8812f0f440fec30dd745c91871ac57ebbadcd23ceafbdf7035f29bf0092feb5087ad72ad208dd12966bfcb88b339884e08cff4d167d87@194.180.176.105:38645"
  ]
}' | jq
```

### admin_addTrustedPeer

The `addTrustedPeer` method allows a remote node to always connect, even if slots are full.

Parameters:

- url: string, required

Returns:

result: bool

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "admin_addTrustedPeer",
  "params": [
    "enode://1f5a9bd8bd4abb4ecec8812f0f440fec30dd745c91871ac57ebbadcd23ceafbdf7035f29bf0092feb5087ad72ad208dd12966bfcb88b339884e08cff4d167d87@194.180.176.105:38645"
  ]
}' | jq
```

### admin_datadir

The `datadir` administrative property can be queried for the absolute path the running Geth node currently uses to store all its databases.

Parameters:

None

Returns:

result: string

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "admin_datadir"
}' | jq
```

### admin_exportChain

The `exportChain` method exports the current blockchain into a local file. It optionally takes a first and last block number, in which case it exports only that range of blocks.

Parameters:

- fn: string, required, filen name

Returns:

result: bool, indicating whether the operation succeeded

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "admin_exportChain",
  "params": [
    "filename"
  ]
}' | jq
```

### admin_importChain

The `importChain` method imports an exported list of blocks from a local file. Importing involves processing the blocks and inserting them into the canonical chain. The state from the parent block of this range is required. It returns a boolean indicating whether the operation succeeded.

Parameters:

- file: string, required, filen name

Returns:

result: bool, indicating whether the operation succeeded

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "admin_importChain",
  "params": [
    "filename"
  ]
}' | jq
```

### admin_nodeInfo

The `nodeInfo` administrative property can be queried for all the information known about the running Geth node at the networking granularity. These include general information about the node itself as a participant of the P2P overlay protocol, as well as specialized information added by each of the running application protocols (e.g. eth, les, shh, bzz).

Parameters:

None

Returns:

result: object NodeInfo:

- id: string, unique node identifier (also the encryption key)
- name: string, name of the node, including client type, version, OS, custom data
- enode: string, enode URL for adding this peer from remote peers
- ip: string, IP address of the node
- ports: object
  - discovery: int, UDP listening port for discovery protocol
  - listener: int, TCP listening port for RLPx
- listenAddr: string
- protocols:  object

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "admin_nodeInfo"
}' | jq
```

### admin_peerEvents

The `peerEvents` creates an RPC subscription which receives peer events from the node's p2p server. The type of events emitted by the server are as follows:

- add: emitted when a peer is added
- drop: emitted when a peer is dropped
- msgsend: emitted when a message is successfully sent to a peer
- msgrecv: emitted when a message is received from a peer

Parameters:

None

Returns:

result: object Subscription

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "admin_peerEvents"
}' | jq
```

### admin_peers

The `peers` administrative property can be queried for all the information known about the connected remote nodes at the networking granularity.

Parameters:

None

Returns:

result: array of PeerInfo:

- id: string,unique node identifier (also the encryption key)
- name: string, name of the node, including client type, version, OS, custom data
- caps: array of string, sum-protocols advertised by this particular peer
- network object:
  - localAddress: string, local endpoint of the TCP data connection
  - remoteAddress: string, remote endpoint of the TCP data connection
  - inbound: bool
  - trusted: bool
  - static: bool
- protocols: object, sub-protocol specific metadata fields

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "admin_peers"
}' | jq
```

### admin_removePeer

The `removePeer` method disconnects from a remote node if the connection exists. It returns a boolean indicating validations succeeded. Note a true value doesn't necessarily mean that there was a connection which was disconnected.

Parameters:

- url: string, required

Returns:

result: bool, indicating validations succeeded

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "admin_removePeer",
  "params": [
    "enode://1f5a9bd8bd4abb4ecec8812f0f440fec30dd745c91871ac57ebbadcd23ceafbdf7035f29bf0092feb5087ad72ad208dd12966bfcb88b339884e08cff4d167d87@194.180.176.105:38645"
  ]
}' | jq
```

### admin_removeTrustedPeer

The `removeTrustedPeer` method removes a remote node from the trusted peer set, but it does not disconnect it automatically.

Parameters:

- url: string, required

Returns:

result: bool, indicating validations succeeded

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "admin_removeTrustedPeer",
  "params": [
    "enode://1f5a9bd8bd4abb4ecec8812f0f440fec30dd745c91871ac57ebbadcd23ceafbdf7035f29bf0092feb5087ad72ad208dd12966bfcb88b339884e08cff4d167d87@194.180.176.105:38645"
  ]
}' | jq
```

### admin_startRPC

The `startRPC` method starts the HTTP RPC API server.

Parameters:

- host: string, optional, network interface to open the listener socket on (defaults to "localhost")
- port: int, optional, network port to open the listener socket on (defaults to 8546)
- cors: string, optional, cross-origin resource sharing header to use (defaults to "")
- apis: string, optional, API modules to offer over this interface (defaults to "eth,net,web3")
- vhosts: string, optional

Returns:

result: bool, indicating whether the operation succeeded

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "admin_startRPC"
}' | jq
```

### admin_startWS

The startWS administrative method starts an WebSocket based JSON RPC API webserver to handle client requests.

Parameters:

- host: string, optional, network interface to open the listener socket on (defaults to "localhost")
- port: int, optional, network port to open the listener socket on (defaults to 8546)
- cors: string, optional, cross-origin resource sharing header to use (defaults to "")
- apis: string, optional, API modules to offer over this interface (defaults to "eth,net,web3")

Returns:

result: bool, indicating whether the operation succeeded

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "admin_startWS"
}' | jq
```

### admin_stopRPC

The `stopRPC` method shuts down the HTTP server.

Parameters:

None

Returns:

result: bool, indicating whether the operation succeeded

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "admin_stopRPC"
}' | jq
```

### admin_stopWS

The `stopWS` administrative method closes the currently open WebSocket RPC endpoint.

Parameters:

None

Returns:

result: bool, indicating whether the endpoint was closed or not

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "admin_stopWS"
}' | jq
```

## module debug

The `debug` API gives you access to several non-standard RPC methods, which will allow you to inspect, debug and set certain debugging flags during runtime.

### debug_blockProfile

The `blockProfile` method turns on block profiling for the given duration and writes profile data to disk. It uses a profile rate of 1 for most accurate information. If a different rate is desired, set the rate and write the profile manually using debug_writeBlockProfile.

Parameters:

- file: string, required, file name
- nsec: uint, required, number of seconds

Returns:

result: error

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_blockProfile",
  "params": [
    "block-profile.bin",
    10
  ]
}' | jq
```

### debug_chaindbCompact

The `chaindbCompact` method flattens the entire key-value database into a single level, removing all unused slots and merging all keys.

Parameters:

None

Returns:

result: error

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_chaindbCompact"
}' | jq
```

### debug_chaindbProperty

The `chaindbProperty` method returns leveldb properties of the key-value database.

Parameters:

- property: string, required

Returns:

result: string

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_chaindbProperty",
  "params": [
    ""
  ]
}' | jq
```

### debug_cpuProfile

The `cpuProfile` method turns on CPU profiling for the given duration and writes profile data to disk.

Parameters:

- file: string, required, file name
- nsec: uint, required, number of seconds

Returns:

result: error

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_cpuProfile",
  "params": [
    "cpu-profile.bin",
    10
  ]
}' | jq
```

### debug_dbGet

The `dbGet` method returns the raw value of a key stored in the database.

Parameters:

- key: string, required

Returns:

result: array of byte

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_dbGet",
  "params": [
    "key"
  ]
}' | jq
```

### debug_dumpBlock

The `dumpBlock` method retrieves the entire state of the database at a given block.

Parameters:

- number: BlockNumber, required, block number

Returns:

result: object Dump

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_dumpBlock",
  "params": [
    "earliest"
  ]
}' | jq
```

### debug_getBadBlocks

The `getBadBlocks` method returns a list of the last 'bad blocks' that the client has seen on the network and returns them as a JSON list of block-hashes.

Parameters:

None

Returns:

result: array of BadBlockArgs

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_getBadBlocks"
}' | jq
```

### debug_gcStats

The `gcStats` method returns garbage collection statistics.

Parameters:

None

Returns:

result: ojbect GCStats

See <https://golang.org/pkg/runtime/debug/#GCStats> for information about the fields of the returned object.

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_gcStats"
}' | jq
```

### debug_getBlockRlp

The `getBlockRlp` retrieves the RLP encoded for of a single block.

Parameters:

- number: uint64, required, block number

Returns:

result: string

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_getBlockRlp",
  "params": [
    0
  ]
}' | jq
```

### debug_getModifiedAccountsByHash

The `getModifiedAccountsByHash` method returns all accounts that have changed between the two blocks specified. A change is defined as a difference in nonce, balance, code hash, or storage hash. With one parameter, returns the list of accounts modified in the specified block.

Parameters:

- startHash: hash, required, start block hash
- endHash: hash optional, end block hash

Returns:

result: array of address

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_getModifiedAccountsByNumber",
  "params": [
    "start-hash",
    "end-hash"
  ]
}' | jq
```

### debug_getModifiedAccountsByNumber

The `getModifiedAccountsByNumber` method returns all accounts that have changed between the two blocks specified. A change is defined as a difference in nonce, balance, code hash or storage hash.

Parameters:

- startNum: uint64, required, start block number
- endNum: uint64, optional, end block number

Returns:

result: array of address

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_getModifiedAccountsByNumber",
  "params": [
    1
  ]
}' | jq
```

### debug_goTrace

The `goTrace` method turns on Go runtime tracing for the given duration and writes trace data to disk.

Parameters:

- file: string, required, file name
- nsec: uint, required, number of seconds

Returns:

result: error

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_goTrace",
  "params": [
    "go-trace.bin",
    10
  ]
}' | jq
```

### debug_freeOSMemory

The debug `freeOSMemory` forces garbage collection.

Parameters:

None

Returns:

result: null

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_freeOSMemory"
}' | jq
```

### debug_memStats

The `memStats` method returns detailed runtime memory statistics.

Parameters:

None

Returns:

result: object MemStats

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_memStats"
}' | jq
```

### debug_mutexProfile

The `mutexProfile` method turns on mutex profiling for nsec seconds and writes profile data to file. It uses a profile rate of 1 for most accurate information. If a different rate is desired, set the rate and write the profile manually.

Parameters:

- file: string, required, file name
- nsec: uint, required, number of seconds

Returns:

result: error

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_mutexProfile",
  "params": [
    "mutex-profile.bin",
    10
  ]
}' | jq
```

### debug_preimage

The `preimage` method returns the preimage for a sha3 hash, if known.

Parameters:

- hash: hash, required

Returns:

result: array of bytes

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_preimage",
  "params": [
    "hash",
  ]
}' | jq
```

### debug_printBlock

The `printBlock` method retrieves a block and returns its pretty printed form.

Parameters:

- number: uint64, required, block number

Returns:

result: string

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_printBlock",
  "params": [
    0
  ]
}' | jq
```

### debug_seedHash

The `seedHash` method retrieves the seed hash of a block.

Parameters:

- number: uint64, required, block number

Returns:

result: string

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_seedHash",
  "params": [
    0
  ]
}' | jq
```

### debug_setBlockProfileRate

The `setBlockProfileRate` method sets the rate (in samples/sec) of goroutine block profile data collection. A non-zero rate enables block profiling, setting it to zero stops the profile. Collected profile data can be written using `debug_writeBlockProfile`.

Parameters:

- rate: int, required

Returns:

result: null

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_setBlockProfileRate",
  "params": [
    0
  ]
}' | jq
```

### debug_setGCPercent

The `setGCPercent` method sets the garbage collection target percentage. A negative value disables garbage collection.

Parameters:

- v: int, required

Returns:

result: int

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_setGCPercent",
  "params": [
    80
  ]
}' | jq
```

### debug_setHead

The `setHead` method sets the current head of the local chain by block number. Note, this is a destructive action and may severely damage your chain. Use with extreme caution.

Parameters:

- number: uint64, required, block number

Returns:

result: string

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_setHead",
  "params": [
    "0x544b420"
  ]
}' | jq
```

### debug_stacks

The `stacks` method returns a printed representation of the stacks of all goroutines. Note that the web3 wrapper for this method takes care of the printing and does not return the string.

Parameters:

None

Returns:

result: string

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_stacks"
}' | jq
```

### debug_startCPUProfile

The `startCPUProfile` method turns on CPU profiling indefinitely, writing to the given file.

Parameters:

- file: string, required, file name

Returns:

result: error

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_startCPUProfile",
  "params": [
    "cpu-profile.bin"
  ]
}' | jq
```

### debug_startGoTrace

The `startGoTrace` starts writing a Go runtime trace to the given file.

Parameters:

- file: string, required, file name

Returns:

result: error

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_startGoTrace",
  "params": [
    "go-trace.bin"
  ]
}' | jq
```

### debug_stopCPUProfile

The `stopCPUProfile` method stops an ongoing CPU profile.

Parameters:

None

Returns:

result: error

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_stopCPUProfile"
}' | jq
```

### debug_stopGoTrace

The `stopGoTrace` method stops writing the Go runtime trace.

Parameters:

None

Returns:

result: error

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_stopGoTrace"
}' | jq
```

### debug_storageRangeAt

The `storageRangeAt` method returns the storage at the given block height and transaction index. The result can be paged by providing a maxResult to cap the number of storage slots returned as well as specifying the offset via keyStart (hash of storage key).

Parameters:

- blockHash: Hash, required
- txIndex: int, required
- contractAddress: address, required
- keyStart: array of bytes, required
- maxResult: int, required

Returns:

result: object StorageRangeResult

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_storageRangeAt"
}' | jq
```

### debug_traceBlock

The `traceBlock` method will return a full stack trace of all invoked opcodes of all transaction that were included in this block. Note, the parent of this block must be present or it will fail. For the second parameter see TraceConfig reference.

Parameters:

- blob: array of byte, required, the RLP encoded block
- config: object of TraceConfig, optional

Returns:

result: array of object txTraceResult

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_writeMemProfile",
  "params": [
    "memory-profile.bin",
  ]
}' | jq
```

### debug_traceBlockByHash

The `traceBlockByHash` method accepts a block hash and will replay the block that is already present in the database.

Parameters:

- hash: Hash, required, block hash
- config: TraceConfig, optional

Returns:

result: array of object txTraceResult

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_traceBlockByHash",
  "params": [
    "block-hash"
  ]
}' | jq
```

### debug_traceBlockByNumber

The `traceBlockByNumber` method accepts a block number and will replay the block that is already present in the database.

Parameters:

- number: BlockNumber, required, block number
- config: TraceConfig, optional

Returns:

result: array of object txTraceResult

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "traceBlockByNumber",
  "params": [
    "latest"
  ]
}' | jq
```

### debug_traceBlockFromFile

The `traceBlockFromFile` meothod accepts a file containing the RLP of the block.

Parameters:

- file: string, required, file name
- config: object of TraceConfig, optional

Returns:

result: array of object txTraceResult

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_traceBlockFromFile",
  "params": [
    "filename"
  ]
}' | jq
```

### debug_traceCall

The `traceCall` method lets you run an eth_call within the context of the given block execution using the final state of parent block as the base.

Parameters:

- args: TransactionArgs, required
- blockNrOrHash: BlockNumberOrHash, required, hash or number
- config: TraceCallConfig, optional

Returns:

same as debug_traceTransaction

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_traceCall",
  "params": [
    {
      "to": "0x46eda75e7ca73cb1c2f83c3927211655420dbc44",
      "data": "0x3fb5c1cb00000000000000000000000000000000000000000000000000000000000003e7"
    },
    "latest",
  ]
}' | jq
```

### debug_traceTransaction

The `traceTransaction` method debugging method will attempt to run the transaction in the exact same manner as it was executed on the network. It will replay any transaction that may have been executed prior to this one before it will finally attempt to execute the transaction that corresponds to the given hash.

Parameters:

- hash: Hash, required, transaction hash
- config: TraceConfig, optional

Returns:

result: object

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_traceTransaction",
  "params": [
    "tx-hash"
  ]
}' | jq
```

### debug_verbosity

The `verbosity` method sets the logging verbosity ceiling. Log messages with level up to and including the given level will be printed.

Parameters:

- level: int, required

Returns:

result: null

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_verbosity",
  "params": [
    3
  ]
}' | jq
```

### debug_vmodule

The `vmodule` method sets the logging verbosity pattern.

Parameters:

- pattern: string, required

Returns:

result: error

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_vmodule",
  "params": [
    "eth/*=3,p2p=4"
  ]
}' | jq
```

### debug_writeBlockProfile

The `writeBlockProfile` method writes a goroutine blocking profile to the given file.

Parameters:

- file: string, required

Returns:

result: error

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_writeBlockProfile",
  "params": [
    "block-profile.bin"
  ]
}' | jq
```

### debug_writeMemProfile

The `writeMemProfile` method writes an allocation profile to the given file. Note that the profiling rate cannot be set through the API, it must be set on the command line using the `--pprof-memprofilerate` flag.

Parameters:

- file: string, required, file name

Returns:

result: error

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_writeMemProfile",
  "params": [
    "memory-profile.bin",
  ]
}' | jq
```

### debug_writeMutexProfile

The `writeMutexProfile` method writes a goroutine blocking profile to the given file.

Parameters:

- file: string, required, file name

Returns:

result: error

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "debug_writeMutexProfile",
  "params": [
    "mutex-profile.bin",
  ]
}' | jq
```

## module eth

## module miner

## module net

## module personal

## module rpc

## module shh

## module txpool
