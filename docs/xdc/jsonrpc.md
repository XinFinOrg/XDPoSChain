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

### eth_accounts

The `accounts` method returns a list of addresses owned by the client.

Parameters:

None

Returns

result: array of address

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_accounts"
}' | jq
```

### eth_blobBaseFee

The `blobBaseFee` method returns the expected base fee for blobs in the next block.

Parameters:

None

Returns:

result: big.Int, The expected base fee in wei, represented as a hexadecimal.

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_blobBaseFee"
}' | jq
```

### eth_blockNumber

The `blockNumber` method returns the current latest block number.

Parameters:

None

Returns:

result: uint64, A hexadecimal of an integer representing the current block number the client is on.

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_blockNumber"
}' | jq
```

### eth_call

The `call` method executes a new message call immediately, without creating a transaction on the block chain. Often used for executing read-only smart contract functions, for example the balanceOf for an ERC-20 contract.

Parameters:

- args: object TransactionArgs, required
- blockNrOrHash: object BlockNumberOrHash, optional
- overrides: object StateOverride, optional

Returns:

result: array of byte, the return value of executed contract.

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 8001,
  "method": "eth_call",
  "params": [
    {
      "to": "0x0000000000000000000000000000000000000088",
      "data": "0x0db02622"
    },
    "latest"
  ]
}' | jq
```

### eth_chainId

The `chainId` method returns the currently configured chain ID, a value used in replay-protected transaction signing as introduced by EIP-155.

Parameters:

None

Returns:

result: uint64, a hexadecimal of the current chain ID.

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_chainId"
}' | jq
```

### eth_coinbase

The `coinbase` method returns the client coinbase address. The coinbase address is the account to pay mining rewards to. This is the alias for `eth_etherbase`.

Parameters:

None

Returns:

result: address

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_coinbase"
}' | jq
```

### eth_createAccessList

The `createAccessList` method creates an EIP2930 type accessList based on a given Transaction. The accessList contains all storage slots and addresses read and written by the transaction, except for the sender account and the precompiles. This method uses the same transaction call Transaction Call Object and blockNumberOrTag object as eth_call. An accessList can be used to unstuck contracts that became inaccessible due to gas cost increases.

Parameters:

- args: object transactionArgs, required
  - from: optional, 20 bytes. The address of the sender.
  - to: 20 bytes. address the transaction is directed to.
  - gas: optional, hexadecimal value of the gas provided for the transaction execution.
  - gasPrice: optional, hexadecimal value gas price, in wei, provided by the sender. The default is 0. Used only in non-EIP-1559 transactions.
  - maxPriorityFeePerGas: optional, maximum fee, in wei, the sender is willing to pay per gas above the base fee. See EIP-1559 transactions. If used, must specify maxFeePerGas.
  - maxFeePerGas: optional, maximum total fee (base fee + priority fee), in wei, the sender is willing to pay per gas. See EIP-1559 transactions. If used, must specify maxPriorityFeePerGas.
  - value: optional, hexadecimal of the value transferred, in wei.
  - data: optional, hash of the method signature and encoded parameters. See Ethereum contract ABI specification.
- blockNrOrHash: BlockNumberOrHash, optional, a string representing a block number, block hash, or one of the string tags
  - latest
  - earliest
  - pending
  - finalized.

Returns:

result: object accessListResult:

- accessList: A list of objects with the following fields:
  - address: Addresses to be accessed by the transaction.
  - storageKeys: Storage keys to be accessed by the transaction.
- gasUsed: A hexadecimal string representing the approximate gas cost for the transaction if the access list is included.

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_createAccessList",
  "params": [
    {
      "from": "0x3bc5885c2941c5cda454bdb4a8c88aa7f248e312",
      "data": "0x20965255",
      "gasPrice": "0x3b9aca00",
      "gas": "0x3d0900",
      "to": "0x00f5f5f3a25f142fafd0af24a754fafa340f32c7"
    },
    "latest"
  ]
}' | jq
```

### eth_etherbase

The `etherbase` method returns the client coinbase address. The etherbase address is the account to pay mining rewards to.

Parameters:

None

Returns:

result: address

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_etherbase"
}' | jq
```

### eth_estimateGas

The `estimateGas` method generates and returns an estimate of how much gas is necessary to allow the transaction to complete. The transaction will not be added to the blockchain. Note that the estimate may be significantly more than the amount of gas actually used by the transaction, for a variety of reasons including EVM mechanics and node performance.

Parameters:

- args: object TransactionArgs, required
- blockNrOrHash: object BlockNumberOrHash, optional
- overrides: object StateOverride, optional

Returns:

result: uint64

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1004,
  "method": "eth_estimateGas",
  "params": [
    {
      "from": "0xD4CE02705041F04135f1949Bc835c1Fe0885513c",
      "to": "0x85f33E1242d87a875301312BD4EbaEe8876517BA",
      "value": "0x1"
    }
  ]
}' | jq
```

### eth_feeHistory

The `feeHistory` returns transaction base fee per gas and effective priority fee per gas for the requested block range.

Parameters:

- blockCount math.HexOrDecimal64, required, Number of blocks in the requested range. Between 1 and 1024 blocks can be requested in a single query. If blocks in the specified block range are not available, then only the fee history for available blocks is returned.
- lastBlock: BlockNumber, required, integer representing the highest number block of the requested range, or one of the string tags `latest`, `earliest`, or `pending`.
- rewardPercentiles: array of integers, optional, a monotonically increasing list of percentile values to sample from each block's effective priority fees per gas in ascending order, weighted by gas used.

Returns:

result: object feeHistoryResult

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1004,
  "method": "eth_feeHistory",
  "params": [
    "0x3",
    "latest",
    [20,50]
  ]
}' | jq
```

### eth_gasPrice

The `gasPrice` method returns the current gas price in wei.

Parameters:

None.

Returns:

result: big.Int

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1003,
  "method": "eth_gasPrice"
}' | jq
```

### eth_getBalance

The `getBalance` returns the balance of the account of a given address. The balance is in wei.

Parameters:

- address: address, required, a string representing the address (20 bytes) to check for balance.
- blockNrOrHash: object BlockNumberOrHash, required, a hexadecimal block number, or one of the string tags latest, earliest, pending, or finalized.

Returns:

result: big.Int

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1003,
  "method": "eth_getBalance",
  "params": [
    "0xD4CE02705041F04135f1949Bc835c1Fe0885513c",
    "latest"
  ]
}' | jq
```

### eth_getBlockByHash

The `getBlockByHash` returns information about a block whose hash is in the request.

Parameters:

- blockHash: hash, required, block hash
- fullTx: bool, required, if true returns the full transaction objects, if false returns only the hashes of the transactions

Returns:

result: object

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1003,
  "method": "eth_getBlockByHash",
  "params": [
    "0xb6fbeabaa5682445b825c5bb02faf9290a38be44d9a47834b65224478923ebce",
    true
  ]
}' | jq
```

### eth_getBlockByNumber

The `getBlockByNumber` method returns information about a block by block number.

Parameters

- blockNr: BlockNumber, integer of a block number, or the string "earliest", "latest", "pending", or "finalized", as in the default block parameter.
- fullTx: bool, if true returns the full transaction objects, if false only the hashes of the transactions.

result: object

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC}  -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_getBlockByNumber",
  "params": [
    "latest",
    true
  ]
}' | jq
```

### eth_getBlockReceipts

The `getBlockReceipts` returns the block receipts for the given block hash or number or tag.

Parameters:

- blockNrOrHash: BlockNumberOrHash, required, hexadecimal or decimal integer representing a block number, or one of the string tags:
  - latest
  - earliest
  - pending
  - finalized

note: pending returns the same data as latest.

Returns:

result: object, block object or null when there is no corresponding block.

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1004,
  "method": "eth_getBlockReceipts",
  "params": [
    "latest"
  ]
}' | jq
```

### eth_getBlockTransactionCountByHash

The `getBlockTransactionCountByHash` method returns the number of transactions in the block with the given block hash.

Parameters:

- blockHash: hash, required, block hash

Returns:

result: uint, block transaction count

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1004,
  "method": "eth_getBlockTransactionCountByHash",
  "params": [
    "0xb6fbeabaa5682445b825c5bb02faf9290a38be44d9a47834b65224478923ebce"
  ]
}' | jq
```

### eth_getBlockTransactionCountByNumber

The `getBlockTransactionCountByNumber` method returns the number of transactions in the block with the given block number.

Parameters:

- blockNr: BlockNumber, required, block number,  or one of the string tags latest, earliest, pending, or finalized.

Returns:

result: uint, block transaction count

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1004,
  "method": "eth_getBlockTransactionCountByNumber",
  "params": [
    "latest"
  ]
}' | jq
```

### eth_getCode

The `getCode` method returns the compiled byte code of a smart contract, if any, at a given address.

Parameters:

- address: address, required
- blockNrOrHash: BlockNumberOrHash, required

Returns:

result: array of byte

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1004,
  "method": "eth_getCode",
  "params": [
    "0x0000000000000000000000000000000000000088",
    "latest"
  ]
}' | jq
```

### eth_getLogs

The `getLogs` method returns an array of all the logs matching the given filter object.

Parameters:

- crit: ojbect FilterCriteria, a filter object containing the following:

- address: optional, contract address (20 bytes) or a list of addresses from which logs should originate.
- fromBlock: optional, default is "latest", a hexadecimal block number, or one of the string tags latest, earliest, pending, safe, or finalized. See the default block parameter.
- toBlock: optional, default is "latest", a hexadecimal block number, or one of the string tags latest, earliest, pending, safe, or finalized. See the default block parameter.
- topics: optional, array of 32 bytes DATA topics. Topics are order-dependent.
- blockhash: optional, restricts the logs returned to the single block referenced in the 32-byte hash blockHash. Using blockHash is equivalent to setting fromBlock and toBlock to the block number referenced in the blockHash. If blockHash is present in the filter criteria, then neither fromBlock nor toBlock are allowed.

Returns:

result: array of Log

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1004,
  "method": "eth_getLogs",
  "params": [
    {
      "address": "0x53350795c11cee781a7e174479778f848d76ab2a",
      "fromBlock": "0x22b2277",
      "toBlock": "0x22b2277",
      "topics": [
        [
          "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
          "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
          "0x6a12b3df6cba4203bd7fd06b816789f87de8c594299aed5717ae070fac781bac"
        ]
      ]
    }
  ]
}' | jq
```

### eth_getOwnerByCoinbase

The `getOwnerByCoinbase` return masternode owner of the given coinbase address.

Parameters:

- coinbase: address, required, account
- blockNr: BlockNumber, required, block number

Returns:

result: address

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_getOwnerByCoinbase",
  "params": [
    "0xD4CE02705041F04135f1949Bc835c1Fe0885513c",
    "latest"
  ]
}' | jq
```

### eth_getProof

The `getProof` returns the account and storage values of the specified account including the Merkle-proof. The block number can be nil, in which case the value is taken from the latest known block.

Parameters:

- account: address, required
- keys: array of string, required
- blockNumber: big.Int, optional

Returns:

result: object AccountResult

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_getProof",
  "params": [
    "0xe5cB067E90D5Cd1F8052B83562Ae670bA4A211a8",
    [
      "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
      "0x283s34c8e2b1456f09832c71e5d6a0b4f8c9e1d3a2b5c7f0e6d4a8b2c1f3e5d7"
    ],
    "latest"
  ],
}' | jq
```

### eth_getStorageAt

The `getStorageAt` method returns the value from a storage position at a given address.

Parameters:

- address: address, required
- key: string, required
- blockNrOrHash: BlockNumberOrHash, required

Returns:

result: array of byte

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_getStorageAt",
  "params": [
    "0xfe3b557e8fb62b89f4916b721be55ceb828dbd73",
    "0x0",
    "latest"
  ],
}' | jq
```

### eth_getRawTransactionByBlockHashAndIndex

Teh `getRawTransactionByBlockHashAndIndex` method returns the bytes of the transaction for the given block hash and index.

Parameters:

- blockHash: hash, required, block hash
- index: uint, required, transaction index

Returns:

result: object

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_getRawTransactionByBlockHashAndIndex",
  "params": [
    "0xb6fbeabaa5682445b825c5bb02faf9290a38be44d9a47834b65224478923ebce",
    0
  ]
}' | jq
```

### eth_getRawTransactionByBlockNumberAndIndex

The `getRawTransactionByBlockNumberAndIndex` returns the bytes of the transaction for the given block number and index.

Parameters:

- blockNr: BlockNumber, required, blcok number
- index: uint, required, transaction index

Returns:

result: object

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_getRawTransactionByBlockNumberAndIndex",
  "params": [
    "latest",
    0
  ]
}' | jq
```

### eth_getRawTransactionByHash

The `getRawTransactionByHash` method returns the bytes of the transaction for the given hash.

Parameters:

- hash, required, transaction hash

Returns:

result: array of byte

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_getRawTransactionByHash",
  "params": [
    "0x5bbcde52084defa9d1c7068a811363cc27a25c80d7e495180964673aa5f47687"
  ]
}' | jq
```

### eth_getRewardByHash

The `getRewardByHash` method returns the reward by block hash.

Parameters:

- hash, required, block hash

Returns:

result: object

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_getRewardByHash",
  "params": [
    "0xb6fbeabaa5682445b825c5bb02faf9290a38be44d9a47834b65224478923ebce"
  ]
}' | jq
```

### eth_getTransactionAndReceiptProof

The `getTransactionAndReceiptProof` method returns the Trie transaction and receipt proof of the given transaction hash.

Parameters:

- hash, required, transaction hash

Returns:

result: object

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_getTransactionAndReceiptProof",
  "params": [
    "0xbf83342ccdd6592eff8e2acfed87e23e852d684a4e2cfade89ba3b304c2b66a9"
  ]
}' | jq
```

### eth_getTransactionByBlockHashAndIndex

The `getTransactionByBlockHashAndIndex` method returns information about a transaction given block hash and transaction index position.

Parameters:

- blockHash: hash, required, a string representing the hash (32 bytes) of a block
- index: uint, required, a hexadecimal of the integer representing the position in the block

Returns:

result: object RPCTransaction

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_getTransactionByBlockHashAndIndex",
  "params": [
    "0xb6fbeabaa5682445b825c5bb02faf9290a38be44d9a47834b65224478923ebce",
    "0x0"
  ]
}' | jq
```

### eth_getTransactionByBlockNumberAndIndex

The `getTransactionByBlockNumberAndIndex` method returns information about a transaction given block number and transaction index position.

Parameters:

- blockNr: BlockNumber, required, a hexadecimal block number, or one of the string tags latest, earliest, pending, or finalized
- index: uint, required, a hexadecimal of the integer representing the position in the block

Returns:

result: object RPCTransaction

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_getTransactionByBlockNumberAndIndex",
  "params": [
    "0x548f4f1",
    "0x0"
  ]
}' | jq
```

### eth_getTransactionByHash

The `getTransactionByHash` method returns information about a transaction for a given hash.

Parameters:

- hash: hash, required, a string representing the hash (32 bytes) of a transaction

Returns:

result: object RPCTransaction

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_getTransactionByHash",
  "params": [
    "0xbf83342ccdd6592eff8e2acfed87e23e852d684a4e2cfade89ba3b304c2b66a9"
  ]
}' | jq
```

### eth_getTransactionCount

The `getTransactionCount` method returns the number of transactions sent from an address.

Parameters:

- address: address, required, a string representing the address (20 bytes)
- blockNrOrHash: BlockNumberOrHash, required, a hexadecimal block number, or one of the string tags latest, earliest, pending, or finalized.

Returns:

result: uint64

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_getTransactionCount",
  "params": [
    "0xD4CE02705041F04135f1949Bc835c1Fe0885513c",
    "latest"
  ]
}' | jq
```

### eth_getTransactionReceipt

The `getTransactionReceipt` method returns the receipt of a transaction given transaction hash. Note that the receipt is not available for pending transactions.

Parameters:

- hash: hash, required, a string representing the hash (32 bytes) of a transaction

Returns:

result: object

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 5002,
  "method": "eth_getTransactionReceipt",
  "params": [
    "0xbf83342ccdd6592eff8e2acfed87e23e852d684a4e2cfade89ba3b304c2b66a9"
  ]
}' | jq
```

### eth_getUncleByBlockHashAndIndex

The `getUncleByBlockHashAndIndex` method returns information about an uncle of a block given the block hash and the uncle index position.

Parameters:

- blockHash: hash, required, a string representing the hash (32 bytes) of a block.
- index: uint, required, a hexadecimal equivalent of the integer indicating the uncle's index position.

Returns:

result: object

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 5002,
  "method": "eth_getUncleByBlockHashAndIndex",
  "params": [
    "0xb6fbeabaa5682445b825c5bb02faf9290a38be44d9a47834b65224478923ebce",
    "0x0"
  ]
}' | jq
```

### eth_getUncleByBlockNumberAndIndex

The `getUncleByBlockNumberAndIndex` method returns information about an uncle of a block given the block number and the uncle index position.

Parameters:

- blockNr: BlockNumber, required, a hexadecimal block number, or one of the string tags latest, earliest, pending, or finalized
- index: uint, required, a hexadecimal equivalent of the integer indicating the uncle's index position

Returns:

result: object

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 5002,
  "method": "eth_getUncleByBlockNumberAndIndex",
  "params": [
    "0x548f4f1",
    "0x0"
  ]
}' | jq
```

### eth_getUncleCountByBlockHash

The `getUncleCountByBlockHash` method returns the number of uncles in a block from a block matching the given block hash.

Parameters:

- blockHash: hash, required, a string representing the hash (32 bytes) of a block

Returns:

result: uint

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 5002,
  "method": "eth_getUncleCountByBlockHash",
  "params": [
    "0xb6fbeabaa5682445b825c5bb02faf9290a38be44d9a47834b65224478923ebce"
  ]
}' | jq
```

### eth_getUncleCountByBlockNumber

The `getUncleCountByBlockNumber` method returns the number of uncles in a block from a block matching the given block number.

Parameters:

- blockNr: BlockNumber, required, a hexadecimal block number, or one of the string tags latest, earliest, pending, or finalized

Returns:

result: uint

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 5002,
  "method": "eth_getUncleCountByBlockNumber",
  "params": [
    "latest"
  ]
}' | jq
```

### eth_getWork

The `getWork` method returns the hash of the current block, the seed hash, and the boundary condition to be met ("target").

Parameters:

None

Returns:

result: array of string, with the following properties:

- Current block header PoW-hash (32 bytes).
- The seed hash used for the DAG (32 bytes).
- The boundary condition ("target") (32 bytes), 2^256 / difficulty.

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 5002,
  "method": "eth_getWork"
}' | jq
```

### eth_hashrate

The `hashrate` method returns the number of hashes per second that the node is mining with. Only applicable when the node is mining.

Parameters:

None

Returns:

result: uint64

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 5002,
  "method": "eth_hashrate"
}' | jq
```

### eth_maxPriorityFeePerGas

The `maxPriorityFeePerGas` method returns an estimate of how much priority fee, in wei, you need to be included in a block.

Parameters:

None

Returns

result: big.Int, a hexadecimal value of the priority fee, in wei, needed to be included in a block.

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1002,
  "method": "eth_maxPriorityFeePerGas"
}' | jq
```

### eth_mining

The `mining` method returns true if client is actively mining new blocks.

Parameters:

None

Returns

result: bool

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 5002,
  "method": "eth_mining"
}' | jq
```

### eth_pendingTransactions

The `pendingTransactions` returns the transactions that are in the transaction pool and have a from address that is one of the accounts this node manages.

Parameters:

None

Returns:

result: array of RPCTransaction

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1004,
  "method": "eth_pendingTransactions"
}' | jq
```

### eth_protocolVersion

The `protocolVersion` method returns the current Ethereum protocol version.

Parameters:

None

Returns:

result: uint

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1004,
  "method": "eth_protocolVersion"
}' | jq
```

### eth_resend

The `resend` method accepts an existing transaction and a new gas price and limit. It will remove the given transaction from the pool and reinsert it with the new gas price and limit.

Parameters:

- sendArgs: object TransactionArgs, required, the arguments to construct a new transaction
- gasPrice: big.Int, optional, gas price
- gasLimit: uint64, optional, gas limit

Returns:

result: hash, transaction hash

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_resend",
  "params":[
    {
      "from": "0xca7a99380131e6c76cfa622396347107aeedca2d",
      "to": "0x8c9f4468ae04fb3d79c80f6eacf0e4e1dd21deee",
      "value": "0x1",
      "gas": "0x9999",
      "maxFeePerGas": "0x5d21dba00",
      "maxPriorityPerGas": "0x5d21dba00"
    },
    "0x5d21dba99",
    "0x5d21dba99"
  ]
}' | jq
```

### eth_sendRawTransaction

The `sendRawTransaction` method submits a pre-signed transaction for broadcast to the Ethereum network.

Parameters:

- input: array of byte

Returns:

result: hash

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_sendRawTransaction",
  "params":[
    "0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675"
  ]
}' | jq
```

### eth_sendTransaction

The `sendTransaction` method creates new message call transaction or a contract creation, if the data field contains code, and signs it using the account specified in from.

Parameters:

- args: object TransactionArgs

Returns:

result: hash

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_sendTransaction",
  "params":[
    {
      from: "0xb60e8dd61c5d32be8058bb8eb970870f07233155",
      to: "0xd46e8dd67c5d32be8058bb8eb970870f07244567",
      gas: "0x76c0",
      gasPrice: "0x9184e72a000",
      value: "0x9184e72a",
      input: "0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675"
    }
  ]
}' | jq
```

### eth_sign

The `sign` method calculates an Ethereum specific signature with: `sign(keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)))`.

By adding a prefix to the message makes the calculated signature recognizable as an Ethereum specific signature. This prevents misuse where a malicious dapp can sign arbitrary data (e.g. transaction) and use the signature to impersonate the victim.

Note: the address to sign with must be unlocked.

Parameters:

- addr: address, required, account address
- data: array of byte, required, message to sign

Returns:

result: array of byte

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_sign",
  "params":[
    "0xD4CE02705041F04135f1949Bc835c1Fe0885513c",
    "0x1234abcd"
  ]
}' | jq
```

### eth_signTransaction

The `signTransaction` method signs a transaction that can be submitted to the network at a later time using with `eth_sendRawTransaction`.

Parameters:

- args: object TransactionArgs, required
  - nonce: uint64, optional, anti-replay parameter
  - to: address, optional, recipient address, or null if this is a contract creation transaction
  - from: address, required, sender address
  - value: big.Int, optional, value to be transferred, in wei
  - data: array of byte, optional, compiled code of a contract or hash of the invoked method signature and encoded parameters
  - input: same as data
  - gas: uint64, optional, gas provided by the sender
  - gasPrice: big.Int, optional, gas price, in wei, provided by the sender
  - maxPriorityFeePerGas: big.Int, optional, maximum fee, in wei, the sender is willing to pay per gas above the base fee
  - maxFeePerGas: big.Int, optional, maximum total fee (base fee + priority fee), in wei, the sender is willing to pay per gas.
  - accessList: array of object, optional, list of addresses and storage keys the transaction plans to access
  - chainId: big.Int, optional, chain ID

Returns:

result: object SignTransactionResult

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_signTransaction",
  "params": [
    {
      "data":"0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675",
      "from": "0xb60e8dd61c5d32be8058bb8eb970870f07233155",
      "gas": "0x76c0",
      "gasPrice": "0x9184e72a000",
      "to": "0xd46e8dd67c5d32be8058bb8eb970870f07244567",
      "value": "0x9184e72a"
    }
  ]
}' | jq
```

### eth_submitWork

The `submitWork` method can be used by external miner to submit their POW solution. It returns an indication if the work was accepted.

Note, this is not an indication if the provided work was valid!

Parameters:

- nonce: BlockNonce, required
- solution: hash, required
- digest: hash, required

Returns:

result: bool

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_submitWork",
  "params": [
   "0x0000000000000001",
   "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
   "0xD1FE5700000000000000000000000000D1FE5700000000000000000000000000"
  ]
}' | jq
```

### eth_syncing

The `syncing` method returns an object with data about the sync status or false.

Parameters:

None

Returns:

result: bool

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_syncing"
}' | jq
```

### Filter methods

#### eth_getFilterChanges

The `getFilterChanges` method polling method for a filter, which returns an array of logs which occurred since the last poll. Filter must be created by calling either `eth_newFilter` or `eth_newBlockFilter`.

Parameters:

- id: string, required, a string denoting the filter ID

Returns:

result: object

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_getFilterChanges",
  "params": [
   "0x68ce60ffdb0c9480c307b0c3d2ae9391"
  ]
}' | jq
```

#### eth_getFilterLogs

The `getFilterLogs` method returns an array of all logs matching the filter with the given filter ID.

Parameters:

- id: string, required, a string denoting the filter ID

Returns:

result: array of Log, Log objects contain the following keys and their values:

- address: Address from which this log originated.
- blockHash: The hash of the block where this log was in. null when it's a pending log.
- blockNumber: The block number where this log was in. null when it's a pending log.
- data: DATA. Contains the non-indexed arguments of the log.
- logIndex: A hexadecimal of the log index position in the block. null when it is a pending log.
- removed: true when the log was removed, due to a chain reorganization. false if it's a valid log.
- topics: Array of DATA. An array of 0 to 4 32-bytes DATA of indexed log arguments. In Solidity the first topic is the hash of the signature of the event (for example, Deposit(address,bytes32,uint256)), except when you declared the event with the anonymous specifier.
- transactionHash: A hash of the transactions from which this log was created. null when it's a pending log.
- transactionIndex: A hexadecimal of the transactions index position from which this log was created. null when it's a pending log.

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_getFilterLogs",
  "params": [
   "0x68ce60ffdb0c9480c307b0c3d2ae9391"
  ]
}' | jq
```

#### eth_newBlockFilter

The `newBlockFilter` method creates a filter in the node, to notify when a new block arrives. To check if the state has changed, call `eth_getFilterChanges`.

Parameters:

None

Returns:

result: string

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_newBlockFilter"
}' | jq
```

#### eth_newFilter

The `newFilter` method creates a filter object based on the given filter options, to notify when the state changes (logs). To check if the state has changed, call `eth_getFilterChanges`.

Parameters:

- crit: ojbect FilterCriteria, a filter object with the following keys and their values:

- address: optional, a contract address or a list of addresses from which logs should originate.
- fromBlock: optional, default is latest, a hexadecimal block number, or one of the string tags latest, earliest, pending, safe, or finalized. See the default block parameter.
- toBlock: optional, default is latest, a hexadecimal block number, or one of the string tags latest, earliest, pending, safe, or finalized. See the default block parameter.
- topics: aoptional, an array of 32 bytes DATA topics. Topics are order-dependent.

Returns:

result: string

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_newFilter",
  "params": [
    {
      "fromBlock": "0x2bb7231",
      "toBlock": "0x2bb7233"
    }
  ]
}' | jq
```

#### eth_newPendingTransactionFilter

The `newPendingTransactionFilter` method creates a filter in the node, to notify when new pending transactions arrive. To check if the state has changed, call `eth_getFilterChanges`.

Parameters:

None

Returns:

result: string

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_newPendingTransactionFilter"
}' | jq
```

#### eth_uninstallFilter

The `uninstallFilter` method uninstalls a filter with given ID. This method should always be called when watching is no longer needed. Additionally, filters time out when they aren't requested with `eth_getFilterChanges` for a period of time.

Parameters:

- id: string, required, a string denoting the ID of the filter to be uninstalled.

Returns:

result: bool, true if the filter was successfully uninstalled, otherwise false

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "eth_uninstallFilter",
  "params": [
    "0x43f0c93bf463861b7c15a5d11d402d9b"
  ]
}' | jq
```

## module miner

The `miner` API is now deprecated because mining was switched off at the transition to proof-of-stake. It existed to provide remote control the node's mining operation and set various mining specific settings. It is provided here for historical interest!

### miner_getHashrate

The `getHashrate` method get hashrate in H/s (Hash operations per second).

Parameters:

None

Returns:

result: uint64

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "miner_getHashrate"
}' | jq
```

### miner_setEtherbase

The `getHashrate` method get hashrate in H/s (Hash operations per second).

Parameters:

- etherbase: address, required

Returns:

result: bool

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "miner_setEtherbase",
  "params": [
    "0xD4CE02705041F04135f1949Bc835c1Fe0885513c"
  ]
}' | jq
```

### miner_setExtra

The `setExtra` method sets the extra data a miner can include when miner blocks. This is capped at 32 bytes.

Parameters:

- extra: string, required

Returns:

result: bool

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "miner_setExtra",
  "params": [
    "string"
  ]
}' | jq
```

### miner_setGasPrice

The `setGasPrice` method sets the minimal accepted gas price when mining transactions. Any transactions that are below this limit are excluded from the mining process.

Parameters:

- gasPrice: big.Int, required

Returns:

result: bool

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "miner_setGasPrice",
  "params": [
    "0x1"
  ]
}' | jq
```

### miner_start

The `start` method start the miner with the given number of threads. If threads is nil the number of workers started is equal to the number of logical CPUs that are usable by this process. If mining is already running, this method adjust the number of threads allowed to use.

Parameters:

- threads: int, optional

Returns:

result: bool

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "miner_start",
  "params": [
    1
  ]
}' | jq
```

### miner_stop

The `stop` method stop the CPU mining operation.

Parameters:

None

Returns:

result: bool

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "miner_stop"
}' | jq
```

## module net

The `net` API provides insight about the networking aspect of the client.

### net_listening

The `listening` method returns an indication if the node is listening for network connections.

Parameters:

None

Returns:

result: bool, always listening

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "net_listening"
}' | jq
```

### net_peerCount

The `peerCount` method returns the number of connected peers.

Parameters:

None

Returns:

result: uint

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "net_peerCount"
}' | jq
```

### net_version

The `version` method returns the devp2p network ID

Parameters:

None

Returns:

result: string

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "net_version"
}' | jq
```

## module rpc

### rpc_modules

The `modules` returns the list of RPC services with their version number.

Parameters:

None

Returns:

result: ojbect

Example:

Request:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "rpc_modules"
}' | jq
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": {
    "XDPoS": "1.0",
    "debug": "1.0",
    "eth": "1.0",
    "net": "1.0",
    "personal": "1.0",
    "rpc": "1.0",
    "txpool": "1.0",
    "web3": "1.0"
  }
}
```

## module txpool

### txpool_content

The `content` method lists the exact details of all the transactions currently pending for inclusion in the next block(s), as well as the ones that are being scheduled for future execution only.

The result is an object with two fields pending and queued. Each of these fields are associative arrays, in which each entry maps an origin-address to a batch of scheduled transactions. These batches themselves are maps associating nonces with actual transactions.

Please note, there may be multiple transactions associated with the same account and nonce. This can happen if the user broadcast multiple ones with varying gas allowances (or even completely different transactions).

Parameters:

None

Returns:

result: ojbect

Example:

Request:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "txpool_content"
}' | jq
```

### txpool_contentFrom

The `contentFrom` method retrieves the transactions contained within the txpool, returning pending as well as queued transactions of this address, grouped by nonce.

Parameters:

- addr: addrress, required

Returns:

result: ojbect

Example:

Request:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "txpool_contentFrom",
  "params": [
    "0xD4CE02705041F04135f1949Bc835c1Fe0885513c"
  ]
}' | jq
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": {
    "pending": {},
    "queued": {}
  }
}
```

### txpool_inspect

The `inspect` lists a textual summary of all the transactions currently pending for inclusion in the next block(s), as well as the ones that are being scheduled for future execution only. This is a method specifically tailored to developers to quickly see the transactions in the pool and find any potential issues.

The result is an object with two fields pending and queued. Each of these fields are associative arrays, in which each entry maps an origin-address to a batch of scheduled transactions. These batches themselves are maps associating nonces with transactions summary strings.

Please note, there may be multiple transactions associated with the same account and nonce. This can happen if the user broadcast multiple ones with varying gas allowances (or even completely different transactions).

Parameters:

None

Returns:

result: ojbect

Example:

Request:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "txpool_inspect"
}' | jq
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": {
    "pending": {},
    "queued": {}
  }
}
```

### txpool_status

The `status` method returns the number of pending and queued transaction in the pool.

The result is an object with two fields pending and queued, each of which is a counter representing the number of transactions in that particular state.

Parameters:

None

Returns:

result: ojbect

Example:

Request:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "txpool_status"
}' | jq
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": {
    "pending": "0x3",
    "queued": "0x0"
  }
}
```
