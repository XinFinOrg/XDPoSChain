# Module debug

The `debug` API gives you access to several non-standard RPC methods, which will allow you to inspect, debug and set certain debugging flags during runtime.

## Method debug_blockProfile

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

## Method debug_chaindbCompact

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

## Method debug_chaindbProperty

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

## Method debug_cpuProfile

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

## Method debug_dbGet

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

## Method debug_dumpBlock

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

## Method debug_getBadBlocks

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

## Method debug_gcStats

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

## Method debug_getBlockRlp

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

## Method debug_getModifiedAccountsByHash

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

## Method debug_getModifiedAccountsByNumber

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

## Method debug_goTrace

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

## Method debug_freeOSMemory

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

## Method debug_memStats

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

## Method debug_mutexProfile

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

## Method debug_preimage

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

## Method debug_printBlock

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

## Method debug_setBlockProfileRate

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

## Method debug_setGCPercent

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

## Method debug_setHead

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

## Method debug_stacks

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

## Method debug_startCPUProfile

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

## Method debug_startGoTrace

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

## Method debug_stopCPUProfile

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

## Method debug_stopGoTrace

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

## Method debug_storageRangeAt

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

## Method debug_traceBlock

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

## Method debug_traceBlockByHash

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

## Method debug_traceBlockByNumber

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

## Method debug_traceBlockFromFile

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

## Method debug_traceCall

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

## Method debug_traceTransaction

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

## Method debug_verbosity

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

## Method debug_vmodule

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

## Method debug_writeBlockProfile

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

## Method debug_writeMemProfile

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

## Method debug_writeMutexProfile

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
