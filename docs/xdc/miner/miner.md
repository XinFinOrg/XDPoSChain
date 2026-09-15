
# Module miner

The `miner` API is now deprecated because mining was switched off at the transition to proof-of-stake. It existed to provide remote control the node's mining operation and set various mining specific settings. It is provided here for historical interest!

## Method miner_setEtherbase

The `setEtherbase` method sets the etherbase (mining reward recipient) account.

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": true
}
```

## Method miner_setExtra

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": true
}
```

## Method miner_setGasPrice

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": true
}
```

## Method miner_start

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": true
}
```

## Method miner_stop

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": true
}
```

## Method miner_getHashrate

The `getHashrate` method returns the current mining hashrate in H/s.

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

## Method miner_getWork

The `getWork` method returns current mining work package.

Parameters:

None

Returns:

result: array of string, `[pow-hash, seed-hash, target]`

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "miner_getWork"
}' | jq
```

## Method miner_submitWork

The `submitWork` method submits a mined nonce solution.

Parameters:

- nonce: string, required, 8-byte hex nonce
- powHash: string, required, 32-byte work identifier (the `pow-hash` value returned by `miner_getWork`)
- mixDigest: string, required, 32-byte mix digest for the submitted nonce

Use `miner_getWork` result as `[pow-hash, seed-hash, target]` and pass only `pow-hash` as the second parameter here. The third parameter must be the computed mix digest (not `seed-hash`).

Returns:

result: bool

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "miner_submitWork",
  "params": [
    "0x0000000000000001",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x0000000000000000000000000000000000000000000000000000000000000000"
  ]
}' | jq
```

## Method miner_submitHashrate

The `submitHashrate` method submits the miner's hashrate estimate.

Parameters:

- hashrate: uint64, required, hexadecimal quantity
- id: string, required, miner identifier hash

Returns:

result: bool

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "miner_submitHashrate",
  "params": [
    "0x1",
    "0x0000000000000000000000000000000000000000000000000000000000000001"
  ]
}' | jq
```
