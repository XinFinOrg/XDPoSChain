# Module web3

## Method web3_clientVersion

The `clientVersion` method returns the current client version string.

Parameters:

None

Returns:

result: string

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "web3_clientVersion"
}' | jq
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": "XDC/v2.7.0-devnet-abbf357e-20260327/linux-amd64/go1.25.8"
}
```

## Method web3_sha3

The `sha3` method calculates Keccak-256 of the given data.

Parameters:

- data: DATA, required, hex-encoded bytes

Returns:

result: DATA, 32-byte hash

Example:

```shell
curl -s -X POST -H "Content-Type: application/json" ${RPC} -d '{
  "jsonrpc": "2.0",
  "id": 1001,
  "method": "web3_sha3",
  "params": [
    "0x68656c6c6f20776f726c64"
  ]
}' | jq
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": "0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"
}
```
