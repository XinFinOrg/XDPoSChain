
# Module rpc

## Method rpc_modules

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
