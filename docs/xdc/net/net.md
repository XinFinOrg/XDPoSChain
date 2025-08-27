
# Module net

The `net` API provides insight about the networking aspect of the client.

## Method net_listening

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": true
}
```


## Method net_peerCount

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": "0x10"
}
```


## Method net_version

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": "50"
}
```

