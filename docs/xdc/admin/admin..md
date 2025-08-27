# Module admin

The `admin` API gives you access to several non-standard RPC methods, which will allow you to have a fine grained control over your Geth instance, including but not limited to network peer and RPC endpoint management.

## Method admin_addPeer

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": true
}
```

## Method admin_addTrustedPeer

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": true
}
```

## Method admin_datadir

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": "/home/node/xdc_chain/mainnet_2"
}
```

## Method admin_exportChain

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": true
}
```

## Method admin_importChain

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": true
}
```

## Method admin_nodeInfo

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

Response:

See [admin_nodeInfo_response.json](./admin_nodeInfo_response.json)

## Method admin_peerEvents

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

## Method admin_peers

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

Response:

See [admin_peers_response.json](./admin_peers_response.json)

## Method admin_removePeer

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": true
}
```

## Method admin_removeTrustedPeer

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": true
}
```

## Method admin_startRPC

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

## Method admin_startWS

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": true
}
```

## Method admin_stopRPC

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

## Method admin_stopWS

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": true
}
```

