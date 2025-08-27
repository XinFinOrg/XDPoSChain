
# Module eth

## Method eth_accounts

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": [
    "0x077961a99e124088bc386c3183b369187c5be295",
    "0x8cd4b6b24f2cd0b83d49876f932254823e875547",
    "0xdcc8153ceddf2e4935bed915eb4180ec42fcb69c"
  ]
}
```


## Method eth_blobBaseFee

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": "0x0"
}
```


## Method eth_blockNumber

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": "0x57d1892"
}
```


## Method eth_call

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 8001,
  "result": "0x00000000000000000000000000000000000000000000000000000000000000d5"
}
```


## Method eth_chainId

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": "0x32"
}
```


## Method eth_coinbase

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": "0x077961a99e124088bc386c3183b369187c5be295"
}
```


## Method eth_createAccessList

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": {
    "accessList": [],
    "gasUsed": "0x5318"
  }
}
```


## Method eth_etherbase

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": "0x077961a99e124088bc386c3183b369187c5be295"
}
```


## Method eth_estimateGas

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1004,
  "result": "0x5208"
}
```


## Method eth_feeHistory

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1004,
  "result": {
    "oldestBlock": "0x580dca8",
    "reward": [
      [
        "0x333905980",
        "0x333905980"
      ],
      [
        "0x333905980",
        "0x333905980"
      ],
      [
        "0x333905980",
        "0x333905980"
      ]
    ],
    "baseFeePerGas": [
      "0x0",
      "0x0",
      "0x0",
      "0x0"
    ],
    "gasUsedRatio": [
      7.032857142857143e-05,
      0.0018736880952380953,
      0.00014065714285714287
    ]
  }
}
```


## Method eth_gasPrice

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1003,
  "result": "0x2e90edd00"
}
```


## Method eth_getBalance

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1003,
  "result": "0x38479c061d157125"
}
```


## Method eth_getBlockByHash

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

Response:

```json
See [eth_getBlockByHash_response.json](eth_getBlockByHash_response.json)
```


## Method eth_getBlockByNumber

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

Response:

```json
See [eth_getBlockByNumber_response.json](eth_getBlockByNumber_response.json)
```


## Method eth_getBlockReceipts

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

Response:

```json
See [eth_getBlockReceipts_response.json](eth_getBlockReceipts_response.json)
```


## Method eth_getBlockTransactionCountByHash

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1004,
  "result": "0x3"
}
```


## Method eth_getBlockTransactionCountByNumber

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1004,
  "result": "0x6"
}
```


## Method eth_getCode

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

Response:

```json
See [eth_getCode_response.json](eth_getCode_response.json)
```


## Method eth_getLogs

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
      "toBlock": "0x21b2277",
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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1004,
  "result": []
}
```


## Method eth_getOwnerByCoinbase

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": "0x0000000000000000000000000000000000000000"
}
```

## Method eth_getStorageAt

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": "0x0000000000000000000000000000000000000000000000000000000000000000"
}
```


## Method eth_getRawTransactionByBlockHashAndIndex

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
    "0x0"
  ]
}' | jq
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": "0xf9016e825e8f85037e11d600830f424094ecf4ea7907e779b8a7d0f90cb95fe06f43b610fb80b90104414bf3890000000000000000000000003fb46c4db76d8e9f69f3f8388f43a7ca7e140807000000000000000000000000951857744785e80e2de051c32ee7b25f9c458c420000000000000000000000000000000000000000000000000000000000000064000000000000000000000000d844d373f4ef676665fcc18d9b6c89464a36f2d20000000000000000000000000000000000000000000000000000000068254fab000000000000000000000000000000000000000000000fccf103db7d22e000000000000000000000000000000000000000000000000000acee08ed426a20ae8400000000000000000000000000000000000000000000000000000000000000008188a05b1d0e4565493e5f815e26d622c6b9f5c7f23e269eac6ed950446ff7a10e3197a0025df537fe481c63c7defaaaccdd91105a0088f720789ecf5728460a4c3c0fc2"
}
```


## Method eth_getRawTransactionByBlockNumberAndIndex

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
    "latest","0x0"
  ]
}' | jq
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": "0xf86d808506fc23ac008261a894fbeeebf296a1eb603544ad2861f7f629217d6cff881bae52266f39c400808188a0529fb389ebe066852e0bc0251497b7663860147deb553e93560c593d742d3881a014556772149e85ab5031e4690db7c1a00c37f223fa6b408b2515c0fab8e040d9"
}
```


## Method eth_getRawTransactionByHash

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": "0x"
}
```


## Method eth_getRewardByHash

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": null
}
```


## Method eth_getTransactionAndReceiptProof

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": {
    "blockHash": "0xb6fbeabaa5682445b825c5bb02faf9290a38be44d9a47834b65224478923ebce",
    "key": "0x80",
    "receiptProofKeys": [
      "0x473f2a6554298d1b72b3a73e266bee07f5f93509534f716428cf3d233bb25ec7",
      "0xf8487e8af578fb2cc3fef425f28cbb15fab131e3557eb67874f1a80e7fc1a9f5"
    ],
    "receiptProofValues": [
      "0xf851a068bb429e7d2063f286c6091187ce9c7d2147c2644efd9a8944934a6dc14f50be80808080808080a0f8487e8af578fb2cc3fef425f28cbb15fab131e3557eb67874f1a80e7fc1a9f58080808080808080",
      "0xf904a530b904a1f9049e01830256bab9010000000020000000002000000000000000000000000000000000000000000000000080000008020000000000800200000000000000000420000000000000200000000000000000000800000008000008010000000000000000000000000000080000000000000000100000000000000000000000000000000000000010000800000000001000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000480000000040000000002000000000004000000000000000000000040000000000000000000000030000000000000000000000000000000000000000000040000000000000010f90393f89b943fb46c4db76d8e9f69f3f8388f43a7ca7e140807f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000712d30c0975386b043e09224433f400ea87cab7da000000000000000000000000061b7b0009fced05695ee811b7f8f78ba37c38344a00000000000000000000000000000000000000000000000000a5ae491119b0000f89b94951857744785e80e2de051c32ee7b25f9c458c42f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000712d30c0975386b043e09224433f400ea87cab7da0000000000000000000000000d844d373f4ef676665fcc18d9b6c89464a36f2d2a00000000000000000000000000000000000000000000000b593895f85bc3bea71f89b943fb46c4db76d8e9f69f3f8388f43a7ca7e140807f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000d844d373f4ef676665fcc18d9b6c89464a36f2d2a0000000000000000000000000712d30c0975386b043e09224433f400ea87cab7da0000000000000000000000000000000000000000000000fccf103db7d22e00000f89b943fb46c4db76d8e9f69f3f8388f43a7ca7e140807f863a08c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925a0000000000000000000000000d844d373f4ef676665fcc18d9b6c89464a36f2d2a0000000000000000000000000ecf4ea7907e779b8a7d0f90cb95fe06f43b610fba0000000000000000000000000000000000000314dc3a0f41e5c923c6637280000f9011c94712d30c0975386b043e09224433f400ea87cab7df863a0c42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67a0000000000000000000000000ecf4ea7907e779b8a7d0f90cb95fe06f43b610fba0000000000000000000000000d844d373f4ef676665fcc18d9b6c89464a36f2d2b8a0000000000000000000000000000000000000000000000fccf103db7d22e00000ffffffffffffffffffffffffffffffffffffffffffffff4a6c76a07a43c4158f0000000000000000000000000000000000000000363decaa6e4099f6e686ca910000000000000000000000000000000000000000220948b5cb625b7056562c32ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff86c3"
    ],
    "receiptRoot": "0x473f2a6554298d1b72b3a73e266bee07f5f93509534f716428cf3d233bb25ec7",
    "txProofKeys": [
      "0xa417362c60be564f32c58a2134c4a96ae7667d170537c58a207e95faaf37fae9",
      "0x254e83386c61197750483c05b48b21e2d356827082cade0d9107d6015e2f28a5"
    ],
    "txProofValues": [
      "0xf851a024f4fd8be1fcb465204601a37ba06036414fae5bdbf213c0d3e778da088e5d1280808080808080a0254e83386c61197750483c05b48b21e2d356827082cade0d9107d6015e2f28a58080808080808080",
      "0xf9017530b90171f9016e825e8f85037e11d600830f424094ecf4ea7907e779b8a7d0f90cb95fe06f43b610fb80b90104414bf3890000000000000000000000003fb46c4db76d8e9f69f3f8388f43a7ca7e140807000000000000000000000000951857744785e80e2de051c32ee7b25f9c458c420000000000000000000000000000000000000000000000000000000000000064000000000000000000000000d844d373f4ef676665fcc18d9b6c89464a36f2d20000000000000000000000000000000000000000000000000000000068254fab000000000000000000000000000000000000000000000fccf103db7d22e000000000000000000000000000000000000000000000000000acee08ed426a20ae8400000000000000000000000000000000000000000000000000000000000000008188a05b1d0e4565493e5f815e26d622c6b9f5c7f23e269eac6ed950446ff7a10e3197a0025df537fe481c63c7defaaaccdd91105a0088f720789ecf5728460a4c3c0fc2"
    ],
    "txRoot": "0xa417362c60be564f32c58a2134c4a96ae7667d170537c58a207e95faaf37fae9"
  }
}
```


## Method eth_getTransactionByBlockHashAndIndex

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": {
    "blockHash": "0xb6fbeabaa5682445b825c5bb02faf9290a38be44d9a47834b65224478923ebce",
    "blockNumber": "0x548f4f1",
    "from": "0xd844d373f4ef676665fcc18d9b6c89464a36f2d2",
    "gas": "0xf4240",
    "gasPrice": "0x37e11d600",
    "hash": "0xbf83342ccdd6592eff8e2acfed87e23e852d684a4e2cfade89ba3b304c2b66a9",
    "input": "0x414bf3890000000000000000000000003fb46c4db76d8e9f69f3f8388f43a7ca7e140807000000000000000000000000951857744785e80e2de051c32ee7b25f9c458c420000000000000000000000000000000000000000000000000000000000000064000000000000000000000000d844d373f4ef676665fcc18d9b6c89464a36f2d20000000000000000000000000000000000000000000000000000000068254fab000000000000000000000000000000000000000000000fccf103db7d22e000000000000000000000000000000000000000000000000000acee08ed426a20ae840000000000000000000000000000000000000000000000000000000000000000",
    "nonce": "0x5e8f",
    "to": "0xecf4ea7907e779b8a7d0f90cb95fe06f43b610fb",
    "transactionIndex": "0x0",
    "value": "0x0",
    "type": "0x0",
    "v": "0x88",
    "r": "0x5b1d0e4565493e5f815e26d622c6b9f5c7f23e269eac6ed950446ff7a10e3197",
    "s": "0x25df537fe481c63c7defaaaccdd91105a0088f720789ecf5728460a4c3c0fc2"
  }
}
```


## Method eth_getTransactionByBlockNumberAndIndex

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": {
    "blockHash": "0xb6fbeabaa5682445b825c5bb02faf9290a38be44d9a47834b65224478923ebce",
    "blockNumber": "0x548f4f1",
    "from": "0xd844d373f4ef676665fcc18d9b6c89464a36f2d2",
    "gas": "0xf4240",
    "gasPrice": "0x37e11d600",
    "hash": "0xbf83342ccdd6592eff8e2acfed87e23e852d684a4e2cfade89ba3b304c2b66a9",
    "input": "0x414bf3890000000000000000000000003fb46c4db76d8e9f69f3f8388f43a7ca7e140807000000000000000000000000951857744785e80e2de051c32ee7b25f9c458c420000000000000000000000000000000000000000000000000000000000000064000000000000000000000000d844d373f4ef676665fcc18d9b6c89464a36f2d20000000000000000000000000000000000000000000000000000000068254fab000000000000000000000000000000000000000000000fccf103db7d22e000000000000000000000000000000000000000000000000000acee08ed426a20ae840000000000000000000000000000000000000000000000000000000000000000",
    "nonce": "0x5e8f",
    "to": "0xecf4ea7907e779b8a7d0f90cb95fe06f43b610fb",
    "transactionIndex": "0x0",
    "value": "0x0",
    "type": "0x0",
    "v": "0x88",
    "r": "0x5b1d0e4565493e5f815e26d622c6b9f5c7f23e269eac6ed950446ff7a10e3197",
    "s": "0x25df537fe481c63c7defaaaccdd91105a0088f720789ecf5728460a4c3c0fc2"
  }
}
```


## Method eth_getTransactionByHash

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": {
    "blockHash": "0xb6fbeabaa5682445b825c5bb02faf9290a38be44d9a47834b65224478923ebce",
    "blockNumber": "0x548f4f1",
    "from": "0xd844d373f4ef676665fcc18d9b6c89464a36f2d2",
    "gas": "0xf4240",
    "gasPrice": "0x37e11d600",
    "hash": "0xbf83342ccdd6592eff8e2acfed87e23e852d684a4e2cfade89ba3b304c2b66a9",
    "input": "0x414bf3890000000000000000000000003fb46c4db76d8e9f69f3f8388f43a7ca7e140807000000000000000000000000951857744785e80e2de051c32ee7b25f9c458c420000000000000000000000000000000000000000000000000000000000000064000000000000000000000000d844d373f4ef676665fcc18d9b6c89464a36f2d20000000000000000000000000000000000000000000000000000000068254fab000000000000000000000000000000000000000000000fccf103db7d22e000000000000000000000000000000000000000000000000000acee08ed426a20ae840000000000000000000000000000000000000000000000000000000000000000",
    "nonce": "0x5e8f",
    "to": "0xecf4ea7907e779b8a7d0f90cb95fe06f43b610fb",
    "transactionIndex": "0x0",
    "value": "0x0",
    "type": "0x0",
    "v": "0x88",
    "r": "0x5b1d0e4565493e5f815e26d622c6b9f5c7f23e269eac6ed950446ff7a10e3197",
    "s": "0x25df537fe481c63c7defaaaccdd91105a0088f720789ecf5728460a4c3c0fc2"
  }
}
```


## Method eth_getTransactionCount

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": "0x1"
}
```


## Method eth_getTransactionReceipt

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

Response:

See [eth_getTransactionReceipt_response.json](./eth_getTransactionReceipt_response.json)


## Method eth_getUncleByBlockHashAndIndex

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 5002,
  "result": null
}
```


## Method eth_getUncleByBlockNumberAndIndex

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 5002,
  "result": null
}
```


## Method eth_getUncleCountByBlockHash

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 5002,
  "result": "0x0"
}
```


## Method eth_getUncleCountByBlockNumber

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 5002,
  "result": "0x0"
}
```


## Method eth_getWork

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

Response:

```json

```


## Method eth_hashrate

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 5002,
  "result": "0x0"
}
```


## Method eth_maxPriorityFeePerGas

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1002,
  "result": "0x333905980"
}
```


## Method eth_mining

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 5002,
  "result": false
}
```


## Method eth_pendingTransactions

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1004,
  "result": []
}
```


## Method eth_protocolVersion

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1004,
  "result": "0x64"
}
```


## Method eth_resend

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": "0x85d995eba9763907fdf35cd2034144dd9d53ce4c7f567f1d9592d67e8c5e3c3b"
}
```


## Method eth_sendRawTransaction

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": "0x85d995eba9763907fdf35cd2034144dd9d53ce4c7f567f1d9592d67e8c5e3c3b"
}
```


## Method eth_sendTransaction

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": "0x85d995eba9763907fdf35cd2034144dd9d53ce4c7f567f1d9592d67e8c5e3c3b"
}
```


## Method eth_sign

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

Response:

```json
{
  "id":1,
  "jsonrpc": "2.0",
  "result": "0xa3f20717a250c2b0b729b7e5becbff67fdaef7e0699da4de7ca5895b02a170a12d887fd3b17bfdce3481f10bea41f45ba9f709d39ce8325427b57afcfc994cee1b"
}
```


## Method eth_signTransaction

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
      "nonce":"0x1"
    }
  ]
}' | jq
```

Response:

```json
{
  "v": "0x1",
  "r": "0x51991c5099327d3c7eaa745de60c52a93555e5cbc418eb9b405fe92d986dee08",
  "s": "0x65b1d20a39360c31de69f872244e23a3549b702e11bc7d8eb3586812ac62be8d"
}
```


## Method eth_submitWork

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": false
}
```


## Method eth_syncing

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": false
}
```


## Method Filter methods

## Method# eth_getFilterChanges

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": []
}
```


## Method# eth_getFilterLogs

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

## Method eth_newBlockFilter

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": "0x2b5dddffaad1435838168a59fd0b7bd0"
}
```


### Method eth_newFilter

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": "0x28e04254af38edfd1925af411eb8b6b1"
}
```

## Method eth_newPendingTransactionFilter

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": "0x6c6a174e72b1d72d44f3b212269bfcf8"
}
```

### Method eth_uninstallFilter

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": false
}
```

