
# Module txpool

## Method txpool_content

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

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1001,
  "result": {
    "pending": {
      "xdc6a7B501F6Becea116623eF1C85304d0983a42FA0": {
        "257783": {
          "blockHash": null,
          "blockNumber": null,
          "from": "0x6a7b501f6becea116623ef1c85304d0983a42fa0",
          "gas": "0x7362",
          "gasPrice": "0x2e90edd00",
          "hash": "0x63cb7582191467f9ea0f91e56033185be96374625e28565b3e34cab4ba4f4739",
          "input": "0xafb91b2e000000000000000000000000d4b0e654a0b07d522b28fb1f20a8ba3c07617db30000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000277b22726f6c65223a2275736572222c2267616d654964223a322c226576656e744964223a34347d00000000000000000000000000000000000000000000000000",
          "nonce": "0x3eef7",
          "to": "0x30632a3c801031a5d6a1b3589966b60ee2fbc301",
          "transactionIndex": null,
          "value": "0x0",
          "type": "0x0",
          "v": "0x88",
          "r": "0x87b1fa4d4e23f61fb503f1cdf7791a0ccd76ae8fd8c9b5c8e74f3f9a62913f9a",
          "s": "0x45dfee63317820545d85e9001fdb8f1561bc63c44f7bf4d19726c4fb4d4259e5"
        }
      }
    },
    "queued": {}
  }
}
```

## Method txpool_contentFrom

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

## Method txpool_inspect

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

## Method txpool_status

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
