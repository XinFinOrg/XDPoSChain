
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
