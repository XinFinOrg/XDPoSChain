// Copyright 2018 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package rawdb contains a collection of low level database accessors.
package rawdb

import (
	"encoding/binary"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/metrics"
)

// The fields below define the low level database schema prefixing.
var (
	// Data item prefixes (use single byte to avoid mixing data types, avoid `i`, used for indexes).
	headerPrefix       = []byte("h") // headerPrefix + num (uint64 big endian) + hash -> header
	headerTDSuffix     = []byte("t") // headerPrefix + num (uint64 big endian) + hash + headerTDSuffix -> td
	headerHashSuffix   = []byte("n") // headerPrefix + num (uint64 big endian) + headerHashSuffix -> hash
	headerNumberPrefix = []byte("H") // headerNumberPrefix + hash -> num (uint64 big endian)

	blockBodyPrefix     = []byte("b") // blockBodyPrefix + num (uint64 big endian) + hash -> block body
	blockReceiptsPrefix = []byte("r") // blockReceiptsPrefix + num (uint64 big endian) + hash -> block receipts

	txLookupPrefix        = []byte("l") // txLookupPrefix + hash -> transaction/receipt lookup metadata
	bloomBitsPrefix       = []byte("B") // bloomBitsPrefix + bit (uint16 big endian) + section (uint64 big endian) + hash -> bloom bits
	SnapshotAccountPrefix = []byte("a") // SnapshotAccountPrefix + account hash -> account trie value
	SnapshotStoragePrefix = []byte("o") // SnapshotStoragePrefix + account hash + storage hash -> storage trie value
	codePrefix            = []byte("c") // codePrefix + code hash -> account code

	preimagePrefix = []byte("secure-key-")      // preimagePrefix + hash -> preimage
	configPrefix   = []byte("ethereum-config-") // config prefix for the db

	// Chain index prefixes (use `i` + single byte to avoid mixing data types).
	BloomBitsIndexPrefix = []byte("iB") // BloomBitsIndexPrefix is the data table of a chain indexer to track its progress

	preimageCounter    = metrics.NewRegisteredCounter("db/preimage/total", nil)
	preimageHitCounter = metrics.NewRegisteredCounter("db/preimage/hits", nil)
)

const (
	// freezerHeaderTable indicates the name of the freezer header table.
	freezerHeaderTable = "headers"

	// freezerHashTable indicates the name of the freezer canonical hash table.
	freezerHashTable = "hashes"

	// freezerBodiesTable indicates the name of the freezer block body table.
	freezerBodiesTable = "bodies"

	// freezerReceiptTable indicates the name of the freezer receipts table.
	freezerReceiptTable = "receipts"

	// freezerDifficultyTable indicates the name of the freezer total difficulty table.
	freezerDifficultyTable = "diffs"
)

// encodeBlockNumber encodes a block number as big endian uint64
func encodeBlockNumber(number uint64) []byte {
	enc := make([]byte, 8)
	binary.BigEndian.PutUint64(enc, number)
	return enc
}

// headerNumberKey = headerNumberPrefix + hash
func headerNumberKey(hash common.Hash) []byte {
	return append(headerNumberPrefix, hash.Bytes()...)
}

// blockBodyKey = blockBodyPrefix + num (uint64 big endian) + hash
func blockBodyKey(number uint64, hash common.Hash) []byte {
	return append(append(blockBodyPrefix, encodeBlockNumber(number)...), hash.Bytes()...)
}

// blockReceiptsKey = blockReceiptsPrefix + num (uint64 big endian) + hash
func blockReceiptsKey(number uint64, hash common.Hash) []byte {
	return append(append(blockReceiptsPrefix, encodeBlockNumber(number)...), hash.Bytes()...)
}
