// Copyright 2020 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package ethtest

import (
	"crypto/rand"
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
)

func largeNumber(megabytes int) *big.Int {
	buf := make([]byte, megabytes*1024*1024)
	rand.Read(buf)
	bigint := new(big.Int)
	bigint.SetBytes(buf)
	return bigint
}

func largeBuffer(megabytes int) []byte {
	buf := make([]byte, megabytes*1024*1024)
	rand.Read(buf)
	return buf
}

func largeBlock() *types.Block {
	return types.NewBlockWithHeader(largeHeader())
}

func randHash() common.Hash {
	var h common.Hash
	rand.Read(h[:])
	return h
}

// largeHeader keeps the body hashes consistent with the empty body: the node
// drops inconsistent bodies silently, which would hide the oversized-field
// rejection these cases assert on
func largeHeader() *types.Header {
	return &types.Header{
		MixDigest:   randHash(),
		ReceiptHash: randHash(),
		TxHash:      types.EmptyRootHash,
		Nonce:       types.BlockNonce{},
		Extra:       []byte{},
		Bloom:       types.Bloom{},
		GasUsed:     0,
		Coinbase:    common.Address{},
		GasLimit:    0,
		UncleHash:   types.EmptyUncleHash,
		Time:        1337,
		ParentHash:  randHash(),
		Root:        randHash(),
		Number:      largeNumber(2),
		Difficulty:  largeNumber(2),
	}
}
