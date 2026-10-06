// Copyright 2019 The go-ethereum Authors
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

package core

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/trie"
)

// TestStatePrefetcherToleratesNilStateDB pins the nil StateDB guard of
// statePrefetcher.Prefetch. A nil state used to reach the prefetcher and panic
// in its goroutine (issue #1738: StateDB.Finalise on a nil receiver), which
// takes the whole node down because a panic in a goroutine cannot be recovered.
func TestStatePrefetcherToleratesNilStateDB(t *testing.T) {
	t.Parallel()

	gspec := &Genesis{BaseFee: big.NewInt(params.InitialBaseFee), Config: params.AllEthashProtocolChanges}
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer chain.Stop()

	// An empty block is enough: with the guard in place the prefetcher returns
	// before it looks at the state, without it the final IntermediateRoot call
	// dereferences the nil state.
	block := types.NewBlock(&types.Header{Number: big.NewInt(1), GasLimit: 100_000}, nil, nil, trie.NewStackTrie(nil))

	newStatePrefetcher(chain.Config(), chain, chain.Engine()).Prefetch(block, nil, vm.Config{}, nil)
}
