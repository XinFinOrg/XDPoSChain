// Copyright 2015 The go-ethereum Authors
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
	"time"

	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/trie"
)

// Tests that simple header verification works, for both good and bad blocks.
func TestHeaderVerification(t *testing.T) {
	// Create a simple chain to verify
	var (
		testdb    = rawdb.NewMemoryDatabase()
		gspec     = &Genesis{Config: params.TestChainConfig}
		genesis   = gspec.MustCommit(testdb)
		blocks, _ = GenerateChain(gspec.Config, genesis, ethash.NewFaker(), testdb, 8, nil)
	)
	headers := make([]*types.Header, len(blocks))
	for i, block := range blocks {
		headers[i] = block.Header()
	}
	// Run the header checker for blocks one-by-one, checking for both valid and invalid nonces
	chain, err := NewBlockChain(testdb, nil, gspec, ethash.NewFaker(), vm.Config{})
	defer chain.Stop()
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < len(blocks); i++ {
		for j, valid := range []bool{true, false} {
			var results <-chan error
			if valid {
				engine := ethash.NewFaker()
				_, results = engine.VerifyHeaders(chain, []*types.Header{headers[i]}, []bool{true})
			} else {
				engine := ethash.NewFakeFailer(headers[i].Number.Uint64())
				_, results = engine.VerifyHeaders(chain, []*types.Header{headers[i]}, []bool{true})
			}
			// Wait for the verification result
			select {
			case result := <-results:
				if (result == nil) != valid {
					t.Errorf("test %d.%d: validity mismatch: have %v, want %v", i, j, result, valid)
				}
			case <-time.After(time.Second):
				t.Fatalf("test %d.%d: verification timeout", i, j)
			}
			// Make sure no more data is returned
			select {
			case result := <-results:
				t.Fatalf("test %d.%d: unexpected result returned: %v", i, j, result)
			case <-time.After(25 * time.Millisecond):
			}
		}
		chain.InsertChain(blocks[i : i+1])
	}
}

func TestValidateBodyBlockOversizedOsakaByBlockNumber(t *testing.T) {
	testdb := rawdb.NewMemoryDatabase()
	cfg := *params.TestChainConfig
	cfg.OsakaBlock = big.NewInt(2)
	gspec := &Genesis{Config: &cfg}
	genesis := gspec.MustCommit(testdb)

	chain, err := NewBlockChain(testdb, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()

	validator := NewBlockValidator(&cfg, chain, ethash.NewFaker())
	oversizedData := make([]byte, params.MaxBlockSize+1024)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    0,
		Gas:      params.TxGas,
		GasPrice: big.NewInt(1),
		Data:     oversizedData,
	})

	newOversizedBlock := func(number uint64, ts uint64) *types.Block {
		header := &types.Header{
			ParentHash: genesis.Hash(),
			Number:     new(big.Int).SetUint64(number),
			Time:       ts,
			GasLimit:   30_000_000,
		}
		return types.NewBlock(header, &types.Body{Transactions: []*types.Transaction{tx}}, nil, trie.NewStackTrie(nil))
	}

	preOsaka := newOversizedBlock(1, ^uint64(0))
	if err := validator.ValidateBody(preOsaka); err == ErrBlockOversized {
		t.Fatalf("pre-Osaka block should not trigger ErrBlockOversized")
	}

	postOsaka := newOversizedBlock(2, 0)
	if err := validator.ValidateBody(postOsaka); err != ErrBlockOversized {
		t.Fatalf("post-Osaka oversized block mismatch: have %v, want %v", err, ErrBlockOversized)
	}
}
