// Copyright 2026 The XDPoSChain Authors
// This file is part of the XDPoSChain library.
//
// The XDPoSChain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The XDPoSChain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the XDPoSChain library. If not, see <http://www.gnu.org/licenses/>.

package legacypool

import (
	"crypto/ecdsa"
	"errors"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/txpool"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/event"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/trie"
)

// TestSignTxAdmissionRules checks that the pool admits only sign transactions
// that are valid for the next block: well-formed calls from a signer.
func TestSignTxAdmissionRules(t *testing.T) {
	t.Parallel()

	candidateKey, _ := crypto.GenerateKey()
	outsiderKey, _ := crypto.GenerateKey()
	candidate := crypto.PubkeyToAddress(candidateKey.PublicKey)

	tests := []struct {
		name string
		tx   func(signer types.Signer) *types.Transaction
		want error
	}{
		{"well-formed from a signer", func(signer types.Signer) *types.Transaction {
			return types.MustSignNewTx(candidateKey, signer, &types.LegacyTx{To: &common.BlockSignersBinary, Gas: 200000, GasPrice: big.NewInt(0), Value: big.NewInt(0), Data: signTxData(0)})
		}, nil},
		{"malformed call", func(signer types.Signer) *types.Transaction {
			return types.MustSignNewTx(candidateKey, signer, &types.LegacyTx{To: &common.BlockSignersBinary, Gas: 200000, GasPrice: big.NewInt(0), Value: big.NewInt(0), Data: make([]byte, 100)})
		}, core.ErrSignTxData},
		{"value", func(signer types.Signer) *types.Transaction {
			return types.MustSignNewTx(candidateKey, signer, &types.LegacyTx{To: &common.BlockSignersBinary, Gas: 200000, GasPrice: big.NewInt(0), Value: big.NewInt(1), Data: signTxData(0)})
		}, core.ErrSignTxValue},
		{"typed transaction", func(signer types.Signer) *types.Transaction {
			return types.MustSignNewTx(candidateKey, signer, &types.DynamicFeeTx{ChainID: signer.ChainID(), To: &common.BlockSignersBinary, Gas: 200000, GasFeeCap: big.NewInt(0), GasTipCap: big.NewInt(0), Value: big.NewInt(0), Data: signTxData(0)})
		}, core.ErrSignTxType},
		{"from a non-signer", func(signer types.Signer) *types.Transaction {
			return types.MustSignNewTx(outsiderKey, signer, &types.LegacyTx{To: &common.BlockSignersBinary, Gas: 200000, GasPrice: big.NewInt(0), Value: big.NewInt(0), Data: signTxData(0)})
		}, txpool.ErrSpecialTxNotFromSigner},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool, _ := setupPool()
			defer pool.Close()
			pool.SetSigner(func(addr common.Address) bool { return addr == candidate })
			testAddBalance(pool, candidate, big.NewInt(1_000_000_000_000_000))

			tx := tt.tx(pool.signer)
			err := pool.addRemoteSync(tx)
			if !errors.Is(err, tt.want) || (tt.want == nil && err != nil) {
				t.Fatalf("add: err = %v, want %v", err, tt.want)
			}
			if inPool := pool.all.Get(tx.Hash()) != nil; inPool != (tt.want == nil) {
				t.Fatalf("in pool = %v, want %v", inPool, tt.want == nil)
			}
		})
	}
}

// reorgTestChain is a testBlockChain that also serves blocks by hash, so a
// pool reset can walk a reorg.
type reorgTestChain struct {
	*testBlockChain
	blocks map[common.Hash]*types.Block
}

func (bc *reorgTestChain) GetBlock(hash common.Hash, number uint64) *types.Block {
	return bc.blocks[hash]
}

// TestReorgReinjectionChecksSpecialTxs checks that the special transactions of
// a block dropped by a reorg go through the pool's basic validation before
// they are reinjected, while regular transactions are reinjected as before.
func TestReorgReinjectionChecksSpecialTxs(t *testing.T) {
	t.Parallel()

	candidateKey, _ := crypto.GenerateKey()
	otherCandidateKey, _ := crypto.GenerateKey()
	outsiderKey, _ := crypto.GenerateKey()
	payerKey, _ := crypto.GenerateKey()
	candidate := crypto.PubkeyToAddress(candidateKey.PublicKey)
	otherCandidate := crypto.PubkeyToAddress(otherCandidateKey.PublicKey)
	payer := crypto.PubkeyToAddress(payerKey.PublicKey)

	diskdb := rawdb.NewMemoryDatabase()
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabase(diskdb))
	chain := &reorgTestChain{
		testBlockChain: newTestBlockChain(params.TestChainConfig, 10000000, statedb, new(event.Feed)),
		blocks:         make(map[common.Hash]*types.Block),
	}
	pool, _ := setupPoolWithChain(chain)
	defer pool.Close()
	pool.SetSigner(func(addr common.Address) bool { return addr == candidate || addr == otherCandidate })
	testAddBalance(pool, payer, big.NewInt(1_000_000_000_000_000))

	signer := pool.signer
	signTx := func(key *ecdsa.PrivateKey, nonce uint64, data []byte) *types.Transaction {
		return types.MustSignNewTx(key, signer, &types.LegacyTx{Nonce: nonce, To: &common.BlockSignersBinary, Gas: 200000, GasPrice: big.NewInt(0), Value: big.NewInt(0), Data: data})
	}
	valid := signTx(candidateKey, 0, signTxData(0))
	// Each sign tx has its own sender at nonce 0, so only the checks under
	// test decide whether it comes back.
	malformed := signTx(otherCandidateKey, 0, make([]byte, 100))
	outsider := signTx(outsiderKey, 0, signTxData(0))
	regular := pricedTransaction(0, 100000, big.NewInt(common.DefaultMinGasPrice), payerKey)

	genesis := types.NewBlock(&types.Header{Number: big.NewInt(0), Root: types.EmptyRootHash, GasLimit: 10000000}, nil, nil, trie.NewStackTrie(nil))
	dropped := types.NewBlock(&types.Header{ParentHash: genesis.Hash(), Number: big.NewInt(1), Root: types.EmptyRootHash, GasLimit: 10000000},
		&types.Body{Transactions: types.Transactions{valid, malformed, outsider, regular}}, nil, trie.NewStackTrie(nil))
	canonical := types.NewBlock(&types.Header{ParentHash: genesis.Hash(), Number: big.NewInt(1), Root: types.EmptyRootHash, GasLimit: 10000000, Extra: []byte("canonical")},
		nil, nil, trie.NewStackTrie(nil))
	for _, block := range []*types.Block{genesis, dropped, canonical} {
		chain.blocks[block.Hash()] = block
	}

	<-pool.requestReset(dropped.Header(), canonical.Header())

	for _, want := range []struct {
		name string
		tx   *types.Transaction
		in   bool
	}{
		{"valid sign tx", valid, true},
		{"malformed sign tx", malformed, false},
		{"sign tx from a non-signer", outsider, false},
		{"regular tx", regular, true},
	} {
		if inPool := pool.all.Get(want.tx.Hash()) != nil; inPool != want.in {
			t.Errorf("%s: in pool = %v, want %v", want.name, inPool, want.in)
		}
	}
}

// laggingHeadChain is a testBlockChain whose head is a given block number.
type laggingHeadChain struct {
	*testBlockChain
	head uint64
}

func (bc *laggingHeadChain) CurrentBlock() *types.Header {
	header := bc.testBlockChain.CurrentBlock()
	header.Number = new(big.Int).SetUint64(bc.head)
	return header
}

// TestSignTxAdmittedWhilePoolHeadLags checks that the pool admits the sign
// transaction a node creates for a block it has just imported or mined, before
// the pool has reset to that block. The pool moves to a new head
// asynchronously, so its head can still be the signed block's parent.
func TestSignTxAdmittedWhilePoolHeadLags(t *testing.T) {
	t.Parallel()

	key, _ := crypto.GenerateKey()
	addr := crypto.PubkeyToAddress(key.PublicKey)
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
	// The node imported block 15, a merge block; the pool is still at 14.
	chain := &laggingHeadChain{testBlockChain: newTestBlockChain(params.TestChainConfig, 10000000, statedb, new(event.Feed)), head: 14}
	pool, _ := setupPoolWithChain(chain)
	defer pool.Close()
	pool.SetSigner(func(a common.Address) bool { return a == addr })

	data := common.Hex2Bytes(common.HexSignMethod)
	data = append(data, common.LeftPadBytes(big.NewInt(15).Bytes(), 32)...)
	data = append(data, common.Hash{0x15}.Bytes()...)
	tx := types.MustSignNewTx(key, pool.signer, &types.LegacyTx{To: &common.BlockSignersBinary, Gas: 200000, GasPrice: big.NewInt(0), Value: big.NewInt(0), Data: data})
	if err := pool.Add([]*types.Transaction{tx}, true)[0]; err != nil {
		t.Fatalf("sign tx for the block just imported was rejected: %v", err)
	}
}

// TestSignTxAdmissionLookahead checks the cap on how far past its head the pool
// accepts a signed block: a pool head lagging a whole merge range still admits
// the honest sign transaction, while one signing further ahead is refused.
func TestSignTxAdmissionLookahead(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		signed int64
		want   error
	}{
		{"pool head lags a merge range", 30, nil},
		{"beyond one merge range", 45, core.ErrSignTxFutureBlock},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, _ := crypto.GenerateKey()
			addr := crypto.PubkeyToAddress(key.PublicKey)
			statedb, _ := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
			chain := &laggingHeadChain{testBlockChain: newTestBlockChain(params.TestChainConfig, 10000000, statedb, new(event.Feed)), head: 15}
			pool, _ := setupPoolWithChain(chain)
			defer pool.Close()
			pool.SetSigner(func(a common.Address) bool { return a == addr })

			data := common.Hex2Bytes(common.HexSignMethod)
			data = append(data, common.LeftPadBytes(big.NewInt(tt.signed).Bytes(), 32)...)
			data = append(data, common.Hash{0x15}.Bytes()...)
			tx := types.MustSignNewTx(key, pool.signer, &types.LegacyTx{To: &common.BlockSignersBinary, Gas: 200000, GasPrice: big.NewInt(0), Value: big.NewInt(0), Data: data})
			err := pool.Add([]*types.Transaction{tx}, true)[0]
			if !errors.Is(err, tt.want) || (tt.want == nil && err != nil) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}
