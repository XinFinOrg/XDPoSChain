// Copyright 2026 The go-ethereum Authors
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
	"errors"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/trie"
)

var errBatchParentNotCanonical = errors.New("parent of batch is not canonical")

// sharedStateEngine is an ethash faker without block rewards, so a block without transactions
// keeps the state root of its parent - the shape an XDPoS block without transactions and rewards
// has, and what makes a stored block share the state an earlier execution produced.
//
// Its header verification looks the parent of the batch up by canonical number, the way the XDPoS
// verification of an epoch switch looks up its gap block, so a batch sitting on blocks that are
// stored but not canonical is rejected before its body is validated - the failure insertChain
// rebuilds those ancestors for.
type sharedStateEngine struct {
	*ethash.Ethash
}

func (e sharedStateEngine) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))
	for i, header := range headers {
		if i == 0 {
			parent := chain.GetHeaderByNumber(header.Number.Uint64() - 1)
			if parent == nil || parent.Hash() != header.ParentHash {
				results <- errBatchParentNotCanonical
				continue
			}
		}
		results <- nil
	}
	return abort, results
}

// Finalize keeps the state of the block untouched: no block reward, no uncles, so a block
// without transactions has exactly the state root of its parent.
func (e sharedStateEngine) Finalize(chain consensus.ChainReader, header *types.Header, state vm.StateDB, parentState *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	return types.NewBlock(header, &types.Body{Transactions: txs, Uncles: uncles}, receipts, trie.NewStackTrie(nil)), nil
}

// makeSharedStateChain generates six blocks, where block 3 has no transactions and therefore
// the same state root as block 2.
func makeSharedStateChain(t *testing.T) (*Genesis, sharedStateEngine, []*types.Block) {
	t.Helper()

	return makeSharedStateChainWithCode(t, nil)
}

// makeSharedStateChainWithCode builds the same chain as makeSharedStateChain, with code attached
// to the account the transfers call into when code is not nil. Code that emits a log gives the
// blocks of a rebuild receipts and logs of their own, which a caller asserting on a rebuild needs.
func makeSharedStateChainWithCode(t *testing.T, code []byte) (*Genesis, sharedStateEngine, []*types.Block) {
	t.Helper()

	var (
		key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr   = crypto.PubkeyToAddress(key.PublicKey)
		config = *params.TestChainConfig
		alloc  = types.GenesisAlloc{addr: {Balance: big.NewInt(params.Ether)}}
		engine = sharedStateEngine{ethash.NewFaker()}
	)
	if code != nil {
		alloc[common.Address{0xaa}] = types.Account{Balance: new(big.Int), Code: code}
	}
	gspec := &Genesis{
		Alloc:   alloc,
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  &config,
	}
	// EIP-2935 stores the parent hash in the state of every block, and EIP-7934 is scheduled
	// together with it, so stay before Prague: the point of the chain is that block 3 keeps
	// the state root of block 2.
	config.PragueBlock, config.OsakaBlock = nil, nil

	// A transfer into an account with code runs it, so the gas limit has to cover more than
	// the transfer cost. It stays the transfer cost when there is no code, which keeps the
	// chain of makeSharedStateChain byte for byte the one it always was.
	gas := uint64(params.TxGas)
	if code != nil {
		gas += 10000
	}
	signer := types.LatestSigner(gspec.Config)
	_, blocks, _ := GenerateChainWithGenesis(gspec, engine, 6, func(i int, b *BlockGen) {
		if i == 2 {
			return
		}
		tx, err := types.SignTx(types.NewTransaction(b.TxNonce(addr), common.Address{0xaa}, big.NewInt(1), gas, b.BaseFee(), nil), signer, key)
		if err != nil {
			t.Fatalf("failed to sign tx: %v", err)
		}
		b.AddTx(tx)
	})
	if blocks[2].Root() != blocks[1].Root() {
		t.Fatalf("block 3 does not share the state of block 2")
	}
	return gspec, engine, blocks
}

// writeStateless stores blocks the way insertSidechain does: body, header and total
// difficulty, but no state, no receipts and no canonical marker.
func writeStateless(t *testing.T, chain *BlockChain, blocks []*types.Block) {
	t.Helper()

	for _, block := range blocks {
		ptd := chain.GetTd(block.ParentHash(), block.NumberU64()-1)
		if ptd == nil {
			t.Fatalf("missing total difficulty of the parent of block %d", block.NumberU64())
		}
		if err := chain.writeBlockWithoutState(block, new(big.Int).Add(ptd, block.Difficulty())); err != nil {
			t.Fatalf("failed to write block %d: %v", block.NumberU64(), err)
		}
	}
}

func assertCanonical(t *testing.T, chain *BlockChain, blocks []*types.Block) {
	t.Helper()

	if head := chain.CurrentBlock().Number.Uint64(); head != blocks[len(blocks)-1].NumberU64() {
		t.Fatalf("chain head mismatch: have %d, want %d", head, blocks[len(blocks)-1].NumberU64())
	}
	for _, block := range blocks {
		if hash := rawdb.ReadCanonicalHash(chain.db, block.NumberU64()); hash != block.Hash() {
			t.Fatalf("block %d is not canonical", block.NumberU64())
		}
	}
}

// TestInsertChainReimportsStatelessAncestors covers a node that restarted after an unclean
// shutdown: the downloader resumes above the highest stored block, which an earlier sidechain
// import wrote without state, and the next batch's header verification resolves its parent by
// canonical number. The ancestors are neither canonical nor executed, so the batch is rejected
// unless they are rebuilt before it is verified - which is what insertChain does now.
func TestInsertChainReimportsStatelessAncestors(t *testing.T) {
	gspec, engine, blocks := makeSharedStateChain(t)

	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer chain.Stop()

	writeStateless(t, chain, blocks[:5])

	if n, err := chain.InsertChain(blocks[5:]); err != nil {
		t.Fatalf("block %d: batch on stored ancestors without state reported as failure: %v", n, err)
	}
	assertCanonical(t, chain, blocks)
}

// logEmittingCode emits one log with no topics and no data, then stops. A transfer into the
// account holding it runs it, so every block built from such a transfer leaves a receipt with a
// log behind.
var logEmittingCode = []byte{0x60, 0x00, 0x60, 0x00, 0xa0, 0x00}

// TestInsertChainReportsTheLogsTheReimportRan covers what a rebuild hands back besides its events:
// re-running the stored ancestors executes their transactions, and the logs that produces belong
// to the import that triggered the rebuild, like the logs of the batch itself.
func TestInsertChainReportsTheLogsTheReimportRan(t *testing.T) {
	gspec, engine, blocks := makeSharedStateChainWithCode(t, logEmittingCode)

	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer chain.Stop()

	writeStateless(t, chain, blocks[:5])

	if _, _, logs, err := chain.insertChain(blocks[5:], true); err != nil {
		t.Fatalf("batch on stored ancestors without state reported as failure: %v", err)
	} else {
		// Block 3 is the one without transactions; the others carry a call into the log
		// emitter, the batch's own block included.
		seen := make(map[uint64]bool)
		for _, entry := range logs {
			seen[entry.BlockNumber] = true
		}
		for _, number := range []uint64{1, 2, 4, 5, 6} {
			if !seen[number] {
				t.Fatalf("logs of block %d are missing: have %v", number, seen)
			}
		}
	}
	assertCanonical(t, chain, blocks)
}

// TestInsertChainLeavesLighterStatelessAncestorsAlone is the other side of the fork-choice rule:
// ancestors that do not outweigh the head would only be taken as a side chain, so they are left
// where they are and the batch is rejected as before.
func TestInsertChainLeavesLighterStatelessAncestorsAlone(t *testing.T) {
	gspec, engine, blocks := makeSharedStateChain(t)

	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer chain.Stop()

	// A heavier canonical chain of six blocks on a different branch.
	_, canon, _ := GenerateChainWithGenesis(gspec, engine, 6, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{0xbb})
	})
	if n, err := chain.InsertChain(canon); err != nil {
		t.Fatalf("block %d: failed to insert the canonical chain: %v", n, err)
	}
	writeStateless(t, chain, blocks[:4])

	if _, err := chain.InsertChain(blocks[4:5]); !errors.Is(err, errBatchParentNotCanonical) {
		t.Fatalf("insert error mismatch: have %v, want %v", err, errBatchParentNotCanonical)
	}
	assertCanonical(t, chain, canon)
}

// TestInsertChainAnnouncesTheHeadTheReimportMoved covers the events of a rebuild: moving the head
// is what subscribers follow, and the batch raises a single head event for the highest block that
// moved it. The rebuild's own event must not be delivered as well, and must not be dropped when
// the batch behind it does not move the head any further.
func TestInsertChainAnnouncesTheHeadTheReimportMoved(t *testing.T) {
	gspec, engine, blocks := makeSharedStateChain(t)

	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer chain.Stop()

	writeStateless(t, chain, blocks[:5])

	// The batch is the block whose parent the rebuild has to import first, and the block on
	// top of it. Both move the head in turn - once during the rebuild, once during the batch -
	// and the events of the call are what a subscriber following the head sees. The inner
	// method is called directly because that is where the events are returned.
	if n, events, _, err := chain.insertChain(blocks[4:], true); err != nil {
		t.Fatalf("block %d: batch on stored ancestors without state reported as failure: %v", n, err)
	} else {
		var heads []*types.Block
		for _, event := range events {
			if ev, ok := event.(ChainHeadEvent); ok {
				heads = append(heads, ev.Block)
			}
		}
		if len(heads) != 1 {
			t.Fatalf("head events mismatch: have %d, want exactly 1", len(heads))
		}
		if want := blocks[len(blocks)-1]; heads[0].Hash() != want.Hash() {
			t.Fatalf("head event mismatch: have %d, want %d", heads[0].NumberU64(), want.NumberU64())
		}
	}
	assertCanonical(t, chain, blocks)
}
