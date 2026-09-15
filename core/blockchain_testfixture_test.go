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
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// newInsertChainTester returns a memory chain over a fresh genesis together with a
// generated batch of total blocks, of which the first imported ones are already
// inserted. Keeping total larger than imported lets callers re-deliver blocks that
// are on disk and extend the chain afterwards. A nil engine means the ethash faker;
// blocks are always generated with it, so a custom engine must accept those.
func newInsertChainTester(t *testing.T, engine consensus.Engine, total, imported int) (*BlockChain, types.Blocks) {
	t.Helper()

	if engine == nil {
		engine = ethash.NewFaker()
	}
	key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	address := crypto.PubkeyToAddress(key.PublicKey)
	gspec := &Genesis{
		Alloc:   types.GenesisAlloc{address: {Balance: big.NewInt(1000000000000000)}},
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.TestChainConfig,
	}
	_, blocks, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), total, nil)

	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	t.Cleanup(chain.Stop)

	if n, err := chain.InsertChain(blocks[:imported]); err != nil {
		t.Fatalf("block %d: failed to insert into chain: %v", n, err)
	}
	return chain, blocks
}

// failVerifyEngine fails header verification for a single block number, so a batch
// can be made to fail in the middle instead of at its first block.
type failVerifyEngine struct {
	consensus.Engine
	failNumber uint64
	failErr    error
}

func (e *failVerifyEngine) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))
	go func() {
		for _, header := range headers {
			var err error
			if header.Number.Uint64() == e.failNumber {
				err = e.failErr
			}
			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// failBodyValidator fails body validation for a single block number, so a batch can be
// made to fail in the middle through the body-validation path, while the header verifier
// of the embedded engine still accepts every header.
type failBodyValidator struct {
	Validator
	failNumber uint64
	failErr    error
}

func (v *failBodyValidator) ValidateBody(block *types.Block) error {
	if block.NumberU64() == v.failNumber {
		return v.failErr
	}
	return v.Validator.ValidateBody(block)
}

// newPrunedCanonicalChain imports 2*TriesInMemory generated blocks, so that everything
// but the last TriesInMemory of them is outside the state window: their blocks are stored
// and canonical, their state is gone. The engine and the genesis database are returned as
// well, since generating a competing fork needs both.
func newPrunedCanonicalChain(t *testing.T) (*BlockChain, types.Blocks, consensus.Engine, ethdb.Database) {
	t.Helper()

	engine := ethash.NewFaker()
	gspec := &Genesis{
		Alloc:   types.GenesisAlloc{},
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.TestChainConfig,
	}
	genDb := rawdb.NewMemoryDatabase()
	if _, err := gspec.Commit(genDb); err != nil {
		t.Fatalf("failed to commit genesis: %v", err)
	}
	// Generate and import the canonical chain
	blocks, _ := GenerateChain(gspec.Config, gspec.ToBlock(), engine, genDb, 2*TriesInMemory, nil)
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	t.Cleanup(chain.Stop)

	if n, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("block %d: failed to insert into chain: %v", n, err)
	}
	return chain, blocks, engine, genDb
}

// testSideImport imports a sidechain (S) onto a canonical chain (C), where
//
//   - S holds blocks [Sn...Sm] and is longer than C, so it wins fork choice
//   - the common ancestor sits at prune point + blocksBetweenCommonAncestorAndPruneblock
//   - S is prepended with numCanonBlocksInSidechain blocks taken from C
//
// Ported from upstream geth's testSideImport, added there by 8577b5b020
// ("core: more tests for sidechain import, fixes #19105 (#19113)"). The prepended
// canonical blocks are the shape that was misread as a ghost-state attack, and the
// negative blocksBetweenCommonAncestorAndPruneblock cases put the fork point below the
// prune window, so S starts on canonical blocks whose state is gone.
func testSideImport(t *testing.T, numCanonBlocksInSidechain, blocksBetweenCommonAncestorAndPruneblock int) {
	t.Helper()

	chain, blocks, engine, genDb := newPrunedCanonicalChain(t)

	lastPrunedIndex := len(blocks) - TriesInMemory - 1
	lastPrunedBlock := blocks[lastPrunedIndex]
	firstNonPrunedBlock := blocks[len(blocks)-TriesInMemory]

	// Verify pruning of lastPrunedBlock
	if chain.HasBlockAndFullState(lastPrunedBlock.Hash(), lastPrunedBlock.NumberU64()) {
		t.Errorf("block %d not pruned", lastPrunedBlock.NumberU64())
	}
	// Verify firstNonPrunedBlock is not pruned
	if !chain.HasBlockAndFullState(firstNonPrunedBlock.Hash(), firstNonPrunedBlock.NumberU64()) {
		t.Errorf("block %d pruned", firstNonPrunedBlock.NumberU64())
	}

	// Generate the fork chain, make it longer than the canonical one
	parentIndex := lastPrunedIndex + blocksBetweenCommonAncestorAndPruneblock
	parent := blocks[parentIndex]
	fork, _ := GenerateChain(params.TestChainConfig, parent, engine, genDb, 2*TriesInMemory, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{2})
	})
	// Prepend the canonical blocks the sidechain shares with the canonical chain
	var sidechain []*types.Block
	for i := numCanonBlocksInSidechain; i > 0; i-- {
		sidechain = append(sidechain, blocks[parentIndex+1-i])
	}
	sidechain = append(sidechain, fork...)

	if _, err := chain.InsertChain(sidechain); err != nil {
		t.Errorf("got error, %v", err)
	}
	head := chain.CurrentBlock()
	if got := fork[len(fork)-1].Hash(); got != head.Hash() {
		t.Fatalf("head wrong, expected %x got %x", got, head.Hash())
	}
}

// rewindHeadMarkers rewinds the chain head markers onto the given block without
// removing anything from disk, mimicking what a crash or an interrupted rollback
// leaves behind: the block and its state are on disk, but the head stops below it.
//
// It goes through Rollback, the call a real rewind makes, rather than writing the
// internal marker directly: that is what keeps the canonical mappings of the blocks
// it rewinds over in place, which is the shape the adoption paths are about.
func rewindHeadMarkers(chain *BlockChain, block *types.Block) {
	head := chain.CurrentBlock()
	if head == nil || head.Number.Uint64() <= block.NumberU64() {
		return
	}
	// Rollback walks the slice from its end, so it has to be in ascending order.
	hashes := make([]common.Hash, 0, head.Number.Uint64()-block.NumberU64())
	for n := block.NumberU64() + 1; n <= head.Number.Uint64(); n++ {
		if hash := chain.GetCanonicalHash(n); hash != (common.Hash{}) {
			hashes = append(hashes, hash)
		}
	}
	chain.Rollback(hashes)
}

// failFromEngine fails every header at or above fromNumber, which is what the XDPoS
// engines produce for a chain ahead of the local clock: v1 and v2 check the timestamp
// before the parent lookup with zero tolerance (engine_v1/engine.go,
// engine_v2/verifyHeader.go), so every block after the first future one also reports
// ErrFutureBlock instead of ErrUnknownAncestor.
type failFromEngine struct {
	consensus.Engine
	fromNumber uint64
	failErr    error
}

func (e *failFromEngine) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))
	go func() {
		for _, header := range headers {
			var err error
			if header.Number.Uint64() >= e.fromNumber {
				err = e.failErr
			}
			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// recordingProposedEngine records the headers the future-block queue hands to the
// proposed-block hook.
type recordingProposedEngine struct {
	consensus.Engine
	mu   sync.Mutex
	seen []common.Hash
}

func (e *recordingProposedEngine) HandleProposedBlock(chain consensus.ChainReader, header *types.Header) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seen = append(e.seen, header.Hash())
	return nil
}
func (e *recordingProposedEngine) handled() []common.Hash {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]common.Hash(nil), e.seen...)
}

// newFarFutureChain builds a short chain whose first block is past the window the future
// queue accepts, so that refusing it says something about this node's clock rather than
// about the block. The engine decides verification; the genesis only carries the balance
// block generation needs.
func newFarFutureChain(t *testing.T, engine consensus.Engine) (*BlockChain, types.Blocks) {
	t.Helper()

	key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	gspec := &Genesis{
		Alloc:   types.GenesisAlloc{crypto.PubkeyToAddress(key.PublicKey): {Balance: big.NewInt(1000000000000000)}},
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.TestChainConfig,
		// Generated blocks inherit the genesis timestamp, so every one of them lands past
		// the window the future queue accepts.
		Timestamp: uint64(time.Now().Unix()) + 2*maxTimeFutureBlocks,
	}
	_, blocks, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 3, nil)
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	t.Cleanup(chain.Stop)
	return chain, blocks
}
