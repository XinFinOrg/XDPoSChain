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
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestProcFutureBlocksEvictsKnownBlockThatDoesNotBeatTheHead covers a parked block that is
// already stored with its state - ValidateBody reports ErrKnownBlock for it - while the head
// sits at or above it: InsertChain succeeds without adopting the block, so nothing else would
// ever take the entry out of the queue and futureBlocksLoop would re-verify it on every
// 100ms tick. Dropping it is safe, because the block and its state are on disk: a batch that
// carries it again adopts it through the known-block path.
func TestProcFutureBlocksEvictsKnownBlockThatDoesNotBeatTheHead(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 3, 0)

	// Import #1: it is the head, stored together with its state.
	if n, err := chain.InsertChain(blocks[:1]); err != nil {
		t.Fatalf("block %d: failed to import the head: %v", n, err)
	}
	if !chain.HasBlockAndFullState(blocks[0].Hash(), blocks[0].NumberU64()) {
		t.Fatal("the head must be known with its state, otherwise the shape is not covered")
	}
	// Re-park it, the way a clock that steps back leaves it behind: the block is delivered
	// again while its timestamp is momentarily ahead of the local clock.
	chain.futureBlocks.Add(blocks[0].Hash(), blocks[0])

	chain.procFutureBlocks()

	if chain.futureBlocks.Contains(blocks[0].Hash()) {
		t.Fatal("a stored block that cannot beat the head must leave the future queue")
	}
	if want := uint64(1); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
}

// TestInsertChainAdvancesHeadOverKnownBlocks covers blocks that are already stored
// with their state but sit above the head, which happens after a rollback or when
// a side chain segment was executed without being adopted. They carry no work to
// redo, but they still have to move the head instead of halting the import.
func TestInsertChainAdvancesHeadOverKnownBlocks(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		funds   = big.NewInt(1000000000000000)
		gspec   = &Genesis{
			Alloc:   types.GenesisAlloc{address: {Balance: funds}},
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.TestChainConfig,
		}
	)
	db := rawdb.NewMemoryDatabase()
	chain, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer chain.Stop()

	_, blocks, _ := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 10, nil)
	if n, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("failed to insert block %d: %v", n, err)
	}

	// Move the head back while leaving the blocks and their state on disk.
	rollback := blocks[4]
	rewindHeadMarkers(chain, rollback)
	if have, want := chain.CurrentBlock().Number.Uint64(), rollback.NumberU64(); have != want {
		t.Fatalf("unexpected head after rollback: have %d want %d", have, want)
	}

	if _, err := chain.InsertChain(blocks[5:]); err != nil {
		t.Fatalf("failed to re-insert known blocks: %v", err)
	}
	if have, want := chain.CurrentBlock().Number.Uint64(), blocks[len(blocks)-1].NumberU64(); have != want {
		t.Fatalf("head did not advance over known blocks: have %d want %d", have, want)
	}
}

// TestBlockBeatsHead pins the fork-choice rule shared by writeBlockWithState and
// the known-block paths: a block is adopted on a strictly higher total difficulty,
// or on an equal one with a higher number. A taller chain carrying a lower total
// difficulty must lose, which is where the known-block path used to diverge, and a
// shorter chain carrying a higher total difficulty must win, which an adoption gate
// that compared block numbers instead would have refused.
func TestBlockBeatsHead(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		funds   = big.NewInt(1000000000000000)
		gspec   = &Genesis{
			Alloc:   types.GenesisAlloc{address: {Balance: funds}},
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.TestChainConfig,
		}
	)
	db := rawdb.NewMemoryDatabase()
	chain, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer chain.Stop()

	// The head sits at height 10 with a total difficulty of 100.
	head := &types.Header{Number: big.NewInt(10), Difficulty: big.NewInt(1)}
	rawdb.WriteTd(db, head.Hash(), head.Number.Uint64(), big.NewInt(100))

	// candidate builds a block that lands on parentTd + 1 and stores that total difficulty for
	// the block itself - the record blockBeatsHead compares, and the one writeBlockWithState
	// writes when it executes a block. The parent's record is deliberately left out: the
	// comparison must not need it, or a block this node executed would lose fork choice on a
	// parent record this node happens to have lost.
	candidate := func(parentNumber uint64, parentTd int64, number uint64) *types.Block {
		parent := &types.Header{Number: big.NewInt(int64(parentNumber)), Difficulty: big.NewInt(1)}
		block := types.NewBlockWithHeader(&types.Header{
			ParentHash: parent.Hash(),
			Number:     big.NewInt(int64(number)),
			Difficulty: big.NewInt(1),
		})
		rawdb.WriteTd(db, block.Hash(), block.NumberU64(), new(big.Int).Add(block.Difficulty(), big.NewInt(parentTd)))
		return block
	}
	for _, tc := range []struct {
		name         string
		parentNumber uint64
		parentTd     int64
		number       uint64
		want         bool
	}{
		{"higher number but lower total difficulty", 19, 5, 20, false},
		{"higher total difficulty", 29, 200, 30, true},
		{"lower number but higher total difficulty", 5, 200, 6, true},
		{"equal total difficulty, higher number", 39, 99, 40, true},
		{"equal total difficulty, equal number", 9, 99, 10, false},
		{"equal total difficulty, lower number", 4, 99, 5, false},
	} {
		got, err := chain.blockBeatsHead(candidate(tc.parentNumber, tc.parentTd, tc.number), head)
		if err != nil {
			t.Fatalf("%s: blockBeatsHead reported %v", tc.name, err)
		}
		if got != tc.want {
			t.Fatalf("%s: blockBeatsHead = %v, want %v", tc.name, got, tc.want)
		}
	}
	// A candidate this node holds no total difficulty for cannot be compared and
	// must leave the current chain in place.
	orphan := types.NewBlockWithHeader(&types.Header{
		ParentHash: common.HexToHash("0xdeadbeef"),
		Number:     big.NewInt(20),
		Difficulty: big.NewInt(1),
	})
	if got, err := chain.blockBeatsHead(orphan, head); err != nil || got {
		t.Fatalf("a candidate with an unknown total difficulty must not beat the head, have %v err=%v", got, err)
	}
	// A head this node holds no record for, and no head at all, are not the same case as an
	// unknown parent: the comparison cannot be made at all, so fork choice cannot answer
	// "does not beat the head" without silently leaving the chain where it is. The two are
	// reported as the local condition of this node that headTd raises, by the same read
	// writeKnownBlock and writeBlockWithState go through.
	for _, unmeasurable := range []*types.Header{
		nil,
		{Number: big.NewInt(60), Difficulty: big.NewInt(1)},
	} {
		got, err := chain.blockBeatsHead(candidate(49, 1, 50), unmeasurable)
		if err == nil {
			t.Fatalf("a head this node cannot measure must be reported, have %v", got)
		}
		if !errors.Is(err, ErrLocalInsertCondition) {
			t.Fatalf("unexpected error: have %v want %v", err, ErrLocalInsertCondition)
		}
		if got {
			t.Fatalf("a block must not beat a head this node cannot measure")
		}
	}
}

// TestWriteKnownBlockReportsAMissingStoredTotalDifficulty covers the record the adoption path
// compares. A block this node executed carries the total difficulty writeBlockWithState wrote
// next to its body and its receipts, so the adoption reads that record; reading its absence as
// "this block does not beat the head" would leave the head where it is with no trace at all,
// which is the syncing shape #2534 was about. It is reported as the local condition it is.
//
// A block below the head is used on purpose: taking the head itself would leave the read of the
// head's own record to answer first, and the case this covers would not be the one exercised.
func TestWriteKnownBlockReportsAMissingStoredTotalDifficulty(t *testing.T) {
	chain, _ := newInsertChainTester(t, nil, 6, 6)

	head := chain.CurrentBlock()
	number := head.Number.Uint64() - 1
	block := chain.GetBlock(chain.GetCanonicalHash(number), number)
	if block == nil || !chain.HasExecutedBlock(block.Hash(), block.NumberU64()) {
		t.Fatal("the block below the head must be on disk and executed, otherwise the shape is not covered")
	}
	// Drop only the block's own record: its parent's, its body, its receipts and its state all
	// stay where they are. The read is cached, so the cache is dropped as well - otherwise the
	// cache, not the database, is what the assertion would be reading.
	rawdb.DeleteTd(chain.db, block.Hash(), block.NumberU64())
	chain.hc.tdCache.Purge()

	adopted, promoted, err := chain.writeKnownBlock(block)
	if !errors.Is(err, ErrLocalInsertCondition) {
		t.Fatalf("a stored block with no total difficulty of its own must be reported, have %v", err)
	}
	if !IsLocalInsertError(err) {
		t.Fatalf("the missing record is a condition of this node, not of the block: %v", err)
	}
	if adopted != nil || promoted {
		t.Fatalf("a block whose total difficulty cannot be read must not be adopted, have %v promoted=%v", adopted, promoted)
	}
	if have := chain.CurrentBlock().Number.Uint64(); have != head.Number.Uint64() {
		t.Fatalf("the head must stay where it is: have %d want %d", have, head.Number.Uint64())
	}
}

// TestInsertChainReportsAMissingStoredTotalDifficulty covers the record the adoption path
// reads on the path a batch takes before it ever reaches writeKnownBlock: the skip loop
// compares the candidate's own total difficulty against the head, and a missing record must
// not be folded into "does not beat the head" there either - that answer leaves the head
// where it is and reports the batch as a success.
//
// Both cases run the same batch against the same shape with only the record dropped, so the
// control is what says the difference comes from the record and not from the shape.
func TestInsertChainReportsAMissingStoredTotalDifficulty(t *testing.T) {
	cases := []struct {
		name     string
		dropTd   bool
		wantErr  bool
		wantHead uint64
	}{
		{"record in place", false, false, 4},
		{"record dropped", true, true, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chain, blocks := newInsertChainTester(t, nil, 5, 5)
			rewindHeadMarkers(chain, blocks[2]) // head stops at #3, blocks #4 and #5 stay on disk

			block := blocks[3] // #4, known and ahead of the head
			if !chain.HasExecutedBlock(block.Hash(), block.NumberU64()) {
				t.Fatal("precondition: #4 must have been executed by this node")
			}
			if have := chain.CurrentBlock().Number.Uint64(); have != 3 {
				t.Fatalf("precondition: the head must stop at #3, have %d", have)
			}
			if tc.dropTd {
				// Drop only the block's own record: its parent's, its body, its receipts and
				// its state all stay where they are. The read is cached, so the cache is
				// dropped as well - otherwise the cache would be what the assertion reads.
				rawdb.DeleteTd(chain.db, block.Hash(), block.NumberU64())
				chain.hc.tdCache.Purge()
			}
			n, err := chain.InsertChain(types.Blocks{block})
			if tc.wantErr {
				if !errors.Is(err, ErrLocalInsertCondition) {
					t.Fatalf("block %d: a known block with no total difficulty of its own must be reported, have %v", n, err)
				}
				if !IsLocalInsertError(err) {
					t.Fatalf("the missing record is a condition of this node, not of the block: %v", err)
				}
			} else if err != nil {
				t.Fatalf("block %d: the batch must be adopted: %v", n, err)
			}
			if have := chain.CurrentBlock().Number.Uint64(); have != tc.wantHead {
				t.Fatalf("head: have %d want %d", have, tc.wantHead)
			}
		})
	}
}

// TestIsGapBlock covers the epoch/gap predicate shared by writeBlockWithState,
// writeKnownBlock and reorg. A zero epoch must never match, otherwise the modulus
// would divide by zero.
func TestIsGapBlock(t *testing.T) {
	block := func(number int64) *types.Block {
		return types.NewBlockWithHeader(&types.Header{Number: big.NewInt(number)})
	}
	xdpos := &BlockChain{chainConfig: &params.ChainConfig{XDPoS: &params.XDPoSConfig{Epoch: 900, Gap: 450}}}
	if !xdpos.isGapBlock(block(450)) {
		t.Fatalf("block 450 must be the gap block of epoch 900")
	}
	for _, number := range []int64{0, 1, 449, 451, 899, 900, 1351} {
		if xdpos.isGapBlock(block(number)) {
			t.Fatalf("block %d must not be a gap block of epoch 900", number)
		}
	}
	// 1350 % 900 == 450, so the next epoch carries its own gap block.
	if !xdpos.isGapBlock(block(1350)) {
		t.Fatalf("block 1350 must be the gap block of the second epoch")
	}
	// A zero epoch has no gap block instead of dividing by zero.
	zero := &BlockChain{chainConfig: &params.ChainConfig{XDPoS: &params.XDPoSConfig{Epoch: 0, Gap: 0}}}
	if zero.isGapBlock(block(0)) || zero.isGapBlock(block(450)) {
		t.Fatalf("a zero epoch must not produce a gap block")
	}
	// A zero gap must not match the epoch boundaries. engine_v2.UpdateMasternodes only
	// accepts num%Epoch == Epoch-Gap, which a zero gap makes unreachable, so accepting
	// those blocks here would call UpdateM1 at every epoch switch and hit its log.Crit.
	noGap := &BlockChain{chainConfig: &params.ChainConfig{XDPoS: &params.XDPoSConfig{Epoch: 900, Gap: 0}}}
	if noGap.isGapBlock(block(900)) || noGap.isGapBlock(block(1800)) {
		t.Fatalf("a zero gap must not turn an epoch boundary into a gap block")
	}
	// A gap equal to the epoch puts the gap block on the epoch switch block, which is
	// num%Epoch == Epoch-Gap == 0 for both the engine and this predicate.
	fullGap := &BlockChain{chainConfig: &params.ChainConfig{XDPoS: &params.XDPoSConfig{Epoch: 900, Gap: 900}}}
	if !fullGap.isGapBlock(block(900)) {
		t.Fatalf("with Gap == Epoch the epoch switch block is the gap block")
	}
	if fullGap.isGapBlock(block(450)) {
		t.Fatalf("with Gap == Epoch no mid-epoch block is a gap block")
	}
	// A gap beyond the epoch never matches the engine, whose Epoch-Gap underflows there.
	overGap := &BlockChain{chainConfig: &params.ChainConfig{XDPoS: &params.XDPoSConfig{Epoch: 900, Gap: 1000}}}
	for _, number := range []int64{0, 100, 800, 900, 1800} {
		if overGap.isGapBlock(block(number)) {
			t.Fatalf("block %d must not be a gap block when Gap > Epoch", number)
		}
	}
	// Chains without XDPoS have no gap blocks at all.
	if (&BlockChain{chainConfig: &params.ChainConfig{}}).isGapBlock(block(450)) {
		t.Fatalf("a chain without XDPoS must not have gap blocks")
	}
}

// TestInsertChainSucceedsWhenKnownBlocksAreOnDisk covers the case where the import
// loop stops on a block that is already on disk while the rest of the batch is on
// disk too: the batch really is fully imported, so it must not be reported as a
// failure and the next batch must still be able to extend the chain.
func TestInsertChainSucceedsWhenKnownBlocksAreOnDisk(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 7, 5)
	rewindHeadMarkers(chain, blocks[1]) // head stops at #2, blocks #3..#5 stay on disk

	if n, err := chain.InsertChain(blocks[2:5]); err != nil {
		t.Fatalf("block %d: batch that is fully on disk reported as failure: %v", n, err)
	}
	// The batch is on disk with its state and wins fork choice, so it is adopted instead
	// of leaving the head behind: nothing else would move it.
	if want := uint64(5); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	for i := 2; i < 5; i++ {
		if block := chain.GetBlockByNumber(blocks[i].NumberU64()); block == nil || block.Hash() != blocks[i].Hash() {
			t.Fatalf("block #%d is not canonical after the batch was adopted", blocks[i].NumberU64())
		}
	}
	// The truncated batch must not leave the chain stuck: importing the following
	// batch on top of the blocks that are already on disk has to work.
	if n, err := chain.InsertChain(blocks[5:]); err != nil {
		t.Fatalf("block %d: failed to insert the following batch: %v", n, err)
	}
	if want := uint64(7); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
}

// TestInsertChainAdoptsKnownBatchAheadOfHead covers the case the ErrKnownBlock
// normalisation used to leave behind: every block of the batch is on disk with its state,
// but the head sits below it, because the batch was imported and then rolled back. The
// head is adopted here - the downloader cannot anchor its ancestor search above the local
// head, so a head that stays behind makes every following sync fetch the same range again.
func TestInsertChainAdoptsKnownBatchAheadOfHead(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 5, 5)
	rewindHeadMarkers(chain, blocks[2]) // head stops at #3, blocks #4..#5 stay on disk

	n, err := chain.InsertChain(blocks[3:]) // #4 and #5 are known and ahead of the head
	if err != nil {
		t.Fatalf("block %d: batch that is fully on disk reported as failure: %v", n, err)
	}
	if want := uint64(5); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	if block := chain.GetBlockByNumber(5); block == nil || block.Hash() != blocks[4].Hash() {
		t.Fatalf("block #5 is not canonical after the batch was adopted")
	}
	// Adopting must not touch the blocks themselves: they were executed when they were
	// first imported, so their receipts and state are still the ones written back then.
	if !chain.HasBlockAndFullState(blocks[4].Hash(), 5) {
		t.Fatal("block #5 lost its state while being adopted")
	}
}

// TestInsertChainImportsPastKnownBlockAheadOfHead covers the batch of
// TestInsertChainAdoptsKnownBatchAheadOfHead with one difference: the blocks after
// the known one were never imported. Adopting the known block moves the head onto
// it, so the rest of the batch executes on its state and the batch completes
// instead of being cut short by the known block - a head left below the known
// block is what made every following sync fetch the same range again.
func TestInsertChainImportsPastKnownBlockAheadOfHead(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 5, 3)
	rewindHeadMarkers(chain, blocks[1]) // head stops at #2, block #3 stays on disk

	if n, err := chain.InsertChain(blocks[2:]); err != nil { // #3 is known, #4 and #5 are not
		t.Fatalf("block %d: batch stopped by a known block reported as failure: %v", n, err)
	}
	if want := uint64(5); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	for i := 3; i < len(blocks); i++ {
		if block := chain.GetBlockByNumber(blocks[i].NumberU64()); block == nil || block.Hash() != blocks[i].Hash() {
			t.Fatalf("block #%d was not imported after the known block was adopted", blocks[i].NumberU64())
		}
	}
}

// TestWriteKnownBlockReorgsToKnownFork covers the reorg branch of writeKnownBlock:
// a known block that sits above the head but not on it must reorganise the chain
// instead of being silently ignored.
func TestWriteKnownBlockReorgsToKnownFork(t *testing.T) {
	genDb, _, blockchain, err := newCanonical(ethash.NewFaker(), 0, true)
	if err != nil {
		t.Fatalf("failed to create pristine chain: %v", err)
	}
	defer blockchain.Stop()

	canonical := makeBlockChain(blockchain.chainConfig, blockchain.Genesis(), 10, ethash.NewFaker(), genDb, 10)
	if _, err := blockchain.InsertChain(canonical); err != nil {
		t.Fatalf("failed to insert canonical chain: %v", err)
	}
	// The fork shares genesis, so it is stored as a side chain together with its
	// state and its blocks stay known from here on.
	fork := makeBlockChain(blockchain.chainConfig, blockchain.Genesis(), 10, ethash.NewFaker(), genDb, 20)
	if _, err := blockchain.InsertChain(fork); err != nil {
		t.Fatalf("failed to insert the fork: %v", err)
	}
	if head := blockchain.CurrentBlock(); head.Hash() != canonical[len(canonical)-1].Hash() {
		t.Fatalf("head moved onto the fork, want it kept as a side chain: have %x, want %x", head.Hash(), canonical[len(canonical)-1].Hash())
	}
	// Roll the head below the fork point so the first re-imported known block does
	// not sit on the head and writeKnownBlock has to reorganise.
	rewindHeadMarkers(blockchain, canonical[2])
	if _, err := blockchain.InsertChain(fork[3:]); err != nil {
		t.Fatalf("failed to re-insert known fork blocks: %v", err)
	}
	head, want := blockchain.CurrentBlock(), fork[len(fork)-1]
	if head.Hash() != want.Hash() {
		t.Fatalf("head did not reorg onto the known fork: have %d (%x), want %d (%x)",
			head.Number.Uint64(), head.Hash(), want.NumberU64(), want.Hash())
	}
}

// logDeliveryFixture is the setup the known-block delivery tests share: a canonical chain
// carrying no transactions at all, and a fork that emits a single anonymous log from the
// block at logAt. Because the canonical chain is silent, every log observed below can only
// come from the fork.
type logDeliveryFixture struct {
	chain     *BlockChain
	canonical []*types.Block
	fork      []*types.Block

	// logs and events drain what the corresponding feed delivered since the fixture was
	// built. Both subscriptions are installed before the chains are imported, so the
	// canonical import is fully covered.
	logs   func() []*types.Log
	events func() []ChainEvent
}

// newLogDeliveryFixture imports both chains and leaves the fork as a side chain, so the
// head still sits on the canonical chain.
func newLogDeliveryFixture(t *testing.T, logAt int) *logDeliveryFixture {
	t.Helper()

	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		// emitter is a genesis contract whose runtime code emits one anonymous log:
		// PUSH1 0x00, PUSH1 0x00, LOG0, STOP.
		emitter = common.HexToAddress("0x0000000000000000000000000000000000000010")
		gspec   = &Genesis{
			Config: &params.ChainConfig{
				ChainID:        big.NewInt(1338),
				HomesteadBlock: new(big.Int),
				Ethash:         new(params.EthashConfig),
			},
			Alloc: types.GenesisAlloc{
				address: {Balance: big.NewInt(params.Ether)},
				emitter: {Code: []byte{0x60, 0x00, 0x60, 0x00, 0xa0, 0x00}},
			},
			Difficulty: big.NewInt(1),
		}
	)
	engine := ethash.NewFaker()
	genDb := rawdb.NewMemoryDatabase()
	if _, err := gspec.Commit(genDb); err != nil {
		t.Fatalf("failed to commit genesis: %v", err)
	}
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	t.Cleanup(chain.Stop)

	f := &logDeliveryFixture{chain: chain}
	f.canonical = makeBlockChain(chain.chainConfig, chain.Genesis(), 10, engine, genDb, 0x01)
	f.fork, _ = GenerateChain(chain.chainConfig, chain.Genesis(), engine, genDb, 10, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{0: 0x02, 19: byte(i)})
		if i == logAt {
			tx, err := types.SignTx(types.NewTransaction(0, emitter, big.NewInt(0), 100000, big.NewInt(1), nil), types.HomesteadSigner{}, key)
			if err != nil {
				t.Fatalf("failed to sign log transaction: %v", err)
			}
			b.AddTx(tx)
		}
	})

	logsCh := make(chan []*types.Log, 64)
	logsSub := chain.SubscribeLogsEvent(logsCh)
	t.Cleanup(logsSub.Unsubscribe)
	f.logs = func() []*types.Log {
		var got []*types.Log
		for {
			select {
			case batch := <-logsCh:
				got = append(got, batch...)
			default:
				return got
			}
		}
	}

	chainCh := make(chan ChainEvent, 64)
	chainSub := chain.SubscribeChainEvent(chainCh)
	t.Cleanup(chainSub.Unsubscribe)
	f.events = func() []ChainEvent {
		var got []ChainEvent
		for {
			select {
			case ev := <-chainCh:
				got = append(got, ev)
			default:
				return got
			}
		}
	}

	if _, err := chain.InsertChain(f.canonical); err != nil {
		t.Fatalf("failed to insert canonical chain: %v", err)
	}
	if _, err := chain.InsertChain(f.fork); err != nil {
		t.Fatalf("failed to insert the fork: %v", err)
	}
	if head := chain.CurrentBlock(); head.Hash() != f.canonical[len(f.canonical)-1].Hash() {
		t.Fatalf("head moved onto the fork, want it kept as a side chain: have %x, want %x", head.Hash(), f.canonical[len(f.canonical)-1].Hash())
	}
	return f
}

// TestWriteKnownBlockLogDelivery covers the logs of known blocks that are adopted
// without re-execution. A block that was not canonical yet has never had its logs
// delivered, so promoting it must send them; a rollback re-import is the opposite
// and must not deliver them a second time.
func TestWriteKnownBlockLogDelivery(t *testing.T) {
	f := newLogDeliveryFixture(t, 9)
	drain := f.logs

	// A side chain block is executed but not adopted, so its logs stay unsent.
	if got := drain(); len(got) != 0 {
		t.Fatalf("side chain delivered %d log(s), want none", len(got))
	}

	// Roll the head below the fork point so the fork is adopted through the
	// known-block path, where its logs have to be delivered.
	rewindHeadMarkers(f.chain, f.canonical[2])
	if _, err := f.chain.InsertChain(f.fork[3:]); err != nil {
		t.Fatalf("failed to re-insert known fork blocks: %v", err)
	}
	tip := f.fork[len(f.fork)-1]
	if head := f.chain.CurrentBlock(); head.Hash() != tip.Hash() {
		t.Fatalf("head did not adopt the known fork: have %d (%x), want %d (%x)",
			head.Number.Uint64(), head.Hash(), tip.NumberU64(), tip.Hash())
	}
	logs := drain()
	if len(logs) != 1 {
		t.Fatalf("promoted known block delivered %d log(s), want 1", len(logs))
	}
	if logs[0].BlockNumber != tip.NumberU64() || logs[0].Removed {
		t.Fatalf("unexpected log %+v, want a live log of block %d", logs[0], tip.NumberU64())
	}

	// Re-importing blocks that were canonical already must not repeat their logs:
	// those were delivered when the blocks were first imported.
	rewindHeadMarkers(f.chain, f.fork[4])
	if _, err := f.chain.InsertChain(f.fork[5:]); err != nil {
		t.Fatalf("failed to re-import rolled back blocks: %v", err)
	}
	if got := drain(); len(got) != 0 {
		t.Fatalf("rollback re-import re-delivered %d log(s), want none", len(got))
	}
}

// TestWriteKnownBlockReorgSkipsRebirthLogs covers the non-adjacent rollback: the
// head is rewound several blocks below a known block, so adopting it reorgs the
// retained rollback blocks back in. Rollback keeps their canonical mappings and
// emits no removed logs, so their logs were delivered and must not be sent again;
// only blocks promoted to the canonical chain for the first time may emit here.
func TestWriteKnownBlockReorgSkipsRebirthLogs(t *testing.T) {
	f := newLogDeliveryFixture(t, 5)
	drain := f.logs

	// Adopt the fork over the known-block path; the log block is promoted and
	// its log goes out exactly once.
	rewindHeadMarkers(f.chain, f.canonical[2])
	if _, err := f.chain.InsertChain(f.fork[3:]); err != nil {
		t.Fatalf("failed to adopt the fork over the known-block path: %v", err)
	}
	tip := f.fork[len(f.fork)-1]
	if head := f.chain.CurrentBlock(); head.Hash() != tip.Hash() {
		t.Fatalf("head did not adopt the known fork: have %d (%x), want %d (%x)",
			head.Number.Uint64(), head.Hash(), tip.NumberU64(), tip.Hash())
	}
	logs := drain()
	if len(logs) != 1 || logs[0].BlockNumber != f.fork[5].NumberU64() {
		t.Fatalf("promoted fork delivered %+v, want the single log of block %d", logs, f.fork[5].NumberU64())
	}

	// Rewind the head below the log block. The canonical mappings of the
	// blocks above stay in place, exactly like Rollback leaves them.
	rewindHeadMarkers(f.chain, f.fork[4])
	// Re-import a known block several numbers above the head. The reorg this
	// triggers walks the retained blocks back in and must not repeat their
	// logs.
	if _, err := f.chain.InsertChain(f.fork[9:]); err != nil {
		t.Fatalf("failed to re-import the known block above the rollback point: %v", err)
	}
	if head := f.chain.CurrentBlock(); head.Hash() != tip.Hash() {
		t.Fatalf("head did not advance to the known block: have %d (%x), want %d (%x)",
			head.Number.Uint64(), head.Hash(), tip.NumberU64(), tip.Hash())
	}
	if got := drain(); len(got) != 0 {
		t.Fatalf("reorg over retained rollback blocks re-delivered %d log(s), want none", len(got))
	}
}

// TestWriteKnownBlockChainEvents pins that adopting a known block reaches the
// chain feed. Such a block moves the head, and the subscribers that follow the
// head, eth_subscribe("newHeads") among them, learn about it through ChainEvent
// alone, so skipping the event left them stuck until an executed block arrived.
// The event carries the logs of a block promoted for the first time and none for
// a rollback re-import, whose logs were already delivered.
func TestWriteKnownBlockChainEvents(t *testing.T) {
	f := newLogDeliveryFixture(t, 9)
	drain := f.events

	// Executed blocks are the baseline the known-block path has to match: one
	// event per canonical block, and a side chain that was not adopted sends
	// none of them.
	if events := drain(); len(events) != len(f.canonical) {
		t.Fatalf("canonical import delivered %d chain event(s), want %d", len(events), len(f.canonical))
	}
	// Roll the head below the fork point so the fork is adopted through the
	// known-block path, which has to announce every block it moves the head over.
	rewindHeadMarkers(f.chain, f.canonical[2])
	if _, err := f.chain.InsertChain(f.fork[3:]); err != nil {
		t.Fatalf("failed to re-insert known fork blocks: %v", err)
	}
	events := drain()
	if len(events) != len(f.fork)-3 {
		t.Fatalf("promoted known blocks delivered %d chain event(s), want %d", len(events), len(f.fork)-3)
	}
	for i, ev := range events {
		want := f.fork[i+3]
		if ev.Block.Hash() != want.Hash() || ev.Hash != want.Hash() {
			t.Fatalf("chain event %d is for %x, want %x", i, ev.Block.Hash(), want.Hash())
		}
		// The tip is promoted for the first time and carries the log of its
		// transaction; the blocks below it were executed without any.
		wantLogs := 0
		if i == len(events)-1 {
			wantLogs = 1
		}
		if len(ev.Logs) != wantLogs {
			t.Fatalf("chain event %d carries %d log(s), want %d", i, len(ev.Logs), wantLogs)
		}
	}

	// Re-importing blocks that were canonical already announces them again, since
	// the head moves over them, but must not repeat their logs.
	rewindHeadMarkers(f.chain, f.fork[4])
	if _, err := f.chain.InsertChain(f.fork[5:]); err != nil {
		t.Fatalf("failed to re-import rolled back blocks: %v", err)
	}
	events = drain()
	if len(events) != len(f.fork)-5 {
		t.Fatalf("rollback re-import delivered %d chain event(s), want %d", len(events), len(f.fork)-5)
	}
	for i, ev := range events {
		if want := f.fork[i+5]; ev.Block.Hash() != want.Hash() {
			t.Fatalf("chain event %d is for %x, want %x", i, ev.Block.Hash(), want.Hash())
		}
		if len(ev.Logs) != 0 {
			t.Fatalf("rollback re-import re-delivered %d log(s) of block %d, want none", len(ev.Logs), ev.Block.NumberU64())
		}
	}
}

// TestWriteBlockWithStateRejectsUnknownParentTd pins the contract that sharing the
// fork-choice rule relies on: writeBlockWithState rejects a block whose parent
// total difficulty is unknown instead of silently treating it as a side chain.
// Losing that error while reusing blockBeatsHead would corrupt the chain.
func TestWriteBlockWithStateRejectsUnknownParentTd(t *testing.T) {
	_, _, blockchain, err := newCanonical(ethash.NewFaker(), 0, true)
	if err != nil {
		t.Fatalf("failed to create pristine chain: %v", err)
	}
	defer blockchain.Stop()

	statedb, err := blockchain.State()
	if err != nil {
		t.Fatalf("failed to open state: %v", err)
	}
	orphan := types.NewBlockWithHeader(&types.Header{
		ParentHash: common.HexToHash("0xdeadbeef"),
		Number:     new(big.Int).Add(blockchain.CurrentBlock().Number, big.NewInt(1)),
		Difficulty: big.NewInt(1),
	})
	if _, err := blockchain.WriteBlockWithState(orphan, nil, statedb, nil, nil); !errors.Is(err, consensus.ErrUnknownAncestor) {
		t.Fatalf("unknown parent total difficulty: have %v, want %v", err, consensus.ErrUnknownAncestor)
	}
}

// TestWriteBlockWithStateReportsMissingHeadTd pins what a head this node holds no record for
// means on the executed path. The comparison cannot be made, so the block must not be written
// as a side chain that lost fork choice: that leaves the head where it is with no error and no
// log, and every following block repeats it. The record lives in this node, so the failure is
// the local condition the downloader keeps the peer for.
func TestWriteBlockWithStateReportsMissingHeadTd(t *testing.T) {
	_, _, blockchain, err := newCanonical(ethash.NewFaker(), 5, true)
	if err != nil {
		t.Fatalf("failed to create pristine chain: %v", err)
	}
	defer blockchain.Stop()

	head := blockchain.CurrentBlock()
	// A sibling of the head: the block written below keeps an ancestor whose record is still
	// there, so it gets past the parent read and reaches the head one. A child of the head
	// would stop on the parent's record first, which is the case the test above covers.
	hdr := types.CopyHeader(head)
	hdr.Extra = append(append([]byte{}, hdr.Extra...), 0x01)
	sibling := types.NewBlockWithHeader(hdr)
	if sibling.Hash() == head.Hash() {
		t.Fatal("precondition: the sibling must not carry the head's header")
	}
	if td := blockchain.GetTd(sibling.ParentHash(), sibling.NumberU64()-1); td == nil {
		t.Fatal("precondition: the parent total difficulty must be readable")
	}
	rawdb.DeleteTd(blockchain.ChainDb(), head.Hash(), head.Number.Uint64())
	blockchain.hc.tdCache.Remove(head.Hash())

	parent := blockchain.GetHeader(head.ParentHash, head.Number.Uint64()-1)
	statedb, err := blockchain.StateAt(parent.Root)
	if err != nil {
		t.Fatalf("failed to open the parent state: %v", err)
	}
	status, err := blockchain.WriteBlockWithState(sibling, nil, statedb, nil, nil)
	if !errors.Is(err, ErrLocalInsertCondition) {
		t.Fatalf("unexpected error: have %v want %v", err, ErrLocalInsertCondition)
	}
	if !IsLocalInsertError(err) {
		t.Fatalf("a record missing in this node must not be blamed on the blocks: %v", err)
	}
	if status != NonStatTy {
		t.Fatalf("unexpected status: have %v want %v", status, NonStatTy)
	}
	if now := blockchain.CurrentBlock(); now.Hash() != head.Hash() {
		t.Fatalf("the head moved to #%d %s on a comparison that could not be made", now.Number.Uint64(), now.Hash())
	}
}

// TestWriteKnownBlockReportsMissingHeadTd covers the same read on the known-block path, which
// insertSideChain adopts a stored prefix through: reporting it there is what keeps a missing
// record from leaving the head behind, silently, on a batch the chain reported as imported.
func TestWriteKnownBlockReportsMissingHeadTd(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 5, 5) // head at #5
	rewindHeadMarkers(chain, blocks[2])                 // head stops at #3, #4 and #5 stay on disk

	head := chain.CurrentBlock()
	if !chain.HasExecutedBlock(blocks[3].Hash(), blocks[3].NumberU64()) {
		t.Fatal("precondition: the block must be one this node executed")
	}
	rawdb.DeleteTd(chain.ChainDb(), head.Hash(), head.Number.Uint64())
	chain.hc.tdCache.Remove(head.Hash())

	adopted, promoted, err := chain.writeKnownBlock(blocks[3])
	if !errors.Is(err, ErrLocalInsertCondition) {
		t.Fatalf("unexpected error: have %v want %v", err, ErrLocalInsertCondition)
	}
	if !IsLocalInsertError(err) {
		t.Fatalf("a record missing in this node must not be blamed on the blocks: %v", err)
	}
	if adopted != nil || promoted {
		t.Fatalf("a block was adopted on a comparison that could not be made: %v promoted=%v", adopted, promoted)
	}
	if want := head.Number.Uint64(); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
}

// TestInsertChainIgnoresKnownBlocksBelowTheHead covers the other half of the adoption
// rule: a known block that does not beat the head is skipped rather than adopted, so
// re-delivering blocks the chain already passed never moves the head backwards and never
// announces a head event for them.
func TestInsertChainIgnoresKnownBlocksBelowTheHead(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 5, 5) // head at #5

	headCh := make(chan ChainHeadEvent, 8)
	sub := chain.SubscribeChainHeadEvent(headCh)
	defer sub.Unsubscribe()

	if n, err := chain.InsertChain(blocks[1:3]); err != nil { // #2 and #3, both below the head
		t.Fatalf("block %d: re-delivering blocks below the head failed: %v", n, err)
	}
	if want := uint64(5); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("head moved to %d, want it kept at %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	select {
	case ev := <-headCh:
		t.Fatalf("a block below the head was announced as the new head: #%d", ev.Block.NumberU64())
	default:
	}
}

// TestKnownBlockNeverExecutedIsNotAdopted pins the execution gate of writeKnownBlock: a
// block this node never executed must not become the head just because it is on disk and
// names a state root the trie database happens to resolve.
//
// writeBlockWithoutState is the only production writer that leaves a block on disk without
// its state and without its receipts - insertSideChain uses it for the blocks of a segment
// whose ancestors are pruned - so such a block can name any root that already exists.
// What the insertion paths answer for such a block is deliberately not pinned here: the
// import either skips it as known or executes it and rejects it at ValidateState, and
// either is safe. The invariant this test does pin is that the head must not move onto it.
func TestKnownBlockNeverExecutedIsNotAdopted(t *testing.T) {
	cases := []struct {
		name string
		root func(parent *types.Block) common.Hash
	}{
		// trie.New resolves no node at all for these two, so OpenTrie succeeds without any
		// state being present.
		{"empty root", func(*types.Block) common.Hash { return types.EmptyRootHash }},
		{"zero root", func(*types.Block) common.Hash { return common.Hash{} }},
		// A root that really is in the database, borrowed from another block.
		{"root of another block", func(parent *types.Block) common.Hash { return parent.Root() }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, _, chain, err := newCanonical(ethash.NewFaker(), 4, true)
			if err != nil {
				t.Fatalf("could not make new canonical in test: %v", err)
			}
			defer chain.Stop()

			head := chain.CurrentBlock()
			parent := chain.GetBlock(head.Hash(), head.Number.Uint64())
			if parent == nil {
				t.Fatal("parent block missing")
			}
			// The successor carries the parent's transactions and uncle hash, so the state
			// root is the only thing that is a lie about it.
			header := types.CopyHeader(parent.Header())
			header.Number = new(big.Int).Add(parent.Number(), big.NewInt(1))
			header.ParentHash = parent.Hash()
			header.Time = parent.Time() + 1
			header.Difficulty = ethash.CalcDifficulty(chain.chainConfig, header.Time, parent.Header())
			header.Root = tt.root(parent)
			block := types.NewBlockWithHeader(header).WithBody(types.Body{Transactions: parent.Transactions()})

			td := new(big.Int).Add(parent.Difficulty(), chain.GetTd(parent.Hash(), parent.NumberU64()))
			if err := chain.writeBlockWithoutState(block, td); err != nil {
				t.Fatalf("could not store the block without its state: %v", err)
			}
			// The two preconditions the gate works against: no receipts, and a state root
			// that resolves anyway, so only the receipts tell the two apart.
			if rawdb.HasReceipts(chain.ChainDb(), block.Hash(), block.NumberU64()) {
				t.Fatal("the block must have no receipts, it was never executed")
			}
			if !chain.HasBlockAndFullState(block.Hash(), block.NumberU64()) {
				t.Fatal("the block must look stored with its state, otherwise the shape is not covered")
			}
			// Either the import skips it as known and leaves the head alone, or it executes
			// the block and rejects it at ValidateState. Both are safe, so the error is not
			// pinned - only the invariant below is.
			_, _ = chain.InsertChain(types.Blocks{block})
			if got := chain.CurrentBlock(); got.Hash() == block.Hash() {
				t.Fatalf("the head moved to #%d %s, a block this node never executed", got.Number.Uint64(), got.Hash())
			}
		})
	}
}

// TestInsertChainReportsMissingHeadTd pins the other half of the fork-choice skip: the loop
// cannot decide whether a known block beats the head without the head's total difficulty, and
// answering "no" for a record that is merely missing would report the batch as imported while
// leaving the head where it is. The record lives in this node, so the batch fails with the local
// sentinel - the peer that delivered a range this node already stores is not at fault.
func TestInsertChainReportsMissingHeadTd(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 6, 6) // head at #6
	rewindHeadMarkers(chain, blocks[3])                 // head stops at #4, #5 and #6 stay on disk

	// With the record readable the batch is adopted, which is what a missing one must not be
	// mistaken for.
	head := chain.CurrentBlock()
	if td := chain.GetTd(head.Hash(), head.Number.Uint64()); td == nil {
		t.Fatal("precondition: the head total difficulty must be readable")
	}
	rawdb.DeleteTd(chain.ChainDb(), head.Hash(), head.Number.Uint64())
	chain.hc.tdCache.Remove(head.Hash())

	n, err := chain.InsertChain(blocks[4:6]) // #5 and #6, both already executed
	if err == nil {
		t.Fatalf("block %d: a head without a total difficulty must be reported", n)
	}
	if !errors.Is(err, ErrLocalInsertCondition) {
		t.Fatalf("unexpected error: have %v want %v", err, ErrLocalInsertCondition)
	}
	if !IsLocalInsertError(err) {
		t.Fatalf("a record missing in this node must not be blamed on the blocks: %v", err)
	}
	// Nothing may have been adopted on the way to the report: the loop stopped before it
	// could decide, so the head stays where the rewind left it.
	if now := chain.CurrentBlock().Number.Uint64(); now != 4 {
		t.Fatalf("unexpected head number: have %d want 4", now)
	}
}

// TestInsertChainAdoptsStoredBodyOfKnownBlock pins that adopting a known block uses the copy
// this node executed, not the one the batch carried. A block hash covers only its header, and
// ValidateBody answers ErrKnownBlock before it compares the body, so a batch can hand a stored
// header together with a body this node never executed. Adopting it would index and announce
// transactions that are not in this chain.
func TestInsertChainAdoptsStoredBodyOfKnownBlock(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 5, 5)
	rewindHeadMarkers(chain, blocks[2]) // head stops at #3, blocks #4..#5 stay on disk

	headEvents := make(chan ChainEvent, 4)
	sub := chain.SubscribeChainEvent(headEvents)
	defer sub.Unsubscribe()

	// The header of the stored #4 under a body this node never executed.
	forgedTx := types.NewTransaction(0, common.Address{1}, big.NewInt(1), 21000, big.NewInt(1), nil)
	forged := types.NewBlockWithHeader(blocks[3].Header()).WithBody(types.Body{
		Transactions: types.Transactions{forgedTx},
	})
	if forged.Hash() != blocks[3].Hash() {
		t.Fatalf("the forged block does not carry the stored header: have %v want %v", forged.Hash(), blocks[3].Hash())
	}
	if n, err := chain.InsertChain(types.Blocks{forged}); err != nil {
		t.Fatalf("block %d: adopting a known block reported failure: %v", n, err)
	}
	if want := uint64(4); chain.CurrentBlock().Number.Uint64() != want {
		t.Fatalf("unexpected head number: have %d want %d", chain.CurrentBlock().Number.Uint64(), want)
	}
	if got := chain.GetCanonicalHash(4); got != blocks[3].Hash() {
		t.Fatalf("unexpected canonical hash: have %v want %v", got, blocks[3].Hash())
	}
	// The head was adopted, so writeHeadBlock indexed the transactions of the body it was
	// handed. The forged transaction is not in this chain and must not be indexed.
	if entry := rawdb.ReadTxLookupEntry(chain.ChainDb(), forgedTx.Hash()); entry != nil {
		t.Fatalf("the forged transaction was indexed at block %d by the adoption", *entry)
	}
	// The announced head has to be the stored block as well.
	select {
	case ev := <-headEvents:
		if ev.Block.Hash() != blocks[3].Hash() {
			t.Fatalf("unexpected announced block: have %v want %v", ev.Block.Hash(), blocks[3].Hash())
		}
		if got, want := len(ev.Block.Transactions()), len(blocks[3].Transactions()); got != want {
			t.Fatalf("the announced head carries %d transactions, want %d: the body of the batch was announced", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the adopted head was not announced")
	}
}

// TestInsertChainAdoptsKnownBatchAheadOfHeadWithXDPoS is the XDPoS counterpart of
// TestInsertChainAdoptsKnownBatchAheadOfHead: the same rollback-and-redeliver shape, but on a
// chain driven by the real XDPoS faker instead of ethash. The ethash fixture cannot show that
// the adoption path leaves the engine's own view of the head intact, and XDPoS reads the block
// author back out of the seal (processTradingAndLendingStates), so a batch that is adopted
// rather than executed has to keep the engine able to place it.
func TestInsertChainAdoptsKnownBatchAheadOfHeadWithXDPoS(t *testing.T) {
	// Epoch 3 with Gap 0, the fixture of TestReorgSignalsEpochSwitchOnIntermediateBlock: the
	// epoch switch blocks sit inside the chain, and Gap 0 keeps the masternode-set refresh
	// (UpdateM1, which needs snapshots) out of the adoption.
	cfg := params.TestXDPoSMockChainConfig.Clone()
	xdpos := *cfg.XDPoS
	xdpos.Epoch = 3
	xdpos.Gap = 0
	xdpos.SkipV1Validation = true
	cfg.XDPoS = &xdpos

	engine := XDPoS.NewFaker(rawdb.NewMemoryDatabase(), cfg)
	if engine == nil {
		t.Fatal("failed to create the XDPoS faker engine")
	}
	// An XDPoS genesis has to name signers, and the faker engine never reads them.
	extraData := make([]byte, 32)
	for _, signer := range []common.Address{{1}, {2}, {3}, {4}} {
		extraData = append(extraData, signer.Bytes()...)
	}
	genesis := &Genesis{BaseFee: big.NewInt(params.InitialBaseFee), Config: cfg, ExtraData: extraData}
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer chain.Stop()
	signals := observeCheckpointSignals()
	defer signals.stop() // block 3 switches the epoch and signals the staking loop

	blocks := makeSealedChain(t, cfg, genesis, engine, 5)
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("failed to insert the chain: %v", err)
	}
	if head := chain.CurrentBlock(); head.Number.Uint64() != 5 {
		t.Fatalf("head after the initial import: have %d, want 5", head.Number.Uint64())
	}
	// Rewind the head markers to block 3 without touching the blocks themselves: 4 and 5 stay
	// stored and executed, and a rollback leaves their canonical mappings in place, which is
	// what makes the batch below a re-delivery of an already imported range.
	rewindHeadMarkers(chain, blocks[2])
	if head := chain.CurrentBlock(); head.Number.Uint64() != 3 {
		t.Fatalf("head after the rollback: have %d, want 3", head.Number.Uint64())
	}

	n, err := chain.InsertChain(blocks[3:])
	if err != nil {
		t.Fatalf("block %d: batch that is fully on disk reported as failure: %v", n, err)
	}
	if head := chain.CurrentBlock(); head.Number.Uint64() != 5 {
		t.Fatalf("head after the adoption: have %d, want 5", head.Number.Uint64())
	}
	if block := chain.GetBlockByNumber(5); block == nil || block.Hash() != blocks[4].Hash() {
		t.Fatal("block #5 is not canonical after the batch was adopted")
	}
	// The blocks were executed when they were first imported, so the adoption has to recognise
	// them as executed rather than run them again, and their receipts and state have to be the
	// ones written back then.
	for i := uint64(4); i <= 5; i++ {
		if !chain.HasExecutedBlock(blocks[i-1].Hash(), i) {
			t.Fatalf("block #%d is not reported as executed after the adoption", i)
		}
	}
}

// TestKnownNotAdoptedMeterIgnoresKnownBlocksBelowTheHead pins the line the meter's own contract
// draws: it counts the known blocks above the head that a batch did not adopt, because that is
// the shape in which a batch reports success without moving the head. A known block below the
// head is the routine skip of a block that is already canonical, and the other two call sites of
// the meter - the skip loop of the canonical import path and the stored-prefix adoption of
// insertSideChain - ask for the height before they count. This call site is the third one.
//
// The batch is contiguous and sits below the head: it re-delivers #3 and #4 under a head at #5.
// Its first block is one this node does not count as executed - the marker an execution leaves is
// taken off, the body, the receipts and the state it was executed with stay - so the import runs
// it again, and the block after it is met as a known block while the head stands above both of
// them. That is the shape a database written before the marker holds, which is why the case is
// only reachable once the marker is what "known" is read from.
func TestKnownNotAdoptedMeterIgnoresKnownBlocksBelowTheHead(t *testing.T) {
	chain, blocks := newInsertChainTester(t, nil, 6, 5)

	// Both blocks of the batch must sit below the head, otherwise this is not the case under test.
	if head, last := chain.CurrentBlock().Number.Uint64(), blocks[3].NumberU64(); last >= head {
		t.Fatalf("the batch must sit below the head: head at #%d, last block #%d", head, last)
	}
	// Take the marker off the first block, leaving the body, the receipts and the state it was
	// executed with on disk. It is this node's own execution that is not recorded on it, so the
	// import runs it again - and running it is what writes the marker back.
	first := blocks[2]
	rawdb.DeleteExecutedMarker(chain.ChainDb(), first.Hash(), first.NumberU64())
	if chain.HasExecutedBlock(first.Hash(), first.NumberU64()) {
		t.Fatal("the batch must not open with a known block, otherwise the skip loop consumes it")
	}
	before := blockKnownNotAdoptedMeter.Snapshot().Count()

	if n, err := chain.InsertChain(types.Blocks{first, blocks[3]}); err != nil {
		t.Fatalf("block %d: the batch was not imported: %v", n, err)
	}
	// The shape was reached: the first block was executed again, and the head did not move, which
	// is what leaves the second block as a known block the batch adopted nothing for.
	if !rawdb.HasExecutedMarker(chain.ChainDb(), first.Hash(), first.NumberU64()) {
		t.Fatal("the first block was not executed again, the batch did not take the shape under test")
	}
	if head := chain.CurrentBlock().Number.Uint64(); head != 5 {
		t.Fatalf("the batch must not move the head: have #%d, want #5", head)
	}
	if after := blockKnownNotAdoptedMeter.Snapshot().Count(); after != before {
		t.Fatalf("a known block below the head was counted as not adopted: %d -> %d", before, after)
	}
}
