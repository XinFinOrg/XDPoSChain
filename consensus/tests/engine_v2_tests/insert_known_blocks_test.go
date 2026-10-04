package engine_v2_tests

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/accounts"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// splitLikeDownloader cuts blocks into the segments the downloader hands to
// InsertChain for an XDPoS chain (processFullSyncContent): a segment ends at every
// gap block, every block before an epoch switch and every epoch switch block.
func splitLikeDownloader(blocks []*types.Block, epoch, gap uint64) [][]*types.Block {
	var (
		segments [][]*types.Block
		current  []*types.Block
	)
	for _, block := range blocks {
		current = append(current, block)
		if n := block.NumberU64() % epoch; n == 0 || n == epoch-1 || n == epoch-gap {
			segments = append(segments, current)
			current = nil
		}
	}
	if len(current) > 0 {
		segments = append(segments, current)
	}
	return segments
}

// createLeaderSealedBlock creates the next V2 block like CreateBlock, but has the
// round's leader seal it in every round. CreateBlock leaves the rounds led by
// voterAddr to the test signer to simulate a penalty, which full header verification
// (as InsertChain runs it) rejects with ErrNotItsTurn.
func createLeaderSealedBlock(t *testing.T, blockchain *core.BlockChain, config *params.ChainConfig, parent *types.Block, number int, round int64, signer common.Address, signFn func(accounts.Account, []byte) ([]byte, error)) *types.Block {
	block := CreateBlock(blockchain, config, parent, number, round, signer.Hex(), signer, signFn, nil, nil, "")
	masternodes := getMasternodesList(signer)
	if masternodes[uint64(round)%config.XDPoS.Epoch%uint64(len(masternodes))] != voterAddr {
		return block
	}
	voter, voterSignFn, err := getSignerAndSignFn(voterKey)
	if err != nil {
		t.Fatalf("failed to get voter signer: %v", err)
	}
	header := block.Header()
	header.Coinbase = voter
	sealHeader(blockchain, header, voter, voterSignFn)
	return types.NewBlockWithHeader(header)
}

// Tests that a node whose head sits below blocks it still stores with their state
// re-imports them when the downloader delivers them again, so the epoch switch
// block that follows can read its gap block from the canonical chain.
//
// This is the stall seen on Apothem: InsertChain skipped the stored segments and
// reported success, the canonical chain stayed below the gap block, and the epoch
// switch block was then rejected with "getSnapshot fail to get header by number".
func TestInsertChainReimportsKnownBlocksBeforeEpochSwitch(t *testing.T) {
	config := params.TestXDPoSMockChainConfig
	epoch, gap := config.XDPoS.Epoch, config.XDPoS.Gap

	// V2 starts after block 900, so block 1800 (round 900) is the first V2 epoch
	// switch block and block 1350 is the gap block its masternode snapshot is read from.
	const (
		head        = 1300
		gapBlock    = 1350
		epochSwitch = 1800
	)
	// The helper's blocks up to the head are never verified again. The blocks above
	// it are, in full, so they are built here with every round sealed by its leader.
	blockchain, _, parent, signer, signFn, _ := PrepareXDCTestBlockChainForV2Engine(t, head, config, nil)
	engine := blockchain.Engine().(*XDPoS.XDPoS)
	config = blockchain.Config() // the helper adjusts the config it builds the chain with

	var (
		blocks   = make([]*types.Block, 0, epochSwitch-head-1)
		tds      = make([]*big.Int, 0, epochSwitch-head-1)
		receipts = make([]types.Receipts, 0, epochSwitch-head-1)
	)
	for n := head + 1; n < epochSwitch; n++ {
		round := int64(n) - config.XDPoS.V2.SwitchBlock.Int64()
		block := createLeaderSealedBlock(t, blockchain, config, parent, n, round, signer, signFn)
		if err := engine.VerifyHeader(blockchain, block.Header(), true); err != nil {
			t.Fatalf("block %d fails full verification: %v", n, err)
		}
		if err := blockchain.InsertBlock(block); err != nil {
			t.Fatalf("failed to insert block %d: %v", n, err)
		}
		if uint64(n)%epoch == epoch-gap {
			if err := blockchain.UpdateM1(); err != nil {
				t.Fatalf("failed to update masternodes at block %d: %v", n, err)
			}
		}
		blocks = append(blocks, block)
		tds = append(tds, new(big.Int).Set(blockchain.GetTd(block.Hash(), block.NumberU64())))
		receipts = append(receipts, blockchain.GetReceiptsByHash(block.Hash()))
		parent = block
	}
	// The epoch switch block itself is only needed for its number: verifying it
	// starts with reading the masternode snapshot of its gap block, which is the
	// step that failed on the stalled nodes.
	round := int64(epochSwitch) - config.XDPoS.V2.SwitchBlock.Int64()
	switchHeader := CreateBlock(blockchain, config, parent, epochSwitch, round, signer.Hex(), signer, signFn, nil, nil, "").Header()
	if isSwitch, _, err := engine.IsEpochSwitch(switchHeader); err != nil || !isSwitch {
		t.Fatalf("block %d is not an epoch switch block (err %v)", epochSwitch, err)
	}
	gapHash := blockchain.GetCanonicalHash(gapBlock)
	if snap, err := engine.EngineV2.GetSnapshot(blockchain, switchHeader); err != nil || snap.Hash != gapHash {
		t.Fatalf("snapshot of block %d not at gap block %d before the rewind (err %v)", epochSwitch, gapBlock, err)
	}

	// Move the head down to block 1300, then put blocks 1301-1799 back on disk
	// without making them canonical: the state the stalled nodes were in.
	if err := blockchain.SetHead(head); err != nil {
		t.Fatalf("failed to set head: %v", err)
	}
	db := blockchain.ChainDb()
	for i, block := range blocks {
		rawdb.WriteBlock(db, block)
		rawdb.WriteTd(db, block.Hash(), block.NumberU64(), tds[i])
		rawdb.WriteReceipts(db, block.Hash(), block.NumberU64(), receipts[i])
		if !blockchain.HasBlockAndFullState(block.Hash(), block.NumberU64()) {
			t.Fatalf("block %d is not stored with its state", block.NumberU64())
		}
	}
	if got := blockchain.CurrentBlock().Number.Uint64(); got != head {
		t.Fatalf("head not moved down: have #%d, want #%d", got, head)
	}
	if got := blockchain.GetCanonicalHash(gapBlock); got != (common.Hash{}) {
		t.Fatalf("gap block %d still canonical", gapBlock)
	}

	// Deliver the blocks again in the downloader's segments: 1301-1350, 1351-1799.
	for _, segment := range splitLikeDownloader(blocks, epoch, gap) {
		if n, err := blockchain.InsertChain(segment); err != nil {
			t.Fatalf("failed to import block %d: %v", segment[n].NumberU64(), err)
		}
	}
	snap, err := engine.EngineV2.GetSnapshot(blockchain, switchHeader)
	if err != nil {
		t.Fatalf("snapshot of epoch switch block %d unavailable: %v", epochSwitch, err)
	}
	if snap.Hash != gapHash {
		t.Fatalf("snapshot of block %d at %x, want gap block %d %x", epochSwitch, snap.Hash, gapBlock, gapHash)
	}
	last := blocks[len(blocks)-1]
	if got := blockchain.CurrentBlock().Number.Uint64(); got != last.NumberU64() {
		t.Fatalf("head not advanced: have #%d, want #%d", got, last.NumberU64())
	}
	for _, block := range blocks {
		if got := blockchain.GetCanonicalHash(block.NumberU64()); got != block.Hash() {
			t.Fatalf("block %d not canonical: have %x, want %x", block.NumberU64(), got, block.Hash())
		}
	}
}
