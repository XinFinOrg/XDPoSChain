// Copyright 2025 The XDC Authors
// This file is part of the XDC library.
//
// The XDC library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The XDC library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the XDC library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// newTdTestChain creates a header-only chain of n blocks whose config switches
// to XDPoS v2 strictly above switchBlock. With full=true a full block chain is
// injected instead.
func newTdTestChain(t *testing.T, n int, switchBlock int64, full bool) (*BlockChain, ethdb.Database) {
	t.Helper()

	genesis := &Genesis{
		BaseFee:   big.NewInt(params.InitialBaseFee),
		ExtraData: make([]byte, 32+crypto.SignatureLength), // XDPoS genesis needs a signer slot
		Config: func() *params.ChainConfig {
			cfg := params.TestXDPoSMockChainConfig.Clone()
			cfg.XDPoS.V2.SwitchBlock = big.NewInt(switchBlock)
			return cfg
		}(),
	}
	engine := ethash.NewFaker()
	blockchain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create test chain: %v", err)
	}
	t.Cleanup(func() { blockchain.Stop() })

	if full {
		genDb, blocks := makeBlockChainWithGenesis(genesis, n, engine, canonicalSeed)
		if _, err := blockchain.InsertChain(blocks); err != nil {
			t.Fatalf("failed to seed test chain: %v", err)
		}
		return blockchain, genDb
	}
	genDb, headers := makeHeaderChainWithGenesis(genesis, n, engine, canonicalSeed)
	if _, err := blockchain.InsertHeaderChain(headers, 1); err != nil {
		t.Fatalf("failed to seed test chain: %v", err)
	}
	return blockchain, genDb
}

// TestWriteHeaderExtendsMissingParentTd verifies that a chain head without a
// TD entry (legacy chaindata predating the TD index) no longer blocks header
// insertion: the parent header exists, so the header is written without a TD
// entry and the fork choice falls back to a height comparison.
func TestWriteHeaderExtendsMissingParentTd(t *testing.T) {
	for _, tc := range []struct {
		name        string
		switchBlock int64 // 900: all blocks v1, 0: all blocks v2
	}{
		{"v1 region", 900},
		{"v2 region", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blockchain, genDb := newTdTestChain(t, 10, tc.switchBlock, false)

			// Drop the head's TD entry to simulate legacy chaindata.
			head := blockchain.CurrentHeader()
			rawdb.DeleteTd(blockchain.db, head.Hash(), head.Number.Uint64())
			blockchain.hc.tdCache.Purge()

			// Generate one more header extending the head.
			chain := makeHeaderChain(blockchain.chainConfig, head, 1, ethash.NewFaker(), genDb, forkSeed)
			if _, err := blockchain.InsertHeaderChain(chain, 1); err != nil {
				t.Fatalf("extending a head without TD failed: %v", err)
			}
			newHead := blockchain.CurrentHeader()
			if newHead.Number.Uint64() != 11 {
				t.Fatalf("expected canonical head to advance to 11, have %d", newHead.Number.Uint64())
			}
			// The TD of the new header cannot be computed and must stay absent.
			if td := blockchain.GetTd(newHead.Hash(), newHead.Number.Uint64()); td != nil {
				t.Fatalf("expected missing TD for extended header, have %v", td)
			}
		})
	}
}

// TestWriteBlockWithStateExtendsMissingParentTd verifies the full-block path:
// a head without a TD entry accepts a new block whose TD stays absent. The
// write path is exercised directly because the consensus insertion loop
// requires a real XDPoS engine.
func TestWriteBlockWithStateExtendsMissingParentTd(t *testing.T) {
	for _, tc := range []struct {
		name        string
		switchBlock int64 // 900: all blocks v1, 0: all blocks v2
	}{
		{"v1 region", 900},
		{"v2 region", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blockchain, genDb := newTdTestChain(t, 10, tc.switchBlock, false)

			// Drop the head's TD entry to simulate legacy chaindata.
			head := blockchain.CurrentBlock()
			rawdb.DeleteTd(blockchain.db, head.Hash(), head.Number.Uint64())
			blockchain.hc.tdCache.Purge()

			// Build the next block directly and run its write path.
			chain := makeHeaderChain(blockchain.chainConfig, head, 1, ethash.NewFaker(), genDb, forkSeed)
			block := types.NewBlockWithHeader(chain[0])
			statedb, err := state.New(head.Root, blockchain.stateCache)
			if err != nil {
				t.Fatalf("failed to create parent state: %v", err)
			}
			status, err := blockchain.writeBlockWithState(block, nil, statedb, nil, nil)
			if err != nil {
				t.Fatalf("extending a head without TD failed: %v", err)
			}
			if status != CanonStatTy {
				t.Fatalf("expected CanonStatTy, have %v", status)
			}
			// The TD of the new block cannot be computed and must stay absent.
			if td := blockchain.GetTd(block.Hash(), block.NumberU64()); td != nil {
				t.Fatalf("expected missing TD for extended block, have %v", td)
			}
		})
	}
}

// TestWriteHeaderRejectsMissingParentHeader verifies that the ErrUnknownAncestor
// sentinel is retained for a genuinely unknown parent header, keeping the sync
// gap-detection semantics intact.
func TestWriteHeaderRejectsMissingParentHeader(t *testing.T) {
	blockchain, genDb := newTdTestChain(t, 5, 0, false)

	// Generate two headers, skipping the first one: the second has an unknown
	// parent from the chain's perspective.
	head := blockchain.CurrentHeader()
	chain := makeHeaderChain(blockchain.chainConfig, head, 2, ethash.NewFaker(), genDb, forkSeed)
	if _, err := blockchain.hc.WriteHeader(chain[1]); err != consensus.ErrUnknownAncestor {
		t.Fatalf("expected ErrUnknownAncestor for missing parent header, have %v", err)
	}
}

// TestInsertReceiptChainMissingHeadTd verifies that legacy chaindata with a
// missing head TD no longer freezes the snap block: the fork-choice comparison
// falls back to a height check and the snap head still advances.
func TestInsertReceiptChainMissingHeadTd(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		funds   = big.NewInt(1000000000000000000)
		gspec   = &Genesis{
			Alloc:   types.GenesisAlloc{address: {Balance: funds}},
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.TestChainConfig,
		}
	)
	_, blocks, receipts := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 11, nil)

	db := rawdb.NewMemoryDatabase()
	chain, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	headers := make([]*types.Header, len(blocks))
	for i, block := range blocks {
		headers[i] = block.Header()
	}
	if n, err := chain.InsertHeaderChain(headers, 1); err != nil {
		t.Fatalf("failed to insert headers: n=%d err=%v", n, err)
	}
	if n, err := chain.InsertReceiptChain(blocks[:10], receipts[:10]); err != nil {
		t.Fatalf("failed to insert receipts: n=%d err=%v", n, err)
	}
	if snap := chain.CurrentSnapBlock().Number.Uint64(); snap != 10 {
		t.Fatalf("snap head mismatch before TD deletion: have %d, want 10", snap)
	}
	// Delete the TDs of the snap head and of the next block to simulate legacy
	// chaindata, then reopen with a fresh TD cache so the deletion is visible.
	chain.Stop()
	rawdb.DeleteTd(db, blocks[9].Hash(), blocks[9].NumberU64())
	rawdb.DeleteTd(db, blocks[10].Hash(), blocks[10].NumberU64())

	chain, err = NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to reopen blockchain: %v", err)
	}
	defer chain.Stop()

	// The nil head TD must not freeze the snap head: the fork-choice comparison
	// falls back to a height check and advances the snap block.
	if n, err := chain.InsertReceiptChain(blocks[10:], receipts[10:]); err != nil {
		t.Fatalf("failed to insert receipts with missing TD: n=%d err=%v", n, err)
	}
	if snap := chain.CurrentSnapBlock().Number.Uint64(); snap != 11 {
		t.Fatalf("snap head mismatch after missing-TD insert: have %d, want 11", snap)
	}
}

// TestInsertReceiptChainSkipsRewoundHead verifies that a receipt batch whose
// head was removed by a concurrent rewind does not repoint the snap marker
// above the rewind. The race is simulated deterministically by removing the
// head's TD and canonical-hash markers, exactly what SetHead deletes when it
// rewinds past the batch head. The header itself is retained so the insertion
// loop passes its header-existence check, reproducing the state seen when the
// rewind interleaves between that check and the snap promotion.
func TestInsertReceiptChainSkipsRewoundHead(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		funds   = big.NewInt(1000000000000000000)
		gspec   = &Genesis{
			Alloc:   types.GenesisAlloc{address: {Balance: funds}},
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.TestChainConfig,
		}
	)
	_, blocks, receipts := GenerateChainWithGenesis(gspec, ethash.NewFaker(), 11, nil)

	db := rawdb.NewMemoryDatabase()
	chain, err := NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	headers := make([]*types.Header, len(blocks))
	for i, block := range blocks {
		headers[i] = block.Header()
	}
	if n, err := chain.InsertHeaderChain(headers, 1); err != nil {
		t.Fatalf("failed to insert headers: n=%d err=%v", n, err)
	}
	if n, err := chain.InsertReceiptChain(blocks[:10], receipts[:10]); err != nil {
		t.Fatalf("failed to insert receipts: n=%d err=%v", n, err)
	}
	if snap := chain.CurrentSnapBlock().Number.Uint64(); snap != 10 {
		t.Fatalf("snap head mismatch before rewind simulation: have %d, want 10", snap)
	}
	// Simulate a concurrent SetHead rewinding past the batch head: delete the
	// head's TD and canonical-hash markers and reopen with fresh caches so the
	// deletions are visible.
	chain.Stop()
	rawdb.DeleteTd(db, blocks[10].Hash(), blocks[10].NumberU64())
	rawdb.DeleteCanonicalHash(db, blocks[10].NumberU64())

	chain, err = NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to reopen blockchain: %v", err)
	}
	defer chain.Stop()

	if n, err := chain.InsertReceiptChain(blocks[10:], receipts[10:]); err != nil {
		t.Fatalf("failed to insert receipts: n=%d err=%v", n, err)
	}
	// The rewind-deleted head must not advance the snap marker: it is no
	// longer canonical, so the promotion must be skipped.
	if snap := chain.CurrentSnapBlock().Number.Uint64(); snap != 10 {
		t.Fatalf("snap head mismatch after rewind simulation: have %d, want 10", snap)
	}
	if hash := rawdb.ReadHeadFastBlockHash(db); hash != blocks[9].Hash() {
		t.Fatalf("head fast block hash mismatch: have %x, want %x", hash, blocks[9].Hash())
	}
}

// TestWriteHeaderTieKeepsCurrentWithoutTds verifies that a competing header at
// the same height as the current head does not win a coin-flip reorganisation
// when the fork-choice weight of either side is unknown (missing TD entries on
// legacy chaindata). The comparison falls back to a height tie, and the
// competing header must deterministically stay on the side chain.
func TestWriteHeaderTieKeepsCurrentWithoutTds(t *testing.T) {
	for _, tc := range []struct {
		name        string
		switchBlock int64 // 900: all blocks v1, 0: all blocks v2
	}{
		{"v1 region", 900},
		{"v2 region", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blockchain, genDb := newTdTestChain(t, 10, tc.switchBlock, false)

			// Drop the TD entries of the head and of its parent to simulate
			// legacy chaindata on both sides of the comparison.
			head := blockchain.CurrentHeader()
			rawdb.DeleteTd(blockchain.db, head.Hash(), head.Number.Uint64())
			rawdb.DeleteTd(blockchain.db, head.ParentHash, head.Number.Uint64()-1)
			blockchain.hc.tdCache.Purge()

			// Generate a competing header at the same height extending the
			// parent and write it through the header chain.
			parent := blockchain.GetHeaderByNumber(head.Number.Uint64() - 1)
			chain := makeHeaderChain(blockchain.chainConfig, parent, 1, ethash.NewFaker(), genDb, forkSeed)
			status, err := blockchain.hc.WriteHeader(chain[0])
			if err != nil {
				t.Fatalf("writing competing header failed: %v", err)
			}
			if status != SideStatTy {
				t.Fatalf("expected competing header to stay on the side chain, have status %v", status)
			}
			if current := blockchain.CurrentHeader(); current.Hash() != head.Hash() {
				t.Fatalf("canonical head changed on a missing-TD tie: have %x, want %x", current.Hash(), head.Hash())
			}
		})
	}
}
