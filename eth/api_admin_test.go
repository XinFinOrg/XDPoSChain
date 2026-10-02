// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package eth

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// newHasAllBlocksChain returns a chain whose head is the second of three generated blocks,
// together with the three blocks. The third one is the caller's to store however it likes.
func newHasAllBlocksChain(t *testing.T) (*core.BlockChain, types.Blocks) {
	t.Helper()

	key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	gspec := &core.Genesis{
		Alloc:   types.GenesisAlloc{crypto.PubkeyToAddress(key.PublicKey): {Balance: big.NewInt(1000000000000000)}},
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.TestChainConfig,
	}
	db := rawdb.NewMemoryDatabase()
	genesis := gspec.MustCommit(db)
	engine := ethash.NewFaker()
	blocks, _ := core.GenerateChain(gspec.Config, genesis, engine, db, 3, nil)

	chain, err := core.NewBlockChain(db, nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create tester chain: %v", err)
	}
	t.Cleanup(chain.Stop)
	if _, err := chain.InsertChain(blocks[:2]); err != nil {
		t.Fatalf("failed to seed the chain: %v", err)
	}
	return chain, blocks
}

// TestHasAllBlocksAsksForAnExecutedBlock pins the check AdminAPI.ImportChain makes before it
// skips a batch. The batch precheck used to answer on the body alone, so a block this node had
// only written as a side entry - stored by writeBlockWithoutState, without the receipts and
// the state its execution leaves behind - was reported as already imported and the whole batch
// was skipped with the head left where it was.
//
// The precondition is what makes the assertion say something: the block is on disk, so a false
// answer can only come from this node not having executed it. Answering on the body is what the
// check did before, and it is what this test exists to keep it from going back to.
func TestHasAllBlocksAsksForAnExecutedBlock(t *testing.T) {
	chain, blocks := newHasAllBlocksChain(t)
	side := blocks[2]

	// Store the block the way writeBlockWithoutState does: the body is on disk and neither
	// the receipts nor the state of its execution are.
	rawdb.WriteBlock(chain.ChainDb(), side)

	if !chain.HasBlock(side.Hash(), side.NumberU64()) {
		t.Fatalf("precondition: block #%d must be on disk", side.NumberU64())
	}
	if chain.HasExecutedBlock(side.Hash(), side.NumberU64()) {
		t.Fatalf("precondition: block #%d must not have been executed by this node", side.NumberU64())
	}
	if hasAllBlocks(chain, types.Blocks{side}) {
		t.Fatalf("hasAllBlocks(%d) = true, want false: the block is a side entry this node never executed", side.NumberU64())
	}
}

// TestHasAllBlocksAcceptsAnImportedBatch is the other side of the same check: once this node
// has run the block itself, the batch it belongs to is one the import can skip.
func TestHasAllBlocksAcceptsAnImportedBatch(t *testing.T) {
	chain, blocks := newHasAllBlocksChain(t)
	batch := blocks[2:]

	if _, err := chain.InsertChain(batch); err != nil {
		t.Fatalf("failed to import block #%d: %v", batch[0].NumberU64(), err)
	}
	if !chain.HasExecutedBlock(batch[0].Hash(), batch[0].NumberU64()) {
		t.Fatalf("precondition: block #%d must have been executed by this node", batch[0].NumberU64())
	}
	if !hasAllBlocks(chain, batch) {
		t.Fatalf("hasAllBlocks(%d) = false, want true: the block was executed by this node", batch[0].NumberU64())
	}
}
