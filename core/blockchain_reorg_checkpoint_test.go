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
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// drainCheckpointCh empties the checkpoint channel so that a test only observes the
// signals it triggers itself. SignalCheckpoint coalesces, so a leftover entry would
// make an assertion on the channel pass for the wrong reason.
func drainCheckpointCh() {
	for len(CheckpointCh) > 0 {
		<-CheckpointCh
	}
}

// makeSealedChain builds n blocks from genesis for the fixtures below. The deterministic
// generator does not seal the headers it builds, and XDPoS reads the block author out of
// the seal for every block above the epoch (processTradingAndLendingStates), so each
// header is signed before the next block is built on top of it.
func makeSealedChain(t *testing.T, cfg *params.ChainConfig, genesis *Genesis, engine *XDPoS.XDPoS, n int) []*types.Block {
	t.Helper()
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to parse the signer key: %v", err)
	}
	db := rawdb.NewMemoryDatabase()
	if _, err := genesis.Commit(db); err != nil {
		t.Fatalf("failed to commit the genesis: %v", err)
	}
	var (
		blocks []*types.Block
		parent = genesis.ToBlock()
	)
	for i := 1; i <= n; i++ {
		generated, _ := GenerateChain(cfg, parent, engine, db, 1, func(i int, b *BlockGen) {
			b.SetCoinbase(common.Address{0: byte(i)})
			b.SetExtra(make([]byte, 32+65)) // vanity and the seal that is filled in below
		})
		header := types.CopyHeader(generated[0].Header())
		signature, err := crypto.Sign(engine.EngineV1.SigHash(header).Bytes(), key)
		if err != nil {
			t.Fatalf("failed to sign block %d: %v", i, err)
		}
		copy(header.Extra[len(header.Extra)-65:], signature)
		parent = generated[0].WithSeal(header)
		blocks = append(blocks, parent)
	}
	return blocks
}

// TestReorgSignalsEpochSwitchOnIntermediateBlock pins the checkpoint signal of a reorg
// that promotes an epoch switch block as an intermediate. The import paths signal for
// the block they process - never for the blocks a reorg rewrites on the way to the head
// its caller adopts - so the staking loop in cmd/XDC used to be left on the previous
// epoch's parameters when the head jumped over the boundary, which is the shape a
// re-import of already stored blocks (the #2535 stall) produces.
func TestReorgSignalsEpochSwitchOnIntermediateBlock(t *testing.T) {
	// The fixture is an XDPoS chain that stays on v1, where IsEpochSwitch is decided by
	// the block number, with a small epoch so that the epoch switch block sits next to the
	// head. SkipV1Validation lets the deterministic generator produce blocks the faker
	// engine accepts, and Gap == 0 keeps the masternode-set refresh (UpdateM1, which needs
	// snapshots) out of the reorg, so this test exercises the checkpoint signal alone. The
	// mock config's v2 switch (block 900) is far above the seven blocks below and stays a
	// multiple of the epoch, which is what the config validation asks of it.
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
	blockchain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer blockchain.Stop()

	// Epoch blocks of this fixture are 3 and 6. Re-adopting block 7 over 5 and 6 crosses
	// block 6, and the adopted tip 7 is not an epoch switch block: the premise of the case
	// below, checked here so that a fixture change cannot turn the test into a no-op.
	blocks := makeSealedChain(t, cfg, genesis, engine, 7)
	if isEpochSwitch, err := blockchain.isEpochSwitchBlock(blocks[5]); err != nil || !isEpochSwitch {
		t.Fatalf("block 6 is not an epoch switch block: %v", err)
	}
	if isEpochSwitch, err := blockchain.isEpochSwitchBlock(blocks[6]); err != nil || isEpochSwitch {
		t.Fatalf("block 7 is an epoch switch block: %v", err)
	}
	if _, err := blockchain.InsertChain(blocks); err != nil {
		t.Fatalf("failed to insert the chain: %v", err)
	}
	if head := blockchain.CurrentBlock(); head.Number.Uint64() != 7 {
		t.Fatalf("head after the initial import: have %d, want 7", head.Number.Uint64())
	}
	// The import of blocks 3 and 6 signalled on its own, which is the behaviour the reorg
	// path has to match for the blocks only it touches.
	drainCheckpointCh()

	// Rewind the head markers to block 4 without touching the blocks themselves: 5, 6 and
	// 7 stay stored and executed, and a rollback leaves their canonical mappings in place,
	// which is what makes the adoption below a reorg over all of them.
	blockchain.Rollback([]common.Hash{blocks[4].Hash(), blocks[5].Hash(), blocks[6].Hash()})
	if head := blockchain.CurrentBlock(); head.Number.Uint64() != 4 {
		t.Fatalf("head after the rollback: have %d, want 4", head.Number.Uint64())
	}
	if len(CheckpointCh) != 0 {
		t.Fatal("the rollback signalled a checkpoint, the fixture is not silent before the adoption")
	}
	// Re-importing block 7 on its own is the shape the stored-prefix adoption of a
	// re-delivered batch produces: a known block above the head whose reorg rewrites the
	// stored blocks in between.
	if _, err := blockchain.InsertChain(types.Blocks{blocks[6]}); err != nil {
		t.Fatalf("failed to re-import the known block: %v", err)
	}
	if head := blockchain.CurrentBlock(); head.Number.Uint64() != 7 {
		t.Fatalf("head after the adoption: have %d, want 7", head.Number.Uint64())
	}
	if len(CheckpointCh) == 0 {
		t.Fatal("a reorg promoted epoch switch block 6 without signalling the staking loop")
	}
	drainCheckpointCh()
}
