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
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// makeSealedPrefixAndFork builds a sealed chain of n blocks from genesis plus m sealed blocks
// forked off its block number forkAt, both in one database. The database has to be the one the
// generator built the prefix on: the state a generated block needs lives there, and the
// chain's own database does not hold it in a form GenerateChain can read. Sealing matches
// makeSealedChain, and the fork's blocks carry a coinbase the prefix never uses so that the
// two branches stay distinct.
func makeSealedPrefixAndFork(t *testing.T, cfg *params.ChainConfig, genesis *Genesis, engine *XDPoS.XDPoS, n, forkAt, m int) (prefix, fork []*types.Block) {
	t.Helper()
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to parse the signer key: %v", err)
	}
	db := rawdb.NewMemoryDatabase()
	if _, err := genesis.Commit(db); err != nil {
		t.Fatalf("failed to commit the genesis: %v", err)
	}
	seal := func(parent *types.Block, coinbase common.Address) *types.Block {
		generated, _ := GenerateChain(cfg, parent, engine, db, 1, func(i int, b *BlockGen) {
			b.SetCoinbase(coinbase)
			b.SetExtra(make([]byte, 32+65)) // vanity and the seal that is filled in below
		})
		header := types.CopyHeader(generated[0].Header())
		signature, err := crypto.Sign(engine.EngineV1.SigHash(header).Bytes(), key)
		if err != nil {
			t.Fatalf("failed to sign block %d: %v", parent.NumberU64()+1, err)
		}
		copy(header.Extra[len(header.Extra)-65:], signature)
		return generated[0].WithSeal(header)
	}
	parent := genesis.ToBlock()
	for i := 1; i <= n; i++ {
		parent = seal(parent, common.Address{0: byte(i)})
		prefix = append(prefix, parent)
	}
	parent = prefix[forkAt-1]
	for i := 1; i <= m; i++ {
		parent = seal(parent, common.Address{0: 0xf0, 1: byte(i)})
		fork = append(fork, parent)
	}
	return prefix, fork
}

// TestReorgSignalsEpochSwitchOnIntermediateBlock pins the checkpoint signal of a reorg
// that promotes an epoch switch block as an intermediate. The import paths signal for
// the block they process - never for the blocks a reorg rewrites on the way to the head
// its caller adopts - so the staking loop in cmd/XDC used to be left on the previous
// epoch's parameters when the head jumped over the boundary, which is the shape a
// re-import of already stored blocks (the #2535 stall) produces.
//
// The reorg is raised by a side chain that grows past the head rather than by re-adopting a
// stored block, which keeps the case's coverage independent of the known-block adoption
// path: the promotion that has to signal is the one no import ever processes.
func TestReorgSignalsEpochSwitchOnIntermediateBlock(t *testing.T) {
	signals := observeCheckpointSignals()
	defer signals.stop()

	// The fixture is an XDPoS chain that stays on v1, where IsEpochSwitch is decided by
	// the block number, with a small epoch so that the epoch switch block sits next to the
	// head. SkipV1Validation lets the deterministic generator produce blocks the faker
	// engine accepts, and Gap == 0 keeps the masternode-set refresh (UpdateM1, which needs
	// snapshots) out of the reorg, so this test exercises the checkpoint signal alone. The
	// mock config's v2 switch (block 900) is far above the blocks below and stays a
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

	// Epoch blocks of this fixture are 3 and 6. The stored chain stops at 7, and the side
	// chain grows to 8, whose own height is not an epoch switch block: the case below needs
	// the promoted epoch switch to be an intermediate rather than the adopted head, and
	// every premise is checked here so that a fixture change cannot turn the test into a
	// no-op.
	blocks, side := makeSealedPrefixAndFork(t, cfg, genesis, engine, 7, 4, 4)
	if isEpochSwitch, err := blockchain.isEpochSwitchBlock(blocks[5]); err != nil || !isEpochSwitch {
		t.Fatalf("block 6 is not an epoch switch block: %v", err)
	}
	if isEpochSwitch, err := blockchain.isEpochSwitchBlock(blocks[6]); err != nil || isEpochSwitch {
		t.Fatalf("block 7 is not an epoch switch block: %v", err)
	}
	if isEpochSwitch, err := blockchain.isEpochSwitchBlock(side[1]); err != nil || !isEpochSwitch {
		t.Fatalf("side block 6 is not an epoch switch block: %v", err)
	}
	if isEpochSwitch, err := blockchain.isEpochSwitchBlock(side[3]); err != nil || isEpochSwitch {
		t.Fatalf("side block 8 is not an epoch switch block: %v", err)
	}
	if _, err := blockchain.InsertChain(blocks); err != nil {
		t.Fatalf("failed to insert the chain: %v", err)
	}
	if head := blockchain.CurrentBlock(); head.Number.Uint64() != 7 {
		t.Fatalf("head after the initial import: have %d, want 7", head.Number.Uint64())
	}
	// The import of blocks 3 and 6 signalled on its own, which is the behaviour the reorg
	// path has to match for the blocks only it touches. Drop them, and wait out the quiet so
	// that a signal still on its way cannot be read as the reorg's.
	signals.drain(100 * time.Millisecond)

	// The first three blocks of the side chain are lighter than the head, so they are stored
	// as a side chain and the head stays at 7 - the import signals for the epoch switch block
	// 6 while it is still a side chain, which is that signal spent.
	if _, err := blockchain.InsertChain(side[:3]); err != nil {
		t.Fatalf("failed to insert the side chain: %v", err)
	}
	if head := blockchain.CurrentBlock(); head.Number.Uint64() != 7 {
		t.Fatalf("head after the side chain: have %d, want 7", head.Number.Uint64())
	}
	signals.drain(100 * time.Millisecond)

	// Block 8 makes the side chain heavier than the head, so importing it reorgs onto it. The
	// import only ever processes block 8, which is not an epoch switch block: the block that
	// has to signal here is 6, promoted as an intermediate of the reorg.
	if _, err := blockchain.InsertChain(side[3:]); err != nil {
		t.Fatalf("failed to insert the block that reorgs onto the side chain: %v", err)
	}
	if head := blockchain.CurrentBlock(); head.Number.Uint64() != 8 {
		t.Fatalf("head after the reorg: have %d, want 8", head.Number.Uint64())
	}
	if !signals.waitFor(1, 10*time.Second) {
		t.Fatal("a reorg promoted epoch switch block 6 without signalling the staking loop")
	}
}
