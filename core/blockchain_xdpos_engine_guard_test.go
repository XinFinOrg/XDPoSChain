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

	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// newNonXDPoSInsertChain returns an ethash chain whose config names XDPoS while
// its engine does not. That is the combination the checkpoint notification used
// to dereference a nil engine with. The epoch and gap are chosen so that no
// returned block is a gap block: the masternode refresh a gap block triggers is
// a separate defect and would end the process before the notification is
// reached, which would make the cases below fail for the wrong reason.
func newNonXDPoSInsertChain(t *testing.T, count int) (*BlockChain, []*types.Block) {
	t.Helper()

	engine := ethash.NewFaker()
	genesis := &Genesis{
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.AllEthashProtocolChanges,
	}
	db := rawdb.NewMemoryDatabase()
	chain, err := NewBlockChain(db, &CacheConfig{TrieDirtyDisabled: true}, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create the chain: %v", err)
	}
	t.Cleanup(chain.Stop)

	blocks, _ := GenerateChain(genesis.Config, chain.Genesis(), engine, db, count, nil)
	if len(blocks) != count {
		t.Fatalf("generated %d blocks, want %d", len(blocks), count)
	}
	cfg := params.AllEthashProtocolChanges.Clone()
	cfg.XDPoS = &params.XDPoSConfig{Epoch: 10, Gap: 4, V2: &params.V2{SwitchBlock: big.NewInt(1)}}
	chain.SetChainConfig(cfg)
	for _, block := range blocks {
		if block.NumberU64()%cfg.XDPoS.Epoch == cfg.XDPoS.Epoch-cfg.XDPoS.Gap {
			t.Fatalf("block %d is a gap block, adjust the epoch and gap of this case", block.NumberU64())
		}
	}
	return chain, blocks
}

// insertWithin runs the insertion in its own goroutine so that an insertion
// still sending on the unbuffered CheckpointCh, which has no receiver here,
// fails the case in 30s instead of hanging until the package timeout.
//
// The fuse rests on that unbuffered channel: a notification sent to nobody
// blocks forever. Once PR #2566 replaces the send with the bounded
// core.SignalCheckpoint(), a spurious notification returns at once and this
// stops proving that nothing was sent, and the cases need a receiver that
// asserts the absence of a message instead.
func insertWithin(t *testing.T, insert func() error) {
	t.Helper()

	done := make(chan error, 1)
	go func() { done <- insert() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("insertion failed: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the insertion did not return: the checkpoint notification blocked with no receiver")
	}
}

// TestInsertChainSkipsXDPoSCheckpointNotifyForNonXDPoSEngine pins that the
// downloader path imports a chain whose config names XDPoS but whose engine is
// ethash, without dereferencing a nil XDPoS engine and without blocking on a
// notification such an engine would never need.
//
// Coverage note: the two cases below pin one direction only, that a chain whose
// config names XDPoS while its engine is not imports its blocks and attempts no
// notification. A guard that skipped the notification for every engine would
// pass both, and nothing else in the tree covers that direction: the
// CheckpointCh consumers under consensus/tests only drain the channel. Pinning
// it takes a chain that reaches an epoch switch block on a real XDPoS engine,
// which means crossing a gap block and producing signed blocks, so it is left
// out of this pair deliberately.
func TestInsertChainSkipsXDPoSCheckpointNotifyForNonXDPoSEngine(t *testing.T) {
	chain, blocks := newNonXDPoSInsertChain(t, 3)

	insertWithin(t, func() error {
		if _, err := chain.InsertChain(blocks); err != nil {
			return err
		}
		return nil
	})
	if got, want := chain.CurrentBlock().Hash(), blocks[len(blocks)-1].Hash(); got != want {
		t.Fatalf("head is %s after the insertion, want %s", got, want)
	}
}

// TestInsertBlockSkipsXDPoSCheckpointNotifyForNonXDPoSEngine is the fetcher
// path counterpart of the case above.
func TestInsertBlockSkipsXDPoSCheckpointNotifyForNonXDPoSEngine(t *testing.T) {
	chain, blocks := newNonXDPoSInsertChain(t, 1)

	insertWithin(t, func() error {
		_, _, err := chain.insertBlock(blocks[0])
		return err
	})
	if got, want := chain.CurrentBlock().Hash(), blocks[0].Hash(); got != want {
		t.Fatalf("head is %s after the insertion, want %s", got, want)
	}
}
