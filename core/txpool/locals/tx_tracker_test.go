// Copyright 2025 The go-ethereum Authors
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

package locals

import (
	"fmt"
	"maps"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/txpool"
	"github.com/XinFinOrg/XDPoSChain/core/txpool/legacypool"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
)

var (
	key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	address = crypto.PubkeyToAddress(key.PublicKey)
	funds   = big.NewInt(1000000000000000000)
	gspec   = &core.Genesis{
		Config: params.TestChainConfig,
		Alloc: types.GenesisAlloc{
			address: {Balance: funds},
		},
		BaseFee: big.NewInt(params.InitialBaseFee),
	}
	signer = types.LatestSigner(gspec.Config)
)

type testEnv struct {
	chain   *core.BlockChain
	pool    *txpool.TxPool
	tracker *TxTracker
	genDb   ethdb.Database
}

func newTestEnv(t *testing.T, n int, gasTip uint64, journal string) *testEnv {
	genDb, blocks, _ := core.GenerateChainWithGenesis(gspec, ethash.NewFaker(), n, func(i int, gen *core.BlockGen) {
		gasPrice := big.NewInt(params.InitialBaseFee)
		if baseFee := gen.BaseFee(); baseFee != nil {
			gasPrice = new(big.Int).Set(baseFee)
		}
		tx, err := types.SignTx(types.NewTransaction(gen.TxNonce(address), common.Address{0x00}, big.NewInt(1000), params.TxGas, gasPrice, nil), signer, key)
		if err != nil {
			panic(err)
		}
		gen.AddTx(tx)
	})

	db := rawdb.NewMemoryDatabase()
	chain, err := core.NewBlockChain(db, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}

	legacyPool := legacypool.New(legacypool.DefaultConfig, chain)
	pool, err := txpool.New(gasTip, chain, []txpool.SubPool{legacyPool})
	if err != nil {
		t.Fatalf("Failed to create tx pool: %v", err)
	}
	if n, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("Failed to process block %d: %v", n, err)
	}
	if err := pool.Sync(); err != nil {
		t.Fatalf("Failed to sync the txpool, %v", err)
	}
	return &testEnv{
		chain:   chain,
		pool:    pool,
		tracker: New(journal, time.Minute, gspec.Config, pool),
		genDb:   genDb,
	}
}

func (env *testEnv) close() {
	if err := env.pool.Close(); err != nil {
		panic(fmt.Sprintf("failed to close tx pool: %v", err))
	}
	env.chain.Stop()
}

func (env *testEnv) makeTxs(n int) []*types.Transaction {
	head := env.chain.CurrentHeader()
	state, _ := env.chain.StateAt(head.Root)
	nonce := state.GetNonce(address)
	gasPrice := big.NewInt(params.InitialBaseFee)
	if head.BaseFee != nil {
		gasPrice = new(big.Int).Set(head.BaseFee)
	}

	var txs []*types.Transaction
	for i := 0; i < n; i++ {
		tx, _ := types.SignTx(types.NewTransaction(nonce+uint64(i), common.Address{0x00}, big.NewInt(1000), params.TxGas, gasPrice, nil), signer, key)
		txs = append(txs, tx)
	}
	return txs
}

func TestResubmit(t *testing.T) {
	env := newTestEnv(t, 10, 0, "")
	defer env.close()

	txs := env.makeTxs(10)
	txsA := txs[:len(txs)/2]
	txsB := txs[len(txs)/2:]
	env.pool.Add(txsA, true)

	pending, queued := env.pool.ContentFrom(address)
	if len(pending) != len(txsA) || len(queued) != 0 {
		t.Fatalf("Unexpected txpool content: %d, %d", len(pending), len(queued))
	}
	env.tracker.TrackAll(txs)

	resubmit := env.tracker.recheck(false)
	if len(resubmit) != len(txsB) {
		t.Fatalf("Unexpected transactions to resubmit, got: %d, want: %d", len(resubmit), len(txsB))
	}
	env.tracker.mu.Lock()
	allCopy := maps.Clone(env.tracker.all)
	env.tracker.mu.Unlock()

	if len(allCopy) != len(txs) {
		t.Fatalf("Unexpected transactions being tracked, got: %d, want: %d", len(allCopy), len(txs))
	}
}

func TestJournal(t *testing.T) {
	journalPath := filepath.Join(t.TempDir(), fmt.Sprintf("%d", rand.Int63()))
	env := newTestEnv(t, 10, 0, journalPath)
	defer env.close()

	if err := env.tracker.Start(); err != nil {
		t.Fatalf("Failed to start tracker: %v", err)
	}

	txs := env.makeTxs(10)
	txsA := txs[:len(txs)/2]
	txsB := txs[len(txs)/2:]
	env.pool.Add(txsA, true)

	pending, queued := env.pool.ContentFrom(address)
	if len(pending) != len(txsA) || len(queued) != 0 {
		t.Fatalf("Unexpected txpool content: %d, %d", len(pending), len(queued))
	}
	env.tracker.TrackAll(txsA)
	env.tracker.TrackAll(txsB)
	env.tracker.Stop()

	// Make sure all the transactions are properly journalled
	trackerB := New(journalPath, time.Minute, gspec.Config, env.pool)
	if err := trackerB.journal.load(func(transactions []*types.Transaction) []error {
		trackerB.TrackAll(transactions)
		return nil
	}); err != nil {
		t.Fatalf("Failed to load journal: %v", err)
	}

	trackerB.mu.Lock()
	allCopy := maps.Clone(trackerB.all)
	trackerB.mu.Unlock()

	if len(allCopy) != len(txs) {
		t.Fatalf("Unexpected transactions being tracked, got: %d, want: %d", len(allCopy), len(txs))
	}
}

func TestStartInitializesJournalWriter(t *testing.T) {
	journalPath := filepath.Join(t.TempDir(), fmt.Sprintf("%d", rand.Int63()))
	env := newTestEnv(t, 10, 0, journalPath)
	defer env.close()

	if err := env.tracker.Start(); err != nil {
		t.Fatalf("Failed to start tracker: %v", err)
	}
	defer env.tracker.Stop()

	if env.tracker.journal == nil {
		t.Fatal("Journal should be configured")
	}
	if env.tracker.journal.writer == nil {
		t.Fatal("Journal writer should be initialized before Start returns")
	}
}

func TestStartContinuesOnCorruptedJournal(t *testing.T) {
	journalPath := filepath.Join(t.TempDir(), fmt.Sprintf("%d", rand.Int63()))
	if err := os.WriteFile(journalPath, []byte{0xff, 0x00, 0x01}, 0o644); err != nil {
		t.Fatalf("Failed to create corrupted journal: %v", err)
	}
	env := newTestEnv(t, 10, 0, journalPath)
	defer env.close()

	if err := env.tracker.Start(); err != nil {
		t.Fatalf("Start should continue when journal load fails, got: %v", err)
	}
	defer env.tracker.Stop()

	if env.tracker.journal.writer == nil {
		t.Fatal("Journal writer should be initialized even if journal load fails")
	}
}
