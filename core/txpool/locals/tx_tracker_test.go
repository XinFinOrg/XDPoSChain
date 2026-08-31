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
	"github.com/XinFinOrg/XDPoSChain/rlp"
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
)

type testEnv struct {
	chain   *core.BlockChain
	pool    *txpool.TxPool
	tracker *TxTracker
	genDb   ethdb.Database
	signer  types.Signer
}

func newTestEnv(t *testing.T, n int, gasTip uint64, journal string) *testEnv {
	return newTestEnvWithConfig(t, n, gasTip, journal, params.TestChainConfig)
}

// newTestEnvWithConfig builds an environment around cfg. It builds its own
// genesis and signer instead of touching the package level ones, which the
// tests in this file share.
func newTestEnvWithConfig(t *testing.T, n int, gasTip uint64, journal string, cfg *params.ChainConfig) *testEnv {
	gspec := &core.Genesis{
		Config:  cfg,
		Alloc:   types.GenesisAlloc{address: {Balance: new(big.Int).Set(funds)}},
		BaseFee: big.NewInt(params.InitialBaseFee),
	}
	signer := types.LatestSigner(cfg)
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
		signer:  signer,
	}
}

// nonce returns the next nonce the test account can spend at the current head.
func (env *testEnv) nonce() uint64 {
	head := env.chain.CurrentHeader()
	state, _ := env.chain.StateAt(head.Root)
	return state.GetNonce(address)
}

// gasPrice returns a gas price the gas schedule of the current head admits.
func (env *testEnv) gasPrice() *big.Int {
	if baseFee := env.chain.CurrentHeader().BaseFee; baseFee != nil {
		return new(big.Int).Set(baseFee)
	}
	return big.NewInt(params.InitialBaseFee)
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
		tx, _ := types.SignTx(types.NewTransaction(nonce+uint64(i), common.Address{0x00}, big.NewInt(1000), params.TxGas, gasPrice, nil), env.signer, key)
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

// bumpedPrice returns the lowest gas price that clears the pool's price bump
// over price, the price a replacement has to carry to take a nonce from the
// transaction it replaces.
func bumpedPrice(price *big.Int) *big.Int {
	bumped := new(big.Int).Div(
		new(big.Int).Mul(price, big.NewInt(int64(100+legacypool.DefaultConfig.PriceBump))),
		big.NewInt(100))
	return bumped.Add(bumped, big.NewInt(1))
}

// replacementPair returns two transactions sharing a nonce: the one tracked
// first, and the one that replaces it. The replacement clears the pool's price
// bump, so the pair stands for the substitution the pool accepts; two equally
// priced transactions are not a substitution, the pool rejects them.
func replacementPair(env *testEnv) (replaced, replacement *types.Transaction) {
	nonce := env.nonce()
	mk := func(to common.Address, gasPrice *big.Int) *types.Transaction {
		tx, _ := types.SignTx(types.NewTransaction(nonce, to, big.NewInt(1000), params.TxGas, gasPrice, nil), env.signer, key)
		return tx
	}
	return mk(common.Address{0x00}, env.gasPrice()), mk(common.Address{0x01}, bumpedPrice(env.gasPrice()))
}

// writeReplacementJournal writes a journal holding two transactions that share
// a nonce, the way an older version could have left it behind: a transaction
// together with the one that replaced it, in the order selected by reverse.
func writeReplacementJournal(t *testing.T, reverse bool) (path string, replaced, replacement *types.Transaction) {
	t.Helper()

	env := newTestEnv(t, 10, 0, "")
	defer env.close()

	replaced, replacement = replacementPair(env)
	order := []*types.Transaction{replaced, replacement}
	if reverse {
		order = []*types.Transaction{replacement, replaced}
	}
	var journal []byte
	for _, tx := range order {
		blob, err := rlp.EncodeToBytes(tx)
		if err != nil {
			t.Fatalf("Failed to encode transaction: %v", err)
		}
		journal = append(journal, blob...)
	}
	path = filepath.Join(t.TempDir(), fmt.Sprintf("%d", rand.Int63()))
	if err := os.WriteFile(path, journal, 0o644); err != nil {
		t.Fatalf("Failed to write journal: %v", err)
	}
	return path, replaced, replacement
}

// TestTrackAllKeepsTransactionHeldByPool pins which transaction wins a nonce
// when the pool already holds one of them: the pool decides, because the order
// transactions reach TrackAll is not the order they were accepted in. Add
// tracks a local transaction only after SubPool.Add has released its lock, so
// a replacement can arrive here before the transaction it replaced.
func TestTrackAllKeepsTransactionHeldByPool(t *testing.T) {
	for _, tc := range []struct {
		name     string
		reversed bool
	}{
		{name: "pooled first"},
		{name: "replacement first", reversed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, 10, 0, "")
			defer env.close()

			pooled, replacement := replacementPair(env)
			if err := env.pool.Add([]*types.Transaction{pooled}, true)[0]; err != nil {
				t.Fatalf("failed to add the transaction the pool must hold: %v", err)
			}
			pair := []*types.Transaction{pooled, replacement}
			if tc.reversed {
				pair = []*types.Transaction{replacement, pooled}
			}
			env.tracker.TrackAll(pair)

			env.tracker.mu.Lock()
			defer env.tracker.mu.Unlock()

			if len(env.tracker.all) != 1 {
				t.Fatalf("tracked set must hold a single transaction, got %d", len(env.tracker.all))
			}
			if _, ok := env.tracker.all[pooled.Hash()]; !ok {
				t.Fatalf("the transaction the pool holds must stay tracked: %v", pooled.Hash())
			}
			if kept := env.tracker.byAddr[address].Get(pooled.Nonce()); kept == nil || kept.Hash() != pooled.Hash() {
				t.Fatalf("nonce %d must hold the pooled transaction, got %v", pooled.Nonce(), kept)
			}
		})
	}
}

// TestConcurrentReplacementKeepsPoolTransaction pins the tracker's view of two
// concurrent submissions for the same nonce: the original is added first and
// reaches the tracker last, the window AddLocal leaves between SubPool.Add
// releasing its lock and Track acquiring this one. The transaction the pool
// holds must win the nonce even though it is tracked last, or recheck would
// keep resubmitting the superseded one and the live one would lose the local
// resubmit protection entirely.
func TestConcurrentReplacementKeepsPoolTransaction(t *testing.T) {
	env := newTestEnv(t, 10, 0, "")
	defer env.close()

	nonce := env.nonce()
	price := env.gasPrice()
	mk := func(to common.Address, gasPrice *big.Int) *types.Transaction {
		tx, _ := types.SignTx(types.NewTransaction(nonce, to, big.NewInt(1000), params.TxGas, gasPrice, nil), env.signer, key)
		return tx
	}
	var (
		original    = mk(common.Address{0x00}, price)
		replacement = mk(common.Address{0x01}, bumpedPrice(price))
		added       = make(chan struct{})
		tracked     = make(chan struct{})
		finished    = make(chan error, 2)
	)
	go func() {
		err := env.pool.Add([]*types.Transaction{original}, true)[0]
		close(added)
		<-tracked
		env.tracker.Track(original)
		finished <- err
	}()
	go func() {
		<-added
		err := env.pool.Add([]*types.Transaction{replacement}, true)[0]
		env.tracker.Track(replacement)
		close(tracked)
		finished <- err
	}()
	for i := 0; i < 2; i++ {
		if err := <-finished; err != nil {
			t.Fatalf("failed to submit the transaction: %v", err)
		}
	}

	env.tracker.mu.Lock()
	defer env.tracker.mu.Unlock()

	if len(env.tracker.all) != 1 {
		t.Fatalf("tracked set must hold a single transaction, got %d", len(env.tracker.all))
	}
	if _, ok := env.tracker.all[replacement.Hash()]; !ok {
		t.Fatalf("the replacement the pool holds must stay tracked: %v", replacement.Hash())
	}
}

func TestTrackAllDropsReplacedTransaction(t *testing.T) {
	env := newTestEnv(t, 10, 0, "")
	defer env.close()

	replaced, replacement := replacementPair(env)
	env.tracker.TrackAll([]*types.Transaction{replaced, replacement})

	env.tracker.mu.Lock()
	defer env.tracker.mu.Unlock()

	if len(env.tracker.all) != 1 {
		t.Fatalf("replaced transaction must be dropped: tracking %d", len(env.tracker.all))
	}
	if _, ok := env.tracker.all[replaced.Hash()]; ok {
		t.Fatalf("replaced transaction still tracked: %v", replaced.Hash())
	}
	kept := env.tracker.byAddr[address].Get(replacement.Nonce())
	if kept == nil || kept.Hash() != replacement.Hash() {
		t.Fatalf("nonce %d must hold the replacement, got %v", replacement.Nonce(), kept)
	}
}

func TestRecheckDoesNotResubmitReplacedTransaction(t *testing.T) {
	env := newTestEnv(t, 10, 0, "")
	defer env.close()

	replaced, replacement := replacementPair(env)
	env.tracker.TrackAll([]*types.Transaction{replaced, replacement})

	resubmits := env.tracker.recheck(false)
	if len(resubmits) != 1 || resubmits[0].Hash() != replacement.Hash() {
		t.Fatalf("unexpected transactions to resubmit: %v", resubmits)
	}
}

func TestJournalRotationDropsReplacedTransaction(t *testing.T) {
	journalPath := filepath.Join(t.TempDir(), fmt.Sprintf("%d", rand.Int63()))
	env := newTestEnv(t, 10, 0, journalPath)
	defer env.close()

	if err := env.tracker.Start(); err != nil {
		t.Fatalf("Failed to start tracker: %v", err)
	}
	defer env.tracker.Stop()

	replaced, replacement := replacementPair(env)
	env.tracker.TrackAll([]*types.Transaction{replaced, replacement})

	// Rotate the journal from the tracked set: the replaced transaction has
	// been dropped from it and must not come back.
	env.tracker.recheck(true)

	reloaded := New(journalPath, time.Minute, params.TestChainConfig, env.pool)
	if err := reloaded.journal.load(func(transactions []*types.Transaction) []error {
		reloaded.TrackAll(transactions)
		return nil
	}); err != nil {
		t.Fatalf("Failed to load journal: %v", err)
	}

	reloaded.mu.Lock()
	defer reloaded.mu.Unlock()

	if len(reloaded.all) != 1 {
		t.Fatalf("rotated journal must hold a single transaction, got %d", len(reloaded.all))
	}
	if _, ok := reloaded.all[replacement.Hash()]; !ok {
		t.Fatalf("rotated journal must hold the replacement: %v", replacement.Hash())
	}
}

func TestJournalLoadDropsReplacedTransaction(t *testing.T) {
	journalPath, _, replacement := writeReplacementJournal(t, false)
	env := newTestEnv(t, 10, 0, journalPath)
	defer env.close()

	if err := env.tracker.Start(); err != nil {
		t.Fatalf("Failed to start tracker: %v", err)
	}
	defer env.tracker.Stop()

	env.tracker.mu.Lock()
	defer env.tracker.mu.Unlock()

	if len(env.tracker.all) != 1 {
		t.Fatalf("loading must leave a single transaction, got %d", len(env.tracker.all))
	}
	if _, ok := env.tracker.all[replacement.Hash()]; !ok {
		t.Fatalf("the replacement must survive the load: %v", replacement.Hash())
	}
}

// TestJournalLoadKeepsReplacementPerNonce pins the load path for the reverse
// file order. A journal entry carries no timestamp or sequence number, so an
// older rotation could have written the transaction the user replaced after
// its replacement. Load feeds the file straight into TrackAll, which decides
// the nonce the way the pool would, so the replacement survives whatever order
// the entries come back in.
func TestJournalLoadKeepsReplacementPerNonce(t *testing.T) {
	journalPath, _, replacement := writeReplacementJournal(t, true)
	env := newTestEnv(t, 10, 0, journalPath)
	defer env.close()

	if err := env.tracker.Start(); err != nil {
		t.Fatalf("Failed to start tracker: %v", err)
	}
	defer env.tracker.Stop()

	env.tracker.mu.Lock()
	defer env.tracker.mu.Unlock()

	if len(env.tracker.all) != 1 {
		t.Fatalf("loading must leave a single transaction, got %d", len(env.tracker.all))
	}
	if _, ok := env.tracker.all[replacement.Hash()]; !ok {
		t.Fatalf("the replacement must survive the load whatever the file order is: %v", replacement.Hash())
	}
}

// TestTrackAllKeepsTransactionAcceptedByPool pins the case a dearer tracked
// transaction must not win: the pool accepted this one, so it holds the nonce.
// The dearer one is what an older version journalled after the pool rejected it
// as retryable, and resubmitting it would evict a transaction the user just
// submitted successfully.
func TestTrackAllKeepsTransactionAcceptedByPool(t *testing.T) {
	env := newTestEnv(t, 10, 0, "")
	defer env.close()

	nonce := env.nonce()
	mk := func(to common.Address, gasPrice *big.Int) *types.Transaction {
		tx, _ := types.SignTx(types.NewTransaction(nonce, to, big.NewInt(1000), params.TxGas, gasPrice, nil), env.signer, key)
		return tx
	}
	tracked := mk(common.Address{0x00}, new(big.Int).Mul(env.gasPrice(), big.NewInt(4)))
	accepted := mk(common.Address{0x01}, env.gasPrice())

	env.tracker.Track(tracked)
	if err := env.pool.Add([]*types.Transaction{accepted}, true)[0]; err != nil {
		t.Fatalf("failed to add the transaction the pool must accept: %v", err)
	}
	env.tracker.Track(accepted)

	env.tracker.mu.Lock()
	defer env.tracker.mu.Unlock()

	if len(env.tracker.all) != 1 {
		t.Fatalf("tracked set must hold a single transaction, got %d", len(env.tracker.all))
	}
	if _, ok := env.tracker.all[accepted.Hash()]; !ok {
		t.Fatalf("the transaction the pool accepted must stay tracked: %v", accepted.Hash())
	}
}

// TestTrackAllKeepsReplacementWhenPoolHoldsNeither pins the fallback for two
// transactions the pool has discarded, seen in the order a replacement can
// reach the tracker in: the replacement first, the transaction it replaces
// last. Keeping the replacement is what stops recheck from resubmitting a
// transaction the user already superseded.
//
// This exercises the fallback rule directly rather than the race that reaches
// it: the concurrent interleaving is pinned by
// TestConcurrentReplacementKeepsPoolTransaction, and the pool-discards-both
// state needs no fork to construct.
func TestTrackAllKeepsReplacementWhenPoolHoldsNeither(t *testing.T) {
	env := newTestEnv(t, 10, 0, "")
	defer env.close()

	replaced, replacement := replacementPair(env)
	// Neither is submitted to the pool: what is left once the pool discards
	// both, and the only state the fallback can be decided on.
	env.tracker.Track(replacement)
	env.tracker.Track(replaced)

	env.tracker.mu.Lock()
	defer env.tracker.mu.Unlock()

	if len(env.tracker.all) != 1 {
		t.Fatalf("tracked set must hold a single transaction, got %d", len(env.tracker.all))
	}
	if _, ok := env.tracker.all[replacement.Hash()]; !ok {
		t.Fatalf("the replacement must stay tracked: %v", replacement.Hash())
	}
	if kept := env.tracker.byAddr[address].Get(replacement.Nonce()); kept == nil || kept.Hash() != replacement.Hash() {
		t.Fatalf("nonce %d must hold the replacement, got %v", replacement.Nonce(), kept)
	}
}

// TestTrackAllKeepsTrackedSpecialTransaction pins the exemption that mirrors
// the pool: a regular transaction must not evict a pending special one, so a
// dearer regular transaction must not take the nonce of a tracked special one.
func TestTrackAllKeepsTrackedSpecialTransaction(t *testing.T) {
	env := newTestEnv(t, 10, 0, "")
	defer env.close()

	nonce := env.nonce()
	special, _ := types.SignTx(types.NewTransaction(nonce, common.BlockSignersBinary, big.NewInt(0), params.TxGas, common.Big0, nil), env.signer, key)
	regular, _ := types.SignTx(types.NewTransaction(nonce, common.Address{0x00}, big.NewInt(1000), params.TxGas, bumpedPrice(env.gasPrice()), nil), env.signer, key)

	env.tracker.Track(special)
	env.tracker.Track(regular)

	env.tracker.mu.Lock()
	defer env.tracker.mu.Unlock()

	if len(env.tracker.all) != 1 || env.tracker.all[special.Hash()] == nil {
		t.Fatalf("the special transaction must stay tracked: %v", env.tracker.all)
	}
}

// TestTrackAllLetsSpecialTransactionReplace pins the other half: a special
// transaction always claims its nonce, so it takes it from a dearer tracked
// transaction, exactly as it does in the pool.
func TestTrackAllLetsSpecialTransactionReplace(t *testing.T) {
	env := newTestEnv(t, 10, 0, "")
	defer env.close()

	nonce := env.nonce()
	regular, _ := types.SignTx(types.NewTransaction(nonce, common.Address{0x00}, big.NewInt(1000), params.TxGas, bumpedPrice(env.gasPrice()), nil), env.signer, key)
	special, _ := types.SignTx(types.NewTransaction(nonce, common.BlockSignersBinary, big.NewInt(0), params.TxGas, common.Big0, nil), env.signer, key)

	env.tracker.Track(regular)
	env.tracker.Track(special)

	env.tracker.mu.Lock()
	defer env.tracker.mu.Unlock()

	if len(env.tracker.all) != 1 || env.tracker.all[special.Hash()] == nil {
		t.Fatalf("the special transaction must replace the tracked one: %v", env.tracker.all)
	}
}

// TestTrackAllKeepsFirstTransactionAtEqualPrice pins the tie: equally priced
// transactions are not a substitution, the pool rejects the later one, so the
// transaction already tracked keeps the nonce.
func TestTrackAllKeepsFirstTransactionAtEqualPrice(t *testing.T) {
	env := newTestEnv(t, 10, 0, "")
	defer env.close()

	nonce := env.nonce()
	mk := func(to common.Address) *types.Transaction {
		tx, _ := types.SignTx(types.NewTransaction(nonce, to, big.NewInt(1000), params.TxGas, env.gasPrice(), nil), env.signer, key)
		return tx
	}
	first, second := mk(common.Address{0x00}), mk(common.Address{0x01})

	env.tracker.TrackAll([]*types.Transaction{first, second})

	env.tracker.mu.Lock()
	defer env.tracker.mu.Unlock()

	if len(env.tracker.all) != 1 || env.tracker.all[first.Hash()] == nil {
		t.Fatalf("the first of two equally priced transactions must stay tracked: %v", env.tracker.all)
	}
}

func TestRecheckHoldsBackBelowFloorTransactions(t *testing.T) {
	// Push the gas tier fork past the test chain so the floor resolves to the
	// baseline tier: params.TestChainConfig schedules Gas50x at block 0, which
	// would put the floor at 50x from genesis on. The field cannot be cleared
	// instead, CheckConfigForkOrder requires it. Gas2500xBlock stays nil, which
	// CheckConfigForkOrder accepts; the assignment states it explicitly.
	cfg := *params.TestChainConfig
	cfg.Gas50xBlock = big.NewInt(1000)
	cfg.Gas2500xBlock = nil

	env := newTestEnvWithConfig(t, 1, 0, "", &cfg)
	defer env.close()

	floor := big.NewInt(common.DefaultMinGasPrice)
	nonce := env.nonce()
	mk := func(n uint64, gasPrice *big.Int) *types.Transaction {
		tx, _ := types.SignTx(types.NewTransaction(n, common.Address{0x00}, big.NewInt(1000), params.TxGas, gasPrice, nil), env.signer, key)
		return tx
	}
	// Priced at the floor and one wei below it: the comparison is
	// GasPriceIntCmp(floor) < 0, so only the latter is held back.
	atFloor := mk(nonce, floor)
	belowFloor := mk(nonce+1, new(big.Int).Sub(floor, big.NewInt(1)))

	env.tracker.TrackAll([]*types.Transaction{atFloor, belowFloor})

	resubmits := env.tracker.recheck(false)
	if len(resubmits) != 1 || resubmits[0].Hash() != atFloor.Hash() {
		t.Fatalf("unexpected transactions to resubmit: %v", resubmits)
	}
	// Held back, not dropped: it stays tracked so a lower floor picks it up.
	if len(env.tracker.all) != 2 {
		t.Fatalf("below-floor transaction must stay tracked, got %d", len(env.tracker.all))
	}
}

func TestRecheckResumesAfterFloorDrops(t *testing.T) {
	cfg := *params.TestChainConfig
	cfg.Gas50xBlock = big.NewInt(5)

	env := newTestEnvWithConfig(t, 10, 0, "", &cfg)
	defer env.close()

	// head=10, so the floor resolves at block 11: the 50x tier is active and a
	// baseline-priced transaction is held back.
	tx, _ := types.SignTx(types.NewTransaction(
		env.nonce(), common.Address{0x00}, big.NewInt(1000), params.TxGas,
		big.NewInt(common.DefaultMinGasPrice), nil), env.signer, key)

	env.tracker.Track(tx)
	if resubmits := env.tracker.recheck(false); len(resubmits) != 0 {
		t.Fatalf("transaction below the floor must not be resubmitted: %v", resubmits)
	}
	if len(env.tracker.all) != 1 {
		t.Fatalf("transaction below the floor must stay tracked, got %d", len(env.tracker.all))
	}

	// Roll the head back before the fork: the floor drops to the baseline tier,
	// which is exactly the transaction's price, so it is let through. recheck
	// only filters on Forward(pool.Nonce(sender)), which leaves nonce 10 alone
	// now that the state nonce has fallen back to 3.
	if err := env.chain.SetHead(3); err != nil {
		t.Fatalf("failed to roll back the chain: %v", err)
	}
	if err := env.pool.Sync(); err != nil {
		t.Fatalf("failed to sync the txpool: %v", err)
	}

	resubmits := env.tracker.recheck(false)
	if len(resubmits) != 1 || resubmits[0].Hash() != tx.Hash() {
		t.Fatalf("transaction must be resubmitted once the floor drops: %v", resubmits)
	}
}

// TestRecheckResubmitsSpecialTransactionBelowFloor pins the exemption that keeps
// recheck aligned with admission: special transactions are not priced against
// the floor there either, so a gas tier fork must not strand the ones submitted
// locally, which is what the tracker exists to guard.
func TestRecheckResubmitsSpecialTransactionBelowFloor(t *testing.T) {
	cfg := *params.TestChainConfig
	cfg.Gas50xBlock = big.NewInt(5)

	env := newTestEnvWithConfig(t, 10, 0, "", &cfg)
	defer env.close()

	// head=10, so the floor resolves at block 11 on the 50x tier. The
	// transaction is priced at the baseline tier, which a plain transaction
	// would be held back for.
	tx, _ := types.SignTx(types.NewTransaction(
		env.nonce(), common.BlockSignersBinary, big.NewInt(0), params.TxGas,
		big.NewInt(common.DefaultMinGasPrice), nil), env.signer, key)

	env.tracker.Track(tx)

	resubmits := env.tracker.recheck(false)
	if len(resubmits) != 1 || resubmits[0].Hash() != tx.Hash() {
		t.Fatalf("special transaction below the floor must still be resubmitted: %v", resubmits)
	}
}
