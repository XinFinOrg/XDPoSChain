package core

import (
	"crypto/ecdsa"
	"math/big"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// newReorgLogGenesis is the genesis the reorg-log tests share: a funded signer and a contract
// whose runtime code emits one anonymous log per call (PUSH1 0x00, PUSH1 0x00, LOG0, STOP).
func newReorgLogGenesis(t *testing.T) (*ecdsa.PrivateKey, common.Address, *Genesis) {
	t.Helper()

	key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	address := crypto.PubkeyToAddress(key.PublicKey)
	emitter := common.HexToAddress("0x0000000000000000000000000000000000000010")
	return key, emitter, &Genesis{
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
}

// newReorgLogChains builds two chains from genesis whose blocks each carry one log
// transaction. The fork's transactions use a disjoint transfer-amount range (base 0 vs 100)
// so they hash differently from the canonical ones despite sharing the same nonces.
func newReorgLogChains(t *testing.T, canonicalN, forkN int) (types.Blocks, types.Blocks, *BlockChain, *Genesis, *ethash.Ethash) {
	t.Helper()

	key, emitter, gspec := newReorgLogGenesis(t)
	engine := ethash.NewFaker()
	genDb := rawdb.NewMemoryDatabase()
	if _, err := gspec.Commit(genDb); err != nil {
		t.Fatalf("failed to commit genesis: %v", err)
	}
	emit := func(base uint64) func(int, *BlockGen) {
		return func(i int, b *BlockGen) {
			tx, err := types.SignTx(types.NewTransaction(uint64(i), emitter, big.NewInt(int64(base)+int64(i)+1), 100000, big.NewInt(1), nil), types.HomesteadSigner{}, key)
			if err != nil {
				t.Fatalf("failed to sign log transaction: %v", err)
			}
			b.AddTx(tx)
		}
	}
	bc, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	canonical, _ := GenerateChain(gspec.Config, bc.Genesis(), engine, genDb, canonicalN, emit(0))
	fork, _ := GenerateChain(gspec.Config, bc.Genesis(), engine, genDb, forkN, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{0: 0x02})
		emit(100)(i, b)
	})
	return canonical, fork, bc, gspec, engine
}

// TestReorgPublishesLogsAfterIndexes pins XDC-26: the removed logs are handed to
// subscribers only once the head they describe is the one the node serves.
func TestReorgPublishesLogsAfterIndexes(t *testing.T) {
	canonical, fork, bc, _, _ := newReorgLogChains(t, 4, 5)
	defer bc.Stop()
	if _, err := bc.InsertChain(canonical); err != nil {
		t.Fatalf("failed to insert canonical chain: %v", err)
	}

	removedCh := make(chan RemovedLogsEvent)
	holdCh := make(chan RemovedLogsEvent)
	rebornCh := make(chan []*types.Log)
	removedSub := bc.SubscribeRemovedLogsEvent(removedCh)
	defer removedSub.Unsubscribe()
	holdSub := bc.SubscribeRemovedLogsEvent(holdCh)
	defer holdSub.Unsubscribe()
	rebornSub := bc.SubscribeLogsEvent(rebornCh)
	// Drain independently of the observation below so InsertChain's synchronous log
	// sends complete even when the removed batch never arrives.
	rebornStop := make(chan struct{})
	rebornDone := make(chan struct{})
	go func() {
		defer close(rebornDone)
		for {
			select {
			case <-rebornCh:
			case <-rebornStop:
				return
			}
		}
	}()
	defer func() {
		rebornSub.Unsubscribe()
		close(rebornStop)
		<-rebornDone
	}()

	type observation struct {
		removedCount  int
		headAtRemoved common.Hash
		canonicalAt4  common.Hash
		oldTxVisible  bool
		lookupBlocked bool
	}
	observerStop := make(chan struct{})
	observerDone := make(chan struct{})
	got := make(chan observation, 1)
	go func() {
		defer close(observerDone)
		var ev RemovedLogsEvent
		select {
		case e, ok := <-removedCh:
			if !ok {
				return
			}
			ev = e
		case <-time.After(5 * time.Second):
			return
		case <-observerStop:
			return
		}
		o := observation{
			removedCount:  len(ev.Logs),
			headAtRemoved: bc.CurrentBlock().Hash(),
			canonicalAt4:  bc.GetCanonicalHash(4),
		}
		// The lookup must not block: the reorg that announced these removals has
		// released its write lock. Bound the wait so a mutation that publishes
		// mid-reorg fails here instead of hanging the suite.
		txCh := make(chan bool, 1)
		go func() {
			tx, _, _, _ := bc.ReadTransaction(canonical[0].Transactions()[0].Hash())
			txCh <- tx != nil
		}()
		select {
		case o.oldTxVisible = <-txCh:
		case <-time.After(2 * time.Second):
			o.lookupBlocked = true
		case <-observerStop:
			return
		}
		// The publisher cannot return yet: its rmLogsFeed send is still blocked on
		// holdCh, which has no receiver until this observation is done. Without the
		// barrier the read above could run after an early publication moved the head.
		select {
		case <-holdCh:
		case <-observerStop:
			return
		}
		select {
		case got <- o:
		case <-observerStop:
		}
	}()

	// Run the import in a worker so the test can report a publication that never arrives:
	// both removal feeds are unbuffered, so once the observer gives up, a send still waiting
	// on them would hold InsertChain forever instead of failing at the assertions.
	insertDone := make(chan struct{})
	var insertErr error
	go func() {
		defer close(insertDone)
		_, insertErr = bc.InsertChain(fork)
	}()
	// Unsubscribe first: feed.remove interrupts the pending send, which is what lets a blocked
	// InsertChain return. Join it before failing, so the defers below cannot stop the chain
	// under a running import.
	unblockImport := func() {
		close(observerStop)
		removedSub.Unsubscribe()
		holdSub.Unsubscribe()
		<-insertDone
		<-observerDone
	}
	select {
	case o := <-got:
		unblockImport()
		if o.removedCount != len(canonical) {
			t.Fatalf("removed logs mismatch: have %d, want %d", o.removedCount, len(canonical))
		}
		if want := fork[len(fork)-1].Hash(); o.headAtRemoved != want {
			t.Fatalf("removed logs observed at head %x, want the adopted head %x", o.headAtRemoved, want)
		}
		if want := fork[len(fork)-2].Hash(); o.canonicalAt4 != want {
			t.Fatalf("canonical hash #4 at removal delivery: have %x, want %x", o.canonicalAt4, want)
		}
		if o.lookupBlocked {
			t.Fatal("the transaction lookup blocked on the reorg's write lock when the removal was announced")
		}
		if o.oldTxVisible {
			t.Fatal("a transaction of the abandoned chain is still visible when its removal is announced")
		}
	case <-time.After(5 * time.Second):
		unblockImport()
		if insertErr != nil {
			t.Fatalf("failed to insert the longer fork: %v", insertErr)
		}
		t.Fatal("removed logs never reached the subscriber")
	}
	if insertErr != nil {
		t.Fatalf("failed to insert the longer fork: %v", insertErr)
	}
}

// TestReorgPublishesRebornLogsAfterIndexes pins the reborn half of the contract: the logs of the
// blocks a reorg promotes reach subscribers only once the head is the adopted one, in ascending
// block order and marked live. The adopted head's own logs arrive on the same feed afterwards.
func TestReorgPublishesRebornLogsAfterIndexes(t *testing.T) {
	canonical, fork, bc, _, _ := newReorgLogChains(t, 4, 5)
	defer bc.Stop()
	if _, err := bc.InsertChain(canonical); err != nil {
		t.Fatalf("failed to insert canonical chain: %v", err)
	}

	rebornCh := make(chan []*types.Log)
	holdCh := make(chan []*types.Log)
	rebornSub := bc.SubscribeLogsEvent(rebornCh)
	holdSub := bc.SubscribeLogsEvent(holdCh)

	type observation struct {
		logs []*types.Log
		head common.Hash
	}
	got := make(chan observation, 1)
	stop := make(chan struct{})
	observerDone := make(chan struct{})
	go func() {
		defer close(observerDone)
		var o observation
		select {
		case o.logs = <-rebornCh:
			o.head = bc.CurrentBlock().Hash()
		case <-time.After(5 * time.Second):
			return
		case <-stop:
			return
		}
		// The publisher is blocked on holdCh here, so an early publication records the old
		// head instead of the adopted one.
		select {
		case <-holdCh:
		case <-stop:
			return
		}
		select {
		case got <- o:
		case <-stop:
			return
		}
		// Keep consuming: the adopted head's own logs are published on this feed too, and a
		// send nobody receives would hold InsertChain.
		for {
			select {
			case <-rebornCh:
			case <-holdCh:
			case <-stop:
				return
			}
		}
	}()

	insertDone := make(chan struct{})
	var insertErr error
	go func() {
		defer close(insertDone)
		_, insertErr = bc.InsertChain(fork)
	}()
	unblock := func() {
		close(stop)
		rebornSub.Unsubscribe()
		holdSub.Unsubscribe()
		<-insertDone
		<-observerDone
	}

	select {
	case o := <-got:
		unblock()
		if insertErr != nil {
			t.Fatalf("failed to insert the longer fork: %v", insertErr)
		}
		want := fork[:len(fork)-1] // the two chains part at genesis, so every block but the head is promoted
		if len(o.logs) != len(want) {
			t.Fatalf("reborn batch carries %d log(s), want %d", len(o.logs), len(want))
		}
		for i, log := range o.logs {
			if log.BlockHash != want[i].Hash() || log.BlockNumber != want[i].NumberU64() || log.Removed {
				t.Fatalf("reborn log %d = %+v, want the live log of block %d (%x)", i, log, want[i].NumberU64(), want[i].Hash())
			}
		}
		if wantHead := fork[len(fork)-1].Hash(); o.head != wantHead {
			t.Fatalf("reborn logs observed at head %x, want the adopted head %x", o.head, wantHead)
		}
	case <-time.After(5 * time.Second):
		unblock()
		if insertErr != nil {
			t.Fatalf("failed to insert the longer fork: %v", insertErr)
		}
		t.Fatal("reborn logs never reached the subscriber")
	}
}

// TestReorgPublishesRemovedBeforeReborn pins the order of the two reorg batches: the removals
// reach subscribers before any of the reborn logs. Both feeds are unbuffered, so the publisher
// cannot hand the reborn batch over before the removed one was received.
func TestReorgPublishesRemovedBeforeReborn(t *testing.T) {
	canonical, fork, bc, _, _ := newReorgLogChains(t, 4, 5)
	defer bc.Stop()
	if _, err := bc.InsertChain(canonical); err != nil {
		t.Fatalf("failed to insert canonical chain: %v", err)
	}

	removedCh := make(chan RemovedLogsEvent)
	rebornCh := make(chan []*types.Log)
	removedSub := bc.SubscribeRemovedLogsEvent(removedCh)
	rebornSub := bc.SubscribeLogsEvent(rebornCh)

	type batch struct {
		removed bool
		logs    []*types.Log
	}
	got := make(chan batch, 4)
	stop := make(chan struct{})
	forwardDone := make(chan struct{})
	go func() {
		defer close(forwardDone)
		for {
			select {
			case ev := <-removedCh:
				got <- batch{removed: true, logs: ev.Logs}
			case logs := <-rebornCh:
				got <- batch{logs: logs}
			case <-stop:
				return
			}
		}
	}()

	insertDone := make(chan struct{})
	var insertErr error
	go func() {
		defer close(insertDone)
		_, insertErr = bc.InsertChain(fork)
	}()
	unblockImport := func() {
		close(stop)
		removedSub.Unsubscribe()
		rebornSub.Unsubscribe()
		<-insertDone
		<-forwardDone
	}

	var first, second batch
	select {
	case first = <-got:
	case <-time.After(5 * time.Second):
		unblockImport()
		t.Fatal("no reorg batch reached the subscriber")
	}
	if !first.removed {
		unblockImport()
		t.Fatalf("first reorg batch is the reborn batch (%d log(s)), want the removed batch", len(first.logs))
	}
	select {
	case second = <-got:
	case <-time.After(5 * time.Second):
		unblockImport()
		t.Fatal("the reborn batch never reached the subscriber")
	}
	unblockImport()
	if insertErr != nil {
		t.Fatalf("failed to insert the longer fork: %v", insertErr)
	}
	if len(first.logs) != len(canonical) {
		t.Fatalf("removed batch carries %d log(s), want %d", len(first.logs), len(canonical))
	}
	for i, log := range first.logs {
		if !log.Removed {
			t.Fatalf("removed log %d is not marked as removed: %+v", i, log)
		}
		// The removals keep the legacy forward order: ascending block numbers from the fork
		// point to the old head.
		if want := canonical[i]; log.BlockHash != want.Hash() || log.BlockNumber != want.NumberU64() {
			t.Fatalf("removed log %d is block %d (%x), want block %d (%x)", i, log.BlockNumber, log.BlockHash, want.NumberU64(), want.Hash())
		}
	}
	if second.removed {
		t.Fatalf("second reorg batch is another removed batch (%d log(s)), want the reborn batch", len(second.logs))
	}
	if want := len(fork) - 1; len(second.logs) != want {
		t.Fatalf("reborn batch carries %d log(s), want %d", len(second.logs), want)
	}
	for i, log := range second.logs {
		if log.Removed {
			t.Fatalf("reborn log %d is marked as removed: %+v", i, log)
		}
	}
}

// TestReorgFailurePublishesNoLogs pins the other half: a reorg that fails has rewritten
// nothing, so it must not announce removals.
func TestReorgFailurePublishesNoLogs(t *testing.T) {
	canonical, fork, bc, _, _ := newReorgLogChains(t, 4, 5)
	defer bc.Stop()
	if _, err := bc.InsertChain(canonical); err != nil {
		t.Fatalf("failed to insert canonical chain: %v", err)
	}

	// Drop a body the reorg has to read while collecting removals.
	rawdb.DeleteBody(bc.db, canonical[1].Hash(), 2)
	bc.blockCache.Purge()
	bc.bodyCache.Purge()
	bc.bodyRLPCache.Purge()

	removedCh := make(chan RemovedLogsEvent, 8)
	defer bc.SubscribeRemovedLogsEvent(removedCh).Unsubscribe()

	if _, err := bc.InsertChain(fork); err == nil {
		t.Fatal("the reorg over a missing body succeeded")
	}
	if n := len(removedCh); n != 0 {
		t.Fatalf("failed reorg published %d removed batches", n)
	}
}

// TestReorgFailureKeepsHeadAndIndexes pins the failed-reorg contract the publication order
// extends to: a body missing from the middle of the new chain fails the reorg before the
// forward loop writes the first head, so the head, the canonical markers and the transaction
// index stay the old chain's and nothing is published.
func TestReorgFailureKeepsHeadAndIndexes(t *testing.T) {
	canonical, fork, bc, _, _ := newReorgLogChains(t, 4, 5)
	defer bc.Stop()
	if _, err := bc.InsertChain(canonical); err != nil {
		t.Fatalf("failed to insert canonical chain: %v", err)
	}
	// Store the fork as a side chain first, so the import below is the block that wins fork
	// choice and triggers the reorg, not the side-chain import.
	if _, err := bc.InsertChain(fork[:len(fork)-1]); err != nil {
		t.Fatalf("failed to insert the fork as a side chain: %v", err)
	}
	// Snapshot the raw lookup entries of both chains: the canonical ones must survive the
	// failed reorg and the fork's must not appear. ReadTransaction alone cannot tell a stray
	// entry from a missing one: it only resolves transactions through canonical blocks.
	lookups := make(map[common.Hash]*uint64)
	for _, blocks := range []types.Blocks{canonical, fork} {
		for _, block := range blocks {
			for _, tx := range block.Transactions() {
				lookups[tx.Hash()] = rawdb.ReadTxLookupEntry(bc.db, tx.Hash())
			}
		}
	}
	// The canonical entries are what give the snapshot its teeth: each canonical block was
	// the head when it was imported, and the head write is what stored them.
	for _, block := range canonical {
		if rawdb.ReadTxLookupEntry(bc.db, block.Transactions()[0].Hash()) == nil {
			t.Fatalf("canonical transaction %x has no lookup entry before the failed reorg", block.Transactions()[0].Hash())
		}
	}
	// Drop the body of the second block the forward loop walks: the head of the block below
	// it is written before this read is reached.
	gap := fork[1]
	rawdb.DeleteBody(bc.db, gap.Hash(), gap.NumberU64())
	bc.blockCache.Purge()
	bc.bodyCache.Purge()
	bc.bodyRLPCache.Purge()

	head := bc.CurrentBlock()
	removedCh := make(chan RemovedLogsEvent, 8)
	defer bc.SubscribeRemovedLogsEvent(removedCh).Unsubscribe()
	rebornCh := make(chan []*types.Log, 8)
	defer bc.SubscribeLogsEvent(rebornCh).Unsubscribe()

	if _, err := bc.InsertChain(fork[len(fork)-1:]); err == nil {
		t.Fatal("the reorg over a missing intermediate body succeeded")
	}
	if got := bc.CurrentBlock().Hash(); got != head.Hash() {
		t.Fatalf("head moved to %x, want it left at %x", got, head.Hash())
	}
	for _, block := range canonical {
		if got := bc.GetCanonicalHash(block.NumberU64()); got != block.Hash() {
			t.Fatalf("canonical hash #%d moved to %x, want %x", block.NumberU64(), got, block.Hash())
		}
	}
	for _, block := range canonical {
		for _, tx := range block.Transactions() {
			if got, _, _, _ := bc.ReadTransaction(tx.Hash()); got == nil {
				t.Fatalf("abandoned chain's transaction %x no longer resolves", tx.Hash())
			}
		}
	}
	for hash, want := range lookups {
		got := rawdb.ReadTxLookupEntry(bc.db, hash)
		if (got == nil) != (want == nil) || (got != nil && *got != *want) {
			t.Fatalf("fork transaction %x lookup entry changed", hash)
		}
	}
	for _, block := range fork {
		for _, tx := range block.Transactions() {
			if got, _, _, _ := bc.ReadTransaction(tx.Hash()); got != nil {
				t.Fatalf("fork transaction %x entered the index", tx.Hash())
			}
		}
	}
	if n := len(removedCh); n != 0 {
		t.Fatalf("failed reorg published %d removed batches", n)
	}
	if n := len(rebornCh); n != 0 {
		t.Fatalf("failed reorg published %d reborn batches", n)
	}
}

// TestReorgTxLookupLockBlocksReads pins the lock the RPC read path takes: a lookup waits
// while a reorg rewrites the indexes it reads.
func TestReorgTxLookupLockBlocksReads(t *testing.T) {
	_, _, bc, _, _ := newReorgLogChains(t, 1, 1)
	defer bc.Stop()

	bc.txLookupLock.Lock()
	done := make(chan struct{})
	go func() {
		bc.ReadTransaction(common.HexToHash("0x01"))
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("a transaction lookup returned while the reorg held the lookup lock")
	case <-time.After(100 * time.Millisecond):
	}
	bc.txLookupLock.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a transaction lookup did not resume after the reorg released the lock")
	}
}

// TestFlushReorgLogsBatchCapacity pins that a batch keeps no spare capacity over the next
// one: a subscriber that appends to Logs must not overwrite the first log of the following
// batch.
func TestFlushReorgLogsBatchCapacity(t *testing.T) {
	const total = 513
	logs := make([]*types.Log, total)
	for i := range logs {
		logs[i] = &types.Log{BlockNumber: uint64(i)}
	}
	// The two batches share one backing array, so an append into the first one would land on
	// the first log of the second: read the expectation before publication.
	wantNext := logs[total-1]
	bc := new(BlockChain)
	removedCh := make(chan RemovedLogsEvent)
	removedSub := bc.SubscribeRemovedLogsEvent(removedCh)
	defer removedSub.Unsubscribe()
	rebornCh := make(chan []*types.Log)
	rebornSub := bc.SubscribeLogsEvent(rebornCh)
	defer rebornSub.Unsubscribe()

	removedDone := make(chan struct{})
	go func() {
		defer close(removedDone)
		first := <-removedCh
		first.Logs = append(first.Logs, &types.Log{BlockNumber: 9999})
		second := <-removedCh
		if len(second.Logs) != 1 || second.Logs[0] != wantNext {
			t.Errorf("removed batch 2 starts at %v, want the log at index %d", second.Logs, total-1)
		}
	}()
	rebornDone := make(chan struct{})
	go func() {
		defer close(rebornDone)
		first := <-rebornCh
		_ = append(first, &types.Log{BlockNumber: 9999})
		second := <-rebornCh
		if len(second) != 1 || second[0] != wantNext {
			t.Errorf("reborn batch 2 starts at %v, want the log at index %d", second, total-1)
		}
	}()
	bc.flushReorgLogs(logs[:512], true)
	bc.flushReorgLogs(logs[512:], true)
	<-removedDone
	bc.flushReorgLogs(logs[:512], false)
	bc.flushReorgLogs(logs[512:], false)
	<-rebornDone
}

// TestPublishReorgLogsBatchesAcrossBlocks pins the publication's batching: logs are filled into
// batches of up to 512 across block boundaries, and each batch is sent with no spare capacity.
func TestPublishReorgLogsBatchesAcrossBlocks(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		emitter = common.HexToAddress("0x0000000000000000000000000000000000000011")
		// Emitter is a genesis contract whose runtime code emits ten anonymous logs per call:
		// ten times PUSH1 0x00, PUSH1 0x00, LOG0, then STOP.
		emitterCode = []byte{
			0x60, 0x00, 0x60, 0x00, 0xa0,
			0x60, 0x00, 0x60, 0x00, 0xa0,
			0x60, 0x00, 0x60, 0x00, 0xa0,
			0x60, 0x00, 0x60, 0x00, 0xa0,
			0x60, 0x00, 0x60, 0x00, 0xa0,
			0x60, 0x00, 0x60, 0x00, 0xa0,
			0x60, 0x00, 0x60, 0x00, 0xa0,
			0x60, 0x00, 0x60, 0x00, 0xa0,
			0x60, 0x00, 0x60, 0x00, 0xa0,
			0x60, 0x00, 0x60, 0x00, 0xa0,
			0x00,
		}
		gspec = &Genesis{
			Config: &params.ChainConfig{
				ChainID:        big.NewInt(1338),
				HomesteadBlock: new(big.Int),
				Ethash:         new(params.EthashConfig),
			},
			Alloc: types.GenesisAlloc{
				address: {Balance: big.NewInt(params.Ether)},
				emitter: {Code: emitterCode},
			},
			Difficulty: big.NewInt(1),
		}
	)
	const (
		blocks       = 2
		txsPerBlock  = 30
		logsPerTx    = 10
		logsPerBlock = txsPerBlock * logsPerTx
		batchSize    = 512
	)
	engine := ethash.NewFaker()
	genDb := rawdb.NewMemoryDatabase()
	if _, err := gspec.Commit(genDb); err != nil {
		t.Fatalf("failed to commit genesis: %v", err)
	}
	bc, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	defer bc.Stop()
	chain, _ := GenerateChain(gspec.Config, bc.Genesis(), engine, genDb, blocks, func(i int, b *BlockGen) {
		for j := 0; j < txsPerBlock; j++ {
			tx, err := types.SignTx(types.NewTransaction(uint64(i*txsPerBlock+j), emitter, big.NewInt(1), 100000, big.NewInt(1), nil), types.HomesteadSigner{}, key)
			if err != nil {
				t.Fatalf("failed to sign log transaction: %v", err)
			}
			b.AddTx(tx)
		}
	})
	if _, err := bc.InsertChain(chain); err != nil {
		t.Fatalf("failed to insert chain: %v", err)
	}

	removedCh := make(chan RemovedLogsEvent, 4)
	defer bc.SubscribeRemovedLogsEvent(removedCh).Unsubscribe()
	bc.publishReorgLogs(chain, nil)
	close(removedCh)
	var batches [][]*types.Log
	for ev := range removedCh {
		batches = append(batches, ev.Logs)
	}
	if len(batches) != 2 {
		t.Fatalf("publication sent %d batch(es), want 2", len(batches))
	}
	if got := len(batches[0]); got != batchSize {
		t.Fatalf("first batch carries %d log(s), want %d", got, batchSize)
	}
	if got, want := len(batches[1]), blocks*logsPerBlock-batchSize; got != want {
		t.Fatalf("second batch carries %d log(s), want %d", got, want)
	}
	for i, batch := range batches {
		if cap(batch) != len(batch) {
			t.Fatalf("batch %d has capacity %d over length %d", i, cap(batch), len(batch))
		}
		for j, log := range batch {
			if !log.Removed {
				t.Fatalf("batch %d log %d is not marked as removed: %+v", i, j, log)
			}
		}
	}
	// The first batch fills up inside the second block: the boundary has to fall at 512, not at
	// the block edge.
	if got, want := batches[0][logsPerBlock-1].BlockNumber, chain[0].NumberU64(); got != want {
		t.Fatalf("log %d of the first batch is from block %d, want the last log of block %d", logsPerBlock-1, got, want)
	}
	if got, want := batches[0][logsPerBlock].BlockNumber, chain[1].NumberU64(); got != want {
		t.Fatalf("log %d of the first batch is from block %d, want the first log of block %d", logsPerBlock, got, want)
	}
}
