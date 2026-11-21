package core

import (
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

// newReorgLogChains builds two chains from genesis whose blocks each carry one log
// transaction, using a disjoint nonce range so the fork's transactions are new ones.
func newReorgLogChains(t *testing.T, canonicalN, forkN int) (types.Blocks, types.Blocks, *BlockChain, *Genesis, *ethash.Ethash) {
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
	defer bc.SubscribeRemovedLogsEvent(removedCh).Unsubscribe()
	defer bc.SubscribeRemovedLogsEvent(holdCh).Unsubscribe()
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
	got := make(chan observation, 1)
	go func() {
		var ev RemovedLogsEvent
		select {
		case e, ok := <-removedCh:
			if !ok {
				return
			}
			ev = e
		case <-time.After(5 * time.Second):
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
		}
		// The publisher cannot return yet: its rmLogsFeed send is still blocked on
		// holdCh, which has no receiver until this observation is done. Without the
		// barrier the read above could run after an early publication moved the head.
		<-holdCh
		got <- o
	}()

	if _, err := bc.InsertChain(fork); err != nil {
		t.Fatalf("failed to insert the longer fork: %v", err)
	}
	select {
	case o := <-got:
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
		t.Fatal("removed logs never reached the subscriber")
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
