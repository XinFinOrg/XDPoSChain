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

package txpool_test

import (
	"math/big"
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
	"github.com/XinFinOrg/XDPoSChain/event"
	"github.com/XinFinOrg/XDPoSChain/params"
)

var (
	syncTestKey, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	syncTestAddress = crypto.PubkeyToAddress(syncTestKey.PublicKey)
	syncTestFunds   = big.NewInt(1000000000000000000)
	syncTestGenesis = &core.Genesis{
		Config: params.TestChainConfig,
		Alloc: types.GenesisAlloc{
			syncTestAddress: {Balance: syncTestFunds},
		},
		BaseFee: big.NewInt(params.InitialBaseFee),
	}
	syncTestSigner = types.LatestSigner(syncTestGenesis.Config)
)

// newSyncTestEnv builds a chain of n blocks (each consuming one nonce of the
// test address) and a txpool layered on top of it.
func newSyncTestEnv(t *testing.T, n int) (*core.BlockChain, *txpool.TxPool) {
	t.Helper()

	_, blocks, _ := core.GenerateChainWithGenesis(syncTestGenesis, ethash.NewFaker(), n, func(i int, gen *core.BlockGen) {
		gasPrice := big.NewInt(params.InitialBaseFee)
		if baseFee := gen.BaseFee(); baseFee != nil {
			gasPrice = new(big.Int).Set(baseFee)
		}
		tx, err := types.SignTx(types.NewTransaction(gen.TxNonce(syncTestAddress), common.Address{0x00}, big.NewInt(1000), params.TxGas, gasPrice, nil), syncTestSigner, syncTestKey)
		if err != nil {
			panic(err)
		}
		gen.AddTx(tx)
	})

	db := rawdb.NewMemoryDatabase()
	chain, err := core.NewBlockChain(db, nil, syncTestGenesis, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}
	legacyPool := legacypool.New(legacypool.DefaultConfig, chain)
	pool, err := txpool.New(0, chain, []txpool.SubPool{legacyPool})
	if err != nil {
		t.Fatalf("Failed to create tx pool: %v", err)
	}
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("Failed to insert blocks: %v", err)
	}
	return chain, pool
}

// TestSyncCompletes guards against the Sync() deadlock: the loop must always
// complete the forced reset and notify the waiting caller. Each call must
// return promptly; a bounded timeout turns a deadlock into a fast failure
// instead of hanging the whole test run until the package-wide timeout.
func TestSyncCompletes(t *testing.T) {
	chain, pool := newSyncTestEnv(t, 10)
	defer chain.Stop()
	defer pool.Close()

	for i := 0; i < 100; i++ {
		errc := make(chan error, 1)
		go func() {
			errc <- pool.Sync()
		}()
		select {
		case err := <-errc:
			if err != nil {
				t.Fatalf("Sync call %d failed: %v", i, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("Sync call %d did not return within 5s (deadlock?)", i)
		}
	}
}

// blockingResetPool is a SubPool whose Reset blocks until released, keeping a
// Sync() request pending so the loop-termination path can be exercised.
type blockingResetPool struct {
	started chan struct{} // closed when Reset begins
	release chan struct{} // closed to unblock Reset
}

func (p *blockingResetPool) Filter(tx *types.Transaction) bool { return false }

func (p *blockingResetPool) Init(gasTip uint64, head *types.Header, reserver txpool.Reserver) error {
	return nil
}

func (p *blockingResetPool) Close() error {
	close(p.release)
	return nil
}

func (p *blockingResetPool) Reset(oldHead, newHead *types.Header) {
	close(p.started)
	<-p.release
}

func (p *blockingResetPool) SetGasTip(tip *big.Int) error { return nil }

func (p *blockingResetPool) Has(hash common.Hash) bool { return false }

func (p *blockingResetPool) Get(hash common.Hash) *types.Transaction { return nil }

func (p *blockingResetPool) ValidateTxBasics(tx *types.Transaction) error { return nil }

func (p *blockingResetPool) Add(txs []*types.Transaction, sync bool) []error { return nil }

func (p *blockingResetPool) Pending(filter txpool.PendingFilter) map[common.Address][]*txpool.LazyTransaction {
	return nil
}

func (p *blockingResetPool) SubscribeTransactions(ch chan<- core.NewTxsEvent, reorgs bool) event.Subscription {
	return event.NewSubscription(func(quit <-chan struct{}) error {
		<-quit
		return nil
	})
}

func (p *blockingResetPool) Nonce(addr common.Address) uint64 { return 0 }

func (p *blockingResetPool) Stats() (int, int) { return 0, 0 }

func (p *blockingResetPool) Content() (map[common.Address][]*types.Transaction, map[common.Address][]*types.Transaction) {
	return nil, nil
}

func (p *blockingResetPool) ContentFrom(addr common.Address) ([]*types.Transaction, []*types.Transaction) {
	return nil, nil
}

func (p *blockingResetPool) Status(hash common.Hash) txpool.TxStatus { return txpool.TxStatusUnknown }

func (p *blockingResetPool) SetSigner(f func(address common.Address) bool) {}

func (p *blockingResetPool) IsSigner(addr common.Address) bool { return false }

// TestSyncTerminatedOnClose covers the loop-termination path: a Sync() request
// kept pending by a blocking subpool must receive "pool already terminated"
// when the pool is closed, instead of blocking forever, and both the pool loop
// and the Sync caller must finish.
func TestSyncTerminatedOnClose(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	chain, err := core.NewBlockChain(db, nil, syncTestGenesis, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}
	defer chain.Stop()

	block := &blockingResetPool{started: make(chan struct{}), release: make(chan struct{})}
	pool, err := txpool.New(0, chain, []txpool.SubPool{block})
	if err != nil {
		t.Fatalf("Failed to create tx pool: %v", err)
	}

	errc := make(chan error, 1)
	go func() {
		errc <- pool.Sync()
	}()
	// Wait deterministically until the forced reset started and is stuck in the
	// blocking subpool, i.e. the Sync waiter is live before Close runs.
	select {
	case <-block.started:
	case <-time.After(5 * time.Second):
		t.Fatal("forced reset did not start")
	}

	if err := pool.Close(); err != nil {
		t.Fatalf("Failed to close pool: %v", err)
	}
	select {
	case err := <-errc:
		if err == nil || err.Error() != "pool already terminated" {
			t.Fatalf("Sync returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Sync did not return after pool close")
	}
}
