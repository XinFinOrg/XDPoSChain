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

package bind_test

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	ethereum "github.com/XinFinOrg/XDPoSChain"
	bindv1 "github.com/XinFinOrg/XDPoSChain/accounts/abi/bind"
	"github.com/XinFinOrg/XDPoSChain/accounts/abi/bind/v2"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethclient/simulated"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// delayedBackend reports the first `misses` lookups of any transaction as absent
// from the pool and delegates every later one to the embedded backend, so that a
// caller which has to poll cannot succeed on its first attempt.
type delayedBackend struct {
	*simulated.Backend
	misses int
	calls  int
}

func (b *delayedBackend) TransactionByHash(ctx context.Context, hash common.Hash) (*types.Transaction, bool, error) {
	b.calls++
	if b.calls <= b.misses {
		return nil, false, ethereum.ErrNotFound
	}
	return b.Backend.TransactionByHash(ctx, hash)
}

// minedOnlyBackend simulates a gateway that answers every eth_getTransactionByHash
// lookup with not-found while still serving receipts, so acceptance of a mined
// transaction can only be observed through its receipt.
type minedOnlyBackend struct {
	*simulated.Backend
}

func (b *minedOnlyBackend) TransactionByHash(ctx context.Context, hash common.Hash) (*types.Transaction, bool, error) {
	return nil, false, ethereum.ErrNotFound
}

// receiptlessBackend hides the promoted TransactionReceipt of the embedded backend
// behind a method of another signature, so the type deliberately does not implement
// DeployBackend and WaitAccepted cannot probe receipts through it. It still answers
// every transaction lookup with not-found, like a gateway in front of a node.
type receiptlessBackend struct {
	*minedOnlyBackend
}

func (b *receiptlessBackend) TransactionReceipt(ctx context.Context, hash common.Hash) error {
	return ethereum.ErrNotFound
}

// brokenReceiptBackend serves transaction lookups with not-found and receipt
// lookups with a transport error, so no receipt can be taken as evidence of
// acceptance and the wait has to keep polling until the deadline.
type brokenReceiptBackend struct {
	*minedOnlyBackend
	receiptCalls int
}

func (b *brokenReceiptBackend) TransactionReceipt(ctx context.Context, hash common.Hash) (*types.Receipt, error) {
	b.receiptCalls++
	return nil, errors.New("receipt lookup unavailable")
}

// TestWaitAccepted tests that WaitAccepted returns once the given transaction is
// visible in the pool, that it keeps polling while the pool lookup misses until
// the transaction turns up, that a backend which only serves mined transactions
// still reports a mined one through its receipt, that a backend without receipt
// lookups falls back to transaction lookups only, that it honors the context
// deadline while the transaction never turns up, and that the v1 binding
// forwards to it.
func TestWaitAccepted(t *testing.T) {
	config := *params.TestXDPoSMockChainConfig
	backend := simulated.New(
		types.GenesisAlloc{
			crypto.PubkeyToAddress(testKey.PublicKey): {Balance: big.NewInt(1000000000000000000)},
		},
		10000000,
		&config,
	)
	defer backend.Close()

	head, err := backend.Client().HeaderByNumber(context.Background(), nil)
	if err != nil {
		t.Fatalf("failed to retrieve the head header: %v", err)
	}
	gasPrice := new(big.Int).Add(head.BaseFee, big.NewInt(params.GWei))
	tx, err := types.SignTx(types.NewTransaction(0, common.Address{}, big.NewInt(0), 21000, gasPrice, nil), types.HomesteadSigner{}, testKey)
	if err != nil {
		t.Fatalf("failed to sign transaction: %v", err)
	}
	if err := backend.SendTransaction(context.Background(), tx); err != nil {
		t.Fatalf("failed to submit transaction: %v", err)
	}

	// The transaction is in the pool, so WaitAccepted must return right away.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := bind.WaitAccepted(ctx, backend, tx.Hash()); err != nil {
		t.Fatalf("WaitAccepted returned %v for a transaction that is in the pool", err)
	}

	// A transaction the backend only reports from the second lookup on must still
	// be waited for: the miss must not end the wait with the lookup error.
	delayed := &delayedBackend{Backend: backend, misses: 1}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := bind.WaitAccepted(ctx, delayed, tx.Hash()); err != nil {
		t.Fatalf("WaitAccepted returned %v for a transaction that shows up after one miss", err)
	}
	if delayed.calls < 2 {
		t.Errorf("WaitAccepted gave up after %d lookups, want it to retry at least once", delayed.calls)
	}

	// A gateway that never reports transactions from eth_getTransactionByHash must
	// not stall the wait once the transaction is mined: the receipt proves the
	// pool accepted it.
	backend.Commit()
	if _, err := backend.TransactionReceipt(context.Background(), tx.Hash()); err != nil {
		t.Fatalf("failed to retrieve the receipt of the mined transaction: %v", err)
	}
	minedOnly := &minedOnlyBackend{Backend: backend}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := bind.WaitAccepted(ctx, minedOnly, tx.Hash()); err != nil {
		t.Fatalf("WaitAccepted returned %v for a mined transaction on a backend that only serves receipts", err)
	}

	// A backend that cannot serve receipts must fall back to transaction lookups, so a
	// mined transaction it never reports is not accepted and the deadline is the only way out.
	receiptless := &receiptlessBackend{minedOnlyBackend: minedOnly}
	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := bind.WaitAccepted(ctx, receiptless, tx.Hash()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitAccepted returned %v for a backend without receipt lookups, want %v", err, context.DeadlineExceeded)
	}

	// A receipt lookup that fails for a reason other than not-found must neither
	// be mistaken for acceptance nor end the wait: only the deadline can stop it.
	broken := &brokenReceiptBackend{minedOnlyBackend: minedOnly}
	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := bind.WaitAccepted(ctx, broken, tx.Hash()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitAccepted returned %v for a failing receipt lookup, want %v", err, context.DeadlineExceeded)
	}
	if broken.receiptCalls == 0 {
		t.Fatal("WaitAccepted never probed the receipt while the transaction lookup kept failing")
	}

	// A transaction that is not in the pool must not be reported as accepted,
	// the context deadline is the only way out.
	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := bind.WaitAccepted(ctx, backend, crypto.Keccak256Hash([]byte("missing"))); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitAccepted returned %v for a transaction that is not in the pool, want %v", err, context.DeadlineExceeded)
	}

	// The v1 binding forwards to the v2 implementation.
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := bindv1.WaitAccepted(ctx, backend, tx); err != nil {
		t.Fatalf("bind.WaitAccepted (v1) returned %v for a transaction that is in the pool", err)
	}
}
