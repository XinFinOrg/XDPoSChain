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

	bindv1 "github.com/XinFinOrg/XDPoSChain/accounts/abi/bind"
	"github.com/XinFinOrg/XDPoSChain/accounts/abi/bind/v2"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethclient/simulated"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestWaitAccepted tests that WaitAccepted returns once the given transaction is
// visible in the pool, that it honors the context deadline while the transaction
// is not there yet, and that the v1 binding forwards to it.
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

	// A transaction that is not in the pool must not be reported as accepted,
	// the context deadline is the only way out.
	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := bind.WaitAccepted(ctx, backend, crypto.Keccak256Hash([]byte("missing"))); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitAccepted returned %v for a transaction that is not in the pool, want %v", err, context.DeadlineExceeded)
	}

	// The v1 binding forwards to the v2 implementation.
	if err := bindv1.WaitAccepted(context.Background(), backend, tx); err != nil {
		t.Fatalf("bind.WaitAccepted (v1) returned %v for a transaction that is in the pool", err)
	}
}
