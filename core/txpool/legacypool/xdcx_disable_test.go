// Copyright 2026 The XDPoSChain Authors
// This file is part of the XDPoSChain library.
//
// The XDPoSChain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The XDPoSChain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the XDPoSChain library. If not, see <http://www.gnu.org/licenses/>.

package legacypool

import (
	"errors"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

func xdcxDisableTestConfig() *params.ChainConfig {
	return &params.ChainConfig{
		ChainID:                     big.NewInt(1339),
		TIPXDCXBlock:                big.NewInt(0),
		TIPXDCXReceiverDisableBlock: big.NewInt(100),
	}
}

// TestXDCXSystemTransactionsAfterDisableFork pins the admission rule: once the
// next block is past the receiver disable fork, transactions to the XDCx system
// addresses are not taken, while ordinary transactions still are.
func TestXDCXSystemTransactionsAfterDisableFork(t *testing.T) {
	t.Parallel()

	pool, key := setupPoolWithConfig(xdcxDisableTestConfig())
	defer pool.Close()

	signer := types.LatestSigner(pool.chainconfig)
	from := crypto.PubkeyToAddress(key.PublicKey)
	testAddBalance(pool, from, big.NewInt(1e18))

	systemAddrs := []common.Address{
		common.XDCXAddrBinary,
		common.TradingStateAddrBinary,
		common.XDCXLendingAddressBinary,
		common.XDCXLendingFinalizedTradeAddressBinary,
	}
	sign := func(nonce uint64, to common.Address) *types.Transaction {
		t.Helper()
		tx, err := types.SignTx(types.NewTransaction(nonce, to, common.Big0, params.TxGas, big.NewInt(common.DefaultMinGasPrice), nil), signer, key)
		if err != nil {
			t.Fatalf("failed to sign transaction: %v", err)
		}
		return tx
	}
	setHead := func(number int64) {
		pool.mu.Lock()
		defer pool.mu.Unlock()
		head := *pool.currentHead.Load()
		head.Number = big.NewInt(number)
		pool.currentHead.Store(&head)
	}

	// The block pending on top of head 98 is the last one the fork leaves enabled.
	setHead(98)
	for i, to := range systemAddrs {
		if err := pool.addRemote(sign(uint64(i), to)); err != nil {
			t.Fatalf("transaction to %v rejected before the disable fork: %v", to, err)
		}
	}

	// From head 99 on, the block a pooled transaction can be included in is
	// already past the fork.
	setHead(99)
	for i, to := range systemAddrs {
		if err := pool.addRemote(sign(uint64(len(systemAddrs)+i), to)); !errors.Is(err, ErrXDCXSystemTxDisabled) {
			t.Fatalf("transaction to %v: have %v, want %v", to, err, ErrXDCXSystemTxDisabled)
		}
	}
	if err := pool.addRemote(sign(uint64(len(systemAddrs)), common.Address{0x01})); err != nil {
		t.Fatalf("regular transaction rejected after the disable fork: %v", err)
	}
}

// TestXDCXSystemTransactionsAfterMinerDisableFork pins the earlier leg of the
// guard: between the miner and receiver disable forks the miner no longer
// writes the XDCx roots while importers still read them, so a system
// transaction sealed then would be rejected by peers.
func TestXDCXSystemTransactionsAfterMinerDisableFork(t *testing.T) {
	t.Parallel()

	pool, key := setupPoolWithConfig(&params.ChainConfig{
		ChainID:                     big.NewInt(1339),
		TIPXDCXBlock:                big.NewInt(0),
		TIPXDCXMinerDisableBlock:    big.NewInt(100),
		TIPXDCXReceiverDisableBlock: big.NewInt(200),
	})
	defer pool.Close()

	signer := types.LatestSigner(pool.chainconfig)
	from := crypto.PubkeyToAddress(key.PublicKey)
	testAddBalance(pool, from, big.NewInt(1e18))

	systemAddrs := []common.Address{
		common.XDCXAddrBinary,
		common.TradingStateAddrBinary,
		common.XDCXLendingAddressBinary,
		common.XDCXLendingFinalizedTradeAddressBinary,
	}
	sign := func(nonce uint64, to common.Address) *types.Transaction {
		t.Helper()
		tx, err := types.SignTx(types.NewTransaction(nonce, to, common.Big0, params.TxGas, big.NewInt(common.DefaultMinGasPrice), nil), signer, key)
		if err != nil {
			t.Fatalf("failed to sign transaction: %v", err)
		}
		return tx
	}
	setHead := func(number int64) {
		pool.mu.Lock()
		defer pool.mu.Unlock()
		head := *pool.currentHead.Load()
		head.Number = big.NewInt(number)
		pool.currentHead.Store(&head)
	}

	// The block pending on top of head 98 is the last one before the miner
	// disable fork.
	setHead(98)
	for i, to := range systemAddrs {
		if err := pool.addRemote(sign(uint64(i), to)); err != nil {
			t.Fatalf("transaction to %v rejected before the miner disable fork: %v", to, err)
		}
	}

	// From head 99 on the next block sits between the two disable forks: the
	// miner stopped writing the roots while importers still read them.
	setHead(99)
	for i, to := range systemAddrs {
		if err := pool.addRemote(sign(uint64(len(systemAddrs)+i), to)); !errors.Is(err, ErrXDCXSystemTxDisabled) {
			t.Fatalf("transaction to %v: have %v, want %v", to, err, ErrXDCXSystemTxDisabled)
		}
	}
	if err := pool.addRemote(sign(uint64(len(systemAddrs)), common.Address{0x01})); err != nil {
		t.Fatalf("regular transaction rejected in the miner disable window: %v", err)
	}
}

// TestXDCXSystemTransactionsWithoutXDCX pins the TIPXDCX leg of the guard: on a
// chain where XDCx was never enabled the four addresses are ordinary recipients.
func TestXDCXSystemTransactionsWithoutXDCX(t *testing.T) {
	t.Parallel()

	pool, key := setupPoolWithConfig(&params.ChainConfig{ChainID: big.NewInt(1339)})
	defer pool.Close()

	signer := types.LatestSigner(pool.chainconfig)
	from := crypto.PubkeyToAddress(key.PublicKey)
	testAddBalance(pool, from, big.NewInt(1e18))

	systemAddrs := []common.Address{
		common.XDCXAddrBinary,
		common.TradingStateAddrBinary,
		common.XDCXLendingAddressBinary,
		common.XDCXLendingFinalizedTradeAddressBinary,
	}
	for i, to := range systemAddrs {
		tx, err := types.SignTx(types.NewTransaction(uint64(i), to, common.Big0, params.TxGas, big.NewInt(common.DefaultMinGasPrice), nil), signer, key)
		if err != nil {
			t.Fatalf("failed to sign transaction: %v", err)
		}
		if err := pool.addRemote(tx); err != nil {
			t.Fatalf("transaction to %v rejected on a chain without XDCx: %v", to, err)
		}
	}
}
