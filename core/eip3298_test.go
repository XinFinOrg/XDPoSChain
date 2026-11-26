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

// Settlement tests for EIP-3298 (Removal of Refunds): the end-of-transaction
// refund cap (min(used/5, counter) per EIP-3529) becomes the full counter
// once Bogotá is active. The defensive clamp refund <= gasUsedBeforeRefund is
// retained. The EIP-7623 calldata-floor top-up (settleGas, IsPrague-gated)
// is untouched by this scope.
//
// Spec: https://eips.ethereum.org/EIPS/eip-3298 (full snapshot fetched
// 2026-11-07: hegota-research-20261107/eip-3298.md).

package core

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

func refundCapConfig(bogota bool) *params.ChainConfig {
	cfg := *params.MergedTestChainConfig // London active at block 0 → EIP-3529 quotient 5
	if bogota {
		cfg.BogotaTime = new(uint64)
	}
	return &cfg
}

// newRefundTransition builds a minimal stateTransition carrying only what
// calcRefund reads: the EVM (for the chain config) and the state (for the
// refund counter).
func newRefundTransition(cfg *params.ChainConfig, refund uint64) *stateTransition {
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	if refund > 0 {
		statedb.AddRefund(refund)
	}
	ctx := vm.BlockContext{
		CanTransfer: func(db vm.StateDB, addr common.Address, amount *uint256.Int) bool {
			return db.GetBalance(addr).Cmp(amount) >= 0
		},
		Transfer: func(db vm.StateDB, sender, recipient common.Address, amount *uint256.Int, _ *params.Rules) {
			db.SubBalance(sender, amount, tracing.BalanceChangeTransfer)
			db.AddBalance(recipient, amount, tracing.BalanceChangeTransfer)
		},
		BlockNumber: big.NewInt(0),
	}
	evm := vm.NewEVM(ctx, statedb, cfg, vm.Config{})
	return &stateTransition{state: statedb, evm: evm}
}

// TestEIP3298RefundCapRemoved: a counter above the old 20% cap must be
// returned in full under Bogotá (pre-fix this returns gasUsed/5 — RED).
func TestEIP3298RefundCapRemoved(t *testing.T) {
	const (
		refundCounter      = uint64(10_000)
		gasUsedBeforeRefund = uint64(10_000)
	)
	st := newRefundTransition(refundCapConfig(true), refundCounter)
	if got := st.calcRefund(gasUsedBeforeRefund); got != refundCounter {
		t.Fatalf("Bogotá: calcRefund = %d, want full counter %d (cap removed per EIP-3298)", got, refundCounter)
	}
}

// TestEIP3298RefundCapUnchangedBelowCap: a counter below the old cap binds in
// both worlds. Control case — passes before and after the change.
func TestEIP3298RefundCapUnchangedBelowCap(t *testing.T) {
	const (
		refundCounter      = uint64(1_000)
		gasUsedBeforeRefund = uint64(10_000)
	)
	for name, bogota := range map[string]bool{"amsterdam": false, "bogota": true} {
		st := newRefundTransition(refundCapConfig(bogota), refundCounter)
		if got := st.calcRefund(gasUsedBeforeRefund); got != refundCounter {
			t.Fatalf("%s: calcRefund = %d, want %d", name, got, refundCounter)
		}
	}
}

// TestEIP3298RefundClampRetained: the refund can never exceed the gas
// actually used, even under Bogotá (defensive clamp, documented in the
// EIP-3298 implementation note).
func TestEIP3298RefundClampRetained(t *testing.T) {
	const (
		refundCounter      = uint64(9_000)
		gasUsedBeforeRefund = uint64(5_000)
	)
	st := newRefundTransition(refundCapConfig(true), refundCounter)
	if got := st.calcRefund(gasUsedBeforeRefund); got != gasUsedBeforeRefund {
		t.Fatalf("Bogotá: calcRefund = %d, want clamp to gas used %d", got, gasUsedBeforeRefund)
	}
}
