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

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

// settlementCoinbase is the block coinbase used by the settlement tests.
var settlementCoinbase = common.BytesToAddress([]byte("settlement-coinbase"))

// applyFrameTxBaseFee executes a frame transaction like applyFrameTx but
// with an explicit base fee and coinbase, for settlement testing.
func applyFrameTxBaseFee(t *testing.T, sdb *state.StateDB, ftx *types.FrameTx, baseFee *big.Int) (*ExecutionResult, error) {
	t.Helper()
	ctx := vm.BlockContext{
		CanTransfer:      CanTransfer,
		Transfer:         Transfer,
		GetHash:          func(uint64) common.Hash { return common.Hash{} },
		BlockNumber:      big.NewInt(0),
		Time:             0,
		Random:           &common.Hash{},
		Difficulty:       big.NewInt(0),
		BaseFee:          baseFee,
		BlobBaseFee:      big.NewInt(0),
		GasLimit:         60_000_000,
		CostPerStateByte: params.CostPerStateByte,
		Coinbase:         settlementCoinbase,
	}
	evm := vm.NewEVM(ctx, sdb, cfgFrame, vm.Config{NoBaseFee: true})
	msg, err := TransactionToMessage(types.NewTx(ftx), frameSgn, evm.Context.BaseFee)
	if err != nil {
		t.Fatalf("to message: %v", err)
	}
	gp := NewGasPool(evm.Context.GasLimit)
	evm.SetTxContext(NewEVMTxContext(msg))
	st := newStateTransition(evm, msg, gp, common.Address{})
	return st.execute()
}

// settlementScenario builds a minimal self-verify frame transaction with
// caller-controlled fees and returns it together with its statically known
// max_gas. A single VERIFY frame (flags 0x3, null target) self-approves
// execution and payment via the default verify code, so the transaction
// completes with the payer equal to the sender. Fees are set before
// signing: the canonical signature hash commits to them.
func settlementScenario(t *testing.T, tipCap, feeCap uint64) (*types.FrameTx, uint64) {
	t.Helper()
	ftx := frameTx(0, []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x3, Limits: mkFrameLimits(100_000, 300_000)},
	}, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Fees.GasTipCap = uint256.NewInt(tipCap)
	ftx.Fees.GasFeeCap = uint256.NewInt(feeCap)
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)
	return ftx, ftx.MaxGas()
}

// TestFrameSettlementPriorityFee verifies the EIP-8141 "Transaction
// settlement" rule: priority_fee_paid = min(max_priority_fee_per_gas *
// gas_used, max_cost - base_fee_paid). The per-gas rate is the
// user-specified max_priority_fee_per_gas (not the admission-adjusted
// aggregate divided by max_gas), so a payer whose fee cap binds the
// admission adjustment still pays the full requested tip on the gas
// actually used, bounded by the remaining max_cost.
func TestFrameSettlementPriorityFee(t *testing.T) {
	baseFee := big.NewInt(1)

	// maxGas is fee-independent; derive it once, then express every fee
	// quantity against it.
	_, maxGas := settlementScenario(t, 5, 1)

	t.Run("RoomCapBindsAtAdmission", func(t *testing.T) {
		// feeCap = maxGas + maxGas/2 makes the admission adjustment
		// maxPriorityFee = maxGas/2, i.e. floor(maxPriorityFee/maxGas) ==
		// 0 per gas. The specification still pays tipCap per gas used.
		ftx, _ := settlementScenario(t, 5, maxGas+maxGas/2)
		maxCost := new(big.Int).Mul(new(big.Int).SetUint64(maxGas), baseFee)
		maxCost.Add(maxCost, new(big.Int).SetUint64(maxGas/2)) // required_max_fee + adjusted priority
		balance := new(big.Int).Mul(maxCost, big.NewInt(10))
		sdb := mkState(types.GenesisAlloc{
			senderAddr:         {Balance: balance},
			settlementCoinbase: {Balance: big.NewInt(0)}, // must exist to receive the priority fee
		})
		res, err := applyFrameTxBaseFee(t, sdb, ftx, baseFee)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		gasUsed := new(big.Int).SetUint64(res.UsedGas)
		baseFeePaid := new(big.Int).Mul(gasUsed, baseFee)
		// spec: min(tipCap * gas_used, max_cost - base_fee_paid)
		wantPriority := new(big.Int).Mul(gasUsed, big.NewInt(5))
		if room := new(big.Int).Sub(maxCost, baseFeePaid); wantPriority.Cmp(room) > 0 {
			wantPriority.Set(room)
		}
		if got := sdb.GetBalance(settlementCoinbase).ToBig(); got.Cmp(wantPriority) != 0 {
			t.Fatalf("coinbase priority fee = %v, want %v (gasUsed=%v, maxGas=%v)", got, wantPriority, res.UsedGas, maxGas)
		}
		// Fee conservation: the payer's net debit is exactly
		// base_fee_paid + priority_fee_paid.
		payerDebit := new(big.Int).Sub(balance, sdb.GetBalance(senderAddr).ToBig())
		wantDebit := new(big.Int).Add(baseFeePaid, wantPriority)
		if payerDebit.Cmp(wantDebit) != 0 {
			t.Fatalf("payer debit = %v, want %v (base %v + priority %v)", payerDebit, wantDebit, baseFeePaid, wantPriority)
		}
		// The payer never pays more than tx.fees.max_fee.
		maxFee := new(big.Int).SetUint64(maxGas + maxGas/2)
		if payerDebit.Cmp(maxFee) > 0 {
			t.Fatalf("payer debit %v exceeds max_fee %v", payerDebit, maxFee)
		}
	})

	t.Run("SettlementRoomCapBinds", func(t *testing.T) {
		// feeCap leaves only ~2*gasEstimate of room above the base fee, so
		// the settlement-time cap (not the tip) bounds the priority fee.
		const gasEstimate = uint64(50_000)
		feeCap := maxGas + 2*gasEstimate
		ftx, _ := settlementScenario(t, 5, feeCap)
		maxCost := new(big.Int).SetUint64(feeCap) // adjustment room binds: maxCost == feeCap
		balance := new(big.Int).Mul(maxCost, big.NewInt(10))
		sdb := mkState(types.GenesisAlloc{
			senderAddr:         {Balance: balance},
			settlementCoinbase: {Balance: big.NewInt(0)},
		})
		res, err := applyFrameTxBaseFee(t, sdb, ftx, baseFee)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		gasUsed := new(big.Int).SetUint64(res.UsedGas)
		baseFeePaid := new(big.Int).Mul(gasUsed, baseFee)
		wantPriority := new(big.Int).Mul(gasUsed, big.NewInt(5))
		if room := new(big.Int).Sub(maxCost, baseFeePaid); wantPriority.Cmp(room) > 0 {
			wantPriority.Set(room)
		}
		if got := sdb.GetBalance(settlementCoinbase).ToBig(); got.Cmp(wantPriority) != 0 {
			t.Fatalf("coinbase priority fee = %v, want %v (gasUsed=%v)", got, wantPriority, res.UsedGas)
		}
	})

	t.Run("TipCapBoundsPerGas", func(t *testing.T) {
		// Generous room: the tip cap alone bounds the priority fee; the
		// per-gas rate must never exceed the user-specified tip.
		ftx, _ := settlementScenario(t, 5, 100*maxGas)
		maxCost := new(big.Int).SetUint64(100 * maxGas)
		balance := new(big.Int).Mul(maxCost, big.NewInt(10))
		sdb := mkState(types.GenesisAlloc{
			senderAddr:         {Balance: balance},
			settlementCoinbase: {Balance: big.NewInt(0)},
		})
		res, err := applyFrameTxBaseFee(t, sdb, ftx, baseFee)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		wantPriority := new(big.Int).Mul(new(big.Int).SetUint64(res.UsedGas), big.NewInt(5))
		if got := sdb.GetBalance(settlementCoinbase).ToBig(); got.Cmp(wantPriority) != 0 {
			t.Fatalf("coinbase priority fee = %v, want %v (gasUsed=%v)", got, wantPriority, res.UsedGas)
		}
	})
}
