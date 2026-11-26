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

package types

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/holiman/uint256"
)

var testFrameFeeSender = common.BytesToAddress([]byte("frame-fee-sender"))

// makeFeeTestTx builds a one-frame transaction. max_gas is fee-independent,
// so tests evaluate feeCap expressions against tx.MaxGas() after a first
// construction.
func makeFeeTestTx(tipCap, feeCap uint64) *Transaction {
	return NewFrameTx(
		uint256.NewInt(20118),
		0,
		testFrameFeeSender,
		[]Frame{
			{Mode: FrameModeVerify, Flags: 0x3, Limits: FrameLimits{Execution: 100_000, State: 0}},
		},
		[]FrameSignature{{Scheme: FrameSigSchemeSecp256k1}},
		FrameFees{
			GasTipCap:  uint256.NewInt(tipCap),
			GasFeeCap:  uint256.NewInt(feeCap),
			BlobFeeCap: uint256.NewInt(0),
		},
		nil,
	)
}

// TestFrameTxEffectiveGasPrice verifies the EIP-8141 per-gas price per the
// "Fee budget" rule: base_fee_per_gas + max_priority_fee // max_gas, where
// max_priority_fee is the room-limited aggregate min(tipCap * max_gas,
// max_fee - required_max_fee). EIP-8141 has no per-gas fee cap ("the tip
// cannot be limited to max_fee_per_gas - base_fee_per_gas per gas as under
// EIP-1559"), so the EIP-1559 min(tipCap, feeCap - baseFee) + baseFee formula
// does not apply. The payer "pays ... exactly this much ... per unit of
// gas_used ... when max_fee covers the full tip", making it the
// receipt-effective gas price.
func TestFrameTxEffectiveGasPrice(t *testing.T) {
	run := func(t *testing.T, baseFee *big.Int, tipCap uint64, feeCapOf func(maxGas uint64) uint64, wantOf func(maxGas uint64) *big.Int) {
		t.Helper()
		maxGas := makeFeeTestTx(tipCap, 1).inner.(*FrameTx).MaxGas()
		tx := makeFeeTestTx(tipCap, feeCapOf(maxGas))
		want := wantOf(maxGas)
		got := tx.inner.(*FrameTx).effectiveGasPrice(new(big.Int), baseFee)
		if got.Cmp(want) != 0 {
			t.Fatalf("effectiveGasPrice = %v, want %v (maxGas=%v)", got, want, maxGas)
		}
	}

	t.Run("ZeroBaseFee", func(t *testing.T) {
		// Fee cap far from binding: the price is the user-specified tip.
		// The EIP-1559 formula would return the fee cap itself here.
		run(t, nil, 5,
			func(maxGas uint64) uint64 { return 100 * maxGas },
			func(maxGas uint64) *big.Int { return big.NewInt(5) })
	})
	t.Run("NonZeroBaseFeeNoBinding", func(t *testing.T) {
		run(t, big.NewInt(7), 5,
			func(maxGas uint64) uint64 { return 7*maxGas + 5*maxGas },
			func(maxGas uint64) *big.Int { return big.NewInt(12) })
	})
	t.Run("FeeCapBinds", func(t *testing.T) {
		// Room of 2*maxGas (exact division): price is base fee + 2.
		run(t, big.NewInt(7), 5,
			func(maxGas uint64) uint64 { return 7*maxGas + 2*maxGas },
			func(maxGas uint64) *big.Int { return big.NewInt(9) })
	})
	t.Run("BoundaryFullTip", func(t *testing.T) {
		// feeCap == required + tipCap*maxGas exactly: full tip applies.
		run(t, big.NewInt(7), 5,
			func(maxGas uint64) uint64 { return 7*maxGas + 5*maxGas },
			func(maxGas uint64) *big.Int { return big.NewInt(12) })
	})
	t.Run("BoundaryZeroTip", func(t *testing.T) {
		// feeCap == required exactly: zero tip room.
		run(t, big.NewInt(7), 5,
			func(maxGas uint64) uint64 { return 7 * maxGas },
			func(maxGas uint64) *big.Int { return big.NewInt(7) })
	})
	t.Run("FloorToZero", func(t *testing.T) {
		// Room of maxGas/2 floors to zero per gas: bare base fee
		// (documents the integer-division floor of the aggregate).
		run(t, big.NewInt(7), 5,
			func(maxGas uint64) uint64 { return 7*maxGas + maxGas/2 },
			func(maxGas uint64) *big.Int { return big.NewInt(7) })
	})
}

// TestFrameTxReceiptEffectiveGasPrice verifies the receipt derivation path
// (DeriveFields) surfaces the same value, and that it appears in the RPC
// JSON form.
func TestFrameTxReceiptEffectiveGasPrice(t *testing.T) {
	baseFee := big.NewInt(1000)
	const tipCap, roomPerGas = uint64(5), uint64(3)

	maxGas := makeFeeTestTx(tipCap, 1).inner.(*FrameTx).MaxGas()
	feeCap := uint64(baseFee.Int64())*maxGas + roomPerGas*maxGas
	tx := makeFeeTestTx(tipCap, feeCap)

	signer := NewFrameTxSigner(uint256.NewInt(20118).ToBig())
	receipt := &Receipt{Type: FrameTxType, Status: 1, CumulativeGasUsed: 21_000}
	receipt.DeriveFields(signer, DeriveReceiptContext{
		Tx:      tx,
		GasUsed: 21_000,
		BaseFee: baseFee,
	})
	if want := big.NewInt(1003); receipt.EffectiveGasPrice == nil || receipt.EffectiveGasPrice.Cmp(want) != 0 {
		t.Fatalf("derived EffectiveGasPrice = %v, want %v", receipt.EffectiveGasPrice, want)
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("marshal receipt: %v", err)
	}
	if !strings.Contains(string(raw), `"effectiveGasPrice":"0x3eb"`) { // 1003
		t.Fatalf("RPC JSON missing effectiveGasPrice 0x3eb: %s", raw)
	}
}
