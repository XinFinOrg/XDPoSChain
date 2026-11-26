// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// frame_fee_divergence_test.go — EIP-8141 "Fee budget" conformance tests.
//
// Historical context: the run4 isolated chain-81411 rehearsal (block 13, tx
// 0xb9e902cc…92929e, evidence: mission2-final-20261102-1247/) exposed a fee
// divergence — receipt effectiveGasPrice 12.5 Gwei vs sender balance delta
// reflecting 13.5 Gwei/gas. Root cause: executeFrameTx's admission block
// misread tx.fees.max_fee as a PER-GAS cap (maxFeeTotal = feeCap × maxGas,
// and a feeCap-vs-baseFee comparison), while the EIP-8141 text defines
// max_fee as "a single budget covering execution, state, and blob gas"
// (required_max_fee = max_gas × base_fee_per_gas; tx invalid if
// max_fee < required_max_fee).
//
// Decision (authoritative source: https://eips.ethereum.org/EIPS/eip-8141,
// "Fee budget" + "Transaction settlement" sections, fetched 2026-11-02):
// the aggregate model is normative. The admission block was fixed to the
// spec formulas; TransactionToMessage and calcEffectiveGasTip gained
// FrameTx-specific branches; txpool validation checks the aggregate budget
// against the head base fee.
//
// Spec nuance pinned here: charged == gas_used × effective_gas_price ONLY
// when max_fee covers the full tip. In the room-limited band the normative
// settlement formula charges priority_fee_paid = min(tipCap × gas_used,
// max_cost − base_fee_paid), which can exceed the receipt's per-gas
// effective_gas_price (= GASPRICE = base_fee + max_priority_fee // max_gas).
// Both bands are pinned to hand-computed spec values below.
package core

import (
	"errors"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/holiman/uint256"
)

// frameFeeScenario builds a self-verify (VERIFY, flags 0x3, null target)
// frame transaction whose fees are set BEFORE signing, as the canonical
// signature hash commits to them. Returns the signed tx wrapper and maxGas.
func frameFeeScenario(t *testing.T, tipCap, feeCap uint64) *types.FrameTx {
	t.Helper()
	ftx := frameTx(0, []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x3, Limits: mkFrameLimits(100_000, 300_000)},
	}, []types.FrameSignature{{Scheme: types.FrameSigSchemeSecp256k1}})
	ftx.Fees.GasTipCap = uint256.NewInt(tipCap)
	ftx.Fees.GasFeeCap = uint256.NewInt(feeCap)
	ftx.Fees.BlobFeeCap = uint256.NewInt(0)
	ftx.Signatures = defaultApproveSigs(t, senderKey, ftx)
	return ftx
}

// TestFrameTxFeeFullTipBand: max_fee covers required_max_fee + the full tip
// (tipCap × max_gas). Spec: charged per gas == receipt effective_gas_price
// == GASPRICE == base_fee + tipCap. This is the equality case.
func TestFrameTxFeeFullTipBand(t *testing.T) {
	baseFee := big.NewInt(12_500_000_000) // 12.5 Gwei
	const tipCap = uint64(1_000_000_000)  // 1 Gwei

	// Build once to learn maxGas, then set the spec-valid aggregate budget.
	probe := frameFeeScenario(t, tipCap, 1)
	maxGas := probe.MaxGas()
	required := probe.RequiredMaxFee(baseFee, nil)
	feeCap := new(big.Int).Add(required, new(big.Int).Mul(new(big.Int).SetUint64(maxGas), new(big.Int).SetUint64(tipCap)))

	ftx := frameFeeScenario(t, tipCap, feeCap.Uint64())
	tx := types.NewTx(ftx)

	// 1. msg.GasPrice (RPC/eth_call charging intent) == receipt value.
	msg, err := TransactionToMessage(tx, frameSgn, baseFee)
	if err != nil {
		t.Fatalf("TransactionToMessage: %v", err)
	}
	effective := ftx.EffectiveGasPrice(baseFee)
	if msg.GasPrice.ToBig().Cmp(effective) != 0 {
		t.Fatalf("msg.GasPrice = %v, want %v", msg.GasPrice.ToBig(), effective)
	}
	receipt := &types.Receipt{Type: types.FrameTxType, Status: 1}
	receipt.DeriveFields(frameSgn, types.DeriveReceiptContext{Tx: tx, GasUsed: 1, BaseFee: baseFee})
	if receipt.EffectiveGasPrice.Cmp(effective) != 0 {
		t.Fatalf("receipt effectiveGasPrice = %v, want %v", receipt.EffectiveGasPrice, effective)
	}
	// Full-tip band: per-gas price is base_fee + tipCap.
	wantPrice := big.NewInt(13_500_000_000)
	if effective.Cmp(wantPrice) != 0 {
		t.Fatalf("effective price = %v, want %v", effective, wantPrice)
	}

	// 2. Execution-level settlement: the self-paying sender is debited
	// exactly gas_used × effective; coinbase receives gas_used × tipCap.
	balance := new(big.Int).Mul(feeCap, big.NewInt(3))
	sdb := mkState(types.GenesisAlloc{
		senderAddr:         {Balance: balance},
		settlementCoinbase: {Balance: big.NewInt(0)},
	})
	res, err := applyFrameTxBaseFee(t, sdb, ftx, baseFee)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	gasUsed := new(big.Int).SetUint64(res.UsedGas)
	wantDebit := new(big.Int).Mul(gasUsed, effective)
	debit := new(big.Int).Sub(balance, sdb.GetBalance(senderAddr).ToBig())
	if debit.Cmp(wantDebit) != 0 {
		t.Fatalf("payer debit = %v, want %v (gasUsed %v × %v)", debit, wantDebit, gasUsed, effective)
	}
	wantTip := new(big.Int).Mul(gasUsed, new(big.Int).SetUint64(tipCap))
	if got := sdb.GetBalance(settlementCoinbase).ToBig(); got.Cmp(wantTip) != 0 {
		t.Fatalf("coinbase tip = %v, want %v", got, wantTip)
	}
}

// TestFrameTxFeeRoomLimitedBand: max_fee covers required_max_fee + only half
// the full tip. Spec pins BOTH the receipt price (GASPRICE formula) and the
// settlement charge (min formula) — they intentionally differ here.
func TestFrameTxFeeRoomLimitedBand(t *testing.T) {
	baseFee := big.NewInt(12_500_000_000)
	const tipCap = uint64(2_000_000_000) // 2 Gwei

	probe := frameFeeScenario(t, tipCap, 1)
	maxGas := probe.MaxGas()
	required := probe.RequiredMaxFee(baseFee, nil)
	tipRoom := new(big.Int).Mul(new(big.Int).SetUint64(maxGas/2), new(big.Int).SetUint64(tipCap))
	feeCap := new(big.Int).Add(required, tipRoom)

	ftx := frameFeeScenario(t, tipCap, feeCap.Uint64())
	tx := types.NewTx(ftx)

	// Receipt / msg price: base_fee + tipRoom // maxGas (integer floor
	// division per the spec formula).
	effective := ftx.EffectiveGasPrice(baseFee)
	wantPrice := new(big.Int).Add(baseFee, new(big.Int).Div(new(big.Int).Set(tipRoom), new(big.Int).SetUint64(maxGas)))
	if effective.Cmp(wantPrice) != 0 {
		t.Fatalf("effective price = %v, want %v", effective, wantPrice)
	}
	msg, err := TransactionToMessage(tx, frameSgn, baseFee)
	if err != nil {
		t.Fatalf("TransactionToMessage: %v", err)
	}
	if msg.GasPrice.ToBig().Cmp(effective) != 0 {
		t.Fatalf("msg.GasPrice = %v, want %v", msg.GasPrice.ToBig(), effective)
	}

	// Settlement: priority_fee_paid = min(tipCap × gas_used,
	// max_cost − base_fee_paid) = tipCap × gas_used for gas_used ≪ maxGas,
	// so the payer's per-gas charge is base_fee + tipCap — MORE than the
	// receipt reports. Both values pinned to spec formulas.
	balance := new(big.Int).Mul(feeCap, big.NewInt(3))
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
	wantPriority := new(big.Int).Mul(gasUsed, new(big.Int).SetUint64(tipCap))
	if room := new(big.Int).Sub(feeCap, baseFeePaid); wantPriority.Cmp(room) > 0 {
		wantPriority.Set(room)
	}
	debit := new(big.Int).Sub(balance, sdb.GetBalance(senderAddr).ToBig())
	wantDebit := new(big.Int).Add(baseFeePaid, wantPriority)
	if debit.Cmp(wantDebit) != 0 {
		t.Fatalf("payer debit = %v, want %v (base %v + priority %v)", debit, wantDebit, baseFeePaid, wantPriority)
	}
	// The band distinction: charged per-gas exceeds the receipt price.
	chargedPerGas := new(big.Int).Div(wantDebit, gasUsed)
	if chargedPerGas.Cmp(effective) <= 0 {
		t.Fatalf("room-limited band: charged per-gas %v should exceed receipt price %v", chargedPerGas, effective)
	}
	// Conservation: payer never pays more than tx.fees.max_fee.
	if debit.Cmp(feeCap) > 0 {
		t.Fatalf("payer debit %v exceeds max_fee %v", debit, feeCap)
	}
}

// TestFrameTxFeeBelowRequiredRejected: max_fee below required_max_fee is
// transaction-invalid before any frame executes (EIP-8141 "Fee budget").
func TestFrameTxFeeBelowRequiredRejected(t *testing.T) {
	baseFee := big.NewInt(12_500_000_000)
	probe := frameFeeScenario(t, 1_000_000_000, 1)
	required := probe.RequiredMaxFee(baseFee, nil)
	feeCap := new(big.Int).Sub(required, big.NewInt(1))

	ftx := frameFeeScenario(t, 1_000_000_000, feeCap.Uint64())
	sdb := mkState(types.GenesisAlloc{
		senderAddr:         {Balance: new(big.Int).Mul(required, big.NewInt(3))},
		settlementCoinbase: {Balance: big.NewInt(0)},
	})
	_, err := applyFrameTxBaseFee(t, sdb, ftx, baseFee)
	if err == nil {
		t.Fatal("expected ErrFeeCapTooLow for max_fee below required_max_fee")
	}
	if !errors.Is(err, ErrFeeCapTooLow) {
		t.Fatalf("error = %v, want wrap of ErrFeeCapTooLow", err)
	}
	// Invalidity is pre-execution: no nonce consumed, no balance moved.
	if nonce := sdb.GetNonce(senderAddr); nonce != 0 {
		t.Fatalf("nonce changed to %d despite invalid fee budget", nonce)
	}
}

// TestFrameTxFeeLegacyUnaffected: non-frame transactions keep the EIP-1559
// per-gas formula in TransactionToMessage.
func TestFrameTxFeeLegacyUnaffected(t *testing.T) {
	baseFee := big.NewInt(12_500_000_000)
	key, _ := crypto.GenerateKey()
	legacy := types.NewTx(&types.DynamicFeeTx{
		ChainID:   big.NewInt(1),
		Nonce:     0,
		GasTipCap: big.NewInt(1_000_000_000),
		GasFeeCap: big.NewInt(30_000_000_000),
		Gas:       21_000,
		To:        &senderAddr,
		Value:     big.NewInt(0),
	})
	signed, err := types.SignTx(legacy, frameSgn, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	msg, err := TransactionToMessage(signed, frameSgn, baseFee)
	if err != nil {
		t.Fatalf("TransactionToMessage: %v", err)
	}
	// min(feeCap, baseFee + tipCap) = 13.5 Gwei — unchanged 1559 semantics.
	want := big.NewInt(13_500_000_000)
	if msg.GasPrice.ToBig().Cmp(want) != 0 {
		t.Fatalf("legacy msg.GasPrice = %v, want %v (1559 formula)", msg.GasPrice.ToBig(), want)
	}
}
