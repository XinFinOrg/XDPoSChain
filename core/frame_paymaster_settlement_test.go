// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// frame_paymaster_settlement_test.go — execution-level (EVM-boundary) tests
// for EIP-8141 paymaster sponsorship, closing the gap identified in
// eip8141-completion-gap-audit-20261102: pool/validation-level paymaster
// tests existed, but no test proved the intended paymaster-versus-sender
// balance effects at settlement.
//
// Fee semantics follow the authoritative EIP-8141 "Fee budget" / "Transaction
// settlement" text (aggregate max_fee budget; see frame_fee_divergence_test.go
// header for the decision record). Scenarios here use the full-tip band where
// charged == gas_used × effective_gas_price.
package core

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/holiman/uint256"
)

// canonicalPaymasterRuntime and CanonicalPaymasterSlotSigner are defined in
// frame_validation_test.go / frame_validation.go (355-byte runtime published
// in ethereum/EIPs PR #12041).

// sponsoredScenario builds a three-frame sponsored transaction:
// frame 0 VERIFY (APPROVE_EXECUTION, null target, sender signature),
// frame 1 VERIFY (APPROVE_PAYMENT, canonical paymaster target, sponsor
// signature), frame 2 SENDER (value transfer to recipient, paid by sender).
// Fees are aggregate per EIP-8141 and are set before signing. Returns the
// signed payload, its aggregate fee budget, the recipient, and the sponsor
// address (paymaster storage slot 0 must authorize it).
func sponsoredScenario(t *testing.T, paymaster common.Address, value, baseFeeWei, tipCapWei uint64) (*types.FrameTx, *big.Int, common.Address, common.Address) {
	t.Helper()
	sponsorKey, _ := crypto.GenerateKey()
	sponsor := crypto.PubkeyToAddress(sponsorKey.PublicKey)
	recipient := common.BytesToAddress([]byte("pm-recipient"))

	frames := []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: mkFrameLimits(100_000, 150_000)},
		{Mode: types.FrameModeVerify, Flags: 0x1, Limits: mkFrameLimits(100_000, 150_000), Target: &paymaster},
		{Mode: types.FrameModeSender, Flags: 0x0, Limits: mkFrameLimits(100_000, 500_000), Target: &recipient, Value: uint256.NewInt(value)},
	}
	ftx := frameTx(0, frames, make([]types.FrameSignature, 3))

	// Finalize everything the signature hash commits to BEFORE computing
	// fees: the Signer fields and the fee values both feed intrinsic gas
	// (via MaxGas) and the canonical hash.
	ftx.Signatures[0].Scheme = types.FrameSigSchemeSecp256k1
	ftx.Signatures[0].Signer = senderAddr.Bytes()
	ftx.Signatures[1].Scheme = types.FrameSigSchemeSecp256k1
	ftx.Signatures[1].Signer = sponsor.Bytes()
	ftx.Signatures[2].Scheme = types.FrameSigSchemeSecp256k1
	ftx.Signatures[2].Signer = senderAddr.Bytes()

	// Pass 1: provisional fees, then sign — so the signature bytes exist and
	// MaxGas (which includes per-signature intrinsic costs over the real
	// signature byte lengths) is final.
	ftx.Fees.GasTipCap = uint256.NewInt(tipCapWei)
	ftx.Fees.GasFeeCap = uint256.NewInt(0)
	ftx.Fees.BlobFeeCap = uint256.NewInt(0)
	signAll := func() {
		for i := range ftx.Signatures {
			key := senderKey
			addr := senderAddr
			if i == 1 {
				key, addr = sponsorKey, sponsor
			}
			ftx.Signatures[i].Signature = signFrameEntry(t, ftx, key, addr).Signature
		}
	}
	signAll()

	// Pass 2: the aggregate budget from the FINAL maxGas (fees do not
	// affect intrinsic gas, so maxGas is stable from here), then re-sign —
	// the canonical hash commits to the fees.
	baseFee := new(big.Int).SetUint64(baseFeeWei)
	required := ftx.RequiredMaxFee(baseFee, nil)
	feeCap := new(big.Int).Add(required, new(big.Int).Mul(new(big.Int).SetUint64(ftx.MaxGas()), new(big.Int).SetUint64(tipCapWei)))
	ftx.Fees.GasFeeCap = uint256.MustFromBig(feeCap)
	signAll()
	return ftx, feeCap, recipient, sponsor
}

// TestFramePaymasterSettlement: the canonical paymaster pays the fee; the
// sender pays only the SENDER-frame value and is not charged for gas.
func TestFramePaymasterSettlement(t *testing.T) {
	baseFeeWei := uint64(12_500_000_000) // 12.5 Gwei
	tipCapWei := uint64(1_000_000_000)   // 1 Gwei
	const value = uint64(7_000_000_000)  // 7 Gwei transferred to recipient

	paymaster := common.BytesToAddress([]byte("pm-canonical-instance"))
	ftx, feeCap, recipient, sponsor := sponsoredScenario(t, paymaster, value, baseFeeWei, tipCapWei)
	baseFee := new(big.Int).SetUint64(baseFeeWei)

	// Sender holds only enough for the value transfer; the paymaster holds
	// the max_cost budget. Neither could pay the other's part.
	sdb := mkState(types.GenesisAlloc{
		senderAddr: {Balance: new(big.Int).Mul(new(big.Int).SetUint64(value), big.NewInt(4))},
		paymaster: {
			Balance: new(big.Int).Mul(feeCap, big.NewInt(2)),
			Code:    canonicalPaymasterRuntime,
			Storage: map[common.Hash]common.Hash{
				CanonicalPaymasterSlotSigner: common.BytesToHash(sponsor.Bytes()),
			},
		},
		settlementCoinbase: {Balance: big.NewInt(0)},
	})

	pmBefore := sdb.GetBalance(paymaster).ToBig()
	senderBefore := sdb.GetBalance(senderAddr).ToBig()

	res, err := applyFrameTxBaseFee(t, sdb, ftx, baseFee)
	if err != nil {
		t.Fatalf("execute sponsored tx: %v", err)
	}
	gasUsed := new(big.Int).SetUint64(res.UsedGas)
	effective := ftx.EffectiveGasPrice(baseFee)

	// Paymaster net debit == gas_used × effective (full-tip band).
	pmDebit := new(big.Int).Sub(pmBefore, sdb.GetBalance(paymaster).ToBig())
	wantPmDebit := new(big.Int).Mul(gasUsed, effective)
	if pmDebit.Cmp(wantPmDebit) != 0 {
		t.Fatalf("paymaster debit = %v, want %v (gasUsed %v × %v)", pmDebit, wantPmDebit, gasUsed, effective)
	}
	// Sender debit == exactly the SENDER-frame value: no gas charge.
	senderDebit := new(big.Int).Sub(senderBefore, sdb.GetBalance(senderAddr).ToBig())
	if senderDebit.Cmp(new(big.Int).SetUint64(value)) != 0 {
		t.Fatalf("sender debit = %v, want only the value transfer %v (recipient=%v sender=%v)",
			senderDebit, value, sdb.GetBalance(recipient).ToBig(), sdb.GetBalance(senderAddr).ToBig())
	}
	// Recipient received the value.
	if got := sdb.GetBalance(recipient).ToBig(); got.Cmp(new(big.Int).SetUint64(value)) != 0 {
		t.Fatalf("recipient balance = %v, want %v", got, value)
	}
	// Coinbase received the tip.
	wantTip := new(big.Int).Mul(gasUsed, new(big.Int).SetUint64(tipCapWei))
	if got := sdb.GetBalance(settlementCoinbase).ToBig(); got.Cmp(wantTip) != 0 {
		t.Fatalf("coinbase tip = %v, want %v", got, wantTip)
	}
	// Sender nonce incremented exactly once (by APPROVE).
	if nonce := sdb.GetNonce(senderAddr); nonce != 1 {
		t.Fatalf("sender nonce = %d, want 1", nonce)
	}
}

// TestFramePaymasterInsufficientFunds: a paymaster whose balance is below
// max_cost cannot approve payment; the transaction is invalid and the whole
// transaction (including the sender's value frame) unrolls with no balance
// or nonce effects.
func TestFramePaymasterInsufficientFunds(t *testing.T) {
	baseFeeWei := uint64(12_500_000_000)
	tipCapWei := uint64(1_000_000_000)
	const value = uint64(7_000_000_000)

	paymaster := common.BytesToAddress([]byte("pm-broke-instance"))
	ftx, feeCap, _, sponsor := sponsoredScenario(t, paymaster, value, baseFeeWei, tipCapWei)

	sdb := mkState(types.GenesisAlloc{
		senderAddr: {Balance: new(big.Int).Mul(new(big.Int).SetUint64(value), big.NewInt(4))},
		paymaster: {
			Balance: new(big.Int).Sub(feeCap, big.NewInt(1)), // one wei short of max_cost
			Code:    canonicalPaymasterRuntime,
			Storage: map[common.Hash]common.Hash{
				CanonicalPaymasterSlotSigner: common.BytesToHash(sponsor.Bytes()),
			},
		},
		settlementCoinbase: {Balance: big.NewInt(0)},
	})

	pmBefore := sdb.GetBalance(paymaster).ToBig()
	senderBefore := sdb.GetBalance(senderAddr).ToBig()

	_, err := applyFrameTxBaseFee(t, sdb, ftx, new(big.Int).SetUint64(baseFeeWei))
	if err == nil {
		t.Fatal("expected sponsored tx to fail: paymaster balance below max_cost")
	}
	// Full transaction unroll: no balance or nonce effects anywhere.
	if got := sdb.GetBalance(paymaster).ToBig(); got.Cmp(pmBefore) != 0 {
		t.Fatalf("paymaster balance changed despite unroll: %v → %v", pmBefore, got)
	}
	if got := sdb.GetBalance(senderAddr).ToBig(); got.Cmp(senderBefore) != 0 {
		t.Fatalf("sender balance changed despite unroll: %v → %v", senderBefore, got)
	}
	if nonce := sdb.GetNonce(senderAddr); nonce != 0 {
		t.Fatalf("sender nonce changed to %d despite unroll", nonce)
	}
}
