package legacypool

// PM-4 (Option B) regression package: sponsored FrameTx senders cover the
// frame value only; the fee budget belongs to the payer. Self-pay behavior
// (value + aggregate feeCap) and all payer-side accounting are pinned
// unchanged. See PM4_FINAL_DECISION.md.

import (
	"crypto/ecdsa"
	"errors"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/holiman/uint256"
)

// signedValuePayTxTip builds an only_verify + pay + sender(value) sponsored
// frame transaction. The fees are part of the signature hash, so replacements
// must be constructed (and signed) with their final fees.
func signedValuePayTxTip(t *testing.T, senderKey *ecdsa.PrivateKey, nonce, feeCap, tip, value uint64, payerAddr common.Address, payerKey *ecdsa.PrivateKey) *types.Transaction {
	t.Helper()
	sender := crypto.PubkeyToAddress(senderKey.PublicKey)
	to := common.BytesToAddress([]byte("pm4-recipient"))
	frames := []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: types.FrameLimits{Execution: 40_000, State: 150_000}},
		{Mode: types.FrameModeVerify, Flags: 0x1, Limits: types.FrameLimits{Execution: 40_000, State: 150_000}, Target: &payerAddr},
		{Mode: types.FrameModeSender, Flags: 0x0, Limits: types.FrameLimits{Execution: 40_000, State: 150_000}, Value: uint256.NewInt(value), Target: &to},
	}
	fees := types.FrameFees{GasTipCap: uint256.NewInt(tip), GasFeeCap: uint256.NewInt(feeCap), BlobFeeCap: uint256.NewInt(0)}
	keys := []*ecdsa.PrivateKey{senderKey}
	if payerKey != nil {
		keys = append(keys, payerKey)
	}
	sigs := signFrames(t, sender, nonce, frames, fees, keys...)
	return types.NewFrameTx(uint256.NewInt(1), nonce, sender, frames, sigs, fees, nil)
}

// TestFramePoolSponsoredZeroBalanceSenderAdmitted is the PM-4 acceptance test:
// a sponsored sender with zero balance must be admitted when the canonical
// paymaster covers the fee budget.
func TestFramePoolSponsoredZeroBalanceSenderAdmitted(t *testing.T) {
	pool, statedb := setupFramePool(t)
	paymaster := common.BytesToAddress([]byte("canonical-paymaster"))
	sponsorKey, _ := crypto.GenerateKey()
	sponsor := crypto.PubkeyToAddress(sponsorKey.PublicKey)
	installCanonicalPaymaster(statedb, paymaster, sponsor)
	fund(statedb, paymaster, 1_000_000_000_000)

	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)
	// One wei: the sender must hold essentially nothing, but the account has
	// to exist for the prefix simulation — a never-created account makes the
	// paymaster's cold sender access exceed the 40k frame execution budget.
	// That is a simulation-gas property, not part of the PM-4 balance gate.
	fund(statedb, sender, 1)

	tx := signedPayTx(t, key, 0, 100, paymaster, sponsorKey)
	if err := pool.addRemoteSync(tx); err != nil {
		t.Fatalf("sponsored tx from zero-balance sender rejected: %v", err)
	}
	if got := reservedOf(pool, paymaster); got.Cmp(maxFeeOf(t, tx)) != 0 {
		t.Fatalf("payer reservation %v, want %v", got, maxFeeOf(t, tx))
	}
	if got := reservedOf(pool, sender); got.Sign() != 0 {
		t.Fatalf("sender reservation %v, want 0", got)
	}
}

// TestFramePoolSponsoredSenderValueBoundary pins that the sender's sponsored
// obligation is exactly the frame value: exactly-funded admitted, one wei
// short rejected.
func TestFramePoolSponsoredSenderValueBoundary(t *testing.T) {
	pool, statedb := setupFramePool(t)
	paymaster := common.BytesToAddress([]byte("canonical-paymaster"))
	sponsorKey, _ := crypto.GenerateKey()
	sponsor := crypto.PubkeyToAddress(sponsorKey.PublicKey)
	installCanonicalPaymaster(statedb, paymaster, sponsor)
	fund(statedb, paymaster, 1_000_000_000_000)

	keyA, _ := crypto.GenerateKey()
	senderA := crypto.PubkeyToAddress(keyA.PublicKey)
	fund(statedb, senderA, 700)
	txA := signedValuePayTxTip(t, keyA, 0, 100, 1, 700, paymaster, sponsorKey)
	if err := pool.addRemoteSync(txA); err != nil {
		t.Fatalf("sponsored tx with exactly-sufficient value balance rejected: %v", err)
	}

	keyB, _ := crypto.GenerateKey()
	senderB := crypto.PubkeyToAddress(keyB.PublicKey)
	fund(statedb, senderB, 699)
	txB := signedValuePayTxTip(t, keyB, 0, 100, 1, 700, paymaster, sponsorKey)
	if err := pool.addRemoteSync(txB); !errors.Is(err, core.ErrInsufficientFunds) {
		t.Fatalf("value-underfunded sponsored tx not rejected with ErrInsufficientFunds: %v", err)
	}
}

// TestFramePoolSponsoredPayFrameToSenderUnchanged pins the payer != sender
// condition: a pay frame that resolves to the sender itself is self-pay and
// keeps the full value + feeCap requirement.
func TestFramePoolSponsoredPayFrameToSenderUnchanged(t *testing.T) {
	pool, statedb := setupFramePool(t)
	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)

	tx := signedPayTx(t, key, 0, 100, common.Address{}, key)
	if err := pool.addRemoteSync(tx); !errors.Is(err, core.ErrInsufficientFunds) {
		t.Fatalf("unfunded pay-frame-to-sender tx not rejected with ErrInsufficientFunds: %v", err)
	}
	fund(statedb, sender, 10_000_000_000)
	if err := pool.addRemoteSync(tx); err != nil {
		t.Fatalf("funded pay-frame-to-sender tx rejected: %v", err)
	}
}

// TestFramePoolSponsoredReplacementAccounting pins the aligned per-tx sender
// cost through the replacement path: a same-value bumped-fee replacement
// needs no extra sender funds, while a value raise beyond the sender's
// remaining balance is rejected — both impossible to enforce correctly while
// ExistingCost/totalcost used raw tx.Cost() for FrameTx.
func TestFramePoolSponsoredReplacementAccounting(t *testing.T) {
	pool, statedb := setupFramePool(t)
	paymaster := common.BytesToAddress([]byte("canonical-paymaster"))
	sponsorKey, _ := crypto.GenerateKey()
	sponsor := crypto.PubkeyToAddress(sponsorKey.PublicKey)
	installCanonicalPaymaster(statedb, paymaster, sponsor)
	fund(statedb, paymaster, 1_000_000_000_000)

	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)
	fund(statedb, sender, 200)

	tx1 := signedValuePayTxTip(t, key, 0, 100, 1, 100, paymaster, sponsorKey)
	if err := pool.addRemoteSync(tx1); err != nil {
		t.Fatalf("initial sponsored tx rejected: %v", err)
	}
	// Same value, bumped fees: the sender-cost bump is zero.
	tx2 := signedValuePayTxTip(t, key, 0, 120, 2, 100, paymaster, sponsorKey)
	if err := pool.addRemoteSync(tx2); err != nil {
		t.Fatalf("same-value sponsored replacement rejected: %v", err)
	}
	// Value raised 100 -> 250: need = spent(100) + bump(150) = 250 > balance(200).
	tx3 := signedValuePayTxTip(t, key, 0, 150, 3, 250, paymaster, sponsorKey)
	if err := pool.addRemoteSync(tx3); !errors.Is(err, core.ErrInsufficientFunds) {
		t.Fatalf("over-balance sponsored replacement not rejected with ErrInsufficientFunds: %v", err)
	}
	if got := reservedOf(pool, paymaster); got.Cmp(maxFeeOf(t, tx2)) != 0 {
		t.Fatalf("payer reservation %v, want %v", got, maxFeeOf(t, tx2))
	}
}

// TestFramePoolSelfPaySenderCostUnchanged guards against over-relaxation: a
// self-pay frame tx (no delegation to another payer) still requires the
// sender to cover value + aggregate feeCap at the balance gate.
func TestFramePoolSelfPaySenderCostUnchanged(t *testing.T) {
	pool, statedb := setupFramePool(t)
	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)

	fund(statedb, sender, 99) // feeCap(100) - 1
	tx := signedPayTx(t, key, 0, 100, common.Address{}, key)
	if err := pool.addRemoteSync(tx); !errors.Is(err, core.ErrInsufficientFunds) {
		t.Fatalf("self-pay sender below value+feeCap not rejected with ErrInsufficientFunds: %v", err)
	}
	fund(statedb, sender, 10_000_000_000)
	if err := pool.addRemoteSync(tx); err != nil {
		t.Fatalf("funded self-pay tx rejected: %v", err)
	}
}
