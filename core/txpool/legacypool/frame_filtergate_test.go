// Copyright 2026 The go-ethereum Authors
//
// Fork-gate regression tests for EIP-8141 frame-transaction pool routing
// (Phase B). The static LegacyPool.FilterType gate must be fork-aware:
//
//   - FrameTx fork ACTIVE at the head: type 0x06 routes into the pool and a
//     valid frame tx is admitted (signature, fee, nonce, and sponsorship
//     validation still enforced downstream).
//   - FrameTx fork INACTIVE: type 0x06 is rejected at the gate, with the same
//     external error as before (tx type not supported).
//   - Legacy transactions behave identically on both sides.
//   - Invalid frame txs (bad signature) are rejected even with the fork
//     active.
//
// These tests only exercise synthetic in-process pools; no network I/O.

package legacypool

import (
	"errors"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
)

func TestFrameFilterTypeForkGate(t *testing.T) {
	active, _ := setupFramePool(t)          // FrameTxTime = 0: active at every head time
	inactive, _ := setupForkInactivePool(t) // FrameTxTime nil: fork inactive

	// Static type routing must be fork-aware.
	if !active.FilterType(types.FrameTxType) {
		t.Fatal("fork-active pool: FilterType(0x06) must be true")
	}
	if inactive.FilterType(types.FrameTxType) {
		t.Fatal("fork-inactive pool: FilterType(0x06) must be false")
	}
	// Non-frame types unchanged on both sides.
	for _, kind := range []byte{types.LegacyTxType, types.AccessListTxType, types.DynamicFeeTxType, types.SetCodeTxType} {
		if !active.FilterType(kind) || !inactive.FilterType(kind) {
			t.Fatalf("type %d must remain routable on both pools", kind)
		}
	}
	if active.FilterType(0x7f) || inactive.FilterType(0x7f) {
		t.Fatal("unknown type 0x7f must stay unroutable")
	}

	// Transaction-level filter agrees with the type-level gate.
	key, _ := crypto.GenerateKey()
	frameTx := signedPayTx(t, key, 0, 100, common.Address{}, key)
	if !active.Filter(frameTx) {
		t.Fatal("fork-active pool: Filter(frame tx) must be true")
	}
	if inactive.Filter(frameTx) {
		t.Fatal("fork-inactive pool: Filter(frame tx) must be false")
	}
}

func TestFrameAdmissionForkGate(t *testing.T) {
	active, activeState := setupFramePool(t)
	inactive, inactiveState := setupForkInactivePool(t)

	key, _ := crypto.GenerateKey()
	addr := crypto.PubkeyToAddress(key.PublicKey)
	fund(activeState, addr, 1_000_000_000)
	fund(inactiveState, addr, 1_000_000_000)

	// Fork active: valid self-sponsored frame tx admitted.
	tx := signedPayTx(t, key, 0, 100, common.Address{}, key)
	if err := active.addRemoteSync(tx); err != nil {
		t.Fatalf("fork-active pool rejected valid frame tx: %v", err)
	}
	if !active.Has(tx.Hash()) {
		t.Fatal("fork-active pool: admitted frame tx not found in pool")
	}

	// Fork inactive: the same tx is rejected with the unsupported-type error.
	err := inactive.addRemoteSync(tx)
	if err == nil {
		t.Fatal("fork-inactive pool must reject frame tx")
	}
	if !errors.Is(err, core.ErrTxTypeNotSupported) {
		t.Fatalf("fork-inactive pool rejection must wrap core.ErrTxTypeNotSupported, got %v", err)
	}
	if inactive.Has(tx.Hash()) {
		t.Fatal("fork-inactive pool: rejected frame tx must not be pooled")
	}

	// Legacy compatibility on both sides: a plain transfer is admitted.
	legacyKey, _ := crypto.GenerateKey()
	fund(activeState, crypto.PubkeyToAddress(legacyKey.PublicKey), 1_000_000_000)
	legacyTx := transaction(0, 100_000, legacyKey)
	if err := active.addRemoteSync(legacyTx); err != nil {
		t.Fatalf("fork-active pool rejected legacy tx: %v", err)
	}
	fund(inactiveState, crypto.PubkeyToAddress(legacyKey.PublicKey), 1_000_000_000)
	legacyTx2 := transaction(0, 100_000, legacyKey)
	if err := inactive.addRemoteSync(legacyTx2); err != nil {
		t.Fatalf("fork-inactive pool rejected legacy tx: %v", err)
	}

	// Fork active but invalid: corrupted frame signature must still be
	// rejected (the gate opening must not bypass signature validation).
	bad := signedPayTx(t, key, 1, 100, common.Address{}, key)
	{
		// Re-sign with a different key than the sender entry claims: rebuild
		// the payload with a mismatched signature entry.
		other, _ := crypto.GenerateKey()
		bad = signedPayTx(t, key, 1, 100, common.Address{}, other) // payer key mismatch
	}
	if err := active.addRemoteSync(bad); err == nil {
		t.Fatal("fork-active pool must reject frame tx with mismatched payer signature")
	}
}

// TestFrameAdmissionXDPoSDifficultyHeader is the regression test for the
// live run2 rejection ("type 6 rejected, pool not yet in FrameTx fork").
// XDPoS headers always carry difficulty 1 (out-of-turn) or 2 (in-turn), so
// the Rules.isMerge signal (head.Difficulty.Sign() == 0) is permanently
// false on XDC chains. ValidateTransaction's rules.IsFrameTx check must
// still admit FrameTx when FrameTxTime is active; before the fix the merge
// gate in ChainConfig.Rules made this reject regardless of fork state.
func TestFrameAdmissionXDPoSDifficultyHeader(t *testing.T) {
	pool, statedb := setupFramePool(t)
	key, _ := crypto.GenerateKey()
	fund(statedb, crypto.PubkeyToAddress(key.PublicKey), 1_000_000_000_000)

	// Swap the pool's current head for an XDPoS-style one: non-zero
	// difficulty (in-turn = 2), same number/time.
	head := pool.currentHead.Load()
	xposHead := *head
	xposHead.Difficulty = big.NewInt(2)
	pool.currentHead.Store(&xposHead)

	tx := signedPayTx(t, key, 0, 100, common.Address{}, key)
	if err := pool.addRemoteSync(tx); err != nil {
		t.Fatalf("fork-active pool with XDPoS difficulty header rejected valid frame tx: %v", err)
	}
	if !pool.Has(tx.Hash()) {
		t.Fatal("frame tx not present in pool after admission")
	}

	// Same shape pre-fork must still reject: rebuild the pool with fork
	// inactive and a non-zero difficulty head.
	inactive, instate := setupForkInactivePool(t)
	ihead := inactive.currentHead.Load()
	if ihead == nil {
		// fork-inactive pool may not have synced a head yet; push a minimal one
		ihead = &types.Header{Number: big.NewInt(1), Time: 1, Difficulty: big.NewInt(1)}
		inactive.currentHead.Store(ihead)
	} else {
		ih := *ihead
		ih.Difficulty = big.NewInt(1)
		inactive.currentHead.Store(&ih)
	}
	_ = instate
	ikey, _ := crypto.GenerateKey()
	fund(instate, crypto.PubkeyToAddress(ikey.PublicKey), 1_000_000_000_000)
	itx := signedPayTx(t, ikey, 0, 100, common.Address{}, ikey)
	if err := inactive.addRemoteSync(itx); err == nil {
		t.Fatal("pre-fork pool must reject frame tx even with XDPoS difficulty header")
	} else if !errors.Is(err, core.ErrTxTypeNotSupported) {
		t.Fatalf("pre-fork rejection should be ErrTxTypeNotSupported, got: %v", err)
	}
}
