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

package legacypool

import (
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/txpool"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/event"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

// frameTestApproveCode approves the given APPROVE scope and stops; it is the
// minimal paymaster body used by the frame test fixtures (same bytecode as
// core.frameApproveCode).
func frameTestApproveCode(scope byte) []byte {
	return []byte{0x60, scope, 0x60, 0x00, 0x60, 0x00, 0xaa, 0x00}
}

// setupFramePool returns a pool with the FrameTx fork active at the test
// head, backed by a fresh state database the test can pre-fund. The head is
// reset to an explicit zero-base-fee header: the shared testBlockChain head
// carries no base fee, which this fork prices as the initial base fee and
// would inflate the simulated MaxCost beyond test balances.
func setupFramePool(t *testing.T) (*LegacyPool, *state.StateDB) {
	t.Helper()
	cfg := *params.TestChainConfig
	cfg.FrameTxTime = new(uint64) // 0: fork active at every timestamp
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	blockchain := newTestBlockChain(&cfg, 10_000_000, statedb, new(event.Feed))
	pool := New(testTxPoolConfig, blockchain)
	if err := pool.Init(testTxPoolConfig.PriceLimit, blockchain.CurrentBlock(), newReserver()); err != nil {
		t.Fatalf("failed to init pool: %v", err)
	}
	<-pool.initDoneCh
	head := &types.Header{Number: big.NewInt(0), Time: 0, Difficulty: big.NewInt(0), GasLimit: 10_000_000, BaseFee: big.NewInt(0)}
	pool.Reset(head, head)
	t.Cleanup(func() { pool.Close() })
	return pool, statedb
}

func fund(statedb *state.StateDB, addr common.Address, amount uint64) {
	statedb.SetBalance(addr, uint256.NewInt(amount), tracing.BalanceIncreaseGenesisBalance)
}

// frameSigBytes signs the transaction's canonical signature hash with key and
// returns the EIP-8141 [V || R || S] encoding. The sighash keeps the
// signature-entry list but elides empty-msg signature bytes, so the digest
// must be taken on a template carrying the final entries with empty
// Signature bytes.
func frameSigBytes(t *testing.T, template *types.Transaction, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	rsv, err := crypto.Sign(template.FramePayload().SigHash().Bytes(), key)
	if err != nil {
		t.Fatalf("failed to sign frame digest: %v", err)
	}
	sig := make([]byte, 65) // EIP-8141 carries v first
	sig[0] = rsv[64]
	copy(sig[1:33], rsv[0:32])
	copy(sig[33:65], rsv[32:64])
	return sig
}

func frameSigEntry(addr common.Address) types.FrameSignature {
	return types.FrameSignature{Scheme: types.FrameSigSchemeSecp256k1, Signer: addr.Bytes()}
}

// signFrames returns the frame signature entries for the given keys: entry 0
// approves execution (sender), entry 1 approves payment (payer).
func signFrames(t *testing.T, sender common.Address, nonce uint64, frames []types.Frame, fees types.FrameFees, keys ...*ecdsa.PrivateKey) []types.FrameSignature {
	t.Helper()
	sigs := make([]types.FrameSignature, len(keys))
	for i, key := range keys {
		sigs[i] = frameSigEntry(crypto.PubkeyToAddress(key.PublicKey))
	}
	template := types.NewFrameTx(uint256.NewInt(1), nonce, sender, frames, sigs, fees, nil)
	for i, key := range keys {
		sigs[i].Signature = frameSigBytes(t, template, key)
	}
	return sigs
}

// signedSelfVerifyTx builds a self_verify prefix (flags 0x3). Note: the
// fork's combined-approval opcode path is defective (see Task 6 report), so
// this shape is only usable for tests that never run the validation
// simulation (the fork-gate test).
func signedSelfVerifyTx(t *testing.T, key *ecdsa.PrivateKey, nonce uint64, feeCap uint64) *types.Transaction {
	t.Helper()
	sender := crypto.PubkeyToAddress(key.PublicKey)
	frames := []types.Frame{{Mode: types.FrameModeVerify, Flags: 0x3, Limits: types.FrameLimits{Execution: 40_000, State: 150_000}}}
	sigs := signFrames(t, sender, nonce, frames, frameTestFees(feeCap), key)
	return types.NewFrameTx(uint256.NewInt(1), nonce, sender, frames, sigs, frameTestFees(feeCap), nil)
}

// signedPayTx builds an only_verify + pay prefix. payerKey signs the pay
// frame's default-code approval and must be nil when the payer carries
// deployed code (the pay frame then runs that code instead). A zero payerAddr
// makes the pay frame resolve to the sender (self-sponsored).
func signedPayTx(t *testing.T, senderKey *ecdsa.PrivateKey, nonce uint64, feeCap uint64, payerAddr common.Address, payerKey *ecdsa.PrivateKey) *types.Transaction {
	t.Helper()
	return signedPayTxTip(t, senderKey, nonce, feeCap, 1, payerAddr, payerKey)
}

// signedPayTxTip is signedPayTx with an explicit max_priority_fee_per_gas;
// the fees are part of the signature hash, so replacements with a bumped tip
// must be constructed (and signed) with the final fees.
func signedPayTxTip(t *testing.T, senderKey *ecdsa.PrivateKey, nonce uint64, feeCap, tip uint64, payerAddr common.Address, payerKey *ecdsa.PrivateKey) *types.Transaction {
	t.Helper()
	sender := crypto.PubkeyToAddress(senderKey.PublicKey)
	var target *common.Address
	if payerAddr != (common.Address{}) {
		target = &payerAddr
	}
	frames := []types.Frame{
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: types.FrameLimits{Execution: 40_000, State: 150_000}},
		{Mode: types.FrameModeVerify, Flags: 0x1, Limits: types.FrameLimits{Execution: 40_000, State: 150_000}, Target: target},
	}
	fees := types.FrameFees{GasTipCap: uint256.NewInt(tip), GasFeeCap: uint256.NewInt(feeCap), BlobFeeCap: uint256.NewInt(0)}
	keys := []*ecdsa.PrivateKey{senderKey}
	if payerKey != nil {
		keys = append(keys, payerKey)
	}
	sigs := signFrames(t, sender, nonce, frames, fees, keys...)
	return types.NewFrameTx(uint256.NewInt(1), nonce, sender, frames, sigs, fees, nil)
}

// signedExpiryPayTx prepends an expiry verifier frame (its state-gas limit
// must be zero) to the only_verify + pay prefix.
func signedExpiryPayTx(t *testing.T, senderKey *ecdsa.PrivateKey, nonce uint64, feeCap uint64, payerAddr common.Address, payerKey *ecdsa.PrivateKey, deadline uint64) *types.Transaction {
	t.Helper()
	sender := crypto.PubkeyToAddress(senderKey.PublicKey)
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], deadline)
	verifier := types.FrameExpiryVerifier
	var target *common.Address
	if payerAddr != (common.Address{}) {
		target = &payerAddr
	}
	frames := []types.Frame{
		{Mode: types.FrameModeVerify, Target: &verifier, Flags: 0x0, Data: data[:], Limits: types.FrameLimits{Execution: 10_000}},
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: types.FrameLimits{Execution: 40_000, State: 150_000}},
		{Mode: types.FrameModeVerify, Flags: 0x1, Limits: types.FrameLimits{Execution: 40_000, State: 150_000}, Target: target},
	}
	keys := []*ecdsa.PrivateKey{senderKey}
	if payerKey != nil {
		keys = append(keys, payerKey)
	}
	sigs := signFrames(t, sender, nonce, frames, frameTestFees(feeCap), keys...)
	return types.NewFrameTx(uint256.NewInt(1), nonce, sender, frames, sigs, frameTestFees(feeCap), nil)
}

func frameTestFees(feeCap uint64) types.FrameFees {
	return types.FrameFees{GasTipCap: uint256.NewInt(1), GasFeeCap: uint256.NewInt(feeCap), BlobFeeCap: uint256.NewInt(0)}
}

func reservedOf(pool *LegacyPool, payer common.Address) *big.Int {
	pool.frameRes.mu.Lock()
	defer pool.frameRes.mu.Unlock()
	if reserved := pool.frameRes.reserved[payer]; reserved != nil {
		return new(big.Int).Set(reserved)
	}
	return new(big.Int)
}

func maxFeeOf(t *testing.T, tx *types.Transaction) *big.Int {
	t.Helper()
	return frameTxMaxFee(tx.FramePayload())
}

// --- Component-level accounting tests -------------------------------------

func TestFrameReservationLifecycle(t *testing.T) {
	r := newFrameReservations()
	payer := common.BytesToAddress([]byte("payer"))
	s1 := common.BytesToAddress([]byte("sender-1"))
	s2 := common.BytesToAddress([]byte("sender-2"))

	info1 := &frameReservation{payer: payer, sender: s1, nonce: 0, maxFee: big.NewInt(300), class: framePayerDefaultCode}
	info2 := &frameReservation{payer: payer, sender: s2, nonce: 0, maxFee: big.NewInt(400), class: framePayerDefaultCode}

	if err := r.checkAdmit(info1, big.NewInt(700), nil); err != nil {
		t.Fatalf("first admit failed: %v", err)
	}
	r.take(s1, info1)
	if err := r.checkAdmit(info2, big.NewInt(700), nil); err != nil {
		t.Fatalf("second admit with exactly sufficient balance failed: %v", err)
	}
	r.take(s2, info2)
	if got := r.reservedTotal(payer); got.Cmp(big.NewInt(700)) != 0 {
		t.Fatalf("reserved total %v, want 700", got)
	}
	// Release twice: idempotent, never below zero.
	r.releaseSender(s1)
	r.releaseSender(s1)
	if got := r.reservedTotal(payer); got.Cmp(big.NewInt(400)) != 0 {
		t.Fatalf("reserved total after release %v, want 400", got)
	}
	if r.hasSender(s1) {
		t.Fatal("sender 1 reservation not dropped")
	}
	if !r.hasSender(s2) {
		t.Fatal("sender 2 reservation missing")
	}
}

func TestFrameReservationInsufficientFunds(t *testing.T) {
	r := newFrameReservations()
	payer := common.BytesToAddress([]byte("payer"))
	s1 := common.BytesToAddress([]byte("sender-1"))
	s2 := common.BytesToAddress([]byte("sender-2"))
	info1 := &frameReservation{payer: payer, sender: s1, nonce: 0, maxFee: big.NewInt(300), class: framePayerDefaultCode}
	info2 := &frameReservation{payer: payer, sender: s2, nonce: 0, maxFee: big.NewInt(400), class: framePayerDefaultCode}

	if err := r.checkAdmit(info2, big.NewInt(399), nil); !errors.Is(err, core.ErrInsufficientFunds) {
		t.Fatalf("expected insufficient funds, got %v", err)
	}
	r.take(s1, info1)
	// 700 - 300 reserved = 400 available; a 400-maxFee reservation needs one
	// more wei than the 699 balance leaves.
	if err := r.checkAdmit(info2, big.NewInt(699), nil); !errors.Is(err, core.ErrInsufficientFunds) {
		t.Fatalf("competing reservation overcommit not rejected: %v", err)
	}
	if r.hasSender(s2) {
		t.Fatal("failed admit leaked a reservation")
	}
}

func TestFrameReservationNonCanonicalCap(t *testing.T) {
	r := newFrameReservations()
	pm := common.BytesToAddress([]byte("paymaster"))
	s1 := common.BytesToAddress([]byte("sender-1"))
	s2 := common.BytesToAddress([]byte("sender-2"))
	info1 := &frameReservation{payer: pm, sender: s1, nonce: 0, maxFee: big.NewInt(10), class: framePayerNonCanonical}
	info2 := &frameReservation{payer: pm, sender: s2, nonce: 0, maxFee: big.NewInt(10), class: framePayerNonCanonical}

	r.take(s1, info1)
	if err := r.checkAdmit(info2, big.NewInt(1_000_000), nil); !errors.Is(err, ErrFramePaymasterLimitReached) {
		t.Fatalf("non-canonical paymaster cap not enforced: %v", err)
	}
	// Default-code sponsors are governed by the exposure rule alone: no cap.
	sponsor := common.BytesToAddress([]byte("sponsor"))
	info3 := &frameReservation{payer: sponsor, sender: s2, nonce: 0, maxFee: big.NewInt(10), class: framePayerDefaultCode}
	if err := r.checkAdmit(info3, big.NewInt(1_000_000), nil); err != nil {
		t.Fatalf("default-code sponsor wrongly capped: %v", err)
	}
}

func TestFrameReservationCheckReplace(t *testing.T) {
	r := newFrameReservations()
	payerA := common.BytesToAddress([]byte("payer-a"))
	payerB := common.BytesToAddress([]byte("payer-b"))
	sender := common.BytesToAddress([]byte("sender"))

	oldTx := selfVerifyFixture(sender, 100)
	oldInfo := &frameReservation{payer: payerA, sender: sender, nonce: 0, maxFee: big.NewInt(6000), class: framePayerDefaultCode}
	r.take(sender, oldInfo)

	// Under-bumped max_fee (tip bump alone is not enough).
	newTx := selfVerifyFixture(sender, 110) // +10% feeCap, +0% tip
	newInfo := &frameReservation{payer: payerA, sender: sender, nonce: 0, maxFee: big.NewInt(6600), class: framePayerDefaultCode}
	if err := r.checkReplace(sender, oldTx, newTx, newTx.FramePayload(), newInfo, big.NewInt(1_000_000), nil, 10); !errors.Is(err, txpool.ErrReplaceUnderpriced) {
		t.Fatalf("under-bumped replacement accepted: %v", err)
	}
	// Both fields bumped 10%: accepted, old reservation excluded from funds.
	newTx2 := selfVerifyFixture(sender, 111)
	ftx2 := newTx2.FramePayload()
	ftx2.Fees.GasTipCap = uint256.NewInt(2) // 2 > 1 * 1.1
	newInfo2 := &frameReservation{payer: payerA, sender: sender, nonce: 0, maxFee: maxFeeOf(t, newTx2), class: framePayerDefaultCode}
	if err := r.checkReplace(sender, oldTx, newTx2, ftx2, newInfo2, new(big.Int).Add(maxFeeOf(t, newTx2), big.NewInt(1)), nil, 10); err != nil {
		t.Fatalf("valid replacement rejected: %v", err)
	}
	// Payer shift with insufficient new-payer balance: rejected even though
	// the old payer has plenty.
	newInfo3 := &frameReservation{payer: payerB, sender: sender, nonce: 0, maxFee: maxFeeOf(t, newTx2), class: framePayerDefaultCode}
	if err := r.checkReplace(sender, oldTx, newTx2, ftx2, newInfo3, big.NewInt(1), nil, 10); !errors.Is(err, core.ErrInsufficientFunds) {
		t.Fatalf("payer shift without funds accepted: %v", err)
	}
}

func TestFrameReservationApplyReplacement(t *testing.T) {
	r := newFrameReservations()
	payerA := common.BytesToAddress([]byte("payer-a"))
	payerB := common.BytesToAddress([]byte("payer-b"))
	sender := common.BytesToAddress([]byte("sender"))

	r.take(sender, &frameReservation{payer: payerA, sender: sender, nonce: 0, maxFee: big.NewInt(6000), class: framePayerNonCanonical})
	r.applyReplacement(sender, &frameReservation{payer: payerB, sender: sender, nonce: 0, maxFee: big.NewInt(8000), class: framePayerDefaultCode})

	if got := r.reservedTotal(payerA); got.Sign() != 0 {
		t.Fatalf("old payer still reserved %v", got)
	}
	if got := r.reservedTotal(payerB); got.Cmp(big.NewInt(8000)) != 0 {
		t.Fatalf("new payer reserved %v, want 8000", got)
	}
	if !r.hasSender(sender) {
		t.Fatal("sender reservation lost in replacement")
	}
}

func TestFrameTxPayerInfo(t *testing.T) {
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	sender := common.BytesToAddress([]byte("sender"))
	sponsor := common.BytesToAddress([]byte("sponsor"))
	paymaster := common.BytesToAddress([]byte("paymaster"))
	statedb.SetCode(paymaster, frameTestApproveCode(0x1), tracing.CodeChangeContractCreation)

	// Self-funded: self_verify prefix, payer is the sender.
	info, err := frameTxPayerInfo(selfVerifyFixture(sender, 100).FramePayload(), statedb, 0)
	if err != nil {
		t.Fatal(err)
	}
	if info.payer != sender || info.class != framePayerSelf {
		t.Fatalf("self-funded payer/class wrong: %v %v", info.payer, info.class)
	}
	// Pay frame resolving to the empty-code sender: a default-code sponsor,
	// not the self-funded class.
	info, err = frameTxPayerInfo(payFixture(sender, common.Address{}, 100).FramePayload(), statedb, 0)
	if err != nil {
		t.Fatal(err)
	}
	if info.payer != sender || info.class != framePayerDefaultCode {
		t.Fatalf("self-sponsored pay frame payer/class wrong: %v %v", info.payer, info.class)
	}
	// Default-code sponsor.
	info, err = frameTxPayerInfo(payFixture(sender, sponsor, 100).FramePayload(), statedb, 0)
	if err != nil {
		t.Fatal(err)
	}
	if info.payer != sponsor || info.class != framePayerDefaultCode {
		t.Fatalf("default-code sponsor payer/class wrong: %v %v", info.payer, info.class)
	}
	// Non-canonical paymaster (deployed code).
	info, err = frameTxPayerInfo(payFixture(sender, paymaster, 100).FramePayload(), statedb, 0)
	if err != nil {
		t.Fatal(err)
	}
	if info.payer != paymaster || info.class != framePayerNonCanonical {
		t.Fatalf("non-canonical paymaster payer/class wrong: %v %v", info.payer, info.class)
	}
	// Expiry extraction (deadline 0x0102).
	info, err = frameTxPayerInfo(expiryFixture(sender, common.Address{}, 100, 0x0102).FramePayload(), statedb, 0)
	if err != nil {
		t.Fatal(err)
	}
	if info.expiry != 0x0102 {
		t.Fatalf("expiry %v, want 258", info.expiry)
	}
	// maxFee is the aggregate max_fee budget: the fee cap itself, NOT
	// multiplied by MaxGas (EIP-8141 "Fee budget"; the fee cap is a single
	// aggregate max_cost bound). The blob component (per-unit blob fee cap)
	// is additive and unchanged.
	tx := payFixture(sender, common.Address{}, 100)
	want := new(big.Int).SetUint64(100)
	if frameTxMaxFee(tx.FramePayload()).Cmp(want) != 0 {
		t.Fatal("maxFee not the aggregate fee-cap budget")
	}
}

// --- Pool integration tests ------------------------------------------------

func TestFramePoolAdmissionSelfFunded(t *testing.T) {
	pool, statedb := setupFramePool(t)
	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)
	fund(statedb, sender, 1_000_000_000)

	tx := signedPayTx(t, key, 0, 100, common.Address{}, key)
	if err := pool.addRemoteSync(tx); err != nil {
		t.Fatalf("self-funded frame tx rejected: %v", err)
	}
	if got := reservedOf(pool, sender); got.Cmp(maxFeeOf(t, tx)) != 0 {
		t.Fatalf("reserved %v, want aggregate maxFee %v", got, maxFeeOf(t, tx))
	}
}

func TestFramePoolGatePreserved(t *testing.T) {
	// Without the fork the pool must keep rejecting frame transactions; the
	// reservation machinery must not weaken the existing fork gate.
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	blockchain := newTestBlockChain(params.TestChainConfig, 10_000_000, statedb, new(event.Feed))
	pool := New(testTxPoolConfig, blockchain)
	if err := pool.Init(testTxPoolConfig.PriceLimit, blockchain.CurrentBlock(), newReserver()); err != nil {
		t.Fatalf("failed to init pool: %v", err)
	}
	<-pool.initDoneCh
	defer pool.Close()

	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)
	fund(statedb, sender, 1_000_000_000)
	err := pool.addRemoteSync(signedSelfVerifyTx(t, key, 0, 100))
	if !errors.Is(err, core.ErrTxTypeNotSupported) {
		t.Fatalf("frame tx admitted while fork inactive: %v", err)
	}
	if reservedOf(pool, sender).Sign() != 0 {
		t.Fatal("rejected admission leaked a reservation")
	}
}

func TestFramePoolCompetingReservations(t *testing.T) {
	pool, statedb := setupFramePool(t)
	sponsorKey, _ := crypto.GenerateKey()
	sponsor := crypto.PubkeyToAddress(sponsorKey.PublicKey)
	k1, _ := crypto.GenerateKey()
	k2, _ := crypto.GenerateKey()
	s1 := crypto.PubkeyToAddress(k1.PublicKey)
	s2 := crypto.PubkeyToAddress(k2.PublicKey)

	tx1 := signedPayTx(t, k1, 0, 100, sponsor, sponsorKey)
	tx2 := signedPayTx(t, k2, 0, 100, sponsor, sponsorKey)
	// NOTE: identical shapes and caps do NOT imply identical max_fee: the
	// calldata-floor gas depends on the zero-byte distribution of the
	// signature entries' signer addresses, which varies per key. Compute
	// each transaction's max_fee independently.
	fee1 := maxFeeOf(t, tx1)
	fee2 := maxFeeOf(t, tx2)
	total := new(big.Int).Add(fee1, fee2)

	// Exact fit: both admitted.
	fund(statedb, sponsor, total.Uint64())
	fund(statedb, s1, 1_000_000_000)
	fund(statedb, s2, 1_000_000_000)
	if err := pool.addRemoteSync(tx1); err != nil {
		t.Fatalf("first sponsored tx rejected: %v", err)
	}
	if err := pool.addRemoteSync(tx2); err != nil {
		t.Fatalf("second sponsored tx with exact balance rejected: %v", err)
	}
	if got := reservedOf(pool, sponsor); got.Cmp(total) != 0 {
		t.Fatalf("sponsor reserved %v, want %v (fee1 %v + fee2 %v)", got, total, fee1, fee2)
	}

	// Tight pool: one wei short of the combined exposure must reject the
	// second sender and must not leak a reservation.
	pool2, statedb2 := setupFramePool(t)
	fund(statedb2, sponsor, total.Uint64()-1)
	fund(statedb2, s1, 1_000_000_000)
	fund(statedb2, s2, 1_000_000_000)
	if err := pool2.addRemoteSync(signedPayTx(t, k1, 0, 100, sponsor, sponsorKey)); err != nil {
		t.Fatalf("first sponsored tx rejected: %v", err)
	}
	err := pool2.addRemoteSync(signedPayTx(t, k2, 0, 100, sponsor, sponsorKey))
	if !errors.Is(err, core.ErrInsufficientFunds) {
		t.Fatalf("overcommit not rejected: %v", err)
	}
	if got := reservedOf(pool2, sponsor); got.Cmp(fee1) != 0 {
		t.Fatalf("failed admit leaked reservation: reserved %v, want fee1 %v", got, fee1)
	}
}

func TestFramePoolNonCanonicalPaymasterCap(t *testing.T) {
	pool, statedb := setupFramePool(t)
	paymaster := common.BytesToAddress([]byte("paymaster"))
	k1, _ := crypto.GenerateKey()
	k2, _ := crypto.GenerateKey()
	s1 := crypto.PubkeyToAddress(k1.PublicKey)
	s2 := crypto.PubkeyToAddress(k2.PublicKey)
	statedb.SetCode(paymaster, frameTestApproveCode(0x1), tracing.CodeChangeContractCreation)

	fund(statedb, paymaster, 1_000_000_000_000)
	fund(statedb, s1, 1_000_000_000)
	fund(statedb, s2, 1_000_000_000)

	if err := pool.addRemoteSync(signedPayTx(t, k1, 0, 100, paymaster, nil)); err != nil {
		t.Fatalf("first paymaster-sponsored tx rejected: %v", err)
	}
	err := pool.addRemoteSync(signedPayTx(t, k2, 0, 100, paymaster, nil))
	if !errors.Is(err, ErrFramePaymasterLimitReached) {
		t.Fatalf("MAX_PENDING_TXS_USING_NON_CANONICAL_PAYMASTER not enforced: %v", err)
	}
	if reserved := pool.frameRes.nonCanonicalPending[paymaster]; reserved != 1 {
		t.Fatalf("non-canonical pending count %d, want 1", reserved)
	}
}

func TestFramePoolOneFrameTxPerSender(t *testing.T) {
	pool, statedb := setupFramePool(t)
	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)
	legacyKey, _ := crypto.GenerateKey()
	fund(statedb, sender, 10_000_000_000)
	fund(statedb, crypto.PubkeyToAddress(legacyKey.PublicKey), 10_000_000_000)

	if err := pool.addRemoteSync(signedPayTx(t, key, 0, 100, common.Address{}, key)); err != nil {
		t.Fatalf("first frame tx rejected: %v", err)
	}
	err := pool.addRemoteSync(signedPayTx(t, key, 1, 100, common.Address{}, key))
	if !errors.Is(err, ErrFrameSenderPendingLimit) {
		t.Fatalf("second frame tx from same sender accepted: %v", err)
	}
	// A legacy transaction from another account at the same nonce remains
	// admissible (the rule constrains frame transactions, not the account).
	if err := pool.addRemoteSync(transaction(0, 21000, legacyKey)); err != nil {
		t.Fatalf("legacy tx rejected: %v", err)
	}
}

func TestFramePoolReplacement(t *testing.T) {
	pool, statedb := setupFramePool(t)
	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)
	fund(statedb, sender, 10_000_000_000)

	old := signedPayTx(t, key, 0, 100, common.Address{}, key)
	if err := pool.addRemoteSync(old); err != nil {
		t.Fatalf("initial admission failed: %v", err)
	}
	oldMaxFee := maxFeeOf(t, old)

	// Fee cap bumped >10% but the tip untouched: rejected by the
	// specification replacement rule; the old reservation stays intact.
	under := signedPayTx(t, key, 0, 111, common.Address{}, key)
	err := pool.addRemoteSync(under)
	if !errors.Is(err, txpool.ErrReplaceUnderpriced) {
		t.Fatalf("under-bumped frame replacement accepted: %v", err)
	}
	if got := reservedOf(pool, sender); got.Cmp(oldMaxFee) != 0 {
		t.Fatalf("old reservation disturbed: %v", got)
	}

	// Bump both max_fee and max_priority_fee_per_gas past 10%.
	repl := signedPayTxTip(t, key, 0, 111, 2, common.Address{}, key)
	if err := pool.addRemoteSync(repl); err != nil {
		t.Fatalf("valid replacement rejected: %v", err)
	}
	if got := reservedOf(pool, sender); got.Cmp(maxFeeOf(t, repl)) != 0 {
		t.Fatalf("reservation not shifted: %v, want %v", got, maxFeeOf(t, repl))
	}
	if pool.all.Get(old.Hash()) != nil {
		t.Fatal("old transaction still in pool after replacement")
	}
}

func TestFramePoolReplacementPayerShift(t *testing.T) {
	pool, statedb := setupFramePool(t)
	payerKeyA, _ := crypto.GenerateKey()
	payerKeyB, _ := crypto.GenerateKey()
	payerA := crypto.PubkeyToAddress(payerKeyA.PublicKey)
	payerB := crypto.PubkeyToAddress(payerKeyB.PublicKey)
	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)
	fund(statedb, payerA, 1_000_000_000)
	fund(statedb, payerB, 1_000_000_000)
	fund(statedb, sender, 1_000_000_000)

	old := signedPayTx(t, key, 0, 100, payerA, payerKeyA)
	if err := pool.addRemoteSync(old); err != nil {
		t.Fatalf("initial admission failed: %v", err)
	}
	repl := signedPayTxTip(t, key, 0, 111, 2, payerB, payerKeyB)
	if err := pool.addRemoteSync(repl); err != nil {
		t.Fatalf("payer-shifting replacement rejected: %v", err)
	}
	if got := reservedOf(pool, payerA); got.Sign() != 0 {
		t.Fatalf("old payer still reserved %v", got)
	}
	if got := reservedOf(pool, payerB); got.Cmp(maxFeeOf(t, repl)) != 0 {
		t.Fatalf("new payer reserved %v, want %v", got, maxFeeOf(t, repl))
	}
}

func TestFramePoolRemovalReleases(t *testing.T) {
	pool, statedb := setupFramePool(t)
	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)
	fund(statedb, sender, 1_000_000_000)

	tx := signedPayTx(t, key, 0, 100, common.Address{}, key)
	if err := pool.addRemoteSync(tx); err != nil {
		t.Fatalf("admission failed: %v", err)
	}
	// Simulate inclusion: the account nonce advanced past the pooled tx.
	statedb.SetNonce(sender, 1, tracing.NonceChangeUnspecified)
	pool.demoteUnexecutables()
	if got := reservedOf(pool, sender); got.Sign() != 0 {
		t.Fatalf("reservation not released on inclusion: %v", got)
	}
	if pool.all.Get(tx.Hash()) != nil {
		t.Fatal("included transaction still in pool")
	}
}

func TestFramePoolReorgRelease(t *testing.T) {
	pool, statedb := setupFramePool(t)
	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)
	fund(statedb, sender, 1_000_000_000)

	tx := signedPayTx(t, key, 0, 100, common.Address{}, key)
	if err := pool.addRemoteSync(tx); err != nil {
		t.Fatalf("admission failed: %v", err)
	}
	statedb.SetNonce(sender, 1, tracing.NonceChangeUnspecified)
	head := pool.currentHead.Load()
	pool.Reset(head, head) // reorg path: reset + demote + reinject
	if got := reservedOf(pool, sender); got.Sign() != 0 {
		t.Fatalf("reservation not released through reorg processing: %v", got)
	}
}

// TestFramePoolEvictNearestExpiry: with the pool full, the second eviction
// tier drops the valid frame transaction with the NEAREST expiry deadline
// before the lowest-priority (cheapest) transaction.
func TestFramePoolEvictNearestExpiry(t *testing.T) {
	config := testTxPoolConfig
	config.AccountSlots = 1
	config.AccountQueue = 1
	config.GlobalSlots = 2
	config.GlobalQueue = 1

	cfg := *params.TestChainConfig
	cfg.FrameTxTime = new(uint64)
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	blockchain := newTestBlockChain(&cfg, 10_000_000, statedb, new(event.Feed))
	pool := New(config, blockchain)
	if err := pool.Init(config.PriceLimit, blockchain.CurrentBlock(), newReserver()); err != nil {
		t.Fatalf("failed to init pool: %v", err)
	}
	<-pool.initDoneCh
	defer pool.Close()

	keyX1, _ := crypto.GenerateKey()
	keyX2, _ := crypto.GenerateKey()
	keyC, _ := crypto.GenerateKey()
	keyB, _ := crypto.GenerateKey()
	senderX1 := crypto.PubkeyToAddress(keyX1.PublicKey)
	senderX2 := crypto.PubkeyToAddress(keyX2.PublicKey)
	fromC := crypto.PubkeyToAddress(keyC.PublicKey)
	fund(statedb, senderX1, 1_000_000_000)
	fund(statedb, senderX2, 1_000_000_000)
	fund(statedb, fromC, 1_000_000_000)
	fund(statedb, crypto.PubkeyToAddress(keyB.PublicKey), 1_000_000_000)

	near := signedExpiryPayTx(t, keyX1, 0, 500, common.Address{}, keyX1, 10)
	far := signedExpiryPayTx(t, keyX2, 0, 400, common.Address{}, keyX2, 20)
	cheap := pricedTransaction(0, 21000, big.NewInt(1), keyC)
	for _, tx := range []*types.Transaction{near, far, cheap} {
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatalf("setup tx rejected: %v", err)
		}
	}

	pricier := pricedTransaction(0, 21000, big.NewInt(50), keyB)
	if err := pool.addRemoteSync(pricier); err != nil {
		t.Fatalf("incoming tx rejected: %v", err)
	}
	if pool.all.Get(near.Hash()) != nil {
		t.Fatal("nearest-expiry frame tx was not evicted first")
	}
	if pool.all.Get(far.Hash()) == nil {
		t.Fatal("later-expiry frame tx evicted before the nearest-expiry one")
	}
	if pool.all.Get(cheap.Hash()) == nil {
		t.Fatal("cheapest legacy tx evicted despite a nearer-expiry frame tx being present")
	}
	if pool.all.Get(pricier.Hash()) == nil {
		t.Fatal("incoming tx not admitted")
	}
	if got := reservedOf(pool, senderX1); got.Sign() != 0 {
		t.Fatalf("evicted frame reservation not released: %v", got)
	}
	if got := reservedOf(pool, senderX2); got.Sign() == 0 {
		t.Fatal("surviving frame reservation lost")
	}
}

// TestFramePoolEvictExpiryTiePriority: with two frame transactions sharing
// the nearest deadline, exactly one of them is evicted (tie is local
// policy) and the cheapest legacy transaction still survives.
func TestFramePoolEvictExpiryTiePriority(t *testing.T) {
	config := testTxPoolConfig
	config.AccountSlots = 1
	config.AccountQueue = 1
	config.GlobalSlots = 2
	config.GlobalQueue = 1

	cfg := *params.TestChainConfig
	cfg.FrameTxTime = new(uint64)
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	blockchain := newTestBlockChain(&cfg, 10_000_000, statedb, new(event.Feed))
	pool := New(config, blockchain)
	if err := pool.Init(config.PriceLimit, blockchain.CurrentBlock(), newReserver()); err != nil {
		t.Fatalf("failed to init pool: %v", err)
	}
	<-pool.initDoneCh
	defer pool.Close()

	keyX1, _ := crypto.GenerateKey()
	keyX2, _ := crypto.GenerateKey()
	keyC, _ := crypto.GenerateKey()
	keyB, _ := crypto.GenerateKey()
	fund(statedb, crypto.PubkeyToAddress(keyX1.PublicKey), 1_000_000_000)
	fund(statedb, crypto.PubkeyToAddress(keyX2.PublicKey), 1_000_000_000)
	fund(statedb, crypto.PubkeyToAddress(keyC.PublicKey), 1_000_000_000)
	fund(statedb, crypto.PubkeyToAddress(keyB.PublicKey), 1_000_000_000)

	x1 := signedExpiryPayTx(t, keyX1, 0, 500, common.Address{}, keyX1, 10)
	x2 := signedExpiryPayTx(t, keyX2, 0, 400, common.Address{}, keyX2, 10)
	cheap := pricedTransaction(0, 21000, big.NewInt(1), keyC)
	for _, tx := range []*types.Transaction{x1, x2, cheap} {
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatalf("setup tx rejected: %v", err)
		}
	}

	pricier := pricedTransaction(0, 21000, big.NewInt(50), keyB)
	if err := pool.addRemoteSync(pricier); err != nil {
		t.Fatalf("incoming tx rejected: %v", err)
	}
	survivors := 0
	for _, tx := range []*types.Transaction{x1, x2} {
		if pool.all.Get(tx.Hash()) != nil {
			survivors++
		}
	}
	if survivors != 1 {
		t.Fatalf("tied nearest-expiry evictions: %d survivors, want exactly 1", survivors)
	}
	if pool.all.Get(cheap.Hash()) == nil {
		t.Fatal("cheapest legacy tx evicted despite tied frame expiries being present")
	}
	if pool.all.Get(pricier.Hash()) == nil {
		t.Fatal("incoming tx not admitted")
	}
}

// TestFramePoolEvictionLegacyOnly: without frame transactions in the pool,
// pool-full eviction drops the cheapest transaction (existing behavior,
// third spec tier: lowest priority).
func TestFramePoolEvictionLegacyOnly(t *testing.T) {
	config := testTxPoolConfig
	config.AccountSlots = 1
	config.AccountQueue = 1
	config.GlobalSlots = 2
	config.GlobalQueue = 1

	cfg := *params.TestChainConfig
	cfg.FrameTxTime = new(uint64)
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	blockchain := newTestBlockChain(&cfg, 10_000_000, statedb, new(event.Feed))
	pool := New(config, blockchain)
	if err := pool.Init(config.PriceLimit, blockchain.CurrentBlock(), newReserver()); err != nil {
		t.Fatalf("failed to init pool: %v", err)
	}
	<-pool.initDoneCh
	defer pool.Close()

	keyC1, _ := crypto.GenerateKey()
	keyC2, _ := crypto.GenerateKey()
	keyC3, _ := crypto.GenerateKey()
	keyB, _ := crypto.GenerateKey()
	fund(statedb, crypto.PubkeyToAddress(keyC1.PublicKey), 1_000_000_000)
	fund(statedb, crypto.PubkeyToAddress(keyC2.PublicKey), 1_000_000_000)
	fund(statedb, crypto.PubkeyToAddress(keyC3.PublicKey), 1_000_000_000)
	fund(statedb, crypto.PubkeyToAddress(keyB.PublicKey), 1_000_000_000)

	cheapest := pricedTransaction(0, 21000, big.NewInt(1), keyC1)
	mid := pricedTransaction(0, 21000, big.NewInt(2), keyC2)
	top := pricedTransaction(0, 21000, big.NewInt(3), keyC3)
	for _, tx := range []*types.Transaction{cheapest, mid, top} {
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatalf("setup tx rejected: %v", err)
		}
	}

	pricier := pricedTransaction(0, 21000, big.NewInt(50), keyB)
	if err := pool.addRemoteSync(pricier); err != nil {
		t.Fatalf("incoming tx rejected: %v", err)
	}
	if pool.all.Get(cheapest.Hash()) != nil {
		t.Fatal("cheapest tx not evicted in a pool without frame transactions")
	}
	for _, tx := range []*types.Transaction{mid, top, pricier} {
		if pool.all.Get(tx.Hash()) == nil {
			t.Fatal("non-cheapest tx evicted")
		}
	}
}

// TestFramePoolEvictExpiredBeforePrice: the first eviction tier removes
// frame transactions already invalid against the current head (expired
// expiry deadline) before any price-based selection.
func TestFramePoolEvictExpiredBeforePrice(t *testing.T) {
	// The sanitized minimum pool capacity is GlobalSlots + GlobalQueue =
	// 2 + 1024 slots, so the pool is filled with cheap legacy filler
	// transactions inserted directly (bypassing the async reorg loop).
	// Sender A holds an expired frame tx with a high fee; sender C holds the
	// single cheapest legacy tx. Adding B must evict the expired frame tx
	// (invalid first) rather than the cheapest transaction.
	config := testTxPoolConfig
	config.AccountSlots = 1
	config.AccountQueue = 1
	config.GlobalSlots = 2
	config.GlobalQueue = 1

	cfg := *params.TestChainConfig
	cfg.FrameTxTime = new(uint64)
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	blockchain := newTestBlockChain(&cfg, 10_000_000, statedb, new(event.Feed))
	pool := New(config, blockchain)
	if err := pool.Init(config.PriceLimit, blockchain.CurrentBlock(), newReserver()); err != nil {
		t.Fatalf("failed to init pool: %v", err)
	}
	<-pool.initDoneCh
	defer pool.Close()

	keyA, _ := crypto.GenerateKey()
	keyC, _ := crypto.GenerateKey()
	keyB, _ := crypto.GenerateKey()
	senderA := crypto.PubkeyToAddress(keyA.PublicKey)
	fromC := crypto.PubkeyToAddress(keyC.PublicKey)
	fromB := crypto.PubkeyToAddress(keyB.PublicKey)
	fund(statedb, senderA, 1_000_000_000)
	fund(statedb, fromC, 1_000_000_000)
	fund(statedb, fromB, 1_000_000_000)

	// Head time 0: deadline 4 is still valid at admission.
	expired := signedExpiryPayTx(t, keyA, 0, 500, common.Address{}, keyA, 4)
	if err := pool.addRemoteSync(expired); err != nil {
		t.Fatalf("expiry frame tx rejected at admission: %v", err)
	}
	cheap := pricedTransaction(0, 21000, big.NewInt(1), keyC)
	if err := pool.addRemoteSync(cheap); err != nil {
		t.Fatalf("cheap legacy tx rejected: %v", err)
	}
	// Fill the remaining slots with legacy transactions priced above the
	// cheap tx, each from its own account (AccountSlots = 1).
	fill := int(pool.config.GlobalSlots+pool.config.GlobalQueue) - pool.all.Slots()
	for i := 0; i < fill; i++ {
		key, _ := crypto.GenerateKey()
		fund(statedb, crypto.PubkeyToAddress(key.PublicKey), 1_000_000)
		pool.mu.Lock()
		if _, err := pool.add(pricedTransaction(0, 21000, big.NewInt(2), key)); err != nil {
			pool.mu.Unlock()
			t.Fatalf("filler %d rejected: %v", i, err)
		}
		pool.mu.Unlock()
	}
	if slots := pool.all.Slots(); uint64(slots) < pool.config.GlobalSlots+pool.config.GlobalQueue {
		t.Fatalf("pool not full: %d slots", slots)
	}

	// Advance the head past the deadline.
	newHead := &types.Header{Number: big.NewInt(1), Time: 5, Difficulty: big.NewInt(0), GasLimit: 10_000_000, BaseFee: big.NewInt(0)}
	pool.Reset(newHead, newHead)

	pricier := pricedTransaction(0, 21000, big.NewInt(50), keyB)
	if err := pool.addRemoteSync(pricier); err != nil {
		t.Fatalf("pricier legacy tx rejected: %v", err)
	}
	if pool.all.Get(expired.Hash()) != nil {
		t.Fatal("expired frame tx not evicted before price-based selection")
	}
	if pool.all.Get(cheap.Hash()) == nil {
		t.Fatal("cheapest valid tx evicted despite expired frame tx being present")
	}
	if pool.all.Get(pricier.Hash()) == nil {
		t.Fatal("incoming transaction not admitted after expired-frame eviction")
	}
	if got := reservedOf(pool, senderA); got.Sign() != 0 {
		t.Fatalf("expired frame reservation not released: %v", got)
	}
}

// --- Pure fixtures for component-level tests (no simulation runs) ----------

func selfVerifyFixture(sender common.Address, feeCap uint64) *types.Transaction {
	return types.NewFrameTx(uint256.NewInt(1), 0, sender,
		[]types.Frame{{Mode: types.FrameModeVerify, Flags: 0x3, Limits: types.FrameLimits{Execution: 40_000, State: 150_000}}},
		nil, frameTestFees(feeCap), nil)
}

func payFixture(sender, payer common.Address, feeCap uint64) *types.Transaction {
	var target *common.Address
	if payer != (common.Address{}) {
		target = &payer
	}
	return types.NewFrameTx(uint256.NewInt(1), 0, sender,
		[]types.Frame{
			{Mode: types.FrameModeVerify, Flags: 0x2, Limits: types.FrameLimits{Execution: 40_000, State: 150_000}},
			{Mode: types.FrameModeVerify, Flags: 0x1, Limits: types.FrameLimits{Execution: 40_000, State: 150_000}, Target: target},
		},
		nil, frameTestFees(feeCap), nil)
}

func expiryFixture(sender, payer common.Address, feeCap uint64, deadline uint64) *types.Transaction {
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], deadline)
	verifier := types.FrameExpiryVerifier
	var target *common.Address
	if payer != (common.Address{}) {
		target = &payer
	}
	return types.NewFrameTx(uint256.NewInt(1), 0, sender,
		[]types.Frame{
			{Mode: types.FrameModeVerify, Target: &verifier, Flags: 0x0, Data: data[:], Limits: types.FrameLimits{Execution: 10_000}},
			{Mode: types.FrameModeVerify, Flags: 0x2, Limits: types.FrameLimits{Execution: 40_000, State: 150_000}},
			{Mode: types.FrameModeVerify, Flags: 0x1, Limits: types.FrameLimits{Execution: 40_000, State: 150_000}, Target: target},
		},
		nil, frameTestFees(feeCap), nil)
}

// --- Canonical paymaster (ethereum/EIPs PR #12041) --------------------------

// canonicalPaymasterRuntime is the assembled EIP-8141 canonical paymaster
// runtime published in ethereum/EIPs PR #12041 ("assembled canonical
// paymaster reference bytecode"). Its keccak256 equals
// core.CanonicalPaymasterCodeHash; both were verified locally during
// implementation.
var canonicalPaymasterRuntime = common.FromHex("0x3461002e57366100355760016001b41561005a575f6001b45f54141561005a5760026001b461005a5760015f5faa5b3661005a57005b5f3560f81c8060011461005e57806002146100a557806003146100ec57600414610123575b5f5ffd5b50335f54146100875760016001b41561005a575f6001b45f54141561005a5760026001b461005a575b60025461005a57600135801561005a57600155426201518001600255005b50335f54146100ce5760016001b41561005a575f6001b45f54141561005a5760026001b461005a575b60025461005a57600135801561005a57600355426201518001600255005b50335f54146101155760016001b41561005a575f6001b45f54141561005a5760026001b461005a575b5f6001555f6002555f600355005b600254801561005a57421061005a576001548015610153575f6001555f6002555f5f5f5f845f545af11561005a57005b506003545f555f6003555f60025500")

// installCanonicalPaymaster deploys the canonical runtime at addr with the
// given signer in slot 0 (the standard constructor-writes-storage pattern;
// recognition is on the runtime code hash, so per-instance state does not
// affect it).
func installCanonicalPaymaster(statedb *state.StateDB, addr, signer common.Address) {
	statedb.SetCode(addr, canonicalPaymasterRuntime, tracing.CodeChangeContractCreation)
	statedb.SetState(addr, core.CanonicalPaymasterSlotSigner, common.BytesToHash(signer.Bytes()))
}

func TestFrameTxPayerInfoCanonicalPaymaster(t *testing.T) {
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	sender := common.BytesToAddress([]byte("sender"))
	sponsor := common.BytesToAddress([]byte("sponsor"))
	paymaster := common.BytesToAddress([]byte("canonical-paymaster"))
	installCanonicalPaymaster(statedb, paymaster, sponsor)

	if got := statedb.GetCodeHash(paymaster); got != core.CanonicalPaymasterCodeHash {
		t.Fatalf("fixture code hash %s, want pinned canonical hash %s", got, core.CanonicalPaymasterCodeHash)
	}
	info, err := frameTxPayerInfo(payFixture(sender, paymaster, 100).FramePayload(), statedb, 0)
	if err != nil {
		t.Fatal(err)
	}
	if info.class != framePayerCanonical || info.payer != paymaster {
		t.Fatalf("canonical paymaster classified as %v payer %s", info.class, info.payer)
	}
	// One mutated byte changes the code hash: the instance is then an
	// ordinary non-canonical paymaster.
	mutated := append([]byte(nil), canonicalPaymasterRuntime...)
	mutated[0] ^= 0xff
	statedb.SetCode(paymaster, mutated, tracing.CodeChangeContractCreation)
	info, err = frameTxPayerInfo(payFixture(sender, paymaster, 100).FramePayload(), statedb, 0)
	if err != nil {
		t.Fatal(err)
	}
	if info.class != framePayerNonCanonical {
		t.Fatalf("mutated canonical runtime classified as %v, want non-canonical", info.class)
	}
}

func TestFramePendingWithdrawalAmount(t *testing.T) {
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	sponsor := common.BytesToAddress([]byte("sponsor"))
	paymaster := common.BytesToAddress([]byte("canonical-paymaster"))
	installCanonicalPaymaster(statedb, paymaster, sponsor)

	if got := pendingWithdrawalAmount(statedb, paymaster, framePayerCanonical); got.Sign() != 0 {
		t.Fatalf("pending withdrawal with no action pending: %v, want 0", got)
	}
	statedb.SetState(paymaster, core.CanonicalPaymasterSlotPendingWithdrawal, common.BigToHash(big.NewInt(500)))
	if got := pendingWithdrawalAmount(statedb, paymaster, framePayerCanonical); got.Cmp(big.NewInt(500)) != 0 {
		t.Fatalf("pending withdrawal: %v, want 500 (storage slot 1)", got)
	}
	// Not meaningful for payers that are not canonical paymaster instances.
	if got := pendingWithdrawalAmount(statedb, paymaster, framePayerNonCanonical); got.Sign() != 0 {
		t.Fatalf("non-canonical payer withdrawal: %v, want 0", got)
	}
	if got := pendingWithdrawalAmount(nil, paymaster, framePayerCanonical); got.Sign() != 0 {
		t.Fatalf("nil-state withdrawal: %v, want 0", got)
	}
}

func TestFrameReservationCanonicalPaymaster(t *testing.T) {
	r := newFrameReservations()
	pm := common.BytesToAddress([]byte("canonical-paymaster"))
	s1 := common.BytesToAddress([]byte("sender-1"))
	s2 := common.BytesToAddress([]byte("sender-2"))
	s3 := common.BytesToAddress([]byte("sender-3"))

	// Canonical paymasters are exempt from MAX_PENDING_TXS_USING_NON_CANONICAL_PAYMASTER:
	// two pending transactions from the same instance are admitted.
	info1 := &frameReservation{payer: pm, sender: s1, nonce: 0, maxFee: big.NewInt(300), class: framePayerCanonical}
	info2 := &frameReservation{payer: pm, sender: s2, nonce: 0, maxFee: big.NewInt(400), class: framePayerCanonical}
	if err := r.checkAdmit(info1, big.NewInt(1000), nil); err != nil {
		t.Fatalf("first canonical admission failed: %v", err)
	}
	r.take(s1, info1)
	if err := r.checkAdmit(info2, big.NewInt(1000), nil); err != nil {
		t.Fatalf("canonical paymaster wrongly capped: %v", err)
	}
	r.take(s2, info2)
	if got := r.reservedTotal(pm); got.Cmp(big.NewInt(700)) != 0 {
		t.Fatalf("reserved total %v, want 700", got)
	}

	// The instance's pending withdrawal consumes availability: with 500
	// pending, a 201-max_fee reservation needs 701 balance.
	r2 := newFrameReservations()
	pm2 := common.BytesToAddress([]byte("canonical-paymaster-2"))
	info3 := &frameReservation{payer: pm2, sender: s3, nonce: 0, maxFee: big.NewInt(201), class: framePayerCanonical}
	if err := r2.checkAdmit(info3, big.NewInt(700), big.NewInt(500)); !errors.Is(err, core.ErrInsufficientFunds) {
		t.Fatalf("pending withdrawal not subtracted: %v", err)
	}
	if err := r2.checkAdmit(info3, big.NewInt(700), big.NewInt(499)); err != nil {
		t.Fatalf("admission with exactly sufficient post-withdrawal balance failed: %v", err)
	}
}

func TestFramePoolCanonicalPaymaster(t *testing.T) {
	pool, statedb := setupFramePool(t)
	paymaster := common.BytesToAddress([]byte("canonical-paymaster"))
	sponsorKey, _ := crypto.GenerateKey()
	sponsor := crypto.PubkeyToAddress(sponsorKey.PublicKey)
	k1, _ := crypto.GenerateKey()
	k2, _ := crypto.GenerateKey()
	k3, _ := crypto.GenerateKey()
	installCanonicalPaymaster(statedb, paymaster, sponsor)

	fund(statedb, paymaster, 1_000_000_000_000)
	fund(statedb, crypto.PubkeyToAddress(k1.PublicKey), 1_000_000_000)
	fund(statedb, crypto.PubkeyToAddress(k2.PublicKey), 1_000_000_000)
	fund(statedb, crypto.PubkeyToAddress(k3.PublicKey), 1_000_000_000)

	tx1 := signedPayTx(t, k1, 0, 100, paymaster, sponsorKey)
	tx2 := signedPayTx(t, k2, 0, 100, paymaster, sponsorKey)
	if err := pool.addRemoteSync(tx1); err != nil {
		t.Fatalf("first canonical-sponsored tx rejected: %v", err)
	}
	// The canonical exception admits a second pending transaction from the
	// same instance; a non-canonical paymaster would be capped here.
	if err := pool.addRemoteSync(tx2); err != nil {
		t.Fatalf("canonical paymaster wrongly capped: %v", err)
	}
	want := new(big.Int).Add(maxFeeOf(t, tx1), maxFeeOf(t, tx2))
	if got := reservedOf(pool, paymaster); got.Cmp(want) != 0 {
		t.Fatalf("reserved total %v, want %v", got, want)
	}

	// A matured-timelocked withdrawal pending at the instance reduces the
	// balance available for new reservations; admission must account for it.
	statedb.SetState(paymaster, core.CanonicalPaymasterSlotPendingWithdrawal, common.BigToHash(big.NewInt(999_999_999_900)))
	tx3 := signedPayTx(t, k3, 0, 100, paymaster, sponsorKey)
	if err := pool.addRemoteSync(tx3); !errors.Is(err, core.ErrInsufficientFunds) {
		t.Fatalf("admission ignored pending withdrawal: %v", err)
	}
}

// TestFramePoolCanonicalExemptionHashSpecific: the validation-rule exemption
// applies only to code matching the pinned canonical hash. Other code that
// reads its own storage in a pay frame still violates the storage-read rule.
func TestFramePoolCanonicalExemptionHashSpecific(t *testing.T) {
	pool, statedb := setupFramePool(t)
	paymaster := common.BytesToAddress([]byte("not-canonical-paymaster"))
	sponsorKey, _ := crypto.GenerateKey()
	sponsor := crypto.PubkeyToAddress(sponsorKey.PublicKey)
	k1, _ := crypto.GenerateKey()
	// PUSH1 0 SLOAD POP; then approve PAYMENT. Reads its own slot 0, which
	// the validation storage-read rule forbids outside tx.sender.
	sloadApprove := []byte{0x60, 0x00, 0x54, 0x50, 0x60, 0x01, 0x60, 0x00, 0x60, 0x00, 0xaa, 0x00}
	statedb.SetCode(paymaster, sloadApprove, tracing.CodeChangeContractCreation)
	statedb.SetState(paymaster, core.CanonicalPaymasterSlotSigner, common.BytesToHash(sponsor.Bytes()))
	fund(statedb, paymaster, 1_000_000_000_000)
	fund(statedb, crypto.PubkeyToAddress(k1.PublicKey), 1_000_000_000)

	err := pool.addRemoteSync(signedPayTx(t, k1, 0, 100, paymaster, sponsorKey))
	if err == nil || !strings.Contains(err.Error(), "storage read") {
		t.Fatalf("non-canonical pay frame storage read not rejected: %v", err)
	}
}
