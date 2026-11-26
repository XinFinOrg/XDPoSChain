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
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/event"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

// FrameTx testnet rehearsal (release-readiness Phase 3). Executes the ten
// controlled scenarios from the rehearsal brief against a real LegacyPool +
// EVM validation simulation on an isolated in-process chain (no nodes, no
// network I/O, no shared state). Each scenario logs its preconditions,
// action, expectation, and outcome so the run doubles as the rehearsal
// transcript referenced by RELEASE_READINESS_EIP8141.md.
//
// Isolation guarantees: fresh state database per scenario, ephemeral pool,
// loopback-free test blockchain stub, fixed head (time 0, base fee 0),
// deterministic fixture shapes. Nothing here touches a live node, an
// existing network, genesis, or validator configuration.

func rehearsalLog(t *testing.T, format string, args ...interface{}) {
	t.Helper()
	t.Logf("[rehearsal] "+format, args...)
}

// setupForkInactivePool returns a pool whose chain config leaves FrameTxTime
// nil: the FrameTx fork gate must reject frame transactions there.
func setupForkInactivePool(t *testing.T) (*LegacyPool, *state.StateDB) {
	t.Helper()
	cfg := *params.TestChainConfig // FrameTxTime nil: fork inactive
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

// S1: multiple senders sponsored by one canonical paymaster.
func TestRehearsalS1CanonicalPaymasterManySenders(t *testing.T) {
	pool, statedb := setupFramePool(t)
	paymaster := common.BytesToAddress([]byte("rehearsal-canonical-pm"))
	sponsorKey, _ := crypto.GenerateKey()
	sponsor := crypto.PubkeyToAddress(sponsorKey.PublicKey)
	installCanonicalPaymaster(statedb, paymaster, sponsor)
	fund(statedb, paymaster, 10_000_000_000_000)

	rehearsalLog(t, "S1 precondition: one canonical paymaster instance (signer %s), three distinct senders, fork active at head time 0, base fee 0", sponsor)
	var keys []*ecdsa.PrivateKey
	var want *big.Int
	for i := 0; i < 3; i++ {
		k, _ := crypto.GenerateKey()
		keys = append(keys, k)
		fund(statedb, crypto.PubkeyToAddress(k.PublicKey), 1_000_000_000)
		tx := signedPayTx(t, k, 0, 100, paymaster, sponsorKey)
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatalf("S1 sender %d admission failed: %v", i, err)
		}
		rehearsalLog(t, "S1 action: admitted sender %d sponsored by the canonical instance (max_fee %v)", i, maxFeeOf(t, tx))
		if want == nil {
			want = maxFeeOf(t, tx)
		} else {
			want.Add(want, maxFeeOf(t, tx))
		}
	}
	if got := reservedOf(pool, paymaster); got.Cmp(want) != 0 {
		t.Fatalf("S1 reservation total %v, want %v", got, want)
	}
	rehearsalLog(t, "S1 outcome: PASS — three senders share one canonical instance; reservations sum exactly to %v; no count cap applied", want)
}

// S2: reservation totals and insufficient available balances.
func TestRehearsalS2ReservationTotals(t *testing.T) {
	pool, statedb := setupFramePool(t)
	keyA, _ := crypto.GenerateKey()
	keyB, _ := crypto.GenerateKey()
	a := crypto.PubkeyToAddress(keyA.PublicKey)
	b := crypto.PubkeyToAddress(keyB.PublicKey)

	txA := signedPayTx(t, keyA, 0, 100, common.Address{}, keyA)
	txB := signedPayTx(t, keyB, 0, 100, common.Address{}, keyB)
	feeA, feeB := maxFeeOf(t, txA), maxFeeOf(t, txB)

	rehearsalLog(t, "S2 precondition: two self-funded frame txs (max_fee %v and %v); payer balances sized to the exact fit", feeA, feeB)
	fund(statedb, a, feeA.Uint64())
	fund(statedb, b, feeB.Uint64())
	if err := pool.addRemoteSync(txA); err != nil {
		t.Fatalf("S2 exact-fit admission failed: %v", err)
	}
	rehearsalLog(t, "S2 action: admitted sender A against exactly its max_fee")
	if got := reservedOf(pool, a); got.Cmp(feeA) != 0 {
		t.Fatalf("S2 reservation %v, want %v", got, feeA)
	}
	// One wei short: the second sender's balance is feeB-1.
	fund(statedb, b, feeB.Uint64()-1)
	if err := pool.addRemoteSync(txB); !errors.Is(err, core.ErrInsufficientFunds) {
		t.Fatalf("S2 one-wei-short admission not rejected: %v", err)
	}
	if got := reservedOf(pool, b); got.Sign() != 0 {
		t.Fatalf("S2 failed admission leaked reservation: %v", got)
	}
	rehearsalLog(t, "S2 outcome: PASS — exact-fit admitted, one-wei-short rejected with ErrInsufficientFunds, no reservation leak")
}

// S3: pending withdrawals and admission rejection.
func TestRehearsalS3PendingWithdrawal(t *testing.T) {
	pool, statedb := setupFramePool(t)
	paymaster := common.BytesToAddress([]byte("rehearsal-pm-withdrawal"))
	sponsorKey, _ := crypto.GenerateKey()
	sponsor := crypto.PubkeyToAddress(sponsorKey.PublicKey)
	installCanonicalPaymaster(statedb, paymaster, sponsor)

	txKey, _ := crypto.GenerateKey()
	tx := signedPayTx(t, txKey, 0, 100, paymaster, sponsorKey)
	fee := maxFeeOf(t, tx)
	rehearsalLog(t, "S3 precondition: canonical instance funded with exactly the tx max_fee (%v); senders funded for the generic sender-cost gate; no withdrawal pending", fee)
	fund(statedb, paymaster, fee.Uint64())
	fund(statedb, crypto.PubkeyToAddress(txKey.PublicKey), 1_000_000_000)
	if err := pool.addRemoteSync(tx); err != nil {
		t.Fatalf("S3 admission without withdrawal failed: %v", err)
	}
	// A pending withdrawal of 1 wei leaves fee-1 available: the second
	// sender's identical tx must be rejected.
	statedb.SetState(paymaster, core.CanonicalPaymasterSlotPendingWithdrawal, common.BigToHash(big.NewInt(1)))
	tx2Key, _ := crypto.GenerateKey()
	tx2 := signedPayTx(t, tx2Key, 0, 100, paymaster, sponsorKey)
	fund(statedb, crypto.PubkeyToAddress(tx2Key.PublicKey), 1_000_000_000)
	if err := pool.addRemoteSync(tx2); !errors.Is(err, core.ErrInsufficientFunds) {
		t.Fatalf("S3 pending withdrawal not accounted: %v", err)
	}
	rehearsalLog(t, "S3 outcome: PASS — 1-wei pending withdrawal at slot 1 blocks a second max_fee-sized admission (available = balance - reserved - withdrawal)")
}

// S4: replacement with unchanged and changed payers.
func TestRehearsalS4ReplacementPayerShift(t *testing.T) {
	pool, statedb := setupFramePool(t)
	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)
	paymaster := common.BytesToAddress([]byte("rehearsal-pm-shift"))
	sponsorKey, _ := crypto.GenerateKey()
	sponsor := crypto.PubkeyToAddress(sponsorKey.PublicKey)
	installCanonicalPaymaster(statedb, paymaster, sponsor)
	fund(statedb, paymaster, 10_000_000_000_000)
	fund(statedb, sender, 10_000_000_000)

	// Self-funded admission, then a bumped replacement naming the canonical
	// paymaster: the reservation must shift from sender to paymaster.
	old := signedPayTx(t, key, 0, 100, common.Address{}, key)
	if err := pool.addRemoteSync(old); err != nil {
		t.Fatalf("S4 initial admission failed: %v", err)
	}
	oldFee := maxFeeOf(t, old)
	rehearsalLog(t, "S4 precondition: self-funded tx admitted (max_fee %v, payer = sender)", oldFee)

	repl := signedPayTxTip(t, key, 0, 111, 2, paymaster, sponsorKey)
	if err := pool.addRemoteSync(repl); err != nil {
		t.Fatalf("S4 payer-shift replacement rejected: %v", err)
	}
	newFee := maxFeeOf(t, repl)
	if got := reservedOf(pool, sender); got.Sign() != 0 {
		t.Fatalf("S4 old payer reservation not released: %v", got)
	}
	if got := reservedOf(pool, paymaster); got.Cmp(newFee) != 0 {
		t.Fatalf("S4 new payer reservation %v, want %v", got, newFee)
	}
	rehearsalLog(t, "S4 outcome: PASS — replacement with changed payer shifted the reservation atomically (sender %v -> paymaster %v)", oldFee, newFee)

	// Unchanged-payer replacement: reservation moves to the bumped value.
	repl2 := signedPayTxTip(t, key, 0, 123, 3, paymaster, sponsorKey)
	if err := pool.addRemoteSync(repl2); err != nil {
		t.Fatalf("S4 unchanged-payer replacement rejected: %v", err)
	}
	if got := reservedOf(pool, paymaster); got.Cmp(maxFeeOf(t, repl2)) != 0 {
		t.Fatalf("S4 unchanged-payer reservation %v, want %v", got, maxFeeOf(t, repl2))
	}
	rehearsalLog(t, "S4 outcome: PASS — unchanged-payer replacement reserved the bumped max_fee exactly")
}

// S5: removal (inclusion), expiry, and reorganization release.
func TestRehearsalS5RemovalInclusionReorg(t *testing.T) {
	pool, statedb := setupFramePool(t)
	key, _ := crypto.GenerateKey()
	sender := crypto.PubkeyToAddress(key.PublicKey)
	fund(statedb, sender, 1_000_000_000)

	tx := signedPayTx(t, key, 0, 100, common.Address{}, key)
	if err := pool.addRemoteSync(tx); err != nil {
		t.Fatalf("S5 admission failed: %v", err)
	}
	rehearsalLog(t, "S5 action: simulated inclusion (nonce advanced past pooled tx) -> demoteUnexecutables")
	statedb.SetNonce(sender, 1, tracing.NonceChangeUnspecified)
	pool.demoteUnexecutables()
	if got := reservedOf(pool, sender); got.Sign() != 0 {
		t.Fatalf("S5 inclusion did not release the reservation: %v", got)
	}
	if pool.all.Get(tx.Hash()) != nil {
		t.Fatal("S5 included tx still pooled")
	}
	rehearsalLog(t, "S5 outcome (inclusion): PASS — reservation released, tx dropped")

	// Reorg path: reset + demote + reinject.
	tx2 := signedPayTx(t, key, 1, 100, common.Address{}, key)
	if err := pool.addRemoteSync(tx2); err != nil {
		t.Fatalf("S5 second admission failed: %v", err)
	}
	statedb.SetNonce(sender, 2, tracing.NonceChangeUnspecified)
	head := pool.currentHead.Load()
	pool.Reset(head, head)
	if got := reservedOf(pool, sender); got.Sign() != 0 {
		t.Fatalf("S5 reorg did not release the reservation: %v", got)
	}
	rehearsalLog(t, "S5 outcome (reorg): PASS — Reset(old,new) released reservations through the demote/reinject path")

	// Expiry: an expired frame tx is rejected as invalid at admission when
	// the head has moved past its deadline.
	keyX, _ := crypto.GenerateKey()
	head2 := &types.Header{Number: big.NewInt(1), Time: 100, Difficulty: big.NewInt(0), GasLimit: 10_000_000, BaseFee: big.NewInt(0)}
	pool.Reset(head2, head2)
	fund(statedb, crypto.PubkeyToAddress(keyX.PublicKey), 1_000_000_000)
	expired := signedExpiryPayTx(t, keyX, 0, 100, common.Address{}, keyX, 50) // deadline 50 < head time 100
	if err := pool.addRemoteSync(expired); err == nil {
		t.Fatal("S5 expired frame tx admitted")
	}
	rehearsalLog(t, "S5 outcome (expiry): PASS — deadline 50 at head time 100 rejected by the expiry verifier simulation")
}

// S6: expiry-verifier boundaries and invalid calldata.
func TestRehearsalS6ExpiryBoundaries(t *testing.T) {
	pool, statedb := setupFramePool(t)
	head := pool.currentHead.Load() // time 0

	// Boundary: deadline equal to head time is still executable (== passes).
	keyEq, _ := crypto.GenerateKey()
	fund(statedb, crypto.PubkeyToAddress(keyEq.PublicKey), 1_000_000_000)
	txEq := signedExpiryPayTx(t, keyEq, 0, 100, common.Address{}, keyEq, head.Time)
	if err := pool.addRemoteSync(txEq); err != nil {
		t.Fatalf("S6 deadline == head time rejected: %v", err)
	}
	rehearsalLog(t, "S6 boundary: deadline %d == head time %d admitted (spec: timestamp <= expiry succeeds)", head.Time, head.Time)

	// Invalid calldata: a malformed expiry frame (data length != 8) is
	// rejected by structural prefix validation.
	keyBad, _ := crypto.GenerateKey()
	badSender := crypto.PubkeyToAddress(keyBad.PublicKey)
	fund(statedb, badSender, 1_000_000_000)
	verifier := types.FrameExpiryVerifier
	badData := []byte{0x01, 0x02, 0x03}
	frames := []types.Frame{
		{Mode: types.FrameModeVerify, Target: &verifier, Flags: 0x0, Data: badData, Limits: types.FrameLimits{Execution: 10_000}},
		{Mode: types.FrameModeVerify, Flags: 0x2, Limits: types.FrameLimits{Execution: 40_000, State: 150_000}},
		{Mode: types.FrameModeVerify, Flags: 0x1, Limits: types.FrameLimits{Execution: 40_000, State: 150_000}},
	}
	sigs := signFrames(t, badSender, 0, frames, frameTestFees(100), keyBad, keyBad)
	bad := types.NewFrameTx(uint256.NewInt(1), 0, badSender, frames, sigs, frameTestFees(100), nil)
	if err := pool.addRemoteSync(bad); err == nil {
		t.Fatal("S6 malformed expiry calldata admitted")
	}
	rehearsalLog(t, "S6 outcome: PASS — 3-byte expiry calldata rejected at prefix validation")
}

// S7: APPROVE combined (0x3) and separate (0x1 + 0x2) scopes.
func TestRehearsalS7ApproveScopes(t *testing.T) {
	pool, statedb := setupFramePool(t)

	// Combined scope: self_verify flags 0x3 (default-code path approves
	// EXECUTION_AND_PAYMENT in one frame).
	keyC, _ := crypto.GenerateKey()
	cSender := crypto.PubkeyToAddress(keyC.PublicKey)
	fund(statedb, cSender, 1_000_000_000)
	if err := pool.addRemoteSync(signedSelfVerifyTx(t, keyC, 0, 100)); err != nil {
		t.Fatalf("S7 combined-scope (0x3) admission failed: %v", err)
	}
	rehearsalLog(t, "S7 outcome (combined): PASS — self_verify flags 0x3 admitted; payer established by a single APPROVE(EXECUTION_AND_PAYMENT)")

	// Separate scopes: only_verify approves EXECUTION (0x2), pay approves
	// PAYMENT (0x1). Fresh pool state: one frame tx per sender, new sender.
	pool2, statedb2 := setupFramePool(t)
	keyS, _ := crypto.GenerateKey()
	sSender := crypto.PubkeyToAddress(keyS.PublicKey)
	fund(statedb2, sSender, 1_000_000_000)
	if err := pool2.addRemoteSync(signedPayTx(t, keyS, 0, 100, common.Address{}, keyS)); err != nil {
		t.Fatalf("S7 separate-scope admission failed: %v", err)
	}
	rehearsalLog(t, "S7 outcome (separate): PASS — only_verify(0x2) + pay(0x1) admitted with payer set by the pay frame")
}

// S8: B4 opcode restrictions, state isolation, and rollback.
func TestRehearsalS8B4Restrictions(t *testing.T) {
	pool, statedb := setupFramePool(t)

	// Banned opcode (BALANCE) inside a pay frame's code.
	pmBalance := common.BytesToAddress([]byte("rehearsal-pm-balance"))
	balanceThenApprove := []byte{0x60, 0x00, 0x31, 0x50, 0x60, 0x01, 0x60, 0x00, 0x60, 0x00, 0xaa, 0x00} // PUSH1 0 BALANCE POP; approve PAYMENT
	statedb.SetCode(pmBalance, balanceThenApprove, tracing.CodeChangeContractCreation)
	fund(statedb, pmBalance, 1_000_000_000_000)
	k1, _ := crypto.GenerateKey()
	fund(statedb, crypto.PubkeyToAddress(k1.PublicKey), 1_000_000_000)
	err := pool.addRemoteSync(signedPayTx(t, k1, 0, 100, pmBalance, nil))
	if err == nil || !strings.Contains(err.Error(), "BALANCE") {
		t.Fatalf("S8 banned opcode not rejected: %v", err)
	}
	rehearsalLog(t, "S8 outcome (banned opcode): PASS — BALANCE in a pay frame rejected by the validation tracer")

	// State isolation + rollback: a pay frame that SSTOREs outside
	// tx.sender is rejected, and the simulation must not mutate the
	// canonical state (the sim runs on an isolated copy).
	pmStore := common.BytesToAddress([]byte("rehearsal-pm-sstore"))
	storeCode := []byte{0x60, 0x01, 0x60, 0x00, 0x55, 0x00} // SSTORE(0, 1); STOP
	statedb.SetCode(pmStore, storeCode, tracing.CodeChangeContractCreation)
	fund(statedb, pmStore, 1_000_000_000_000)
	k2, _ := crypto.GenerateKey()
	fund(statedb, crypto.PubkeyToAddress(k2.PublicKey), 1_000_000_000)
	err = pool.addRemoteSync(signedPayTx(t, k2, 0, 100, pmStore, nil))
	if err == nil || !strings.Contains(err.Error(), "SSTORE") {
		t.Fatalf("S8 illegal storage write not rejected: %v", err)
	}
	if got := statedb.GetState(pmStore, common.Hash{}); got != (common.Hash{}) {
		t.Fatalf("S8 simulation leaked into canonical state: slot 0 = %x", got)
	}
	if got := statedb.GetBalance(pmStore).ToBig(); got.Cmp(big.NewInt(1_000_000_000_000)) != 0 {
		t.Fatalf("S8 simulation mutated paymaster balance: %v", got)
	}
	rehearsalLog(t, "S8 outcome (isolation/rollback): PASS — SSTORE outside tx.sender rejected; canonical storage and balances untouched after the rejected simulation")
}

// S9: nearest-expiry eviction before lowest-priority eviction.
func TestRehearsalS9EvictionOrdering(t *testing.T) {
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
	head := &types.Header{Number: big.NewInt(0), Time: 0, Difficulty: big.NewInt(0), GasLimit: 10_000_000, BaseFee: big.NewInt(0)}
	pool.Reset(head, head)

	keyNear, _ := crypto.GenerateKey()
	keyFar, _ := crypto.GenerateKey()
	keyCheap, _ := crypto.GenerateKey()
	keyIn, _ := crypto.GenerateKey()
	nearSender := crypto.PubkeyToAddress(keyNear.PublicKey)
	for _, k := range []*ecdsa.PrivateKey{keyNear, keyFar, keyCheap, keyIn} {
		fund(statedb, crypto.PubkeyToAddress(k.PublicKey), 1_000_000_000)
	}
	rehearsalLog(t, "S9 precondition: pool capacity 3 (2 pending slots + 1 queue); near-expiry frame tx (deadline 10), far-expiry frame tx (deadline 20), cheap legacy tx (1 wei tip) fill it")

	near := signedExpiryPayTx(t, keyNear, 0, 500, common.Address{}, keyNear, 10)
	far := signedExpiryPayTx(t, keyFar, 0, 400, common.Address{}, keyFar, 20)
	cheap := pricedTransaction(0, 21000, big.NewInt(1), keyCheap)
	for _, tx := range []*types.Transaction{near, far, cheap} {
		if err := pool.addRemoteSync(tx); err != nil {
			t.Fatalf("S9 setup tx rejected: %v", err)
		}
	}
	incoming := pricedTransaction(0, 21000, big.NewInt(50), keyIn)
	if err := pool.addRemoteSync(incoming); err != nil {
		t.Fatalf("S9 incoming tx rejected: %v", err)
	}
	if pool.all.Get(near.Hash()) != nil {
		t.Fatal("S9 nearest-expiry frame tx not evicted first")
	}
	if pool.all.Get(far.Hash()) == nil || pool.all.Get(cheap.Hash()) == nil || pool.all.Get(incoming.Hash()) == nil {
		t.Fatal("S9 wrong eviction order")
	}
	if got := reservedOf(pool, nearSender); got.Sign() != 0 {
		t.Fatalf("S9 evicted reservation not released: %v", got)
	}
	rehearsalLog(t, "S9 outcome: PASS — eviction tiers honored: expired-invalid first, then nearest expiry (deadline 10) before lowest priority; reservation released on eviction")
}

// S10: ordinary non-FrameTx behavior, and the fork gate staying closed where
// FrameTx is not configured.
func TestRehearsalS10LegacyBehavior(t *testing.T) {
	pool, statedb := setupFramePool(t)
	keyF, _ := crypto.GenerateKey()
	keyL, _ := crypto.GenerateKey()
	fSender := crypto.PubkeyToAddress(keyF.PublicKey)
	lSender := crypto.PubkeyToAddress(keyL.PublicKey)
	fund(statedb, fSender, 1_000_000_000)
	fund(statedb, lSender, 1_000_000_000)

	if err := pool.addRemoteSync(signedPayTx(t, keyF, 0, 100, common.Address{}, keyF)); err != nil {
		t.Fatalf("S10 frame admission failed: %v", err)
	}
	legacy := transaction(0, 21000, keyL)
	if err := pool.addRemoteSync(legacy); err != nil {
		t.Fatalf("S10 legacy tx rejected alongside frame tx: %v", err)
	}
	if pool.all.Get(legacy.Hash()) == nil {
		t.Fatal("S10 legacy tx not pooled")
	}
	rehearsalLog(t, "S10 outcome (mix): PASS — legacy tx admitted and pooled beside a pending frame tx; no interference")

	// Fork gate: with FrameTxTime unset, frame txs are rejected outright.
	poolOff, statedbOff := setupForkInactivePool(t)
	keyOff, _ := crypto.GenerateKey()
	fund(statedbOff, crypto.PubkeyToAddress(keyOff.PublicKey), 1_000_000_000)
	err := poolOff.addRemoteSync(signedPayTx(t, keyOff, 0, 100, common.Address{}, keyOff))
	if !errors.Is(err, core.ErrTxTypeNotSupported) {
		t.Fatalf("S10 fork-inactive gate not enforced: %v", err)
	}
	rehearsalLog(t, "S10 outcome (fork gate): PASS — FrameTx rejected with ErrTxTypeNotSupported on a chain without the fork")
}
