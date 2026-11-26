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
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/txpool"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// maxPendingNonCanonicalPaymaster is the EIP-8141
// MAX_PENDING_TXS_USING_NON_CANONICAL_PAYMASTER policy constant ("/tmp"
// specification, "Payer Reservations And Exposure"): at most one pending
// public-mempool transaction may use any given non-canonical paymaster.
const maxPendingNonCanonicalPaymaster = 1

// canonicalPaymasterCodeHash identifies the EIP-8141 canonical paymaster
// implementation. Recognition is by runtime code hash, per ethereum/EIPs
// PR #12041 ("Update EIP-8141: assembled canonical paymaster reference
// bytecode", EIP author Marchhill, 2026-10): an instance is canonical iff
// keccak256(runtime code) equals this pinned hash. The hash was verified
// locally against the PR's published 355-byte runtime. The EIP master text
// still leaves the canonical paymaster unspecified (the PR is open at the
// time of writing); per the PR's own text the hash becomes fork-pinned when
// merged, at which point this constant tracks the finalized value.
var canonicalPaymasterCodeHash = core.CanonicalPaymasterCodeHash

// headTime returns the current head timestamp (0 when no head is loaded yet);
// frame prefix freshness and sender-cost derivation use it as "now".
func headTime(pool *LegacyPool) uint64 {
	if head := pool.currentHead.Load(); head != nil {
		return head.Time
	}
	return 0
}

// Canonical paymaster instance storage layout (normative per PR #12041):
// slot 0 signer, slot 1 pending_withdrawal_amount, slot 2 pending_unlock_time,
// slot 3 pending_new_signer. Nodes read these slots directly for admission
// and revalidation; no EVM execution is required to compute solvency.
var (
	canonicalPaymasterSlotPendingWithdrawal = core.CanonicalPaymasterSlotPendingWithdrawal
	canonicalPaymasterSlotUnlockTime        = core.CanonicalPaymasterSlotUnlockTime
)

// pendingWithdrawalAmount returns the EIP-8141 pending_withdrawal_amount
// term for the reservation formula: storage slot 1 of a canonical paymaster
// instance, or zero when no delayed withdrawal is pending. The value is not
// meaningful for payers that are not canonical paymaster instances and is
// reported as zero for them.
func pendingWithdrawalAmount(st *state.StateDB, payer common.Address, class framePayerClass) *big.Int {
	if class != framePayerCanonical || st == nil {
		return new(big.Int)
	}
	return st.GetState(payer, canonicalPaymasterSlotPendingWithdrawal).Big()
}

// framePayerClass classifies the payer of a frame transaction for
// reservation accounting (EIP-8141 "Payer Reservations And Exposure").
type framePayerClass uint8

const (
	// framePayerSelf is a self-funded transaction (no pay frame in the
	// validation prefix). Governed by the per-payer exposure rule alone.
	framePayerSelf framePayerClass = iota
	// framePayerDefaultCode is a pay frame whose target has the empty code
	// hash (a default-code sponsor). Per the specification it "is not a
	// paymaster and is governed by the per-payer exposure rule alone": the
	// balance rule applies, the pending-count cap does not.
	framePayerDefaultCode
	// framePayerNonCanonical is a pay frame whose target carries deployed
	// code whose hash differs from the pinned canonical paymaster code
	// hash. Subject to the balance rule and the
	// MAX_PENDING_TXS_USING_NON_CANONICAL_PAYMASTER cap.
	framePayerNonCanonical
	// framePayerCanonical is a pay frame whose target's runtime code hash
	// equals the pinned canonical paymaster code hash. Subject to the
	// balance rule including the instance's pending withdrawal amount
	// (storage slot 1) and exempt from the pending-count cap.
	framePayerCanonical
)

// frameReservation describes the reservation a single pending frame
// transaction holds against its payer.
type frameReservation struct {
	payer  common.Address
	sender common.Address
	nonce  uint64
	maxFee *big.Int // aggregate fee-cap budget (upper bound of max_cost at any base fee)
	class  framePayerClass
	expiry uint64 // expiry deadline, 0 if the prefix carries no expiry verifier frame
}

// ErrFramePaymasterLimitReached is returned when a frame transaction names a
// non-canonical paymaster that already has
// MAX_PENDING_TXS_USING_NON_CANONICAL_PAYMASTER pending transactions.
var ErrFramePaymasterLimitReached = errors.New("non-canonical paymaster pending transaction limit reached")

// ErrFrameSenderPendingLimit is returned when a sender already has a pending
// frame transaction and submits another one at a different nonce
// (specification: at most one pending frame transaction per sender).
var ErrFrameSenderPendingLimit = errors.New("sender already has a pending frame transaction")

// frameReservations tracks EIP-8141 payer reservations for the public
// mempool: the pending max-fee exposure per payer and the pending count per
// non-canonical paymaster. Reservations are keyed by (sender, nonce): the
// specification admits at most one PENDING frame transaction per sender
// (replacement identity is (sender, nonce)), but a sender may also hold
// QUEUED frame transactions — every admission, queued or pending, reserves
// its payer exposure from submission until removal.
//
// Invariants:
//   - bySender[s][n] is the reservation of the sender's admitted frame
//     transaction at nonce n (at most one per (sender, nonce)).
//   - reserved[p] equals the sum of maxFee over all bySender entries with
//     payer p (queued and pending admissions alike).
//   - nonCanonical[p] equals the number of bySender entries with payer p and
//     class framePayerNonCanonical.
//   - release is idempotent: releasing the same (sender, nonce) twice (or a
//     sender with no reservations) changes nothing.
type frameReservations struct {
	mu                  sync.Mutex
	bySender            map[common.Address]map[uint64]*frameReservation
	reserved            map[common.Address]*big.Int
	nonCanonicalPending map[common.Address]int
}

func newFrameReservations() *frameReservations {
	return &frameReservations{
		bySender:            make(map[common.Address]map[uint64]*frameReservation),
		reserved:            make(map[common.Address]*big.Int),
		nonCanonicalPending: make(map[common.Address]int),
	}
}

// frameTxMaxFee returns the transaction's max_fee: the upper bound of
// max_cost at any base fees. Per the EIP-8141 "Fee budget" section the fee
// cap is a single aggregate max_cost bound, so the reservation exposure is
// GasFeeCap itself — NOT GasFeeCap*MaxGas (the fee cap is not a per-gas
// price). The blob component keeps its per-unit semantics (additive).
func frameTxMaxFee(ftx *types.FrameTx) *big.Int {
	maxFee := ftx.Fees.GasFeeCap.ToBig()
	if len(ftx.BlobHashes) > 0 && ftx.Fees.BlobFeeCap != nil {
		blobGas := uint64(len(ftx.BlobHashes)) * params.BlobTxBlobGasPerBlob
		maxFee.Add(maxFee, new(big.Int).Mul(ftx.Fees.BlobFeeCap.ToBig(), new(big.Int).SetUint64(blobGas)))
	}
	return maxFee
}

// frameTxPayerInfo determines the payer, reservation amount and paymaster
// class of a frame transaction from its validation prefix. The transaction
// must already have passed ValidateMempoolPrefix (admission order); now is
// the current head timestamp, used only for the expiry-deadline bookkeeping
// that drives eviction ordering. st must be the current head state; it is
// used only to inspect payer code.
func frameTxPayerInfo(ftx *types.FrameTx, st *state.StateDB, now uint64) (*frameReservation, error) {
	frames, species, err := ftx.ValidationPrefix(now)
	if err != nil {
		return nil, err
	}
	info := &frameReservation{maxFee: frameTxMaxFee(ftx), payer: ftx.Sender, sender: ftx.Sender, nonce: ftx.Nonce, class: framePayerSelf}
	for i, sp := range species {
		if sp == types.FrameSpeciesExpiry {
			if len(frames[i].Data) == types.FrameExpiryDataLength {
				var deadline uint64
				for _, b := range frames[i].Data {
					deadline = deadline<<8 | uint64(b)
				}
				info.expiry = deadline
			}
			continue
		}
	}
	// Payer derivation is shared with the sender-cost gate
	// (core.FrameTxFeePayer) so the balance check, the reservations and the
	// class-based caps all agree on who pays. Classification still applies
	// whenever a pay frame exists, even when it resolves to the sender.
	if payer, hasPay := core.FrameTxFeePayer(ftx, now); hasPay {
		info.payer = payer
		switch {
		case st != nil && st.GetCodeHash(payer) == canonicalPaymasterCodeHash:
			info.class = framePayerCanonical
		case st == nil || len(st.GetCode(payer)) == 0:
			info.class = framePayerDefaultCode
		default:
			info.class = framePayerNonCanonical
		}
	}
	return info, nil
}

// availableLocked computes the payer balance minus existing reservations and
// (for canonical paymaster instances) the pending withdrawal amount.
func (r *frameReservations) availableLocked(payer common.Address, balance, withdrawal *big.Int) *big.Int {
	avail := new(big.Int).Set(balance)
	if reserved := r.reserved[payer]; reserved != nil {
		avail.Sub(avail, reserved)
	}
	if withdrawal != nil {
		avail.Sub(avail, withdrawal)
	}
	return avail
}

// checkAdmit verifies that a fresh admission (no existing pending tx from
// this sender) may reserve info.maxFee against info.payer. Non-mutating.
func (r *frameReservations) checkAdmit(info *frameReservation, balance, withdrawal *big.Int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.checkAdmitLocked(info, balance, withdrawal)
}

// hasSender reports whether the sender holds any frame reservation
// (queued or pending). It does not implement the admission guard: the
// specification constrains PENDING frame transactions only, so admission
// must consult the pending pool, not the reservation map. Test/debug
// accessor.
func (r *frameReservations) hasSender(sender common.Address) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bySender[sender]) > 0
}

// expiredReservations returns the sender/nonce/expiry of every pending
// reservation whose expiry deadline has passed at the given timestamp
// (deadline semantics per the expiry verifier: a deadline equal to now is
// still executable, so expiration is now > deadline).
func (r *frameReservations) expiredReservations(now uint64) []frameReservation {
	r.mu.Lock()
	defer r.mu.Unlock()
	var expired []frameReservation
	for _, byNonce := range r.bySender {
		for _, info := range byNonce {
			if info.expiry != 0 && now > info.expiry {
				expired = append(expired, *info)
			}
		}
	}
	return expired
}

func (r *frameReservations) checkAdmitLocked(info *frameReservation, balance, withdrawal *big.Int) error {
	if avail := r.availableLocked(info.payer, balance, withdrawal); avail.Cmp(info.maxFee) < 0 {
		return fmt.Errorf("%w: payer %s available balance %v below frame transaction max_fee %v", core.ErrInsufficientFunds, info.payer, avail, info.maxFee)
	}
	if info.class == framePayerNonCanonical && r.nonCanonicalPending[info.payer] >= maxPendingNonCanonicalPaymaster {
		return fmt.Errorf("%w: non-canonical paymaster %s already at MAX_PENDING_TXS_USING_NON_CANONICAL_PAYMASTER (%d)", ErrFramePaymasterLimitReached, info.payer, maxPendingNonCanonicalPaymaster)
	}
	return nil
}

// take records the reservation for an admitted transaction. Callers must
// have run checkAdmit (or checkReplace) first; pool.mu serializes admission.
func (r *frameReservations) take(sender common.Address, info *frameReservation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.takeLocked(sender, info)
}

func (r *frameReservations) takeLocked(sender common.Address, info *frameReservation) {
	// Same-(sender, nonce) re-take (the replacement path re-takes after
	// checkReplace validated the shift): release the old entry first so the
	// payer is never double-counted. Reservations of the sender's OTHER
	// nonces (e.g. a queued frame tx admitted alongside a pending one) are
	// tracked under their own nonce and stay intact.
	if byNonce := r.bySender[sender]; byNonce != nil {
		if stale, ok := byNonce[info.nonce]; ok {
			r.dropLocked(sender, stale)
		}
	}
	if r.bySender[sender] == nil {
		r.bySender[sender] = make(map[uint64]*frameReservation)
	}
	r.bySender[sender][info.nonce] = info
	if reserved := r.reserved[info.payer]; reserved != nil {
		reserved.Add(reserved, info.maxFee)
	} else {
		r.reserved[info.payer] = new(big.Int).Set(info.maxFee)
	}
	if info.class == framePayerNonCanonical {
		r.nonCanonicalPending[info.payer]++
	}
}

// releaseSender releases every reservation held by the sender. Idempotent:
// releasing a sender without reservations (or twice) is a no-op.
func (r *frameReservations) releaseSender(sender common.Address) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.releaseSenderLocked(sender)
}

func (r *frameReservations) releaseSenderLocked(sender common.Address) {
	for _, info := range r.bySender[sender] {
		r.dropLocked(sender, info)
	}
}

// release drops the reservation of the sender's frame transaction at the
// given nonce, if present. Idempotent: releasing a (sender, nonce) without a
// reservation (or twice) is a no-op, so every removal path may call it
// safely. Reservations of the sender's other nonces stay intact.
func (r *frameReservations) release(sender common.Address, nonce uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if info, ok := r.bySender[sender][nonce]; ok {
		r.dropLocked(sender, info)
	}
}

// dropLocked removes info's contribution from the accounting maps. The
// caller must hold r.mu; the (sender, nonce) entry must still be present.
func (r *frameReservations) dropLocked(sender common.Address, info *frameReservation) {
	if byNonce := r.bySender[sender]; byNonce != nil {
		delete(byNonce, info.nonce)
		if len(byNonce) == 0 {
			delete(r.bySender, sender)
		}
	}
	if reserved := r.reserved[info.payer]; reserved != nil {
		reserved.Sub(reserved, info.maxFee)
		if reserved.Sign() <= 0 {
			delete(r.reserved, info.payer)
		}
	}
	if info.class == framePayerNonCanonical {
		if n := r.nonCanonicalPending[info.payer]; n > 1 {
			r.nonCanonicalPending[info.payer] = n - 1
		} else {
			delete(r.nonCanonicalPending, info.payer)
		}
	}
}

// reservedTotal reports the total pending reservation against a payer.
// Test-only accessor.
func (r *frameReservations) reservedTotal(payer common.Address) *big.Int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if reserved := r.reserved[payer]; reserved != nil {
		return new(big.Int).Set(reserved)
	}
	return new(big.Int)
}

// nearestExpiryReservations returns up to limit pending frame reservations
// that carry a still-valid expiry deadline, ordered by nearest (smallest)
// deadline first. Frame transactions without an expiry deadline are not
// included; they fall through to lowest-priority eviction.
func (r *frameReservations) nearestExpiryReservations(now uint64, limit int) []frameReservation {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []frameReservation
	for _, byNonce := range r.bySender {
		for _, info := range byNonce {
			if info.expiry == 0 || now > info.expiry { // 0 = no deadline; expired handled as invalid
				continue
			}
			out = append(out, *info)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].expiry < out[j].expiry })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// checkReplace verifies that replacing the sender's pending transaction old
// with newInfo satisfies the specification replacement rules: both max_fee
// and max_priority_fee_per_gas increase by at least the configured bump, and
// reservation fits the payer's available balance (including the payer's
// pending withdrawal amount) once the old reservation is shifted. newFTX is
// the frame payload of the incoming transaction. Non-mutating;
// applyReplacement must follow a successful list.Add.
func (r *frameReservations) checkReplace(sender common.Address, old, new_ *types.Transaction, newFTX *types.FrameTx, newInfo *frameReservation, balance, withdrawal *big.Int, priceBump uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if oldFTX := old.FramePayload(); oldFTX != nil {
		// Specification replacement rule: both declared fee fields must rise
		// by the node-configured minimum increment. max_fee is aggregate in
		// this encoding; max_priority_fee_per_gas is the per-gas tip cap.
		oldMaxFee := frameTxMaxFee(oldFTX)
		if !bumpMet(oldMaxFee, newInfo.maxFee, priceBump) {
			return fmt.Errorf("%w: frame replacement max_fee %v below required bump over %v", txpool.ErrReplaceUnderpriced, newInfo.maxFee, oldMaxFee)
		}
		if !bumpMet(oldFTX.Fees.GasTipCap.ToBig(), newFTX.Fees.GasTipCap.ToBig(), priceBump) {
			return fmt.Errorf("%w: frame replacement max_priority_fee_per_gas below required bump", txpool.ErrReplaceUnderpriced)
		}
	}
	// The old reservation is released atomically with the shift, so exclude
	// it from the availability check when the payer is unchanged.
	avail := r.availableLocked(newInfo.payer, balance, withdrawal)
	if oldInfo := r.bySender[sender][new_.Nonce()]; oldInfo != nil && oldInfo.payer == newInfo.payer {
		avail.Add(avail, oldInfo.maxFee)
	}
	if avail.Cmp(newInfo.maxFee) < 0 {
		return fmt.Errorf("%w: payer %s available balance %v below replacement max_fee %v", core.ErrInsufficientFunds, newInfo.payer, avail, newInfo.maxFee)
	}
	if newInfo.class == framePayerNonCanonical {
		count := r.nonCanonicalPending[newInfo.payer]
		if oldInfo := r.bySender[sender][new_.Nonce()]; oldInfo != nil && oldInfo.payer == newInfo.payer && oldInfo.class == framePayerNonCanonical {
			count--
		}
		if count >= maxPendingNonCanonicalPaymaster {
			return fmt.Errorf("%w: non-canonical paymaster %s already at MAX_PENDING_TXS_USING_NON_CANONICAL_PAYMASTER (%d)", ErrFramePaymasterLimitReached, newInfo.payer, maxPendingNonCanonicalPaymaster)
		}
	}
	return nil
}

// applyReplacement atomically releases the sender's old reservation and takes
// the new one. Callers must have run checkReplace and list.Add successfully.
// Only the same-(sender, nonce) reservation being replaced is released:
// sibling reservations of the sender's other nonces (e.g. a queued frame tx
// admitted alongside a pending one) must stay intact (review finding B1).
func (r *frameReservations) applyReplacement(sender common.Address, info *frameReservation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if byNonce := r.bySender[sender]; byNonce != nil {
		if stale, ok := byNonce[info.nonce]; ok {
			r.dropLocked(sender, stale)
		}
	}
	r.takeLocked(sender, info)
}

// bumpMet reports whether newVal exceeds oldVal by at least priceBump
// percent (strictly greater, mirroring the pool's replacement semantics).
func bumpMet(oldVal, newVal *big.Int, priceBump uint64) bool {
	if oldVal.Sign() == 0 {
		return newVal.Sign() > 0
	}
	limit := new(big.Int).Mul(oldVal, new(big.Int).SetUint64(100+priceBump))
	limit.Div(limit, new(big.Int).SetUint64(100))
	return newVal.Cmp(limit) > 0
}
