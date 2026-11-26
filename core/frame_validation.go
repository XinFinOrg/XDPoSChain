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
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// ErrFrameValidation is returned when an EIP-8141 frame transaction fails
// public-mempool validation-prefix simulation.
var ErrFrameValidation = errors.New("frame validation simulation failed")

// canonicalExpiryRuntime is the EIP-8141 canonical expiry verifier bytecode
// ("Expiry Verifier Frame"). The TIMESTAMP exception applies only when the
// code deployed at EXPIRY_VERIFIER matches it (or none is deployed and the
// frame is evaluated directly).
var canonicalExpiryRuntime = common.FromHex("0x60083614600a575f5ffd5b5f3560c01c4211601657005b5f5ffd")

// CanonicalPaymasterCodeHash is the pinned keccak256 of the EIP-8141
// canonical paymaster runtime code per ethereum/EIPs PR #12041 ("Update
// EIP-8141: assembled canonical paymaster reference bytecode", EIP author
// Marchhill, 2026-10). Verified locally: keccak256 of the published
// 355-byte runtime equals this hash exactly. The EIP master text still
// leaves the canonical paymaster unspecified (the PR is open at the time
// of writing); per the PR's own text the hash becomes fork-pinned when
// merged, at which point this constant tracks the finalized value.
var CanonicalPaymasterCodeHash = common.HexToHash("0xda42f0d11838c4c0c3129b8b8e93e9718127ad6b315e517e1088125707c4d45c")

// Canonical paymaster instance storage layout, normative per PR #12041:
// nodes read these slots directly for admission and revalidation; no EVM
// execution is required to compute solvency.
var (
	CanonicalPaymasterSlotSigner            = common.BigToHash(big.NewInt(0)) // authorized signer
	CanonicalPaymasterSlotPendingWithdrawal = common.BigToHash(big.NewInt(1)) // pending_withdrawal_amount, 0 when none
	CanonicalPaymasterSlotUnlockTime        = common.BigToHash(big.NewInt(2)) // pending_unlock_time, shared maturity clock
	CanonicalPaymasterSlotNewSigner         = common.BigToHash(big.NewInt(3)) // pending_new_signer, 0 when none
)

// FrameTxFeePayer returns the effective fee payer of a frame transaction as
// determined by its public-mempool validation prefix: the target of the last
// pay frame (a missing target resolves to the sender), defaulting to the
// sender when the prefix contains no pay frame. The second return value
// reports whether a pay frame determined the payer at all; fee delegation to
// an account other than the sender (sponsorship) is caller == payer &&
// hasPay.
//
// now is the node's view of the current block timestamp. Prefix derivation
// includes expiry freshness, so a transaction whose expiry deadline has
// passed yields no payer here; callers must treat that as unsponsored (the
// conservative choice for balance checks) because full prefix validity is
// enforced separately at admission simulation.
func FrameTxFeePayer(ftx *types.FrameTx, now uint64) (common.Address, bool) {
	frames, species, err := ftx.ValidationPrefix(now)
	if err != nil {
		return ftx.Sender, false
	}
	payer := ftx.Sender
	hasPay := false
	for i, sp := range species {
		if sp != types.FrameSpeciesPay {
			continue
		}
		target := ftx.Sender
		if frames[i].Target != nil {
			target = *frames[i].Target
		}
		payer = target
		hasPay = true
	}
	return payer, hasPay
}

// FrameTxSenderCost returns the worst-case balance a transaction's sender
// must hold at pool admission. For EIP-8141 frame transactions whose
// validation prefix delegates fee payment to a different account, the sender
// covers the aggregate frame value only — the payer's maximum-fee solvency
// is enforced by the frame reservations, the validation-prefix simulation
// and on-chain settlement. When the sender self-pays, the requirement is
// value plus the aggregate fee cap, matching the historical gate. All other
// transaction types keep the raw value + gas*feeCap definition.
//
// now is the block timestamp used for prefix freshness (see FrameTxFeePayer);
// state-free accounting sites pass 0, under which expiry freshness never
// fails and payer determination reduces to the structural prefix.
func FrameTxSenderCost(tx *types.Transaction, now uint64) *big.Int {
	if tx.Type() != types.FrameTxType {
		return tx.Cost()
	}
	cost := tx.Value() // aggregate SENDER-frame value
	if payer, hasPay := FrameTxFeePayer(tx.FramePayload(), now); hasPay && payer != tx.FramePayload().Sender {
		return cost // sponsored: fee budget belongs to the payer
	}
	return cost.Add(cost, tx.GasFeeCap())
}

// frameValidationState wraps the copied simulation state and enforces the
// storage-read rule: SLOAD may access only tx.sender's storage, including
// when reached transitively via CALL* or DELEGATECALL, plus any address in
// allowed (the canonical-paymaster target while its exempted pay frame
// executes). Reads through this wrapper also cover the EVM's internal
// storage probes during SSTORE.
type frameValidationState struct {
	vm.StateDB
	sender    common.Address
	allowed   map[common.Address]bool
	violation *error
}

func (s *frameValidationState) GetState(addr common.Address, slot common.Hash) common.Hash {
	if addr != s.sender && !s.allowed[addr] && *s.violation == nil {
		*s.violation = fmt.Errorf("%w: storage read at %s outside tx.sender", ErrFrameValidation, addr)
	}
	return s.StateDB.GetState(addr, slot)
}

// SimulateFrameValidation simulates the public-mempool validation prefix of
// an EIP-8141 frame transaction against an isolated copy of sdb and rejects
// the transaction if any "Validation Trace Rules" violation occurs before
// the payer is established (EIP-8141 "Validation Trace Rules", "Structural
// Rules" 3, 7 and the deploy-frame code-installation rule).
//
// The simulation reuses the consensus frame execution (executeFrame) on a
// StateDB copy, so nested and indirect execution paths are covered exactly
// as in block execution. The validation tracer enforces the banned-opcode
// list (with the specification-defined exceptions), the storage write/read
// restrictions, and the CALL*/EXTCODE* target rules. Simulation stops
// immediately once the payer-setting frame completes successfully
// (structural rule 7).
//
// Simulation work is bounded by the static MAX_VERIFY_GAS check performed
// by ValidateMempoolPrefix (rule 6): the sum of the prefix frames'
// execution limits plus the signature validation cost never exceeds
// MAX_VERIFY_GAS, and each frame's EVM execution is capped by its declared
// execution limit.
func SimulateFrameValidation(sdb *state.StateDB, config *params.ChainConfig, header *types.Header, tx *types.Transaction) error {
	rules := config.Rules(header.Number, header.Difficulty != nil && header.Difficulty.Sign() == 0, header.Time)
	if !rules.IsFrameTx {
		return nil // pool fork gate rejects before this path
	}
	signer := types.NewFrameTxSigner(config.ChainID)
	baseFee := big.NewInt(0)
	if header.BaseFee != nil {
		baseFee = header.BaseFee
	}
	msg, err := TransactionToMessage(tx, signer, baseFee)
	if err != nil {
		return err
	}
	ftx := msg.FrameTx
	if ftx == nil {
		return fmt.Errorf("%w: not a frame transaction", types.ErrTxTypeNotSupported)
	}
	msg.SkipNonceChecks = true // the pool already ordered by nonce; simulation must not require it

	// Structural rules (recognized shapes, expiry freshness, caps) and the
	// prefix frames to simulate.
	if err := ftx.ValidateMempoolPrefix(header.Time); err != nil {
		return err
	}
	frames, species, err := ftx.ValidationPrefix(header.Time)
	if err != nil {
		return err
	}

	precompiles := make(map[common.Address]bool)
	for _, a := range vm.ActivePrecompiles(rules) {
		precompiles[a] = true
	}
	// Isolated state: the copy absorbs every simulation effect. The hooked
	// wrapper emits OnStorageChange/OnCodeChange for the write rules; the
	// read wrapper rejects storage reads outside tx.sender; the validation
	// tracer enforces the opcode and call-target rules. All three share the
	// canonical state for code lookups.
	canonical := sdb.Copy()
	tracer := &frameValidationTracer{state: canonical, precompileSet: precompiles, sender: ftx.Sender}
	var violation error
	hooked := state.NewHookedState(canonical, tracer.Hooks())
	sim := &frameValidationState{StateDB: hooked, sender: ftx.Sender, violation: &violation}

	blobBaseFee := big.NewInt(0) // blob fee irrelevant: blob ops are outside the prefix
	random := header.MixDigest   // post-merge header: non-nil Random makes NewEVM compute merged rules
	evm := vm.NewEVM(vm.BlockContext{
		CanTransfer:      CanTransfer,
		Transfer:         Transfer,
		GetHash:          func(uint64) common.Hash { return common.Hash{} },
		Coinbase:         header.Coinbase,
		BlockNumber:      new(big.Int).Set(header.Number),
		Time:             header.Time,
		Difficulty:       new(big.Int).Set(header.Difficulty),
		Random:           &random,
		BaseFee:          baseFee,
		BlobBaseFee:      blobBaseFee,
		GasLimit:         header.GasLimit,
		CostPerStateByte: params.CostPerStateByte,
	}, sim, config, vm.Config{NoBaseFee: true, Tracer: tracer.Hooks()})

	evm.SetTxContext(NewEVMTxContext(msg))

	// Frame context with the same fee-budget fields the block driver sets.
	// EIP-8141 fee semantics: GasFeeCap/GasTipCap are an aggregate max_fee
	// budget and aggregate priority budget (NOT per-gas values). requiredMaxFee
	// is a total over maxGas (maxGas × baseFee); maxPriorityFee is the room
	// left in the budget, capped by the tip budget. A tx whose aggregate fee
	// cap cannot cover the block base fee is rejected here, visibly, instead
	// of being admitted and then silently skipped by the miner at block-apply
	// time.
	maxGas := ftx.MaxGas()
	requiredMaxFee := new(big.Int).Mul(new(big.Int).SetUint64(maxGas), baseFee)
	feeCap := ftx.Fees.GasFeeCap.ToBig()
	if feeCap.Cmp(requiredMaxFee) < 0 {
		return fmt.Errorf("%w: address %v, maxFee: %v, required: %v", ErrFeeCapTooLow, ftx.Sender.Hex(), feeCap, requiredMaxFee)
	}
	maxPriorityFee := ftx.Fees.GasTipCap.ToBig()
	if room := new(big.Int).Sub(feeCap, requiredMaxFee); maxPriorityFee.Cmp(room) > 0 {
		maxPriorityFee.Set(room)
	}
	if maxPriorityFee.Sign() < 0 {
		maxPriorityFee.SetInt64(0)
	}
	fc := &vm.FrameContext{
		Tx:                   ftx,
		SigHash:              ftx.SigHash(),
		MaxCost:              new(big.Int).Add(requiredMaxFee, maxPriorityFee),
		MaxPriorityFeePerGas: new(big.Int).Div(maxPriorityFee, new(big.Int).SetUint64(maxGas)),
		Receipts:             make([]vm.FrameReceipt, len(ftx.Frames)),
	}
	evm.SetFrameContext(fc)
	sim.Prepare(rules, ftx.Sender, header.Coinbase, nil, vm.ActivePrecompiles(rules), nil)

	st := newStateTransition(evm, msg, NewGasPool(header.GasLimit), header.Coinbase)

	// The tracer reports banned opcodes and illegal call targets; the state
	// wrapper reports illegal storage reads. Both must be consulted after
	// each frame and before accepting.
	for i := range frames {
		if violation != nil {
			return violation
		}
		if tracer.violation != nil {
			return tracer.violation
		}
		sp := species[i]
		tracer.deployFrame = sp == types.FrameSpeciesDeploy
		tracer.allowTime = sp == types.FrameSpeciesExpiry &&
			(len(sim.GetCode(types.FrameExpiryVerifier)) == 0 ||
				bytes.Equal(sim.GetCode(types.FrameExpiryVerifier), canonicalExpiryRuntime))

		// Canonical paymaster exception (EIP-8141, ethereum/EIPs PR #12041):
		// the generic validation trace and opcode rules do not apply to a pay
		// frame whose target's runtime code hash equals the pinned canonical
		// paymaster code hash. The frame still executes — admission requires
		// successful APPROVE(APPROVE_PAYMENT) and the paymaster accounting
		// rules — but its reads of the instance's own storage slots (the
		// normative layout: slots 0-3) are permitted.
		sim.allowed = nil
		if sp == types.FrameSpeciesPay {
			target := ftx.Sender
			if frames[i].Target != nil {
				target = *frames[i].Target
			}
			if canonical.GetCodeHash(target) == CanonicalPaymasterCodeHash {
				sim.allowed = map[common.Address]bool{target: true}
			}
		}

		fc.FrameIdx = i
		receipt, vmerr := st.executeFrame(rules, fc, &ftx.Frames[i], i)
		if tracer.violation != nil {
			// The tracer observes opcodes pre-execution, so its verdict is
			// the more specific rule when both fire.
			return tracer.violation
		}
		if violation != nil {
			return violation
		}
		if vmerr != nil {
			return fmt.Errorf("%w: validation prefix frame %d reverted: %v", ErrFrameValidation, i, vmerr)
		}
		if receipt.Status != 1 {
			return fmt.Errorf("%w: validation prefix frame %d failed (status %d)", ErrFrameValidation, i, receipt.Status)
		}
		// Required APPROVE per species (structural rule 3).
		switch sp {
		case types.FrameSpeciesSelfVerify:
			if !fc.SenderApproved || !fc.PayerSet {
				return fmt.Errorf("%w: self_verify frame %d exited without APPROVE(EXECUTION_AND_PAYMENT)", ErrFrameValidation, i)
			}
		case types.FrameSpeciesOnlyVerify:
			if !fc.SenderApproved {
				return fmt.Errorf("%w: only_verify frame %d exited without APPROVE(EXECUTION)", ErrFrameValidation, i)
			}
		case types.FrameSpeciesPay:
			if !fc.PayerSet {
				return fmt.Errorf("%w: pay frame %d exited without APPROVE(PAYMENT)", ErrFrameValidation, i)
			}
		case types.FrameSpeciesDeploy:
			// The deploy frame must result in non-empty code at tx.sender
			// (conventional code or an EIP-7702 delegation indicator).
			if code := sim.GetCode(ftx.Sender); len(code) == 0 {
				return fmt.Errorf("%w: deploy frame did not install non-empty code at tx.sender", ErrFrameValidation)
			}
		}
		// Rule 7: stop simulation once the payer-setting frame completes.
		if sp == types.FrameSpeciesSelfVerify || sp == types.FrameSpeciesPay {
			break
		}
	}
	return nil
}
