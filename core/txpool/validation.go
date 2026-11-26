// Copyright 2023 The go-ethereum Authors
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

package txpool

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto/kzg4844"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

var (
	// blobTxMinBlobGasPrice is the big.Int version of the configured protocol
	// parameter to avoid constructing a new big integer for every transaction.
	blobTxMinBlobGasPrice = big.NewInt(params.BlobTxMinBlobGasprice)
)

// ValidationOptions define certain differences between transaction validation
// across the different pools without having to duplicate those checks.
type ValidationOptions struct {
	Config *params.ChainConfig // Chain configuration to selectively validate based on current fork rules

	Accept       uint8    // Bitmap of transaction types that should be accepted for the calling pool
	MaxSize      uint64   // Maximum size of a transaction that the caller can meaningfully handle
	MaxBlobCount int      // Maximum number of blobs allowed per transaction
	MinTip       *big.Int // Minimum gas tip needed to allow a transaction into the caller pool
}

// ValidationFunction is an method type which the pools use to perform the tx-validations which do not
// require state access. Production code typically uses ValidateTransaction, whereas testing-code
// might choose to instead use something else, e.g. to always fail or avoid heavy cpu usage.
type ValidationFunction func(tx *types.Transaction, head *types.Header, signer types.Signer, opts *ValidationOptions) error

// ValidateTransaction is a helper method to check whether a transaction is valid
// according to the consensus rules, but does not check state-dependent validation
// (balance, nonce, etc).
//
// This check is public to allow different transaction pools to check the basic
// rules without duplicating code and running the risk of missed updates.
func ValidateTransaction(tx *types.Transaction, head *types.Header, signer types.Signer, opts *ValidationOptions) error {
	// Ensure transactions not implemented by the calling pool are rejected
	if opts.Accept&(1<<tx.Type()) == 0 {
		return fmt.Errorf("%w: tx type %v not supported by this pool", core.ErrTxTypeNotSupported, tx.Type())
	}
	// Before performing any expensive validations, sanity check that the tx is
	// smaller than the maximum limit the pool can meaningfully handle
	if tx.Size() > opts.MaxSize {
		return fmt.Errorf("%w: transaction size %v, limit %v", ErrOversizedData, tx.Size(), opts.MaxSize)
	}
	// Ensure only transactions that have been enabled are accepted
	rules := opts.Config.Rules(head.Number, head.Difficulty.Sign() == 0, head.Time)
	if !rules.IsBerlin && tx.Type() != types.LegacyTxType {
		return fmt.Errorf("%w: type %d rejected, pool not yet in Berlin", core.ErrTxTypeNotSupported, tx.Type())
	}
	if !rules.IsLondon && tx.Type() == types.DynamicFeeTxType {
		return fmt.Errorf("%w: type %d rejected, pool not yet in London", core.ErrTxTypeNotSupported, tx.Type())
	}
	if !rules.IsCancun && tx.Type() == types.BlobTxType {
		return fmt.Errorf("%w: type %d rejected, pool not yet in Cancun", core.ErrTxTypeNotSupported, tx.Type())
	}
	if !rules.IsPrague && tx.Type() == types.SetCodeTxType {
		return fmt.Errorf("%w: type %d rejected, pool not yet in Prague", core.ErrTxTypeNotSupported, tx.Type())
	}
	if tx.Type() == types.FrameTxType {
		// EIP-8141 frame transactions are only admissible once the FrameTx
		// fork is active on this chain. The fork is inactive by default
		// (FrameTxTime unset) on every preset network configuration.
		if !rules.IsFrameTx {
			return fmt.Errorf("%w: type %d rejected, pool not yet in FrameTx fork", core.ErrTxTypeNotSupported, tx.Type())
		}
		// Fork-active validation: protocol-level signature rules and the
		// EIP-7825 gas-limit constraint (EIP-8141 "Constraints"). The
		// payload rules were already enforced by the decoder and by RPC
		// argument validation.
		if err := types.ValidateFrameSignatures(tx); err != nil {
			return err
		}
		if err := types.ValidateFrameGasLimits(tx); err != nil {
			return err
		}
		// EIP-8141 public-mempool rules: recognized validation-prefix
		// shapes, the no-VERIFY-after-prefix rule, the verification-gas
		// caps (MAX_VERIFY_GAS / MAX_VERIFY_STATE_GAS), and expiry-verifier
		// deadline freshness against the current block timestamp.
		if err := types.ValidateFrameMempoolPrefix(tx, head.Time); err != nil {
			return err
		}
	}
	// Check whether the init code size has been exceeded
	if tx.To() == nil {
		if err := vm.CheckMaxInitCodeSize(&rules, uint64(len(tx.Data()))); err != nil {
			return err
		}
	}
	if rules.IsOsaka && !rules.IsAmsterdam && tx.Gas() > params.MaxTxGas {
		return fmt.Errorf("%w (cap: %d, tx: %d)", core.ErrGasLimitTooHigh, params.MaxTxGas, tx.Gas())
	}
	// Transactions can't be negative. This may never happen using RLP decoded
	// transactions but may occur for transactions created using the RPC.
	if tx.Value().Sign() < 0 {
		return ErrNegativeValue
	}
	// Ensure the transaction doesn't exceed the current block limit gas
	if head.GasLimit < tx.Gas() {
		return ErrGasLimit
	}
	// Sanity check for extremely large numbers (supported by RLP or RPC)
	if tx.GasFeeCap().BitLen() > 256 {
		return core.ErrFeeCapVeryHigh
	}
	if tx.GasTipCap().BitLen() > 256 {
		return core.ErrTipVeryHigh
	}
	// Ensure gasFeeCap is greater than or equal to gasTipCap
	if tx.Type() == types.FrameTxType {
		// EIP-8141 "Fee budget": tx.fees.max_fee is a single aggregate
		// budget over max_gas, not a per-gas cap, so the per-gas
		// feeCap >= tipCap comparison does not apply (it would spuriously
		// reject small aggregate budgets). Instead the budget must cover
		// required_max_fee (max_gas * base_fee) of the current head; the
		// authoritative including-block check runs again in frame
		// execution.
		if head.BaseFee != nil {
			required := tx.FramePayload().RequiredMaxFee(head.BaseFee, nil)
			if tx.GasFeeCapIntCmp(required) < 0 {
				return fmt.Errorf("%w: max fee budget %v below required max fee %v", core.ErrFeeCapTooLow, tx.GasFeeCap(), required)
			}
		}
	} else if tx.GasFeeCapIntCmp(tx.GasTipCap()) < 0 {
		return core.ErrTipAboveFeeCap
	}
	// Make sure the transaction is signed properly
	from, err := types.Sender(signer, tx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSender, err)
	}
	// Limit nonce to 2^64-1 per EIP-2681
	if tx.Nonce()+1 < tx.Nonce() {
		return core.ErrNonceMax
	}
	// Sanity check for extremely large numbers (supported by RLP or RPC)
	value, overflow := uint256.FromBig(tx.Value())
	if overflow {
		return core.ErrInsufficientFunds
	}
	// Ensure the transaction has more gas than the bare minimum needed to cover
	// the transaction metadata.
	//
	// XDC: disable EIP-2028 (lower per-non-zero-byte calldata gas) for XDC
	// chains. Canonical XDPoSChain v2.6.8 keeps 68 gas per non-zero byte at all
	// times, so enabling EIP-2028 would diverge from canonical intrinsic-gas
	// calculation on every tx with calldata. This is fed only to IntrinsicGas
	// below, never to FloorDataGas or the rest of validation.
	intrRules := rules
	if opts.Config.IsXDC() {
		intrRules.IsIstanbul = false
	}
	intrGas, err := core.IntrinsicGas(tx.Data(), tx.AccessList(), tx.SetCodeAuthorizations(), from, tx.To(), value, intrRules)
	if err != nil {
		return err
	}
	if tx.Gas() < intrGas {
		return fmt.Errorf("%w: gas %v, minimum needed %v", core.ErrIntrinsicGas, tx.Gas(), intrGas)
	}
	// Ensure the transaction can cover the content floor (EIP-7623 under
	// Prague, EIP-8131 unified floor under Bogotá).
	if rules.IsPrague || rules.IsBogota {
		floorDataGas, err := core.FloorDataGas(rules, from, tx.To(), value, tx.Data(), tx.AccessList(), len(tx.SetCodeAuthorizations()), len(tx.BlobHashes()))
		if err != nil {
			return err
		}
		// Make sure the transaction has sufficient gas allowance to
		// pay the floor cost.
		if tx.Gas() < floorDataGas {
			return fmt.Errorf("%w: gas %v, minimum needed %v", core.ErrFloorDataGas, tx.Gas(), floorDataGas)
		}
		// In Amsterdam, the transaction gas limit is allowed to exceed
		// params.MaxTxGas, but the calldata floor cost is capped by it.
		if rules.IsAmsterdam && max(intrGas, floorDataGas) > params.MaxTxGas {
			return fmt.Errorf("%w: intrinsic cost %v, floor: %v", core.ErrFloorDataGas, intrGas, floorDataGas)
		}
	}
	// Ensure the gasprice is high enough to cover the requirement of the calling pool.
	//
	// XDC parity #928/#188: special transactions to BlockSigners (0x...0089) and
	// RandomizeSMC (0x...0090) are signed by masternodes with gasPrice=0 by
	// design and exempt from gas-price validation (canonical XDPoSChain
	// core/txpool/validation.go). Without this exemption, modern's
	// --miner.gasprice sanitization (0 → 1,000,000) causes the outer txpool
	// gate to reject every sign-tx, so they never enter the pool, never
	// propagate to other validators, and the V2 BFT comeback-from-penalty
	// signal (per-block sign-tx as liveness proof) never reaches V1 peers.
	// Observed on xdc04 modern (devnet-5151) where sign-txs were created
	// (`contracts: masternode signing tx submitted ... nonce=19`) but never
	// reached V1 node1's txpool (pending=0 queued=0).
	if !tx.IsSpecialTransaction() && tx.GasTipCapIntCmp(opts.MinTip) < 0 {
		return fmt.Errorf("%w: gas tip cap %v, minimum needed %v", ErrTxGasPriceTooLow, tx.GasTipCap(), opts.MinTip)
	}
	if tx.Type() == types.BlobTxType {
		return validateBlobSidecar(tx, head, opts)
	}
	if tx.Type() == types.SetCodeTxType {
		if len(tx.SetCodeAuthorizations()) == 0 {
			return errors.New("set code tx must have at least one authorization tuple")
		}
	}
	return nil
}

// validateBlobSidecar implements the blob sidecar validation.
// Note that this doesn't verify the consistency between blobs(cells) and
// proofs. For proof verification, use validateCells.
func validateBlobSidecar(tx *types.Transaction, head *types.Header, opts *ValidationOptions) error {
	if tx.BlobGasFeeCapIntCmp(blobTxMinBlobGasPrice) < 0 {
		return fmt.Errorf("%w: blob fee cap %v, minimum needed %v", ErrTxGasPriceTooLow, tx.BlobGasFeeCap(), blobTxMinBlobGasPrice)
	}
	sidecar := tx.BlobTxSidecar()
	if sidecar == nil {
		return errors.New("missing sidecar in blob transaction")
	}
	hashes := tx.BlobHashes()
	if err := sidecar.ValidateBlobCommitmentHashes(hashes); err != nil {
		return err
	}
	if len(hashes) > opts.MaxBlobCount {
		return fmt.Errorf("%w: blob count %v, limit %v", ErrTxBlobLimitExceeded, len(hashes), opts.MaxBlobCount)
	}
	if sidecar.Version != types.BlobSidecarVersion1 {
		return fmt.Errorf("%w: unexpected sidecar version, want: %d, got: %d", ErrSidecarFormatError, types.BlobSidecarVersion1, sidecar.Version)
	}
	if len(sidecar.Proofs) != len(sidecar.Commitments)*kzg4844.CellProofsPerBlob {
		return fmt.Errorf("%w: invalid number of %d blob proofs expected %d", ErrSidecarFormatError, len(sidecar.Proofs), len(sidecar.Commitments)*kzg4844.CellProofsPerBlob)
	}
	return nil
}

func ValidateCells(sidecar *types.BlobTxCellSidecar) error {
	// Two checks here (custody count check and blobCount check) is duplicated in buffer.go
	// However it is required to 1) serve eth71 peer and direct submission 2) catch any bug in
	// merging cell delivery.
	if sidecar.Custody.OneCount() == 0 {
		return errors.New("blobless blob transaction")
	}
	// Verify whether the blob count is consistent with other parts of the sidecar and the transaction
	blobCount := len(sidecar.Cells) / sidecar.Custody.OneCount()
	if blobCount == 0 {
		return errors.New("blobless blob transaction")
	}
	if blobCount != len(sidecar.Commitments) {
		return fmt.Errorf("invalid number of %d blobs compared to %d commitments", blobCount, len(sidecar.Commitments))
	}
	if len(sidecar.Proofs) != len(sidecar.Commitments)*kzg4844.CellProofsPerBlob {
		return fmt.Errorf("invalid number of %d proofs compared to %d commitments", len(sidecar.Proofs), len(sidecar.Commitments))
	}
	if sidecar.Version != types.BlobSidecarVersion1 {
		return fmt.Errorf("unexpected sidecar version, want: %d, got: %d", types.BlobSidecarVersion1, sidecar.Version)
	}
	return validateCellsOsaka(sidecar)
}

func validateCellsOsaka(sidecar *types.BlobTxCellSidecar) error {
	indices := sidecar.Custody.Indices()
	cellProofs := make([]kzg4844.Proof, 0)
	for blobIdx := range len(sidecar.Commitments) {
		for _, proofIdx := range indices {
			idx := blobIdx*kzg4844.CellProofsPerBlob + int(proofIdx)
			cellProofs = append(cellProofs, sidecar.Proofs[idx])
		}
	}
	if err := kzg4844.VerifyCells(sidecar.Cells, sidecar.Commitments, cellProofs, sidecar.Custody.Indices()); err != nil {
		return fmt.Errorf("%w: %v", ErrKZGVerificationError, err)
	}
	return nil
}

// ValidationOptionsWithState define certain differences between stateful transaction
// validation across the different pools without having to duplicate those checks.
type ValidationOptionsWithState struct {
	State *state.StateDB // State database to check nonces and balances against

	// FirstNonceGap is an optional callback to retrieve the first nonce gap in
	// the list of pooled transactions of a specific account. If this method is
	// set, nonce gaps will be checked and forbidden. If this method is not set,
	// nonce gaps will be ignored and permitted.
	FirstNonceGap func(addr common.Address) uint64

	// UsedAndLeftSlots is an optional callback to retrieve the number of tx slots
	// used and the number still permitted for an account. New transactions will
	// be rejected once the number of remaining slots reaches zero.
	UsedAndLeftSlots func(addr common.Address) (int, int)

	// ExistingExpenditure is a mandatory callback to retrieve the cumulative
	// cost of the already pooled transactions to check for overdrafts.
	ExistingExpenditure func(addr common.Address) *big.Int

	// ExistingCost is a mandatory callback to retrieve an already pooled
	// transaction's cost with the given nonce to check for overdrafts.
	ExistingCost func(addr common.Address, nonce uint64) *big.Int

	// Now is the current block timestamp used for EIP-8141 frame-transaction
	// prefix freshness when deriving the sender's worst-case admission cost
	// (FrameTxSenderCost). Zero is valid (tests, empty chains); state-free
	// accounting never fails expiry freshness, which only tightens the view.
	Now uint64
}

// ValidateTransactionWithState is a helper method to check whether a transaction
// is valid according to the pool's internal state checks (balance, nonce, gaps).
//
// This check is public to allow different transaction pools to check the stateful
// rules without duplicating code and running the risk of missed updates.
func ValidateTransactionWithState(tx *types.Transaction, signer types.Signer, opts *ValidationOptionsWithState) error {
	// Ensure the transaction adheres to nonce ordering
	from, err := types.Sender(signer, tx) // already validated (and cached), but cleaner to check
	if err != nil {
		log.Error("Transaction sender recovery failed", "err", err)
		return err
	}
	next := opts.State.GetNonce(from)
	if next > tx.Nonce() {
		return fmt.Errorf("%w: next nonce %v, tx nonce %v", core.ErrNonceTooLow, next, tx.Nonce())
	}
	// Ensure the transaction doesn't produce a nonce gap in pools that do not
	// support arbitrary orderings
	if opts.FirstNonceGap != nil {
		if gap := opts.FirstNonceGap(from); gap < tx.Nonce() {
			return fmt.Errorf("%w: tx nonce %v, gapped nonce %v", core.ErrNonceTooHigh, tx.Nonce(), gap)
		}
	}
	// Ensure the transactor has enough funds to cover the transaction costs
	var (
		balance = opts.State.GetBalance(from).ToBig()
		cost    = tx.Cost()
	)
	if tx.Type() == types.FrameTxType {
		// EIP-8141: the sender's worst-case self-pay exposure is the aggregate
		// frame value plus the aggregate fee cap. When the validation prefix
		// delegates fee payment to a different payer, the sender covers the
		// frame value only; the payer's maximum-fee solvency, reservations,
		// validation simulation and settlement accounting are enforced by the
		// frame pool and are not weakened here.
		cost = core.FrameTxSenderCost(tx, opts.Now)
	}
	if balance.Cmp(cost) < 0 {
		return fmt.Errorf("%w: balance %v, tx cost %v, overshot %v", core.ErrInsufficientFunds, balance, cost, new(big.Int).Sub(cost, balance))
	}
	// Ensure the transactor has enough funds to cover for replacements or nonce
	// expansions without overdrafts
	spent := opts.ExistingExpenditure(from)
	if prev := opts.ExistingCost(from, tx.Nonce()); prev != nil {
		bump := new(big.Int).Sub(cost, prev)
		need := new(big.Int).Add(spent, bump)
		if balance.Cmp(need) < 0 {
			return fmt.Errorf("%w: balance %v, queued cost %v, tx bumped %v, overshot %v", core.ErrInsufficientFunds, balance, spent, bump, new(big.Int).Sub(need, balance))
		}
	} else {
		need := new(big.Int).Add(spent, cost)
		if balance.Cmp(need) < 0 {
			return fmt.Errorf("%w: balance %v, queued cost %v, tx cost %v, overshot %v", core.ErrInsufficientFunds, balance, spent, cost, new(big.Int).Sub(need, balance))
		}
		// Transaction takes a new nonce value out of the pool. Ensure it doesn't
		// overflow the number of permitted transactions from a single account
		// (i.e. max cancellable via out-of-bound transaction).
		if opts.UsedAndLeftSlots != nil {
			if used, left := opts.UsedAndLeftSlots(from); left <= 0 {
				return fmt.Errorf("%w: pooled %d txs", ErrAccountLimitExceeded, used)
			}
		}
	}
	return nil
}
