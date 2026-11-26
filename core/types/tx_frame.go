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
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rlp"
	"github.com/holiman/uint256"
)

// EIP-8141 Frame Transaction constants (see https://eips.ethereum.org/EIPS/eip-8141).
const (
	FrameTxType = 0x06

	// Frame modes.
	FrameModeDefault = 0 // execute frame as ENTRY_POINT (0xaa)
	FrameModeVerify  = 1 // frame identifies as transaction validation
	FrameModeSender  = 2 // execute frame as tx.sender

	// Frame flags. Bits 0-1 are the approval scope; bit 2 is the atomic batch
	// flag (ATOMIC_BATCH_FLAG). All other bits are reserved.
	FrameApproveScopeMask = 0x3
	FrameAtomicBatchFlag  = 0x4

	// Signature schemes.
	FrameSigSchemeArbitrary = 0x0
	FrameSigSchemeSecp256k1 = 0x1 // signature = v (1B) || r (32B) || s (32B)
	FrameSigSchemeP256      = 0x2 // signature = r || s || qx || qy (32B each)

	// Gas constants.
	FrameTxIntrinsicCost = 12000 // FRAME_TX_INTRINSIC_COST
	FrameTxPerFrameCost  = 475   // FRAME_TX_PER_FRAME_COST
	FrameMaxFrames       = 64    // MAX_FRAMES

	// Signature verification gas (EIP-8141 "Gas Accounting": signature_gas).
	// This is charged once per signature entry, independently of any
	// calldata-token pricing of the signature bytes.
	FrameSigVerifyGasArbitrary = 100  // ARBITRARY
	FrameSigVerifyGasSecp256k1 = 2800 // SECP256K1
	FrameSigVerifyGasP256      = 6700 // P256
)

// Static validation errors for frame transactions.
var (
	errFrameTxNoFrames           = errors.New("frame transaction must contain at least one frame")
	errFrameTxTooManyFrames      = fmt.Errorf("frame transaction exceeds maximum of %d frames", FrameMaxFrames)
	errFrameTxInvalidMode        = errors.New("invalid frame mode")
	errFrameTxInvalidFlags       = errors.New("invalid frame flags")
	errFrameTxValueOnNonSender   = errors.New("frame value is only allowed in SENDER mode")
	errFrameTxAtomicOnVerify     = errors.New("atomic batch flag is not valid on VERIFY frames")
	errFrameTxAtomicLast         = errors.New("atomic batch flag requires a subsequent non-VERIFY frame")
	errFrameTxAtomicScope        = errors.New("batched frames must not carry an approval scope")
	errFrameTxInvalidScheme      = errors.New("invalid signature scheme")
	errFrameTxInvalidSigner      = errors.New("invalid signature signer length")
	errFrameTxArbitrarySigner    = errors.New("ARBITRARY signatures must have an empty signer")
	errFrameTxInvalidMsg         = errors.New("signature msg must be empty or 32 bytes")
	errFrameTxZeroMsgDigest      = errors.New("explicit 32-byte zero msg digest is invalid")
	errFrameTxInvalidBlobHash    = errors.New("invalid blob versioned hash")
	errFrameTxBlobFeeWithoutBlob = errors.New("max_fee_per_blob_gas must be 0 without blobs")
	errFrameTxGasOverflow        = errors.New("cumulative frame gas exceeds 2^64")
	errFrameTxGasLimitExceeded   = errors.New("frame transaction exceeds TX_MAX_GAS_LIMIT")
)

// FrameLimits holds the two-dimensional gas limits of a frame: execution gas
// and state gas (EIP-8037).
type FrameLimits struct {
	Execution uint64
	State     uint64
}

// Frame is a single execution unit of a frame transaction.
type Frame struct {
	Mode   uint8
	Flags  uint8
	Target *common.Address `rlp:"nil"` // nil is allowed; meaning depends on mode
	Limits FrameLimits
	Value  *uint256.Int
	Data   []byte
}

// FrameSignature is a protocol- or bespoke-verified signature entry of a frame
// transaction.
type FrameSignature struct {
	Scheme    uint8
	Signer    []byte // 0 or 20 bytes; must be empty for ARBITRARY
	Msg       []byte // empty (canonical sig hash) or explicit 32-byte digest
	Signature []byte // scheme-dependent raw signature bytes
}

// FrameFees holds the EIP-8141 fee parameters of a frame transaction.
// GasFeeCap is the aggregate maximum wei budget for the whole transaction
// (EIP-8141 "max_fee", compared against MaxGas×baseFee + blob terms), NOT a
// per-gas max_fee_per_gas. GasTipCap and BlobFeeCap are per-gas.
type FrameFees struct {
	GasTipCap  *uint256.Int // per-gas priority fee, a.k.a. max_priority_fee_per_gas
	GasFeeCap  *uint256.Int // aggregate wei budget for the whole tx (EIP-8141 "max_fee")
	BlobFeeCap *uint256.Int // a.k.a. max_fee_per_blob_gas
}

// FrameTx implements the EIP-8141 frame transaction type. It decomposes a
// transaction into a sequence of frames which validate the transaction,
// approve gas payment, and execute user operations.
//
// The RLP payload is:
//
//	[chain_id, nonce, sender, frames, signatures, fees, blob_versioned_hashes]
//	frames     = [[mode, flags, target, limits, value, data], ...]
//	limits     = [execution, state]
//	signatures = [[scheme, signer, msg, signature], ...]
//	fees       = [max_priority_fee_per_gas, max_fee_per_gas, max_fee_per_blob_gas]
type FrameTx struct {
	ChainID    *uint256.Int
	Nonce      uint64
	Sender     common.Address
	Frames     []Frame
	Signatures []FrameSignature
	Fees       FrameFees
	BlobHashes []common.Hash
}

// NewFrameTx creates a new frame transaction with the given fields.
func NewFrameTx(chainID *uint256.Int, nonce uint64, sender common.Address, frames []Frame, sigs []FrameSignature, fees FrameFees, blobHashes []common.Hash) *Transaction {
	return NewTx(&FrameTx{
		ChainID:    chainID,
		Nonce:      nonce,
		Sender:     sender,
		Frames:     frames,
		Signatures: sigs,
		Fees:       fees,
		BlobHashes: blobHashes,
	})
}

// sigHashData returns a copy of the transaction with the raw signature bytes
// of every signature that signs the canonical transaction signature hash
// (empty msg) elided, as required by EIP-8141's compute_sig_hash.
func (tx *FrameTx) sigHashData() *FrameTx {
	cp := *tx
	if tx.Signatures != nil {
		cp.Signatures = make([]FrameSignature, len(tx.Signatures))
		for i, sig := range tx.Signatures {
			cp.Signatures[i] = sig
			if len(sig.Msg) == 0 {
				cp.Signatures[i].Signature = nil
			}
		}
	}
	return &cp
}

// computeSigHash implements the EIP-8141 canonical signature hash:
//
//	keccak(bytes([FRAME_TX_TYPE]) + rlp(tx'))
//
// where tx' is the transaction payload with all empty-msg signature byte
// strings elided.
func (tx *FrameTx) computeSigHash() common.Hash {
	var buf bytes.Buffer
	buf.WriteByte(FrameTxType)
	if err := rlp.Encode(&buf, tx.sigHashData()); err != nil {
		panic(err) // cannot happen for a well-formed transaction
	}
	return crypto.Keccak256Hash(buf.Bytes())
}

// intrinsicGas returns frame_tx_intrinsic_gas, the complete EIP-8141
// intrinsic cost decomposition ("Gas Accounting" section):
//
//	frame_tx_intrinsic_gas = 12000
//	                       + len(frames) * 475
//	                       + frame_data_cost
//	                       + signature_data_cost
//	                       + signature_verification_cost
//	                       + value_transfer_cost
//
// All additions are saturating: any component that would overflow uint64
// pins the result at math.MaxUint64, which necessarily fails the
// TX_MAX_GAS_LIMIT check in ValidateGasLimit.
func (tx *FrameTx) intrinsicGas() uint64 {
	gas := uint64(FrameTxIntrinsicCost) + uint64(len(tx.Frames))*FrameTxPerFrameCost
	// frame_data_cost = sum(calldata_cost(frame.data))
	for i := range tx.Frames {
		gas = saturatingAdd(gas, calldataGas(tx.Frames[i].Data))
	}
	// signature_data_cost and signature_verification_cost
	for _, sig := range tx.Signatures {
		// calldata_cost(signer) + calldata_cost(msg)
		gas = saturatingAdd(gas, calldataGas(sig.Signer))
		gas = saturatingAdd(gas, calldataGas(sig.Msg))
		// 4 * signature_bytes_tokens(sig), where the bytes are priced at the
		// floor (4 tokens/byte) when msg is empty (elided from the canonical
		// hash) and at the standard weighted rate otherwise.
		var sigBytesTokens uint64
		if len(sig.Msg) == 0 {
			sigBytesTokens = calldataFloorTokens(sig.Signature)
		} else {
			sigBytesTokens = calldataTokens(sig.Signature)
		}
		gas = saturatingAdd(gas, saturatingMul(params.TxTokenPerNonZeroByte, sigBytesTokens))
		// signature_gas(scheme)
		gas = saturatingAdd(gas, signatureVerifyGas(sig.Scheme))
	}
	// value_transfer_cost
	gas = saturatingAdd(gas, tx.valueTransferCost())
	return gas
}

// valueTransferCost returns the sum of the per-frame TX_VALUE_COST charges:
// 6000 (params.TxValueCost2780 + params.TransferLogCost2780) for every frame
// carrying a non-zero value to a target that is present and differs from the
// sender (EIP-8141 "Gas Accounting": value_cost).
func (tx *FrameTx) valueTransferCost() uint64 {
	var gas uint64
	for i := range tx.Frames {
		f := &tx.Frames[i]
		if f.Value != nil && !f.Value.IsZero() && f.Target != nil && *f.Target != tx.Sender {
			gas = saturatingAdd(gas, params.TxValueCost2780+params.TransferLogCost2780)
		}
	}
	return gas
}

// signatureVerificationCost returns the sum of the per-entry signature_gas
// charges (EIP-8141 "Gas Accounting": signature_verification_cost).
func (tx *FrameTx) signatureVerificationCost() uint64 {
	var gas uint64
	for _, sig := range tx.Signatures {
		gas = saturatingAdd(gas, signatureVerifyGas(sig.Scheme))
	}
	return gas
}

// signatureVerifyGas returns the signature_gas charge for a scheme. Unknown
// schemes saturate to math.MaxUint64; they are already rejected by
// validateStatic, and this keeps the gas arithmetic total even so.
func signatureVerifyGas(scheme uint8) uint64 {
	switch scheme {
	case FrameSigSchemeArbitrary:
		return FrameSigVerifyGasArbitrary
	case FrameSigSchemeSecp256k1:
		return FrameSigVerifyGasSecp256k1
	case FrameSigSchemeP256:
		return FrameSigVerifyGasP256
	default:
		return math.MaxUint64
	}
}

// calldataTokens implements tokens_in(data) from the EIP-8141 "Gas
// Accounting" section (EIP-7976 pricing): 1 per zero byte, 4 per non-zero
// byte.
func calldataTokens(data []byte) uint64 {
	var tokens uint64
	for _, b := range data {
		if b == 0 {
			tokens++
		} else {
			tokens += params.TxTokenPerNonZeroByte
		}
	}
	return tokens
}

// calldataFloorTokens implements floor_tokens_in(data): 4 tokens per byte
// regardless of content (EIP-7976 calldata floor).
func calldataFloorTokens(data []byte) uint64 {
	return saturatingMul(uint64(len(data)), params.TxTokenPerNonZeroByte)
}

// calldataGas implements calldata_cost(data) = STANDARD_TOKEN_COST *
// tokens_in(data).
func calldataGas(data []byte) uint64 {
	return saturatingMul(params.TxTokenPerNonZeroByte, calldataTokens(data))
}

// CalldataFloorGas returns calldata_floor_gas from the EIP-8141 "Gas
// Accounting" section:
//
//	calldata_floor_gas = 12000
//	                   + len(frames) * 475
//	                   + signature_verification_cost
//	                   + value_transfer_cost
//	                   + TOTAL_COST_FLOOR_PER_TOKEN * calldata_floor_tokens
//
// where calldata_floor_tokens sums the floor token counts of every frame data
// field and of every signature's signer, msg and signature bytes (signature
// bytes are priced at the floor whenever msg is empty).
func (tx *FrameTx) CalldataFloorGas() uint64 {
	gas := uint64(FrameTxIntrinsicCost) + uint64(len(tx.Frames))*FrameTxPerFrameCost
	gas = saturatingAdd(gas, tx.signatureVerificationCost())
	gas = saturatingAdd(gas, tx.valueTransferCost())
	var tokens uint64
	for i := range tx.Frames {
		tokens = saturatingAdd(tokens, calldataFloorTokens(tx.Frames[i].Data))
	}
	for _, sig := range tx.Signatures {
		tokens = saturatingAdd(tokens, calldataFloorTokens(sig.Signer))
		tokens = saturatingAdd(tokens, calldataFloorTokens(sig.Msg))
		// Signature bytes are committed to the hash even when elided, so the
		// floor counts them unconditionally; the standard intrinsic prices
		// them at the floor only when msg is empty.
		tokens = saturatingAdd(tokens, calldataFloorTokens(sig.Signature))
	}
	return saturatingAdd(gas, saturatingMul(params.TxCostFloorPerToken7976, tokens))
}

// MaxGas returns max_gas from the EIP-8141 "Gas Accounting" section:
//
//	max_gas = max(standard_gas_limit, calldata_floor_gas + total_frame_state_gas)
//
// where standard_gas_limit = frame_tx_intrinsic_gas + total_frame_gas
// (execution + state dimensions). This is the transaction's effective gas
// ceiling once frame execution is enabled.
func (tx *FrameTx) MaxGas() uint64 {
	standard := saturatingAdd(tx.intrinsicGas(), tx.totalFrameGas())
	floorPlusState := saturatingAdd(tx.CalldataFloorGas(), tx.totalStateGas())
	if standard > floorPlusState {
		return standard
	}
	return floorPlusState
}

// totalStateGas returns the sum of the declared per-frame state-gas limits.
func (tx *FrameTx) totalStateGas() uint64 {
	var total uint64
	for i := range tx.Frames {
		total = saturatingAdd(total, tx.Frames[i].Limits.State)
	}
	return total
}

// ValidateGasLimit enforces the gas-limit constraint from the EIP-8141
// "Constraints" section (EIP-7825, TX_MAX_GAS_LIMIT):
//
//	max(frame_tx_intrinsic_gas + total_frame_execution_gas, calldata_floor_gas) <= TX_MAX_GAS_LIMIT
//
// Saturating arithmetic guarantees that any overflowing component fails this
// check rather than wrapping.
func (tx *FrameTx) ValidateGasLimit() error {
	exec := saturatingAdd(tx.intrinsicGas(), tx.totalExecutionGas())
	if exec > params.MaxTxGas {
		return fmt.Errorf("%w: intrinsic %d + frame execution %d exceeds TX_MAX_GAS_LIMIT %d", errFrameTxGasLimitExceeded, tx.intrinsicGas(), tx.totalExecutionGas(), params.MaxTxGas)
	}
	if floor := tx.CalldataFloorGas(); floor > params.MaxTxGas {
		return fmt.Errorf("%w: calldata floor %d exceeds TX_MAX_GAS_LIMIT %d", errFrameTxGasLimitExceeded, floor, params.MaxTxGas)
	}
	return nil
}

func saturatingAdd(a, b uint64) uint64 {
	if math.MaxUint64-a < b {
		return math.MaxUint64
	}
	return a + b
}

func saturatingMul(a, b uint64) uint64 {
	if a != 0 && math.MaxUint64/a < b {
		return math.MaxUint64
	}
	return a * b
}

// validateStatic enforces the validity constraints that can be determined
// statically from the specification.
func (tx *FrameTx) validateStatic() error {
	if len(tx.Frames) == 0 {
		return errFrameTxNoFrames
	}
	if len(tx.Frames) > FrameMaxFrames {
		return errFrameTxTooManyFrames
	}
	for _, sig := range tx.Signatures {
		switch sig.Scheme {
		case FrameSigSchemeArbitrary:
			if len(sig.Signer) != 0 {
				return errFrameTxArbitrarySigner
			}
		case FrameSigSchemeSecp256k1, FrameSigSchemeP256:
			if len(sig.Signer) != 0 && len(sig.Signer) != 20 {
				return errFrameTxInvalidSigner
			}
		default:
			return errFrameTxInvalidScheme
		}
		if len(sig.Msg) == 0 {
			// empty msg signs the canonical transaction signature hash
		} else if len(sig.Msg) == 32 {
			zero := true
			for _, b := range sig.Msg {
				if b != 0 {
					zero = false
					break
				}
			}
			if zero {
				return errFrameTxZeroMsgDigest
			}
		} else {
			return errFrameTxInvalidMsg
		}
	}
	if len(tx.BlobHashes) == 0 && tx.Fees.BlobFeeCap != nil && !tx.Fees.BlobFeeCap.IsZero() {
		return errFrameTxBlobFeeWithoutBlob
	}
	for _, h := range tx.BlobHashes {
		if h[0] != 0x01 { // VERSIONED_HASH_VERSION_KZG
			return errFrameTxInvalidBlobHash
		}
	}
	var totalFrameGas uint64
	for i, frame := range tx.Frames {
		if frame.Mode > FrameModeSender {
			return errFrameTxInvalidMode
		}
		if frame.Flags >= 8 {
			return errFrameTxInvalidFlags
		}
		if frame.Mode != FrameModeSender && frame.Value != nil && !frame.Value.IsZero() {
			return errFrameTxValueOnNonSender
		}
		// total_frame_gas accumulates execution + state gas and must stay
		// below 2^64.
		add := frame.Limits.Execution + frame.Limits.State
		if add < frame.Limits.Execution {
			return errFrameTxGasOverflow
		}
		if totalFrameGas > ^uint64(0)-add {
			return errFrameTxGasOverflow
		}
		totalFrameGas += add

		if frame.Flags&FrameAtomicBatchFlag != 0 {
			if frame.Mode == FrameModeVerify {
				return errFrameTxAtomicOnVerify
			}
			if i+1 >= len(tx.Frames) || tx.Frames[i+1].Mode == FrameModeVerify {
				return errFrameTxAtomicLast
			}
		}
		if frame.Flags&FrameAtomicBatchFlag != 0 || (i > 0 && tx.Frames[i-1].Flags&FrameAtomicBatchFlag != 0) {
			if frame.Flags&FrameApproveScopeMask != 0 {
				return errFrameTxAtomicScope
			}
		}
	}
	return nil
}

// ValidateStatic enforces the statically-checkable EIP-8141 payload rules.
// It is the exported entry point for callers outside this package (RPC
// argument validation, tests); frame execution performs the full rule set.
func (tx *FrameTx) ValidateStatic() error {
	return tx.validateStatic()
}

// SigHash returns the canonical EIP-8141 signature hash of the transaction.
func (tx *FrameTx) SigHash() common.Hash {
	return tx.computeSigHash()
}

// IntrinsicGas returns the complete EIP-8141 intrinsic gas decomposition of
// the transaction (see the intrinsicGas method for the formula).
func (tx *FrameTx) IntrinsicGas() uint64 {
	return tx.intrinsicGas()
}

// ValidateFrameGasLimits enforces the EIP-8141 gas-limit constraint (EIP-7825
// TX_MAX_GAS_LIMIT) on a frame transaction. Non-frame transactions are
// rejected with ErrTxTypeNotSupported.
func ValidateFrameGasLimits(tx *Transaction) error {
	if tx.Type() != FrameTxType {
		return fmt.Errorf("%w: not a frame transaction", ErrTxTypeNotSupported)
	}
	return tx.inner.(*FrameTx).ValidateGasLimit()
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *FrameTx) copy() TxData {
	cpy := &FrameTx{
		ChainID: new(uint256.Int).Set(tx.ChainID),
		Nonce:   tx.Nonce,
		Sender:  tx.Sender,
		Fees: FrameFees{
			new(uint256.Int).Set(tx.Fees.GasTipCap),
			new(uint256.Int).Set(tx.Fees.GasFeeCap),
			nil,
		},
		BlobHashes: make([]common.Hash, len(tx.BlobHashes)),
	}
	if tx.Fees.BlobFeeCap != nil {
		cpy.Fees.BlobFeeCap = new(uint256.Int).Set(tx.Fees.BlobFeeCap)
	}
	copy(cpy.BlobHashes, tx.BlobHashes)
	if tx.Frames != nil {
		cpy.Frames = make([]Frame, len(tx.Frames))
		for i, frame := range tx.Frames {
			cpy.Frames[i] = frame
			if frame.Target != nil {
				target := *frame.Target
				cpy.Frames[i].Target = &target
			}
			if frame.Value != nil {
				cpy.Frames[i].Value = new(uint256.Int).Set(frame.Value)
			}
			if frame.Data != nil {
				cpy.Frames[i].Data = make([]byte, len(frame.Data))
				copy(cpy.Frames[i].Data, frame.Data)
			}
		}
	}
	if tx.Signatures != nil {
		cpy.Signatures = make([]FrameSignature, len(tx.Signatures))
		for i, sig := range tx.Signatures {
			cpy.Signatures[i] = sig
			cpy.Signatures[i].Signer = make([]byte, len(sig.Signer))
			copy(cpy.Signatures[i].Signer, sig.Signer)
			cpy.Signatures[i].Msg = make([]byte, len(sig.Msg))
			copy(cpy.Signatures[i].Msg, sig.Msg)
			cpy.Signatures[i].Signature = make([]byte, len(sig.Signature))
			copy(cpy.Signatures[i].Signature, sig.Signature)
		}
	}
	return cpy
}

// accessors

func (tx *FrameTx) txType() byte           { return FrameTxType }
func (tx *FrameTx) chainID() *big.Int      { return tx.ChainID.ToBig() }
func (tx *FrameTx) accessList() AccessList { return nil }
func (tx *FrameTx) data() []byte           { return nil } // frame data lives in tx.Frames
func (tx *FrameTx) gas() uint64            { return tx.intrinsicGas() + tx.totalExecutionGas() }
func (tx *FrameTx) gasPrice() *big.Int     { return tx.Fees.GasFeeCap.ToBig() }
func (tx *FrameTx) gasTipCap() *big.Int    { return tx.Fees.GasTipCap.ToBig() }
func (tx *FrameTx) gasFeeCap() *big.Int    { return tx.Fees.GasFeeCap.ToBig() }
func (tx *FrameTx) nonce() uint64          { return tx.Nonce }
func (tx *FrameTx) to() *common.Address    { return nil } // no single recipient

// totalExecutionGas returns the sum of the execution gas limits of all frames.
func (tx *FrameTx) totalExecutionGas() uint64 {
	var total uint64
	for _, frame := range tx.Frames {
		total = saturatingAdd(total, frame.Limits.Execution)
	}
	return total
}

// totalFrameGas returns the sum of the execution and state gas limits of all
// frames (total_frame_gas in the EIP-8141 specification).
func (tx *FrameTx) totalFrameGas() uint64 {
	var total uint64
	for _, frame := range tx.Frames {
		add := frame.Limits.Execution + frame.Limits.State
		if add < frame.Limits.Execution || total > math.MaxUint64-add {
			return math.MaxUint64
		}
		total += add
	}
	return total
}

// value returns the total value transferred by all SENDER frames.
func (tx *FrameTx) value() *big.Int {
	sum := new(big.Int)
	for _, frame := range tx.Frames {
		if frame.Value != nil {
			sum.Add(sum, frame.Value.ToBig())
		}
	}
	return sum
}

// rawSignatureValues returns zero values: a frame transaction carries its
// signature material in the Signatures list instead of a single (v, r, s)
// triple. Protocol validation of those signatures is implemented in the
// signing milestone.
func (tx *FrameTx) rawSignatureValues() (v, r, s *big.Int) {
	return new(big.Int), new(big.Int), new(big.Int)
}

// setSignatureValues is a no-op for frame transactions, see
// rawSignatureValues.
func (tx *FrameTx) setSignatureValues(chainID, v, r, s *big.Int) {}

// RequiredMaxFee returns the EIP-8141 "Fee budget" required_max_fee:
// max_gas * base_fee_per_gas (+ blob_gas * blob_base_fee when non-nil). The
// transaction is invalid if tx.fees.max_fee is below this value.
func (tx *FrameTx) RequiredMaxFee(baseFee, blobBaseFee *big.Int) *big.Int {
	if baseFee == nil {
		baseFee = new(big.Int)
	}
	required := new(big.Int).Mul(new(big.Int).SetUint64(tx.MaxGas()), baseFee)
	if blobBaseFee != nil {
		blobGas := uint64(len(tx.BlobHashes)) * params.BlobTxBlobGasPerBlob
		required.Add(required, new(big.Int).Mul(new(big.Int).SetUint64(blobGas), blobBaseFee))
	}
	return required
}

// EffectiveGasPrice returns the EIP-8141 per-gas price
// (base_fee_per_gas + max_priority_fee // max_gas) for the given base fee.
// It is the price the payer pays per unit of gas_used and the receipt's
// effective gas price. See the unexported effectiveGasPrice for details.
func (tx *FrameTx) EffectiveGasPrice(baseFee *big.Int) *big.Int {
	return tx.effectiveGasPrice(new(big.Int), baseFee)
}

// effectiveGasPrice returns the EIP-8141 per-gas price from the "Fee
// budget" rule: base_fee_per_gas + max_priority_fee // max_gas, where
// max_priority_fee is the room-limited aggregate min(tipCap * max_gas,
// max_fee - required_max_fee). Frame transactions have no per-gas fee cap
// (EIP-8141: "the tip cannot be limited to max_fee_per_gas -
// base_fee_per_gas per gas as under EIP-1559"), so the EIP-1559
// min(tipCap, feeCap - baseFee) + baseFee formula does not apply. This is
// the price the payer pays exactly per unit of gas_used when max_fee covers
// the full tip, and therefore the receipt-effective gas price.
//
// required_max_fee is computed without the blob component: the blob base
// fee is unavailable at receipt-derivation time. Without blobs this matches
// the driver's GASPRICE exactly; with blobs whose fee room binds it can
// overestimate the room by the blob fee term.
func (tx *FrameTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	if baseFee == nil {
		baseFee = new(big.Int)
	}
	maxGas := tx.MaxGas()
	requiredMaxFee := new(big.Int).Mul(new(big.Int).SetUint64(maxGas), baseFee)
	priority := new(big.Int).Mul(new(big.Int).SetUint64(maxGas), tx.Fees.GasTipCap.ToBig())
	if room := new(big.Int).Sub(tx.Fees.GasFeeCap.ToBig(), requiredMaxFee); priority.Cmp(room) > 0 {
		priority.Set(room)
	}
	if priority.Sign() < 0 {
		// feeCap below required_max_fee is transaction-invalid; clamp so
		// RPC derivation of such payloads cannot report a negative price.
		priority.SetInt64(0)
	}
	perGas := new(big.Int).Div(priority, new(big.Int).SetUint64(maxGas))
	return dst.Add(baseFee, perGas)
}

// sigHash returns the EIP-8141 canonical signature hash. The chainID argument
// is ignored: the chain id is part of the signed payload itself.
func (tx *FrameTx) sigHash(chainID *big.Int) common.Hash {
	return tx.computeSigHash()
}

func (tx *FrameTx) encode(w *bytes.Buffer) error {
	return rlp.Encode(w, tx)
}

func (tx *FrameTx) decode(b []byte) error {
	if err := rlp.DecodeBytes(b, tx); err != nil {
		return err
	}
	return tx.validateStatic()
}
