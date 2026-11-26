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
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/crypto/secp256r1"
)

// secp256R1N is the group order of the NIST P-256 (secp256r1) curve, and
// secp256R1HalfN is N/2 used for the canonical low-s rule.
var (
	secp256R1N     = elliptic.P256().Params().N
	secp256R1HalfN = new(big.Int).Rsh(new(big.Int).Set(secp256R1N), 1)
)

// Signature entry sizes for the EIP-8141 protocol-validated schemes.
const (
	frameSecp256k1SigLen = 65  // v (1B) || r (32B) || s (32B)
	frameP256SigLen      = 128 // r (32B) || s (32B) || qx (32B) || qy (32B)
	frameP256ElemLen     = 32
)

// Signature validation errors.
var (
	errFrameTxSigTooShort     = errors.New("signature entry too short")
	errFrameTxSigTooLong      = errors.New("signature entry too long")
	errFrameTxRecoveryID      = errors.New("invalid signature recovery id")
	errFrameTxInvalidSig      = errors.New("invalid signature values")
	errFrameTxSigRecover      = errors.New("failed to recover signature signer")
	errFrameTxSignerMismatch  = errors.New("recovered signer does not match resolved signer")
	errFrameTxP256Verify      = errors.New("P256 signature verification failed")
	errFrameTxP256ScalarRange = errors.New("P256 scalar out of range")
	errFrameTxP256HighS       = errors.New("P256 signature is not canonical (high-s)")
	errFrameTxP256Address     = errors.New("P256 signer address does not match resolved signer")
)

// sigDigest returns the digest a signature entry signs over: the explicit
// 32-byte msg when present, or the canonical frame transaction signature hash.
func (tx *FrameTx) sigDigest(sig *FrameSignature) common.Hash {
	if len(sig.Msg) == 32 {
		return common.BytesToHash(sig.Msg)
	}
	return tx.computeSigHash()
}

// resolvedSigner returns the signer address a protocol-validated signature
// entry resolves to: the explicit 20-byte signer, or tx.Sender when omitted.
func (tx *FrameTx) resolvedSigner(sig *FrameSignature) common.Address {
	if len(sig.Signer) == 20 {
		return common.BytesToAddress(sig.Signer)
	}
	return tx.Sender
}

// ResolvedSigner returns the resolved signer of signature entry i: the
// explicit 20-byte signer, or tx.Sender when omitted (EIP-8141 common
// validation rules). It returns an error for out-of-range indexes.
func (tx *FrameTx) ResolvedSigner(i int) (common.Address, error) {
	if i < 0 || i >= len(tx.Signatures) {
		return common.Address{}, fmt.Errorf("frame tx: signature index %d out of range (%d entries)", i, len(tx.Signatures))
	}
	return tx.resolvedSigner(&tx.Signatures[i]), nil
}

// ValidateSignatures validates every signature entry of the frame
// transaction according to the EIP-8141 signature rules. It performs all
// protocol-level cryptographic verification before any frame executes:
// every protocol-validated signature (SECP256K1, P256) must validate
// successfully or the whole transaction is invalid. ARBITRARY entries are
// only checked structurally; their bytes are preserved for execution-time
// introspection (SIGDATACOPY) and are never protocol-verified.
//
// Structural checks (scheme validity, signer/msg sizes, zero digest) are
// re-applied here so that transactions constructed in memory — which never
// pass through decode — are validated identically to wire transactions.
func (tx *FrameTx) ValidateSignatures() error {
	for i := range tx.Signatures {
		sig := &tx.Signatures[i]
		if err := tx.validateSignatureEntry(i, sig); err != nil {
			return err
		}
	}
	return nil
}

// ValidateFrameSignatures validates the signature entries of a transaction if
// it is a frame transaction, and returns an error for any other type. It is a
// convenience wrapper for callers holding a generic *Transaction.
func ValidateFrameSignatures(tx *Transaction) error {
	frameTx, ok := tx.inner.(*FrameTx)
	if !ok {
		return fmt.Errorf("%w: not a frame transaction", ErrTxTypeNotSupported)
	}
	return frameTx.ValidateSignatures()
}

// validateSignatureEntry validates a single signature entry, prefixing any
// error with the entry index.
func (tx *FrameTx) validateSignatureEntry(index int, sig *FrameSignature) error {
	if err := tx.checkSignatureStructure(sig); err != nil {
		return fmt.Errorf("frame tx signature %d: %w", index, err)
	}
	switch sig.Scheme {
	case FrameSigSchemeArbitrary:
		// Structurally validated only. Arbitrary signature bytes are opaque
		// to the protocol and are validated by contracts at execution time.
		return nil
	case FrameSigSchemeSecp256k1:
		if err := tx.validateSecp256k1(sig); err != nil {
			return fmt.Errorf("frame tx signature %d: %w", index, err)
		}
		return nil
	case FrameSigSchemeP256:
		if err := tx.validateP256(sig); err != nil {
			return fmt.Errorf("frame tx signature %d: %w", index, err)
		}
		return nil
	default:
		return fmt.Errorf("frame tx signature %d: %w", index, errFrameTxInvalidScheme)
	}
}

// checkSignatureStructure applies the structural rules shared by all schemes.
func (tx *FrameTx) checkSignatureStructure(sig *FrameSignature) error {
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
	// msg length and zero-digest rules.
	if len(sig.Msg) == 0 {
		return nil
	}
	if len(sig.Msg) != 32 {
		return errFrameTxInvalidMsg
	}
	if common.BytesToHash(sig.Msg) == (common.Hash{}) {
		return errFrameTxZeroMsgDigest
	}
	return nil
}

// validateSecp256k1 verifies a SECP256K1 signature entry of the form
// v (1 byte) || r (32 bytes) || s (32 bytes).
func (tx *FrameTx) validateSecp256k1(sig *FrameSignature) error {
	if len(sig.Signature) < frameSecp256k1SigLen {
		return fmt.Errorf("%w: SECP256K1 signature is %d bytes, want %d", errFrameTxSigTooShort, len(sig.Signature), frameSecp256k1SigLen)
	}
	if len(sig.Signature) > frameSecp256k1SigLen {
		return fmt.Errorf("%w: SECP256K1 signature is %d bytes, want %d", errFrameTxSigTooLong, len(sig.Signature), frameSecp256k1SigLen)
	}
	v := sig.Signature[0]
	if v > 1 {
		return errFrameTxRecoveryID
	}
	r := new(big.Int).SetBytes(sig.Signature[1:33])
	s := new(big.Int).SetBytes(sig.Signature[33:65])
	// Reject out-of-range and non-homogeneous (high-s) scalars, matching the
	// transaction signature validity rules applied to all other tx types.
	if !crypto.ValidateSignatureValues(v, r, s, true) {
		return errFrameTxInvalidSig
	}
	// The repository recovery helper expects the 65-byte [R || S || V]
	// layout; EIP-8141 carries v first.
	rsv := make([]byte, 65)
	copy(rsv[0:32], sig.Signature[1:33])
	copy(rsv[32:64], sig.Signature[33:65])
	rsv[64] = v
	pub, err := crypto.Ecrecover(tx.sigDigest(sig).Bytes(), rsv)
	if err != nil {
		return fmt.Errorf("%w: %v", errFrameTxSigRecover, err)
	}
	recovered := common.BytesToAddress(crypto.Keccak256(pub[1:])[12:])
	if resolved := tx.resolvedSigner(sig); recovered != resolved {
		return fmt.Errorf("%w: recovered %s, resolved %s", errFrameTxSignerMismatch, recovered, resolved)
	}
	return nil
}

// validateP256 verifies a P256 (secp256r1) signature entry of the form
// r || s || qx || qy (32 bytes each), using the repository's P256 verifier.
func (tx *FrameTx) validateP256(sig *FrameSignature) error {
	if len(sig.Signature) < frameP256SigLen {
		return fmt.Errorf("%w: P256 signature is %d bytes, want %d", errFrameTxSigTooShort, len(sig.Signature), frameP256SigLen)
	}
	if len(sig.Signature) > frameP256SigLen {
		return fmt.Errorf("%w: P256 signature is %d bytes, want %d", errFrameTxSigTooLong, len(sig.Signature), frameP256SigLen)
	}
	r := new(big.Int).SetBytes(sig.Signature[0:32])
	s := new(big.Int).SetBytes(sig.Signature[32:64])
	qx := new(big.Int).SetBytes(sig.Signature[64:96])
	qy := new(big.Int).SetBytes(sig.Signature[96:128])

	// Canonicality: scalars must satisfy 0 < r < N and 0 < s <= N/2, as
	// required by the EIP for both protocol-validated curves. The underlying
	// verifier would also reject zero/out-of-range scalars, but enforcing
	// the range explicitly keeps the error attributable and enforces low-s,
	// which ECDSA verification alone does not.
	if r.Sign() <= 0 || r.Cmp(secp256R1N) >= 0 || s.Sign() <= 0 || s.Cmp(secp256R1N) >= 0 {
		return errFrameTxP256ScalarRange
	}
	if s.Cmp(secp256R1HalfN) > 0 {
		return errFrameTxP256HighS
	}

	// The signer address of a P256 key is keccak256(qx || qy)[12:].
	addrHash := crypto.Keccak256(sig.Signature[64:96], sig.Signature[96:128])
	derived := common.BytesToAddress(addrHash[12:])
	if resolved := tx.resolvedSigner(sig); derived != resolved {
		return fmt.Errorf("%w: derived %s, resolved %s", errFrameTxP256Address, derived, resolved)
	}
	if !secp256r1.Verify(tx.sigDigest(sig).Bytes(), r, s, qx, qy) {
		return errFrameTxP256Verify
	}
	return nil
}
