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
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/XinFinOrg/XDPoSChain/common"
)

// EIP-8141 "Mempool/Constants": public-mempool admission caps.
const (
	// FrameMaxVerifyGas bounds the sum of declared frame execution-gas
	// limits across the validation prefix plus the intrinsic cost of
	// validating the transaction's signatures (MAX_VERIFY_GAS).
	FrameMaxVerifyGas = 100_000
	// FrameMaxVerifyStateGas bounds the sum of declared frame state-gas
	// limits across the validation prefix (MAX_VERIFY_STATE_GAS).
	FrameMaxVerifyStateGas = 500_000
)

// FrameExpiryDataLength is the EXPIRY_DATA_LENGTH of an expiry verifier
// frame: an 8-byte big-endian unix timestamp (EIP-8141 "Constants").
const FrameExpiryDataLength = 8

// FrameExpiryVerifier is the EIP-8141 canonical expiry verifier address
// (EXPIRY_VERIFIER).
var FrameExpiryVerifier = common.HexToAddress("0x81413f0cF12e9b6a49B1D0439E081c577D57FfFf")

// ErrFrameValidationPrefix is returned when an EIP-8141 frame transaction
// violates the public-mempool validation-prefix rules.
var ErrFrameValidationPrefix = errors.New("invalid frame validation prefix")

// IsExpiryVerifierFrame reports whether the frame is structurally an
// expiry_verify frame (EIP-8141 "Expiry Verifier Frame"): a VERIFY-mode frame
// whose target is EXPIRY_VERIFIER with flags == 0, zero value, zero state-gas
// limit, and exactly FrameExpiryDataLength data bytes.
func (f *Frame) IsExpiryVerifierFrame() bool {
	return f.Mode == FrameModeVerify &&
		f.Target != nil && *f.Target == FrameExpiryVerifier &&
		f.Flags == 0 &&
		len(f.Data) == FrameExpiryDataLength &&
		(f.Value == nil || f.Value.IsZero()) &&
		f.Limits.State == 0
}

// ExpiryDeadline decodes the expiry timestamp of an expiry verifier frame
// (big-endian uint64 unix timestamp). The caller must have verified
// IsExpiryVerifierFrame first.
func (f *Frame) ExpiryDeadline() uint64 {
	return binary.BigEndian.Uint64(f.Data)
}

// prefixClass classifies a frame for validation-prefix shape matching
// (EIP-8141 "Mode Subclassifications" and "Structural Rules").
type prefixClass int

const (
	classSelfVerify prefixClass = iota // VERIFY, resolves to tx.sender, flags 0x3
	classOnlyVerify                    // VERIFY, resolves to tx.sender, flags 0x2
	classPay                           // VERIFY, flags 0x1
	classDeploy                        // DEFAULT, flags 0x0
	classUnknown
)

// FrameSpecies identifies the public-mempool species of a validation-prefix
// frame (EIP-8141 "Mode Subclassifications").
type FrameSpecies uint8

const (
	// FrameSpeciesExpiry is an expiry_verify frame (VERIFY, target
	// EXPIRY_VERIFIER, flags 0x0).
	FrameSpeciesExpiry FrameSpecies = iota
	// FrameSpeciesDeploy is a deploy frame (DEFAULT, flags 0x0).
	FrameSpeciesDeploy
	// FrameSpeciesSelfVerify is a self_verify frame (VERIFY, resolves to
	// tx.sender, flags 0x3).
	FrameSpeciesSelfVerify
	// FrameSpeciesOnlyVerify is an only_verify frame (VERIFY, resolves to
	// tx.sender, flags 0x2).
	FrameSpeciesOnlyVerify
	// FrameSpeciesPay is a pay frame (VERIFY, flags 0x1).
	FrameSpeciesPay
)

// classifyPrefixFrame maps a frame to its validation-prefix class using only
// transaction fields (no state access). Scope bits are masked with
// FrameApproveScopeMask so the ATOMIC_BATCH_FLAG is examined separately.
// Scope values are the EIP-8141 APPROVE scope operand: PAYMENT = 0x1,
// EXECUTION = 0x2, EXECUTION_AND_PAYMENT = 0x3.
func classifyPrefixFrame(sender common.Address, f *Frame) prefixClass {
	flags := f.Flags & FrameApproveScopeMask
	switch f.Mode {
	case FrameModeVerify:
		resolvesToSender := f.Target == nil || *f.Target == sender
		switch flags {
		case 0x3: // APPROVE_EXECUTION_AND_PAYMENT
			if resolvesToSender {
				return classSelfVerify
			}
		case 0x2: // APPROVE_EXECUTION
			if resolvesToSender {
				return classOnlyVerify
			}
		case 0x1: // APPROVE_PAYMENT
			return classPay
		}
	case FrameModeDefault:
		if flags == 0 {
			return classDeploy
		}
	}
	return classUnknown
}

// validationPrefix matches the recognized public-mempool validation prefix
// and returns the exclusive end index of the prefix and the species of each
// prefix frame, in frame order. now is the node's view of the current block
// timestamp.
func (tx *FrameTx) validationPrefix(now uint64) (int, []FrameSpecies, error) {
	frames := tx.Frames

	// Expiry verifier frame: at most one, and only as the first frame. A
	// VERIFY frame targeting EXPIRY_VERIFIER that is not a well-formed
	// expiry verifier frame can never execute successfully, so it is
	// rejected outright rather than shape-matched.
	prefixStart := 0
	var species []FrameSpecies
	for i := range frames {
		if frames[i].Mode == FrameModeVerify && frames[i].Target != nil && *frames[i].Target == FrameExpiryVerifier {
			if i != 0 {
				return 0, nil, fmt.Errorf("%w: expiry verifier frame at index %d, only first frame allowed", ErrFrameValidationPrefix, i)
			}
			if !frames[i].IsExpiryVerifierFrame() {
				return 0, nil, fmt.Errorf("%w: malformed expiry verifier frame", ErrFrameValidationPrefix)
			}
			if deadline := frames[i].ExpiryDeadline(); deadline < now {
				return 0, nil, fmt.Errorf("%w: expiry deadline %d expired at current block timestamp %d", ErrFrameValidationPrefix, deadline, now)
			}
			prefixStart = 1
			species = append(species, FrameSpeciesExpiry)
			break // at most one occurrence is possible: only index 0 is allowed
		}
	}

	// Match one of the four recognized prefix shapes on the frames after
	// the optional expiry verifier frame. The shape's last element sets
	// payer; the match also determines the static end of the prefix.
	rest := frames[prefixStart:]
	var shape []prefixClass
	switch {
	case len(rest) >= 1 && classifyPrefixFrame(tx.Sender, &rest[0]) == classSelfVerify:
		shape = []prefixClass{classSelfVerify}
	case len(rest) >= 2 && classifyPrefixFrame(tx.Sender, &rest[0]) == classDeploy &&
		classifyPrefixFrame(tx.Sender, &rest[1]) == classSelfVerify:
		shape = []prefixClass{classDeploy, classSelfVerify}
	case len(rest) >= 2 && classifyPrefixFrame(tx.Sender, &rest[0]) == classOnlyVerify &&
		classifyPrefixFrame(tx.Sender, &rest[1]) == classPay:
		shape = []prefixClass{classOnlyVerify, classPay}
	case len(rest) >= 3 && classifyPrefixFrame(tx.Sender, &rest[0]) == classDeploy &&
		classifyPrefixFrame(tx.Sender, &rest[1]) == classOnlyVerify &&
		classifyPrefixFrame(tx.Sender, &rest[2]) == classPay:
		shape = []prefixClass{classDeploy, classOnlyVerify, classPay}
	default:
		return 0, nil, fmt.Errorf("%w: unrecognized validation prefix shape", ErrFrameValidationPrefix)
	}
	// Every structural frame of the shape must match; a longer sequence
	// cannot masquerade as a recognized shape.
	for i, want := range shape {
		if got := classifyPrefixFrame(tx.Sender, &rest[i]); got != want {
			return 0, nil, fmt.Errorf("%w: prefix frame %d does not match recognized shape", ErrFrameValidationPrefix, i)
		}
	}
	for _, c := range shape {
		switch c {
		case classSelfVerify:
			species = append(species, FrameSpeciesSelfVerify)
		case classOnlyVerify:
			species = append(species, FrameSpeciesOnlyVerify)
		case classPay:
			species = append(species, FrameSpeciesPay)
		case classDeploy:
			species = append(species, FrameSpeciesDeploy)
		}
	}
	return prefixStart + len(shape), species, nil
}

// ValidationPrefix returns the frames of the recognized public-mempool
// validation prefix and their species, in frame order, after enforcing the
// structural rules (recognized shapes, deploy placement, expiry freshness).
// now is the node's view of the current block timestamp.
func (tx *FrameTx) ValidationPrefix(now uint64) ([]Frame, []FrameSpecies, error) {
	end, species, err := tx.validationPrefix(now)
	if err != nil {
		return nil, nil, err
	}
	return tx.Frames[:end], species, nil
}

// ValidateMempoolPrefix enforces the EIP-8141 public-mempool structural
// rules on the validation prefix (recognized shapes, deploy placement,
// mode/target/scope restrictions, atomic-batch prohibition, the
// no-VERIFY-after-prefix rule) together with the verification-gas caps.
//
// now is the node's view of the current block timestamp; a transaction whose
// expiry verifier deadline is earlier than now must be dropped.
//
// This is a purely static derivation from the transaction payload. For the
// four recognized prefix shapes, the static end of the validation prefix
// (the payer-setting frame) equals the dynamic end (the frame whose
// execution sets payer), because each shape's payer-setter is the last frame
// the shape permits: shapes define no frames between the last structural
// element and the payer-setter, and no VERIFY frame may follow the prefix.
func (tx *FrameTx) ValidateMempoolPrefix(now uint64) error {
	frames := tx.Frames
	prefixEnd, _, err := tx.validationPrefix(now)
	if err != nil {
		return err
	}

	// Rule 5: no ATOMIC_BATCH_FLAG in the validation prefix.
	for i := 0; i < prefixEnd; i++ {
		if frames[i].Flags&FrameAtomicBatchFlag != 0 {
			return fmt.Errorf("%w: atomic batch flag set in validation prefix frame %d", ErrFrameValidationPrefix, i)
		}
	}
	// Rule 8: no VERIFY frame after the validation prefix.
	for i := prefixEnd; i < len(frames); i++ {
		if frames[i].Mode == FrameModeVerify {
			return fmt.Errorf("%w: VERIFY frame after validation prefix at index %d", ErrFrameValidationPrefix, i)
		}
	}

	// Rule 6: verification-gas caps over the validation prefix, including
	// the intrinsic cost of validating the signatures. Both sums use
	// saturating arithmetic so oversized declared limits can never wrap.
	var verifyGas, verifyStateGas uint64
	for i := 0; i < prefixEnd; i++ {
		verifyGas = saturatingAdd(verifyGas, frames[i].Limits.Execution)
		verifyStateGas = saturatingAdd(verifyStateGas, frames[i].Limits.State)
	}
	for i := range tx.Signatures {
		verifyGas = saturatingAdd(verifyGas, signatureVerifyGas(tx.Signatures[i].Scheme))
	}
	if verifyGas > FrameMaxVerifyGas {
		return fmt.Errorf("%w: validation prefix verification gas %d exceeds MAX_VERIFY_GAS %d", ErrFrameValidationPrefix, verifyGas, FrameMaxVerifyGas)
	}
	if verifyStateGas > FrameMaxVerifyStateGas {
		return fmt.Errorf("%w: validation prefix state gas %d exceeds MAX_VERIFY_STATE_GAS %d", ErrFrameValidationPrefix, verifyStateGas, FrameMaxVerifyStateGas)
	}
	return nil
}

// ValidateFrameMempoolPrefix applies the EIP-8141 public-mempool
// validation-prefix rules to a transaction. It returns an error for any
// non-frame transaction.
func ValidateFrameMempoolPrefix(tx *Transaction, now uint64) error {
	frameTx, ok := tx.inner.(*FrameTx)
	if !ok {
		return fmt.Errorf("%w: not a frame transaction", ErrTxTypeNotSupported)
	}
	return frameTx.ValidateMempoolPrefix(now)
}
