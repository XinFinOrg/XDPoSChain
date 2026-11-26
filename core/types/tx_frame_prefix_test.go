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
	"math"
	"math/big"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/holiman/uint256"
)

var (
	prefixTestPaymaster = common.HexToAddress("0x00000000000000000000000000000000deadc0de")
	prefixTestFactory   = common.HexToAddress("0x00000000000000000000000000000000fa0707a1")
	prefixTestUserOp    = common.HexToAddress("0x00000000000000000000000000000000bada55e0")
)

// prefixExpiryFrame builds a well-formed expiry verifier frame with the
// given unix deadline (8-byte big-endian).
func prefixExpiryFrame(deadline uint64) Frame {
	var data [FrameExpiryDataLength]byte
	binary.BigEndian.PutUint64(data[:], deadline)
	return Frame{
		Mode:   FrameModeVerify,
		Target: &FrameExpiryVerifier,
		Flags:  0,
		Data:   data[:],
		Limits: FrameLimits{Execution: 10_000},
	}
}

// prefixLimits returns declared limits that keep a frame comfortably inside
// the verification-gas caps.
func prefixLimits() FrameLimits { return FrameLimits{Execution: 20_000, State: 50_000} }

func oneSecpSig() []FrameSignature {
	return []FrameSignature{{Scheme: FrameSigSchemeSecp256k1}}
}

func mustValidPrefix(t *testing.T, tx *Transaction, now uint64) {
	t.Helper()
	if err := ValidateFrameMempoolPrefix(tx, now); err != nil {
		t.Fatalf("expected valid prefix, got: %v", err)
	}
}

func mustInvalidPrefix(t *testing.T, tx *Transaction, now uint64) {
	t.Helper()
	err := ValidateFrameMempoolPrefix(tx, now)
	if err == nil {
		t.Fatal("expected invalid prefix, got nil")
	}
	if !errors.Is(err, ErrFrameValidationPrefix) {
		t.Fatalf("err = %v, want ErrFrameValidationPrefix", err)
	}
}

// TestFramePrefixRecognizedShapes: all four recognized validation prefixes
// (EIP-8141 "Public Mempool-recognized Validation Prefixes") are admitted,
// each optionally preceded by an expiry verifier frame and followed by
// arbitrary post-prefix (user_op / post_op) frames.
func TestFramePrefixRecognizedShapes(t *testing.T) {
	const now = uint64(1_000_000)
	selfVerify := Frame{Mode: FrameModeVerify, Flags: 0x3, Limits: prefixLimits()}
	onlyVerify := Frame{Mode: FrameModeVerify, Flags: 0x2, Limits: prefixLimits()}
	pay := Frame{Mode: FrameModeVerify, Target: &prefixTestPaymaster, Flags: 0x1, Limits: prefixLimits()}
	deploy := Frame{Mode: FrameModeDefault, Target: &prefixTestFactory, Flags: 0x0, Limits: prefixLimits()}
	userOp := Frame{Mode: FrameModeSender, Target: &prefixTestUserOp, Limits: FrameLimits{Execution: 1_000_000, State: 2_000_000}}

	shapes := map[string][]Frame{
		"SelfRelay":              {selfVerify},
		"SelfRelayDeploy":        {deploy, selfVerify},
		"CanonicalPaymaster":     {onlyVerify, pay},
		"CanonicalPaymasterDepl": {deploy, onlyVerify, pay},
	}
	for name, shape := range shapes {
		t.Run(name, func(t *testing.T) {
			mustValidPrefix(t, makeGasTx(shape, oneSecpSig()), now)
			// Trailing user_op frames are outside the validation prefix.
			withTail := append(append([]Frame{}, shape...), userOp, userOp)
			mustValidPrefix(t, makeGasTx(withTail, oneSecpSig()), now)
			// An expiry verifier frame may precede the shape.
			withExpiry := append([]Frame{prefixExpiryFrame(now + 100)}, shape...)
			mustValidPrefix(t, makeGasTx(withExpiry, oneSecpSig()), now)
			// Expiry + shape + trailing frames.
			full := append(append([]Frame{prefixExpiryFrame(now + 100)}, shape...), userOp)
			mustValidPrefix(t, makeGasTx(full, oneSecpSig()), now)
		})
	}
	// Explicit-target self_verify (target == tx.sender) is equivalent to a
	// null target.
	explicit := Frame{Mode: FrameModeVerify, Target: &gasTestSender, Flags: 0x3, Limits: prefixLimits()}
	mustValidPrefix(t, makeGasTx([]Frame{explicit}, oneSecpSig()), now)
}

// TestFramePrefixRejectsUnknownShapes: anything that is not one of the four
// recognized prefixes is rejected (EIP-8141 structural rule 1).
func TestFramePrefixRejectsUnknownShapes(t *testing.T) {
	const now = uint64(1_000_000)
	mk := func(frames ...Frame) *Transaction { return makeGasTx(frames, oneSecpSig()) }
	sv := Frame{Mode: FrameModeVerify, Flags: 0x3, Limits: prefixLimits()}
	ov := Frame{Mode: FrameModeVerify, Flags: 0x2, Limits: prefixLimits()}
	pay := Frame{Mode: FrameModeVerify, Target: &prefixTestPaymaster, Flags: 0x1, Limits: prefixLimits()}
	deploy := Frame{Mode: FrameModeDefault, Target: &prefixTestFactory, Flags: 0x0, Limits: prefixLimits()}
	userOp := Frame{Mode: FrameModeSender, Target: &prefixTestUserOp, Limits: prefixLimits()}

	cases := map[string][]Frame{
		"EmptyPrefix":            {userOp},
		"PayAlone":               {pay},
		"OnlyVerifyAlone":        {ov},
		"DeployAlone":            {deploy},
		"DeployBetweenVerifyPay": {ov, deploy, pay},         // deploy not first in the prefix
		"DeployInsidePaymaster":  {deploy, ov, deploy, pay}, // second deploy breaks the shape
		"DoubleDeploy":           {deploy, deploy, sv},
		"VerifyFlagsZero":        {{Mode: FrameModeVerify, Flags: 0x0, Limits: prefixLimits()}},
		"DeployWithApproveFlags": {{Mode: FrameModeDefault, Target: &prefixTestFactory, Flags: 0x1, Limits: prefixLimits()}},
		"SelfVerifyWrongTarget":  {{Mode: FrameModeVerify, Target: &prefixTestPaymaster, Flags: 0x3, Limits: prefixLimits()}},
		"OnlyVerifyWrongTarget":  {{Mode: FrameModeVerify, Target: &prefixTestPaymaster, Flags: 0x2, Limits: prefixLimits()}},
		"PayWrongScope":          {{Mode: FrameModeVerify, Target: &prefixTestPaymaster, Flags: 0x2, Limits: prefixLimits()}},
		"TruncatedPaymaster":     {ov, pay, pay}, // second pay is a post-prefix VERIFY
		"SenderModeVerify":       {{Mode: FrameModeSender, Flags: 0x3, Limits: prefixLimits()}},
	}
	for name, frames := range cases {
		t.Run(name, func(t *testing.T) {
			mustInvalidPrefix(t, mk(frames...), now)
		})
	}
	// A DEFAULT-mode flags-0 frame AFTER the validation prefix is a
	// legitimate post_op (EIP-8141: frames after the prefix "may be
	// arbitrary"); deploy-first applies only within the prefix. These are
	// statically indistinguishable from deploy frames and must be accepted.
	t.Run("DeployAfterPrefixIsPostOp", func(t *testing.T) {
		mustValidPrefix(t, mk(sv, deploy), now)
		mustValidPrefix(t, mk(ov, pay, deploy), now)
	})
}

// TestFramePrefixAtomicBatchFlag: no frame in the validation prefix may
// carry the ATOMIC_BATCH_FLAG (EIP-8141 structural rule 5). Post-prefix
// frames are unrestricted.
func TestFramePrefixAtomicBatchFlag(t *testing.T) {
	const now = uint64(1_000_000)
	t.Run("InPrefix", func(t *testing.T) {
		frames := []Frame{
			{Mode: FrameModeVerify, Flags: 0x3 | FrameAtomicBatchFlag, Limits: prefixLimits()},
		}
		mustInvalidPrefix(t, makeGasTx(frames, oneSecpSig()), now)
	})
	t.Run("ExpiryThenFlagged", func(t *testing.T) {
		frames := []Frame{
			prefixExpiryFrame(now + 100),
			{Mode: FrameModeVerify, Flags: 0x3 | FrameAtomicBatchFlag, Limits: prefixLimits()},
		}
		mustInvalidPrefix(t, makeGasTx(frames, oneSecpSig()), now)
	})
	t.Run("PostPrefixOK", func(t *testing.T) {
		frames := []Frame{
			{Mode: FrameModeVerify, Flags: 0x3, Limits: prefixLimits()},
			{Mode: FrameModeSender, Target: &prefixTestUserOp, Flags: FrameAtomicBatchFlag, Limits: prefixLimits()},
		}
		mustValidPrefix(t, makeGasTx(frames, oneSecpSig()), now)
	})
}

// TestFramePrefixNoVerifyAfterPrefix: rule 8 — no VERIFY frame may follow
// the validation prefix.
func TestFramePrefixNoVerifyAfterPrefix(t *testing.T) {
	const now = uint64(1_000_000)
	frames := []Frame{
		{Mode: FrameModeVerify, Flags: 0x3, Limits: prefixLimits()},
		{Mode: FrameModeSender, Target: &prefixTestUserOp, Limits: prefixLimits()},
		{Mode: FrameModeVerify, Flags: 0x0, Limits: prefixLimits()},
	}
	mustInvalidPrefix(t, makeGasTx(frames, oneSecpSig()), now)
}

// TestFramePrefixVerifyGasCaps: rule 6 — the sum of declared execution
// limits across the validation prefix plus the intrinsic signature
// verification cost must not exceed MAX_VERIFY_GAS, and the sum of declared
// state limits must not exceed MAX_VERIFY_STATE_GAS.
func TestFramePrefixVerifyGasCaps(t *testing.T) {
	const now = uint64(1_000_000)
	// One secp256k1 signature contributes 2800 (EIP-8141 signature_gas).
	sigCost := uint64(FrameSigVerifyGasSecp256k1)

	t.Run("ExactlyAtExecCap", func(t *testing.T) {
		frames := []Frame{{Mode: FrameModeVerify, Flags: 0x3, Limits: FrameLimits{Execution: FrameMaxVerifyGas - sigCost}}}
		mustValidPrefix(t, makeGasTx(frames, oneSecpSig()), now)
	})
	t.Run("OneOverExecCap", func(t *testing.T) {
		frames := []Frame{{Mode: FrameModeVerify, Flags: 0x3, Limits: FrameLimits{Execution: FrameMaxVerifyGas - sigCost + 1}}}
		mustInvalidPrefix(t, makeGasTx(frames, oneSecpSig()), now)
	})
	t.Run("SubstantiallyOverExecCap", func(t *testing.T) {
		frames := []Frame{{Mode: FrameModeVerify, Flags: 0x3, Limits: FrameLimits{Execution: math.MaxUint64}}}
		mustInvalidPrefix(t, makeGasTx(frames, oneSecpSig()), now)
	})
	t.Run("ExactlyAtStateCap", func(t *testing.T) {
		frames := []Frame{{Mode: FrameModeVerify, Flags: 0x3, Limits: FrameLimits{Execution: 1_000, State: FrameMaxVerifyStateGas}}}
		mustValidPrefix(t, makeGasTx(frames, oneSecpSig()), now)
	})
	t.Run("OneOverStateCap", func(t *testing.T) {
		frames := []Frame{{Mode: FrameModeVerify, Flags: 0x3, Limits: FrameLimits{Execution: 1_000, State: FrameMaxVerifyStateGas + 1}}}
		mustInvalidPrefix(t, makeGasTx(frames, oneSecpSig()), now)
	})
	t.Run("ExecAndStateAreSeparate", func(t *testing.T) {
		// Execution limits sum (with the 2800 signature cost) to exactly
		// MAX_VERIFY_GAS; state limits sum to exactly
		// MAX_VERIFY_STATE_GAS. Both at their own cap, neither borrowing
		// from the other: the two limits must not be merged.
		frames := []Frame{
			{Mode: FrameModeVerify, Flags: 0x2, Limits: FrameLimits{Execution: 40_000, State: FrameMaxVerifyStateGas}},
			{Mode: FrameModeVerify, Target: &prefixTestPaymaster, Flags: 0x1, Limits: FrameLimits{Execution: FrameMaxVerifyGas - 40_000 - sigCost, State: 0}},
		}
		mustValidPrefix(t, makeGasTx(frames, oneSecpSig()), now)
		// One more state-gas unit on the pay frame exceeds only the state cap.
		frames[1].Limits.State = 1
		mustInvalidPrefix(t, makeGasTx(frames, oneSecpSig()), now)
	})
	t.Run("SumAcrossPrefix", func(t *testing.T) {
		// Each frame is individually under the cap; only the prefix sum
		// must count.
		per := (FrameMaxVerifyGas - sigCost) / 2 // uint64 arithmetic
		frames := []Frame{
			{Mode: FrameModeVerify, Flags: 0x2, Limits: FrameLimits{Execution: per}},
			{Mode: FrameModeVerify, Target: &prefixTestPaymaster, Flags: 0x1, Limits: FrameLimits{Execution: per + 1}},
		}
		mustInvalidPrefix(t, makeGasTx(frames, oneSecpSig()), now)
	})
	t.Run("PostPrefixFramesExempt", func(t *testing.T) {
		// Frames after the payer-setting frame do not count against the
		// verification caps.
		frames := []Frame{
			{Mode: FrameModeVerify, Flags: 0x3, Limits: FrameLimits{Execution: 1_000, State: 1_000}},
			{Mode: FrameModeSender, Target: &prefixTestUserOp, Limits: FrameLimits{Execution: math.MaxUint64, State: math.MaxUint64}},
		}
		mustValidPrefix(t, makeGasTx(frames, oneSecpSig()), now)
	})
}

// TestFramePrefixToolShapeRegression pins the exact admission failure observed
// on the disposable chain-81411 network: the frametx signing tool declared a
// 100_000 execution limit (and 300_000 state limit) on every frame, so the
// two-frame validation prefix summed to 2*100_000 + 2800 (one secp256k1
// signature) = 202_800 > MAX_VERIFY_GAS, and every node rejected the
// transaction with "validation prefix verification gas 202800 exceeds
// MAX_VERIFY_GAS 100000". The corrected tool shape declares tight limits
// (25_000) on the verify frames and must be admitted.
func TestFramePrefixToolShapeRegression(t *testing.T) {
	const now = uint64(1_000_000)

	// Reported (broken) construction: uniform 100k/300k limits.
	broken := []Frame{
		{Mode: FrameModeVerify, Flags: 0x2, Limits: FrameLimits{Execution: 100_000, State: 300_000}},
		{Mode: FrameModeVerify, Target: &prefixTestPaymaster, Flags: 0x1, Limits: FrameLimits{Execution: 100_000, State: 300_000}},
		{Mode: FrameModeSender, Target: &prefixTestUserOp, Flags: 0x0, Limits: FrameLimits{Execution: 100_000, State: 300_000}},
	}
	err := ValidateFrameMempoolPrefix(makeGasTx(broken, oneSecpSig()), now)
	if err == nil {
		t.Fatalf("expected rejection of uniform-100k tool shape")
	}
	if !errors.Is(err, ErrFrameValidationPrefix) {
		t.Fatalf("wrong error: %v", err)
	}
	// Pin the exact arithmetic from the live rejection.
	const want = "verification gas 202800 exceeds MAX_VERIFY_GAS 100000"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not contain %q", err.Error(), want)
	}

	// Corrected construction: tight limits on the validation prefix;
	// the SENDER frame's generous limit is paid from transaction gas and
	// does not count against the verification caps.
	fixed := []Frame{
		{Mode: FrameModeVerify, Flags: 0x2, Limits: FrameLimits{Execution: 25_000, State: 25_000}},
		{Mode: FrameModeVerify, Target: &prefixTestPaymaster, Flags: 0x1, Limits: FrameLimits{Execution: 25_000, State: 25_000}},
		{Mode: FrameModeSender, Target: &prefixTestUserOp, Flags: 0x0, Limits: FrameLimits{Execution: 100_000, State: 300_000}},
	}
	if err := ValidateFrameMempoolPrefix(makeGasTx(fixed, oneSecpSig()), now); err != nil {
		t.Fatalf("corrected tool shape rejected: %v", err)
	}
}

// TestFramePrefixSignatureCostContribution: the intrinsic signature
// verification cost (EIP-8141 signature_gas) counts against MAX_VERIFY_GAS.
func TestFramePrefixSignatureCostContribution(t *testing.T) {
	const now = uint64(1_000_000)
	frame := func() []Frame {
		return []Frame{
			{Mode: FrameModeVerify, Flags: 0x3, Limits: FrameLimits{Execution: FrameMaxVerifyGas - FrameSigVerifyGasP256 - 100}},
		}
	}
	t.Run("ArbitraryIs100", func(t *testing.T) {
		// 100 (ARBITRARY) + frame exec fits, anything more fails.
		sigs := []FrameSignature{{Scheme: FrameSigSchemeArbitrary}}
		mustValidPrefix(t, makeGasTx(frame(), sigs), now)
	})
	t.Run("P256Is6700", func(t *testing.T) {
		sigs := []FrameSignature{{Scheme: FrameSigSchemeP256}}
		mustValidPrefix(t, makeGasTx(frame(), sigs), now)
	})
	t.Run("P256OneOver", func(t *testing.T) {
		frames := []Frame{{Mode: FrameModeVerify, Flags: 0x3, Limits: FrameLimits{Execution: FrameMaxVerifyGas - FrameSigVerifyGasP256 + 1}}}
		sigs := []FrameSignature{{Scheme: FrameSigSchemeP256}}
		mustInvalidPrefix(t, makeGasTx(frames, sigs), now)
	})
	t.Run("MultipleSignaturesSum", func(t *testing.T) {
		// 2800 + 6700 + 100 = 9600 of the cap consumed by signatures.
		sigs := []FrameSignature{
			{Scheme: FrameSigSchemeSecp256k1},
			{Scheme: FrameSigSchemeP256},
			{Scheme: FrameSigSchemeArbitrary},
		}
		frames := []Frame{{Mode: FrameModeVerify, Flags: 0x3, Limits: FrameLimits{Execution: FrameMaxVerifyGas - 9600}}}
		mustValidPrefix(t, makeGasTx(frames, sigs), now)
		frames[0].Limits.Execution++
		mustInvalidPrefix(t, makeGasTx(frames, sigs), now)
	})
}

// TestFramePrefixExpiryVerifier: EIP-8141 "Expiry Verifier Frame" —
// placement, deadline freshness, boundary equality, malformed encodings,
// and combination with each recognized prefix shape.
func TestFramePrefixExpiryVerifier(t *testing.T) {
	now := uint64(1_000_000)
	future := func() Frame { return prefixExpiryFrame(now + 10_000) }

	t.Run("FutureDeadlineEachShape", func(t *testing.T) {
		sv := Frame{Mode: FrameModeVerify, Flags: 0x3, Limits: prefixLimits()}
		ov := Frame{Mode: FrameModeVerify, Flags: 0x2, Limits: prefixLimits()}
		pay := Frame{Mode: FrameModeVerify, Target: &prefixTestPaymaster, Flags: 0x1, Limits: prefixLimits()}
		deploy := Frame{Mode: FrameModeDefault, Target: &prefixTestFactory, Flags: 0x0, Limits: prefixLimits()}
		shapes := map[string][]Frame{
			"SelfRelay":              {future(), sv},
			"SelfRelayDeploy":        {future(), deploy, sv},
			"CanonicalPaymaster":     {future(), ov, pay},
			"CanonicalPaymasterDepl": {future(), deploy, ov, pay},
		}
		for _, frames := range shapes {
			mustValidPrefix(t, makeGasTx(frames, oneSecpSig()), now)
		}
	})
	t.Run("ExpiredDeadline", func(t *testing.T) {
		frames := []Frame{prefixExpiryFrame(now - 1), {Mode: FrameModeVerify, Flags: 0x3, Limits: prefixLimits()}}
		mustInvalidPrefix(t, makeGasTx(frames, oneSecpSig()), now)
	})
	t.Run("BoundaryEqualityAccepted", func(t *testing.T) {
		// The node drops only when the deadline is LESS than the current
		// block timestamp; equality stays valid (execution reverts unless
		// block.timestamp <= expiry).
		frames := []Frame{prefixExpiryFrame(now), {Mode: FrameModeVerify, Flags: 0x3, Limits: prefixLimits()}}
		mustValidPrefix(t, makeGasTx(frames, oneSecpSig()), now)
	})
	t.Run("WrongPlacement", func(t *testing.T) {
		frames := []Frame{
			{Mode: FrameModeVerify, Flags: 0x3, Limits: prefixLimits()},
			future(),
		}
		mustInvalidPrefix(t, makeGasTx(frames, oneSecpSig()), now)
	})
	t.Run("SecondExpiryFrame", func(t *testing.T) {
		frames := []Frame{future(), future(), {Mode: FrameModeVerify, Flags: 0x3, Limits: prefixLimits()}}
		mustInvalidPrefix(t, makeGasTx(frames, oneSecpSig()), now)
	})
	t.Run("MalformedDataLength", func(t *testing.T) {
		f := prefixExpiryFrame(now + 100)
		f.Data = f.Data[:7]
		frames := []Frame{f, {Mode: FrameModeVerify, Flags: 0x3, Limits: prefixLimits()}}
		mustInvalidPrefix(t, makeGasTx(frames, oneSecpSig()), now)
	})
	t.Run("MalformedFlags", func(t *testing.T) {
		f := prefixExpiryFrame(now + 100)
		f.Flags = 0x1
		frames := []Frame{f, {Mode: FrameModeVerify, Flags: 0x3, Limits: prefixLimits()}}
		mustInvalidPrefix(t, makeGasTx(frames, oneSecpSig()), now)
	})
	t.Run("MalformedValue", func(t *testing.T) {
		f := prefixExpiryFrame(now + 100)
		f.Value = uint256.NewInt(1)
		frames := []Frame{f, {Mode: FrameModeVerify, Flags: 0x3, Limits: prefixLimits()}}
		mustInvalidPrefix(t, makeGasTx(frames, oneSecpSig()), now)
	})
	t.Run("MalformedStateLimit", func(t *testing.T) {
		f := prefixExpiryFrame(now + 100)
		f.Limits.State = 1
		frames := []Frame{f, {Mode: FrameModeVerify, Flags: 0x3, Limits: prefixLimits()}}
		mustInvalidPrefix(t, makeGasTx(frames, oneSecpSig()), now)
	})
	t.Run("DeadlineBigEndian", func(t *testing.T) {
		f := prefixExpiryFrame(0x0102030405060708)
		if got := f.ExpiryDeadline(); got != 0x0102030405060708 {
			t.Fatalf("ExpiryDeadline = %#x, want 0x0102030405060708", got)
		}
	})
}

// TestFramePrefixExpiryDeadlineExpirySkipsShapeMatching: the expiry frame
// is skipped when matching shapes — e.g. [expiry_verify, self_verify] is
// recognized as [self_verify].
func TestFramePrefixExpirySkipsShapeMatching(t *testing.T) {
	const now = uint64(1_000_000)
	// [expiry, only_verify, pay] must match the canonical paymaster shape,
	// not be misread as starting with a VERIFY frame.
	frames := []Frame{
		prefixExpiryFrame(now + 100),
		{Mode: FrameModeVerify, Flags: 0x2, Limits: prefixLimits()},
		{Mode: FrameModeVerify, Target: &prefixTestPaymaster, Flags: 0x1, Limits: prefixLimits()},
	}
	mustValidPrefix(t, makeGasTx(frames, oneSecpSig()), now)
}

// TestValidateFrameMempoolPrefixNonFrame: the package-level helper rejects
// non-frame transactions.
func TestValidateFrameMempoolPrefixNonFrame(t *testing.T) {
	if err := ValidateFrameMempoolPrefix(NewTransaction(0, common.Address{}, big.NewInt(0), 0, big.NewInt(0), nil), 0); err == nil {
		t.Fatal("expected error for non-frame transaction")
	}
}
