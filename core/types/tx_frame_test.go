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
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rlp"
	"github.com/holiman/uint256"
)

// sampleFrameTx builds a representative frame transaction used by the
// round-trip and hashing tests.
func sampleFrameTx() *Transaction {
	target := common.HexToAddress("0x00000000000000000000000000000000000aaaaa")
	return NewFrameTx(
		uint256.NewInt(20118), // chainID
		7,                     // nonce
		common.HexToAddress("0x00000000000000000000000000000000000bbbbb"),
		[]Frame{
			// SENDER frame with value and target
			{Mode: FrameModeSender, Flags: 0, Target: &target, Limits: FrameLimits{Execution: 100000, State: 50000}, Value: uint256.NewInt(1234), Data: []byte{0x01, 0x02}},
			// DEFAULT frame with nil target and atomic batch into the next frame
			{Mode: FrameModeDefault, Flags: FrameAtomicBatchFlag, Target: nil, Limits: FrameLimits{Execution: 200000, State: 0}, Value: uint256.NewInt(0), Data: []byte{}},
			// SENDER frame batched with the previous one
			{Mode: FrameModeSender, Flags: 0, Target: nil, Limits: FrameLimits{Execution: 50000, State: 50000}, Value: uint256.NewInt(99), Data: nil},
		},
		[]FrameSignature{
			{Scheme: FrameSigSchemeArbitrary, Signer: nil, Msg: nil, Signature: []byte{0xde, 0xad}},
			{Scheme: FrameSigSchemeSecp256k1, Signer: common.HexToAddress("0x00000000000000000000000000000000000ccccc").Bytes(), Msg: nil, Signature: bytes.Repeat([]byte{0x11}, 65)},
			{Scheme: FrameSigSchemeSecp256k1, Signer: nil, Msg: bytes.Repeat([]byte{0x22}, 32), Signature: bytes.Repeat([]byte{0x33}, 65)},
		},
		FrameFees{
			GasTipCap:  uint256.NewInt(2),
			GasFeeCap:  uint256.NewInt(100),
			BlobFeeCap: uint256.NewInt(0),
		},
		nil, // no blobs
	)
}

func TestFrameTxRoundTrip(t *testing.T) {
	tx := sampleFrameTx()

	bin, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}
	if bin[0] != FrameTxType {
		t.Fatalf("wrong type byte: got %d, want %d", bin[0], FrameTxType)
	}

	var dec Transaction
	if err := dec.UnmarshalBinary(bin); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}
	if dec.Type() != FrameTxType {
		t.Fatalf("decoded wrong type: %d", dec.Type())
	}

	// Compare the decoded payload field by field.
	orig, ok := tx.inner.(*FrameTx)
	if !ok {
		t.Fatal("inner is not *FrameTx")
	}
	dup, ok := dec.inner.(*FrameTx)
	if !ok {
		t.Fatal("decoded inner is not *FrameTx")
	}
	if orig.Nonce != dup.Nonce || orig.ChainID.Cmp(dup.ChainID) != 0 || orig.Sender != dup.Sender {
		t.Fatal("scalar fields mismatch after round trip")
	}
	if len(orig.Frames) != len(dup.Frames) {
		t.Fatalf("frame count mismatch: %d != %d", len(orig.Frames), len(dup.Frames))
	}
	for i := range orig.Frames {
		of, df := orig.Frames[i], dup.Frames[i]
		if of.Mode != df.Mode || of.Flags != df.Flags || of.Limits != df.Limits {
			t.Fatalf("frame %d header mismatch", i)
		}
		if (of.Target == nil) != (df.Target == nil) {
			t.Fatalf("frame %d target nil-ness mismatch", i)
		}
		if of.Target != nil && *of.Target != *df.Target {
			t.Fatalf("frame %d target mismatch", i)
		}
		if of.Value.Cmp(df.Value) != 0 || !bytes.Equal(of.Data, df.Data) {
			t.Fatalf("frame %d value/data mismatch", i)
		}
	}
	if len(orig.Signatures) != len(dup.Signatures) {
		t.Fatalf("signature count mismatch: %d != %d", len(orig.Signatures), len(dup.Signatures))
	}
	for i := range orig.Signatures {
		os, ds := orig.Signatures[i], dup.Signatures[i]
		if os.Scheme != ds.Scheme || !bytes.Equal(os.Signer, ds.Signer) || !bytes.Equal(os.Msg, ds.Msg) || !bytes.Equal(os.Signature, ds.Signature) {
			t.Fatalf("signature %d mismatch", i)
		}
	}
	if orig.Fees.GasTipCap.Cmp(dup.Fees.GasTipCap) != 0 ||
		orig.Fees.GasFeeCap.Cmp(dup.Fees.GasFeeCap) != 0 ||
		orig.Fees.BlobFeeCap.Cmp(dup.Fees.BlobFeeCap) != 0 {
		t.Fatal("fees mismatch after round trip")
	}
	if len(orig.BlobHashes) != len(dup.BlobHashes) {
		t.Fatalf("blob hash count mismatch: %d != %d", len(orig.BlobHashes), len(dup.BlobHashes))
	}

	// Hash must be identical after decoding.
	if tx.Hash() != dec.Hash() {
		t.Fatal("hash mismatch after round trip")
	}
}

func TestFrameTxRLPStreamRoundTrip(t *testing.T) {
	tx := sampleFrameTx()
	buf := new(bytes.Buffer)
	if err := rlp.Encode(buf, tx); err != nil {
		t.Fatalf("EncodeRLP failed: %v", err)
	}
	var dec Transaction
	if err := rlp.DecodeBytes(buf.Bytes(), &dec); err != nil {
		t.Fatalf("DecodeRLP failed: %v", err)
	}
	if dec.Type() != FrameTxType || tx.Hash() != dec.Hash() {
		t.Fatal("RLP stream round trip mismatch")
	}
}

func TestFrameTxInvalidPayloads(t *testing.T) {
	base := func() *FrameTx {
		return sampleFrameTx().inner.(*FrameTx)
	}
	validBlobHash := common.Hash{0x01} // version byte 0x01 + zeros

	tests := []struct {
		name   string
		mutate func(tx *FrameTx)
	}{
		{"no frames", func(tx *FrameTx) { tx.Frames = nil }},
		{"too many frames", func(tx *FrameTx) {
			tx.Frames = make([]Frame, FrameMaxFrames+1)
			for i := range tx.Frames {
				tx.Frames[i] = Frame{Mode: FrameModeDefault, Limits: FrameLimits{Execution: 1}, Value: uint256.NewInt(0)}
			}
		}},
		{"invalid mode", func(tx *FrameTx) { tx.Frames[0].Mode = 3 }},
		{"reserved flags", func(tx *FrameTx) { tx.Frames[0].Flags = 0x8 }},
		{"value on non-sender frame", func(tx *FrameTx) { tx.Frames[1].Value = uint256.NewInt(1) }},
		{"atomic flag on VERIFY frame", func(tx *FrameTx) {
			tx.Frames = []Frame{
				{Mode: FrameModeVerify, Flags: FrameAtomicBatchFlag, Limits: FrameLimits{Execution: 1}, Value: uint256.NewInt(0)},
				{Mode: FrameModeDefault, Limits: FrameLimits{Execution: 1}, Value: uint256.NewInt(0)},
			}
		}},
		{"atomic flag on last frame", func(tx *FrameTx) {
			tx.Frames[2].Flags = FrameAtomicBatchFlag
		}},
		{"atomic batch into VERIFY frame", func(tx *FrameTx) {
			tx.Frames = []Frame{
				{Mode: FrameModeDefault, Flags: FrameAtomicBatchFlag, Limits: FrameLimits{Execution: 1}, Value: uint256.NewInt(0)},
				{Mode: FrameModeVerify, Limits: FrameLimits{Execution: 1}, Value: uint256.NewInt(0)},
			}
		}},
		{"approval scope on batched frame", func(tx *FrameTx) {
			// frame 2 is batched with frame 1 via the atomic flag; give it a scope
			tx.Frames[2].Flags = 0x2
		}},
		{"reserved signature scheme", func(tx *FrameTx) { tx.Signatures[0].Scheme = 0x3 }},
		{"signer on ARBITRARY signature", func(tx *FrameTx) { tx.Signatures[0].Signer = make([]byte, 20) }},
		{"wrong signer length", func(tx *FrameTx) { tx.Signatures[1].Signer = make([]byte, 19) }},
		{"msg wrong length", func(tx *FrameTx) { tx.Signatures[0].Msg = make([]byte, 1) }},
		{"msg 33 bytes", func(tx *FrameTx) { tx.Signatures[0].Msg = make([]byte, 33) }},
		{"explicit zero msg digest", func(tx *FrameTx) { tx.Signatures[2].Msg = make([]byte, 32) }},
		{"blob fee without blobs", func(tx *FrameTx) { tx.Fees.BlobFeeCap = uint256.NewInt(5) }},
		{"bad blob hash version", func(tx *FrameTx) {
			bad := validBlobHash
			bad[0] = 0x02
			tx.BlobHashes = []common.Hash{bad}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := base()
			tt.mutate(tx)
			var buf bytes.Buffer
			if err := tx.encode(&buf); err != nil {
				t.Fatalf("encode failed: %v", err)
			}
			var dec FrameTx
			if err := dec.decode(buf.Bytes()); err == nil {
				t.Fatal("expected decode to reject invalid payload")
			}
		})
	}
}

func TestFrameTxBlobVersionedHashesValid(t *testing.T) {
	tx := sampleFrameTx().inner.(*FrameTx)
	tx.BlobHashes = []common.Hash{{0x01, 0xaa}, {0x01}}
	tx.Fees.BlobFeeCap = uint256.NewInt(10)
	var buf bytes.Buffer
	if err := tx.encode(&buf); err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	var dec FrameTx
	if err := dec.decode(buf.Bytes()); err != nil {
		t.Fatalf("valid blob hashes rejected: %v", err)
	}
	if len(dec.BlobHashes) != 2 || dec.Fees.BlobFeeCap.Uint64() != 10 {
		t.Fatal("blob fields mismatch after round trip")
	}
}

func TestFrameTxSigHashElision(t *testing.T) {
	tx := sampleFrameTx().inner.(*FrameTx)
	h1 := tx.sigHash(nil)

	// Changing the raw signature bytes of an empty-msg (canonical-hash)
	// signature must not change the canonical signature hash.
	mod := tx.copy().(*FrameTx)
	for i := range mod.Signatures {
		if len(mod.Signatures[i].Msg) == 0 {
			for j := range mod.Signatures[i].Signature {
				mod.Signatures[i].Signature[j] ^= 0xff
			}
		}
	}
	if h2 := mod.sigHash(nil); h1 != h2 {
		t.Fatal("canonical sig hash changed when elided signature bytes changed")
	}

	// Changing the raw signature bytes of an explicit-msg signature MUST
	// change the canonical signature hash.
	mod2 := tx.copy().(*FrameTx)
	for i := range mod2.Signatures {
		if len(mod2.Signatures[i].Msg) == 32 {
			for j := range mod2.Signatures[i].Signature {
				mod2.Signatures[i].Signature[j] ^= 0xff
			}
		}
	}
	if h3 := mod2.sigHash(nil); h1 == h3 {
		t.Fatal("canonical sig hash did not change when explicit-msg signature bytes changed")
	}

	// The chainID argument is ignored: the chain id is inside the payload.
	other := big.NewInt(1)
	if h := tx.sigHash(other); h != h1 {
		t.Fatal("sigHash must not depend on the chainID argument")
	}

	// TXPARAM_SIG_HASH introspection value equals compute_sig_hash.
	if tx.computeSigHash() != h1 {
		t.Fatal("computeSigHash mismatch")
	}
}

func TestFrameTxCopyIndependence(t *testing.T) {
	tx := sampleFrameTx().inner.(*FrameTx)
	cpy := tx.copy().(*FrameTx)

	// Mutate everything in the copy.
	cpy.Nonce++
	cpy.Sender = common.HexToAddress("0xdead")
	cpy.ChainID.SetUint64(1)
	cpy.Frames[0].Mode = FrameModeVerify
	cpy.Frames[0].Limits.Execution = 1
	cpy.Frames[0].Limits.State = 2
	cpy.Frames[0].Value.SetUint64(42)
	cpy.Frames[0].Data[0] = 0xff
	otherTarget := common.HexToAddress("0xbeef")
	cpy.Frames[1].Target = &otherTarget
	cpy.Signatures[0].Signature[0] ^= 0xff
	cpy.Signatures[1].Signer[0] ^= 0xff
	cpy.Signatures[2].Msg[0] ^= 0xff
	cpy.Fees.GasTipCap.SetUint64(999)
	cpy.BlobHashes = append(cpy.BlobHashes, common.Hash{0x01})

	if tx.Nonce != 7 || tx.Frames[0].Mode != FrameModeSender || tx.Frames[0].Value.Uint64() != 1234 ||
		tx.Frames[0].Data[0] != 0x01 || tx.Frames[1].Target != nil ||
		tx.Signatures[0].Signature[0] == cpy.Signatures[0].Signature[0] ||
		tx.Signatures[1].Signer[0] == cpy.Signatures[1].Signer[0] ||
		tx.Signatures[2].Msg[0] == cpy.Signatures[2].Msg[0] ||
		tx.Fees.GasTipCap.Uint64() == 999 || len(tx.BlobHashes) != 0 {
		t.Fatal("copy mutation leaked into the original")
	}
}

func TestFrameTxAccessors(t *testing.T) {
	tx := sampleFrameTx()
	inner := tx.inner.(*FrameTx)

	if tx.Type() != FrameTxType {
		t.Fatal("wrong tx type")
	}
	if got := tx.Nonce(); got != 7 {
		t.Fatalf("nonce: got %d", got)
	}
	if got := tx.ChainId(); got.Uint64() != 20118 {
		t.Fatalf("chain id: got %v", got)
	}
	if tx.To() != nil {
		t.Fatal("To must be nil for frame transactions")
	}
	if got := tx.Value(); got.Uint64() != 1234+99 {
		t.Fatalf("value: got %v, want 1333 (sum of SENDER frame values)", got)
	}
	// Gas = complete EIP-8141 intrinsic cost + sum of frame execution limits.
	// Intrinsic: 12000 + 3*475
	//   + frame data {0x01,0x02} -> 32
	//   + sig1 (ARBITRARY, 2B elided -> 32, verify 100)
	//   + sig2 (signer 0x..0ccccc -> 116, sig floor 1040, verify 2800)
	//   + sig3 (msg 32B -> 512, sig weighted 1040, verify 2800)
	//   + value transfer on frame 1 -> 6000
	//   = 27897; + 350000 execution = 377897.
	if got, want := tx.Gas(), inner.intrinsicGas()+(100000+200000+50000); got != want {
		t.Fatalf("gas: got %d, want %d", got, want)
	}
	if got := inner.intrinsicGas(); got != 27897 {
		t.Fatalf("intrinsic gas: got %d, want 27897", got)
	}
	if got := tx.GasTipCap(); got.Uint64() != 2 {
		t.Fatalf("tip cap: got %v", got)
	}
	if got := tx.GasFeeCap(); got.Uint64() != 100 {
		t.Fatalf("fee cap: got %v", got)
	}
	// effectiveGasPrice follows the EIP-8141 "Fee budget" rule: base_fee +
	// min(tipCap * max_gas, feeCap - required_max_fee) // max_gas. With
	// max_gas = 477897, tipCap = 2, feeCap = 100: the priority aggregate is
	// the fee cap itself (2*477897 > 100), i.e. 0 per gas with no base fee;
	// with base fee 50 the required fee dwarfs the fee cap, leaving no room.
	one := big.NewInt(1)
	// Under the aggregate admission rule this fixture tx is fee-invalid
	// (feeCap 100 < required_max_fee = max_gas × baseFee = 477897): the
	// accessor reports ErrGasFeeCapTooLow instead of a meaningless tip.
	if _, err := tx.EffectiveGasTip(one); err == nil {
		t.Fatal("effective tip: expected ErrGasFeeCapTooLow for feeCap below required_max_fee")
	}
	// With a spec-valid budget (feeCap = required + tipCap*max_gas) the
	// effective tip is the full tipCap.
	valid := sampleFrameTx()
	vinner := *valid.inner.(*FrameTx)
	vfees := vinner.Fees
	vfees.GasFeeCap = uint256.MustFromBig(new(big.Int).Add(
		new(big.Int).Mul(new(big.Int).SetUint64(vinner.MaxGas()), one),
		new(big.Int).Mul(new(big.Int).SetUint64(vinner.MaxGas()), vinner.Fees.GasTipCap.ToBig()),
	))
	vinner.Fees = vfees
	vtx := NewTx(&vinner)
	if got, err := vtx.EffectiveGasTip(one); err != nil || got.Uint64() != 2 {
		t.Fatalf("effective tip with valid budget: got %v, err %v, want 2", got, err)
	}
	if got := inner.effectiveGasPrice(new(big.Int), nil); got.Sign() != 0 {
		t.Fatalf("effectiveGasPrice without base fee: got %v, want 0 (fee cap 100 spread over maxGas)", got)
	}
	if got := inner.effectiveGasPrice(new(big.Int), big.NewInt(50)); got.Uint64() != 50 {
		t.Fatalf("effectiveGasPrice with base fee: got %v, want 50 (no tip room)", got)
	}
}

// TestFrameTxTruncatedPayload ensures garbage and truncated inputs are
// rejected, and that existing transaction types still decode (regression).
func TestFrameTxTruncatedAndRegression(t *testing.T) {
	valid, err := sampleFrameTx().MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, len(valid) / 2, len(valid) - 1} {
		var tx Transaction
		if err := tx.UnmarshalBinary(valid[:n]); err == nil {
			t.Fatalf("expected error for truncated payload (%d bytes)", n)
		}
	}
	var tx Transaction
	if err := tx.UnmarshalBinary([]byte{FrameTxType}); err == nil {
		t.Fatal("expected error for bare type byte")
	}
	// Regression: a setcode tx still decodes to its own type.
	sc := NewTx(&SetCodeTx{
		ChainID:   uint256.NewInt(1),
		Nonce:     1,
		GasTipCap: uint256.NewInt(1),
		GasFeeCap: uint256.NewInt(1),
		Gas:       21000,
		To:        common.HexToAddress("0x01"),
		Value:     uint256.NewInt(0),
		V:         uint256.NewInt(0),
		R:         uint256.NewInt(1),
		S:         uint256.NewInt(1),
	})
	bin, err := sc.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var dec Transaction
	if err := dec.UnmarshalBinary(bin); err != nil {
		t.Fatalf("setcode regression decode failed: %v", err)
	}
	if dec.Type() != SetCodeTxType {
		t.Fatalf("setcode regression: got type %d", dec.Type())
	}
}

// TestFrameTxValueTransferCost verifies the EIP-8141 "Gas Accounting"
// value_cost: 6000 (params.TxValueCost2780 + params.TransferLogCost2780)
// for every frame carrying a non-zero value to a target that is present and
// differs from the sender; zero value, self-target, or a nil target charges
// nothing.
func TestFrameTxValueTransferCost(t *testing.T) {
	if params.TxValueCost2780+params.TransferLogCost2780 != 6000 {
		t.Fatalf("value transfer constants sum = %d, want 6000", params.TxValueCost2780+params.TransferLogCost2780)
	}
	other := common.HexToAddress("0x00000000000000000000000000000000deadd00d")
	sender := common.HexToAddress("0x00000000000000000000000000000000beefbeef")
	frameNoValue := Frame{Mode: FrameModeSender, Limits: FrameLimits{Execution: 100_000, State: 0}}
	frameValue := Frame{Mode: FrameModeSender, Target: &other, Limits: FrameLimits{Execution: 100_000, State: 0}, Value: uint256.NewInt(1)}
	frameSelf := Frame{Mode: FrameModeSender, Target: &sender, Limits: FrameLimits{Execution: 100_000, State: 0}, Value: uint256.NewInt(1)}
	frameNilTarget := Frame{Mode: FrameModeSender, Limits: FrameLimits{Execution: 100_000, State: 0}, Value: uint256.NewInt(1)}
	base := (&FrameTx{Sender: sender, Frames: []Frame{frameNoValue}}).intrinsicGas()
	tests := []struct {
		name  string
		frame Frame
		want  uint64
	}{
		{"ValueToOther", frameValue, 6000},
		{"NoValue", frameNoValue, 0},
		{"ValueSelfTarget", frameSelf, 0},
		{"ValueNilTarget", frameNilTarget, 0},
	}
	for _, tc := range tests {
		got := (&FrameTx{Sender: sender, Frames: []Frame{tc.frame}}).intrinsicGas()
		if delta := got - base; delta != tc.want {
			t.Fatalf("%s: value cost = %d, want %d", tc.name, delta, tc.want)
		}
	}
	// Two transferring frames accumulate (compared against an equal-count
	// valueless baseline so the per-frame cost cancels).
	base2 := (&FrameTx{Sender: sender, Frames: []Frame{frameNoValue, frameNoValue}}).intrinsicGas()
	two := (&FrameTx{Sender: sender, Frames: []Frame{frameValue, frameValue}}).intrinsicGas()
	if delta := two - base2; delta != 12_000 {
		t.Fatalf("two frames: value cost = %d, want 12000", delta)
	}
}
