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
	"math"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

// gasTestSender is the declared sender used by the gas tests.
var gasTestSender = common.HexToAddress("0x00000000000000000000000000000000000bbbbb")

// gasTestTarget is a target distinct from the sender.
var gasTestTarget = common.HexToAddress("0x00000000000000000000000000000000000aaaaa")

// makeGasTx builds a minimal frame transaction with one caller-supplied
// signature list, so each test controls exactly one gas component.
func makeGasTx(frames []Frame, sigs []FrameSignature) *Transaction {
	return NewFrameTx(
		uint256.NewInt(20118), // chainID
		0,
		gasTestSender,
		frames,
		sigs,
		FrameFees{
			GasTipCap:  uint256.NewInt(1),
			GasFeeCap:  uint256.NewInt(100),
			BlobFeeCap: uint256.NewInt(0),
		},
		nil,
	)
}

func intrinsicOf(t *testing.T, tx *Transaction) uint64 {
	t.Helper()
	return tx.inner.(*FrameTx).intrinsicGas()
}

func floorOf(t *testing.T, tx *Transaction) uint64 {
	t.Helper()
	return tx.inner.(*FrameTx).CalldataFloorGas()
}

// TestFrameGasBaseCost covers the constant part: 12000 + 475 per frame.
func TestFrameGasBaseCost(t *testing.T) {
	one := makeGasTx([]Frame{{Mode: FrameModeDefault, Limits: FrameLimits{Execution: 1000}}}, nil)
	if got := intrinsicOf(t, one); got != 12000+475 {
		t.Fatalf("intrinsic gas for 1 empty frame: got %d, want %d", got, 12000+475)
	}
	frames := make([]Frame, 3)
	for i := range frames {
		frames[i] = Frame{Mode: FrameModeDefault, Limits: FrameLimits{Execution: 1000}}
	}
	three := makeGasTx(frames, nil)
	if got := intrinsicOf(t, three); got != 12000+3*475 {
		t.Fatalf("intrinsic gas for 3 empty frames: got %d, want %d", got, 12000+3*475)
	}
	if got := floorOf(t, one); got != 12000+475 {
		t.Fatalf("calldata floor for 1 empty frame: got %d, want %d", got, 12000+475)
	}
}

// TestFrameGasCalldata covers frame_data_cost (standard weighted pricing).
func TestFrameGasCalldata(t *testing.T) {
	// data {0x00, 0xff, 0x00}: tokens_in = 1 + 4 + 1 = 6 -> 4 * 6 = 24
	frame := Frame{Mode: FrameModeDefault, Limits: FrameLimits{Execution: 1000}, Data: []byte{0x00, 0xff, 0x00}}
	tx := makeGasTx([]Frame{frame}, nil)
	want := uint64(12000 + 475 + 24)
	if got := intrinsicOf(t, tx); got != want {
		t.Fatalf("intrinsic gas with mixed calldata: got %d, want %d", got, want)
	}
	// floor: 4 tokens/byte * 3 bytes = 12 tokens -> 16 * 12 = 192
	if got := floorOf(t, tx); got != 12000+475+192 {
		t.Fatalf("calldata floor with mixed calldata: got %d, want %d", got, 12000+475+192)
	}
}

// TestFrameGasSignatureSchemes covers signature_verification_cost per scheme.
func TestFrameGasSignatureSchemes(t *testing.T) {
	frame := Frame{Mode: FrameModeDefault, Limits: FrameLimits{Execution: 1000}}
	tests := []struct {
		scheme uint8
		want   uint64
	}{
		{FrameSigSchemeArbitrary, 100},
		{FrameSigSchemeSecp256k1, 2800},
		{FrameSigSchemeP256, 6700},
	}
	for _, tt := range tests {
		sigs := []FrameSignature{{Scheme: tt.scheme}}
		tx := makeGasTx([]Frame{frame}, sigs)
		want := uint64(12000+475) + tt.want
		if got := intrinsicOf(t, tx); got != want {
			t.Fatalf("scheme %d: got %d, want %d", tt.scheme, got, want)
		}
	}
}

// TestFrameGasSignatureData covers signature_data_cost: signer/msg calldata
// cost and the signature-bytes pricing (floor when msg is empty, weighted
// otherwise).
func TestFrameGasSignatureData(t *testing.T) {
	frame := Frame{Mode: FrameModeDefault, Limits: FrameLimits{Execution: 1000}}

	// ARBITRARY, empty msg, 2-byte signature {0x00, 0xff}:
	// sigBytesTokens = floor_tokens = 4 * 2 = 8 -> 4 * 8 = 32; verify = 100.
	sigs := []FrameSignature{{Scheme: FrameSigSchemeArbitrary, Signature: []byte{0x00, 0xff}}}
	tx := makeGasTx([]Frame{frame}, sigs)
	want := uint64(12000+475) + 32 + 100
	if got := intrinsicOf(t, tx); got != want {
		t.Fatalf("empty-msg signature bytes: got %d, want %d", got, want)
	}
	// floor counts the 2 signature bytes: 4 * 2 = 8 tokens -> 16 * 8 = 128.
	if got := floorOf(t, tx); got != 12000+475+100+128 {
		t.Fatalf("floor with elided signature bytes: got %d, want %d", got, 12000+475+100+128)
	}

	// Explicit 32-byte msg of non-zeros, same 2-byte signature:
	// calldata_cost(msg) = 4 * (32 * 4) = 512; sigBytesTokens =
	// tokens_in({0x00, 0xff}) = 1 + 4 = 5 -> 4 * 5 = 20; verify = 100.
	sigs = []FrameSignature{{Scheme: FrameSigSchemeArbitrary, Msg: bytes.Repeat([]byte{0x01}, 32), Signature: []byte{0x00, 0xff}}}
	tx = makeGasTx([]Frame{frame}, sigs)
	want = uint64(12000+475) + 512 + 20 + 100
	if got := intrinsicOf(t, tx); got != want {
		t.Fatalf("explicit-msg signature bytes: got %d, want %d", got, want)
	}

	// 20-byte explicit signer adds calldata_cost(signer) = 4 * (20 * 4) = 320.
	// The signer bytes are all non-zero so the token count is exact.
	sigs = []FrameSignature{{
		Scheme:    FrameSigSchemeSecp256k1,
		Signer:    bytes.Repeat([]byte{0x42}, 20),
		Msg:       bytes.Repeat([]byte{0x01}, 32),
		Signature: bytes.Repeat([]byte{0x02}, 65),
	}}
	tx = makeGasTx([]Frame{frame}, sigs)
	// signer: 320; msg: 512; signature: tokens_in(65 * 0x02) = 65 * 4 = 260 -> 4 * 260 = 1040; verify: 2800
	want = uint64(12000+475) + 320 + 512 + 1040 + 2800
	if got := intrinsicOf(t, tx); got != want {
		t.Fatalf("full signature entry: got %d, want %d", got, want)
	}
	// floor: signer 80 + msg 128 + sig 260 = 468 tokens -> 16 * 468 = 7488
	if got := floorOf(t, tx); got != 12000+475+2800+7488 {
		t.Fatalf("floor with full signature entry: got %d, want %d", got, 12000+475+2800+7488)
	}
}

// TestFrameGasValueTransfer covers value_transfer_cost (TX_VALUE_COST = 6000).
func TestFrameGasValueTransfer(t *testing.T) {
	tests := []struct {
		name  string
		frame Frame
		want  uint64
	}{
		{"value to distinct target", Frame{Mode: FrameModeSender, Limits: FrameLimits{Execution: 1000}, Value: uint256.NewInt(5), Target: &gasTestTarget}, 6000},
		{"value to sender itself", Frame{Mode: FrameModeSender, Limits: FrameLimits{Execution: 1000}, Value: uint256.NewInt(5), Target: &gasTestSender}, 0},
		{"value with nil target", Frame{Mode: FrameModeSender, Limits: FrameLimits{Execution: 1000}, Value: uint256.NewInt(5)}, 0},
		{"zero value to distinct target", Frame{Mode: FrameModeSender, Limits: FrameLimits{Execution: 1000}, Value: uint256.NewInt(0), Target: &gasTestTarget}, 0},
		{"zero value nil target", Frame{Mode: FrameModeSender, Limits: FrameLimits{Execution: 1000}, Value: uint256.NewInt(0)}, 0},
	}
	for _, tt := range tests {
		tx := makeGasTx([]Frame{tt.frame}, nil)
		if got := intrinsicOf(t, tx); got != 12000+475+tt.want {
			t.Fatalf("%s: got %d, want %d", tt.name, got, 12000+475+tt.want)
		}
	}
	// Multiple qualifying frames each pay the cost.
	frames := []Frame{
		{Mode: FrameModeSender, Limits: FrameLimits{Execution: 1000}, Value: uint256.NewInt(1), Target: &gasTestTarget},
		{Mode: FrameModeSender, Limits: FrameLimits{Execution: 1000}, Value: uint256.NewInt(2), Target: &gasTestTarget},
	}
	tx := makeGasTx(frames, nil)
	if got := intrinsicOf(t, tx); got != 12000+2*475+2*6000 {
		t.Fatalf("two value transfers: got %d, want %d", got, 12000+2*475+2*6000)
	}
}

// TestFrameGasCombined stacks every component on one transaction and checks
// intrinsic gas, calldata floor and max_gas.
func TestFrameGasCombined(t *testing.T) {
	frames := []Frame{
		// data {0x01, 0x00}: tokens = 4 + 1 = 5 -> 20; value transfer -> 6000
		{Mode: FrameModeSender, Limits: FrameLimits{Execution: 100000, State: 5000}, Value: uint256.NewInt(7), Target: &gasTestTarget, Data: []byte{0x01, 0x00}},
		// no data, no value
		{Mode: FrameModeDefault, Limits: FrameLimits{Execution: 200000, State: 1000}},
	}
	sigs := []FrameSignature{
		// empty msg, 65 nonzero bytes: floor tokens 260 -> 4 * 260 = 1040; verify 2800
		{Scheme: FrameSigSchemeSecp256k1, Signature: bytes.Repeat([]byte{0x02}, 65)},
		// explicit msg of 32 zeros: calldata_cost(msg) = 4 * 32 = 128; sig bytes 128 nonzero:
		// tokens = 512 -> 2048; verify 6700
		{Scheme: FrameSigSchemeP256, Msg: make([]byte, 32), Signature: bytes.Repeat([]byte{0x03}, 128)},
	}
	tx := makeGasTx(frames, sigs)
	// intrinsic = 12000 + 2*475 + 20 (data) + 1040 + 2800 (sig1) + 128 + 2048 + 6700 (sig2) + 6000 (value)
	want := uint64(12000 + 950 + 20 + 1040 + 2800 + 128 + 2048 + 6700 + 6000)
	if got := intrinsicOf(t, tx); got != want {
		t.Fatalf("combined intrinsic: got %d, want %d", got, want)
	}
	// floor = 12000 + 950 + (2800+6700) + 6000 + 16 * (floor tokens)
	// frame data: 2 bytes -> 8; sig1: 65 -> 260; sig2: msg 128 + sig 512 = 640
	// tokens = 8 + 260 + 640 = 908 -> 16 * 908 = 14528
	wantFloor := uint64(12000 + 950 + 9500 + 6000 + 14528)
	if got := floorOf(t, tx); got != wantFloor {
		t.Fatalf("combined floor: got %d, want %d", got, wantFloor)
	}
	// standard = intrinsic + exec + state = 31558 + 300000 + 6000
	standard := want + 300000 + 6000
	// floor + state = wantFloor + 6000; standard dominates
	if got := tx.inner.(*FrameTx).MaxGas(); got != standard {
		t.Fatalf("max_gas: got %d, want %d", got, standard)
	}
}

// TestFrameGasValidateLimit covers the EIP-7825 constraint:
// max(intrinsic + total execution, calldata_floor_gas) <= TX_MAX_GAS_LIMIT.
func TestFrameGasValidateLimit(t *testing.T) {
	// Well under the cap.
	small := makeGasTx([]Frame{{Mode: FrameModeDefault, Limits: FrameLimits{Execution: 1_000_000, State: 100_000}}}, nil)
	if err := ValidateFrameGasLimits(small); err != nil {
		t.Fatalf("small tx rejected: %v", err)
	}
	// Exactly at the cap passes (constraint is <=).
	intr := intrinsicOf(t, small)
	atCap := makeGasTx([]Frame{{Mode: FrameModeDefault, Limits: FrameLimits{Execution: params.MaxTxGas - intr}}}, nil)
	if err := ValidateFrameGasLimits(atCap); err != nil {
		t.Fatalf("tx exactly at cap rejected: %v", err)
	}
	// One gas over the cap on the execution side fails.
	overCap := makeGasTx([]Frame{{Mode: FrameModeDefault, Limits: FrameLimits{Execution: params.MaxTxGas - intr + 1}}}, nil)
	if err := ValidateFrameGasLimits(overCap); err == nil {
		t.Fatalf("tx over cap on execution side accepted")
	}
	// Floor over the cap fails even when intrinsic + execution is small:
	// ~262145 zero bytes of frame data push the floor past 16.7M while the
	// standard side stays tiny.
	bigData := make([]byte, 262145)
	floorOver := makeGasTx([]Frame{{Mode: FrameModeDefault, Limits: FrameLimits{Execution: 1000}, Data: bigData}}, nil)
	if floorOf(t, floorOver) <= params.MaxTxGas {
		t.Fatalf("test premise broken: floor %d not above cap", floorOf(t, floorOver))
	}
	if err := ValidateFrameGasLimits(floorOver); err == nil {
		t.Fatalf("tx with floor over cap accepted")
	}
}

// TestFrameGasOverflow covers saturating arithmetic: components that would
// overflow uint64 must fail the gas-limit check rather than wrap around.
func TestFrameGasOverflow(t *testing.T) {
	// Three frames each declaring ~2^63 execution gas: totalExecutionGas
	// saturates to math.MaxUint64, so intrinsic + execution exceeds the cap.
	huge := uint64(math.MaxUint64 / 2)
	frames := make([]Frame, 3)
	for i := range frames {
		frames[i] = Frame{Mode: FrameModeDefault, Limits: FrameLimits{Execution: huge}}
	}
	tx := makeGasTx(frames, nil)
	if err := ValidateFrameGasLimits(tx); err == nil {
		t.Fatalf("overflowing execution gas accepted")
	}
	// An unknown signature scheme saturates the intrinsic cost too.
	bad := makeGasTx([]Frame{{Mode: FrameModeDefault, Limits: FrameLimits{Execution: 1000}}}, []FrameSignature{{Scheme: 0x7f}})
	if got := intrinsicOf(t, bad); got != math.MaxUint64 {
		t.Fatalf("unknown scheme: got %d, want math.MaxUint64", got)
	}
	if err := ValidateFrameGasLimits(bad); err == nil {
		t.Fatalf("saturated intrinsic accepted")
	}
}

// TestFrameGasFloorDominatesMaxGas covers the max_gas formula selecting the
// floor + state side.
func TestFrameGasFloorDominatesMaxGas(t *testing.T) {
	// Tiny execution, huge state, and data so the floor exceeds the
	// standard side once state is added.
	frames := []Frame{{Mode: FrameModeDefault, Limits: FrameLimits{Execution: 1000, State: 2_000_000}, Data: bytes.Repeat([]byte{0x00}, 10_000)}}
	tx := makeGasTx(frames, nil)
	standard := intrinsicOf(t, tx) + 1000 + 2_000_000
	floorSide := floorOf(t, tx) + 2_000_000
	if floorSide <= standard {
		t.Fatalf("test premise broken: floor side %d not above standard %d", floorSide, standard)
	}
	if got := tx.inner.(*FrameTx).MaxGas(); got != floorSide {
		t.Fatalf("max_gas: got %d, want floor side %d", got, floorSide)
	}
}

// TestFrameGasAccessorSanity ensures tx.Gas() remains intrinsic + total
// execution gas, the accessor used by generic fee/gas paths until the
// execution milestone defines the final gas-limit semantics.
func TestFrameGasAccessorSanity(t *testing.T) {
	frames := []Frame{
		{Mode: FrameModeDefault, Limits: FrameLimits{Execution: 100000, State: 5000}},
		{Mode: FrameModeDefault, Limits: FrameLimits{Execution: 200000, State: 0}},
	}
	tx := makeGasTx(frames, nil)
	want := intrinsicOf(t, tx) + 300000
	if got := tx.Gas(); got != want {
		t.Fatalf("tx.Gas(): got %d, want %d", got, want)
	}
}
