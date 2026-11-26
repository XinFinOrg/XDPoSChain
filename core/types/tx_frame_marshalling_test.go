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
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/hexutil"
	"github.com/holiman/uint256"
)

// frameTxJSONFixture builds a frame transaction exercising every JSON field:
// targets present and absent, extreme integers, multiple signature schemes,
// and blob fields.
func frameTxJSONFixture() *FrameTx {
	targetA := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	targetB := common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	return &FrameTx{
		ChainID: uint256.NewInt(20118),
		Nonce:   7,
		Sender:  frameTestSender,
		Frames: []Frame{
			{Mode: FrameModeVerify, Limits: FrameLimits{Execution: 21000, State: 1000}, Value: uint256.NewInt(0), Data: []byte{}},
			{Mode: FrameModeDefault, Flags: FrameAtomicBatchFlag, Target: &targetA, Limits: FrameLimits{Execution: math.MaxUint64 - 300000, State: 55555}, Value: uint256.NewInt(0), Data: []byte{0x60, 0x0a, 0x60, 0x00, 0x55}},
			{Mode: FrameModeSender, Target: &targetB, Limits: FrameLimits{Execution: 100000, State: 50000}, Value: new(uint256.Int).Add(uint256.NewInt(99), new(uint256.Int).Lsh(uint256.NewInt(1), 255)), Data: bytes.Repeat([]byte{0xab}, 300)},
		},
		Signatures: []FrameSignature{
			{Scheme: FrameSigSchemeArbitrary, Signature: []byte{0x01, 0x02, 0x03}},
			{Scheme: FrameSigSchemeSecp256k1, Signer: frameTestSender.Bytes(), Signature: bytes.Repeat([]byte{0x11}, 65)},
			{Scheme: FrameSigSchemeP256, Msg: common.BytesToHash([]byte("explicit digest")).Bytes(), Signature: bytes.Repeat([]byte{0x22}, 128)},
		},
		Fees: FrameFees{
			GasTipCap:  uint256.NewInt(2),
			GasFeeCap:  new(uint256.Int).Lsh(uint256.NewInt(1), 200),
			BlobFeeCap: uint256.NewInt(123456789),
		},
		BlobHashes: []common.Hash{
			common.HexToHash("0x01" + strings.Repeat("aa", 30) + "a0"),
			common.HexToHash("0x01" + strings.Repeat("bb", 30) + "b1"),
		},
	}
}

func TestFrameTxJSONRoundTrip(t *testing.T) {
	tx := NewTx(frameTxJSONFixture())

	out, err := json.Marshal(tx)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	// Spot-check the public JSON shape: camelCase keys, hex quantities,
	// type 0x6, and all frame/signature sub-fields.
	for _, want := range []string{
		`"type":"0x6"`, `"chainId":"0x4e96"`, `"nonce":"0x7"`,
		`"sender":"` + strings.ToLower(frameTestSender.Hex()) + `"`,
		`"frames"`, `"mode":"0x1"`, `"flags":"0x4"`, `"target":"0xaaaa`,
		`"limits"`, fmt.Sprintf(`"execution":"0x%x"`, uint64(math.MaxUint64-300000)), `"state":"0xd903"`,
		`"value":"0x8000000000000000000000000000000000000000000000000000000000000063"`,
		`"signatures"`, `"scheme":"0x2"`, `"signer":"0x` + strings.ToLower(frameTestSender.Hex())[2:] + `"`,
		`"msg":"0x`, `"signature":"0x`,
		`"maxPriorityFeePerGas":"0x2"`, `"maxFeePerBlobGas":"0x75bcd15"`,
		`"blobVersionedHashes"`,
	} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("marshalled JSON missing %s\n%s", want, out)
		}
	}

	var decoded Transaction
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if decoded.Hash() != tx.Hash() {
		t.Fatalf("hash mismatch after round trip: have %s, want %s", decoded.Hash(), tx.Hash())
	}
	// A second marshalling must reproduce identical bytes.
	out2, err := json.Marshal(&decoded)
	if err != nil {
		t.Fatalf("re-marshal failed: %v", err)
	}
	if !bytes.Equal(out, out2) {
		t.Fatalf("re-marshal differs:\n%s\n%s", out, out2)
	}
}

func TestFrameTxJSONFieldPreservation(t *testing.T) {
	inner := frameTxJSONFixture()
	tx := NewTx(inner)
	out, err := json.Marshal(tx)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var decoded Transaction
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	got, ok := decoded.inner.(*FrameTx)
	if !ok {
		t.Fatalf("decoded inner is %T, want *FrameTx", decoded.inner)
	}
	if got.ChainID.Cmp(inner.ChainID) != 0 || got.Nonce != inner.Nonce || got.Sender != inner.Sender {
		t.Fatal("scalar fields not preserved")
	}
	if len(got.Frames) != len(inner.Frames) {
		t.Fatalf("frame count mismatch: have %d, want %d", len(got.Frames), len(inner.Frames))
	}
	for i, want := range inner.Frames {
		have := got.Frames[i]
		if have.Mode != want.Mode || have.Flags != want.Flags {
			t.Fatalf("frame %d: mode/flags mismatch", i)
		}
		if (want.Target == nil) != (have.Target == nil) || (want.Target != nil && *want.Target != *have.Target) {
			t.Fatalf("frame %d: target mismatch", i)
		}
		if have.Limits != want.Limits {
			t.Fatalf("frame %d: limits mismatch: have %+v, want %+v", i, have.Limits, want.Limits)
		}
		if have.Value.Cmp(want.Value) != 0 {
			t.Fatalf("frame %d: value mismatch", i)
		}
		if !bytes.Equal(have.Data, want.Data) {
			t.Fatalf("frame %d: data mismatch", i)
		}
	}
	if len(got.Signatures) != len(inner.Signatures) {
		t.Fatalf("signature count mismatch: have %d, want %d", len(got.Signatures), len(inner.Signatures))
	}
	for i, want := range inner.Signatures {
		have := got.Signatures[i]
		if have.Scheme != want.Scheme || !bytes.Equal(have.Signer, want.Signer) || !bytes.Equal(have.Msg, want.Msg) || !bytes.Equal(have.Signature, want.Signature) {
			t.Fatalf("signature %d not preserved", i)
		}
	}
	if got.Fees.GasTipCap.Cmp(inner.Fees.GasTipCap) != 0 || got.Fees.GasFeeCap.Cmp(inner.Fees.GasFeeCap) != 0 {
		t.Fatal("fee caps not preserved")
	}
	if got.Fees.BlobFeeCap == nil || got.Fees.BlobFeeCap.Cmp(inner.Fees.BlobFeeCap) != 0 {
		t.Fatal("blob fee cap not preserved")
	}
	if len(got.BlobHashes) != len(inner.BlobHashes) {
		t.Fatal("blob hashes not preserved")
	}
}

func TestFrameTxJSONMinimal(t *testing.T) {
	// No targets, empty data, no signatures, no blobs, nil blob fee cap.
	inner := &FrameTx{
		ChainID:    uint256.NewInt(1),
		Nonce:      0,
		Sender:     frameTestSender,
		Frames:     []Frame{{Mode: FrameModeDefault, Limits: FrameLimits{Execution: 53000, State: 10000}, Value: uint256.NewInt(0), Data: []byte{}}},
		Signatures: nil,
		Fees:       FrameFees{GasTipCap: uint256.NewInt(1), GasFeeCap: uint256.NewInt(100)},
	}
	tx := NewTx(inner)
	out, err := json.Marshal(tx)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	// Empty optional content must be absent or empty, never garbage.
	for _, unwanted := range []string{`"target"`, `"blobVersionedHashes"`, `"maxFeePerBlobGas"`, `"signatures"`} {
		if bytes.Contains(out, []byte(unwanted)) {
			t.Errorf("minimal JSON unexpectedly contains %s\n%s", unwanted, out)
		}
	}
	var decoded Transaction
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	got := decoded.inner.(*FrameTx)
	if len(got.Signatures) != 0 || got.BlobHashes != nil || got.Fees.BlobFeeCap != nil {
		t.Fatal("optional fields did not round-trip as empty")
	}
	if decoded.Hash() != tx.Hash() {
		t.Fatal("hash mismatch")
	}
}

func TestFrameTxJSONInputAlias(t *testing.T) {
	// "input" is accepted as an alias for the frame calldata field.
	raw := `{
		"type":"0x6","chainId":"0x1","nonce":"0x0",
		"sender":"0x627306090abab3a6e1400e9345bc60c78a8bef57",
		"frames":[{"mode":"0x0","flags":"0x0","limits":{"execution":"0x100","state":"0x0"},"value":"0x0","input":"0x1234"}],
		"maxPriorityFeePerGas":"0x1","maxFeePerGas":"0x64"
	}`
	var decoded Transaction
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("unmarshal with input alias failed: %v", err)
	}
	got := decoded.inner.(*FrameTx)
	if !bytes.Equal(got.Frames[0].Data, []byte{0x12, 0x34}) {
		t.Fatalf("input alias not applied: %x", got.Frames[0].Data)
	}
}

func TestFrameTxJSONInvalid(t *testing.T) {
	valid := func() map[string]interface{} {
		return map[string]interface{}{
			"type":                 "0x6",
			"chainId":              "0x1",
			"nonce":                "0x0",
			"sender":               "0x627306090abab3a6e1400e9345bc60c78a8bef57",
			"frames":               []interface{}{map[string]interface{}{"mode": "0x2", "flags": "0x0", "limits": map[string]interface{}{"execution": "0x100", "state": "0x0"}, "value": "0x0", "data": "0x"}},
			"maxPriorityFeePerGas": "0x1",
			"maxFeePerGas":         "0x64",
			"maxFeePerBlobGas":     "0x0",
			"blobVersionedHashes":  nil,
			"signatures":           []interface{}{},
		}
	}
	cases := []struct {
		name   string
		mutate func(m map[string]interface{})
	}{
		{"missing type", func(m map[string]interface{}) { delete(m, "type") }},
		{"missing chainId", func(m map[string]interface{}) { delete(m, "chainId") }},
		{"missing nonce", func(m map[string]interface{}) { delete(m, "nonce") }},
		{"missing sender", func(m map[string]interface{}) { delete(m, "sender") }},
		{"missing frames", func(m map[string]interface{}) { delete(m, "frames") }},
		{"empty frames", func(m map[string]interface{}) { m["frames"] = []interface{}{} }},
		{"missing maxFeePerGas", func(m map[string]interface{}) { delete(m, "maxFeePerGas") }},
		{"missing maxPriorityFeePerGas", func(m map[string]interface{}) { delete(m, "maxPriorityFeePerGas") }},
		{"too many frames", func(m map[string]interface{}) {
			frames := []interface{}{}
			for i := 0; i < FrameMaxFrames+1; i++ {
				frames = append(frames, map[string]interface{}{"mode": "0x0", "flags": "0x0", "limits": map[string]interface{}{"execution": "0x1", "state": "0x0"}, "value": "0x0", "data": "0x"})
			}
			m["frames"] = frames
		}},
		{"frame mode overflow", func(m map[string]interface{}) {
			m["frames"] = []interface{}{map[string]interface{}{"mode": "0x100", "flags": "0x0", "limits": map[string]interface{}{"execution": "0x1", "state": "0x0"}, "value": "0x0", "data": "0x"}}
		}},
		{"invalid frame mode", func(m map[string]interface{}) {
			m["frames"] = []interface{}{map[string]interface{}{"mode": "0x3", "flags": "0x0", "limits": map[string]interface{}{"execution": "0x1", "state": "0x0"}, "value": "0x0", "data": "0x"}}
		}},
		{"reserved frame flags", func(m map[string]interface{}) {
			m["frames"] = []interface{}{map[string]interface{}{"mode": "0x0", "flags": "0x8", "limits": map[string]interface{}{"execution": "0x1", "state": "0x0"}, "value": "0x0", "data": "0x"}}
		}},
		{"value on non-sender frame", func(m map[string]interface{}) {
			m["frames"] = []interface{}{map[string]interface{}{"mode": "0x1", "flags": "0x0", "limits": map[string]interface{}{"execution": "0x1", "state": "0x0"}, "value": "0x1", "data": "0x"}}
		}},
		{"frame value overflow", func(m map[string]interface{}) {
			m["frames"] = []interface{}{map[string]interface{}{"mode": "0x2", "flags": "0x0", "limits": map[string]interface{}{"execution": "0x1", "state": "0x0"}, "value": "0x1" + strings.Repeat("0", 64), "data": "0x"}}
		}},
		{"arbitrary signature with signer", func(m map[string]interface{}) {
			m["signatures"] = []interface{}{map[string]interface{}{"scheme": "0x0", "signer": "0x627306090abab3a6e1400e9345bc60c78a8bef57", "msg": "0x", "signature": "0x01"}}
		}},
		{"reserved signature scheme", func(m map[string]interface{}) {
			m["signatures"] = []interface{}{map[string]interface{}{"scheme": "0x3", "signer": "0x", "msg": "0x", "signature": "0x01"}}
		}},
		{"msg wrong length", func(m map[string]interface{}) {
			m["signatures"] = []interface{}{map[string]interface{}{"scheme": "0x1", "signer": "0x", "msg": "0x0102", "signature": "0x" + strings.Repeat("11", 65)}}
		}},
		{"msg zero digest", func(m map[string]interface{}) {
			m["signatures"] = []interface{}{map[string]interface{}{"scheme": "0x1", "signer": "0x", "msg": "0x" + strings.Repeat("00", 32), "signature": "0x" + strings.Repeat("11", 65)}}
		}},
		{"bad blob hash version", func(m map[string]interface{}) {
			m["blobVersionedHashes"] = []interface{}{"0x02" + strings.Repeat("aa", 31)}
		}},
		{"blob fee without blobs", func(m map[string]interface{}) {
			m["maxFeePerBlobGas"] = "0x5"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := valid()
			tc.mutate(m)
			raw, err := json.Marshal(m)
			if err != nil {
				t.Fatalf("test setup: %v", err)
			}
			var decoded Transaction
			if err := json.Unmarshal(raw, &decoded); err == nil {
				t.Fatalf("invalid payload accepted: %s", raw)
			}
		})
	}

	t.Run("base payload is valid", func(t *testing.T) {
		raw, err := json.Marshal(valid())
		if err != nil {
			t.Fatalf("test setup: %v", err)
		}
		var decoded Transaction
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("base payload rejected: %v", err)
		}
	})

	t.Run("malformed hex rejected", func(t *testing.T) {
		raw := strings.Replace(`{"type":"0x6","chainId":"0x1","nonce":"0x0","sender":"0x627306090abab3a6e1400e9345bc60c78a8bef57","frames":[{"mode":"0x2","flags":"0x0","limits":{"execution":"0x100","state":"0x0"},"value":"0x0","data":"0xzz"}],"maxPriorityFeePerGas":"0x1","maxFeePerGas":"0x64"}`, "0xzz", "0xzz", 1)
		var decoded Transaction
		if err := json.Unmarshal([]byte(raw), &decoded); err == nil {
			t.Fatal("malformed hex accepted")
		}
	})
}

// TestFrameTxJSONSignatureIntegrity proves the JSON codec preserves
// signature bytes bit-exactly, so protocol validation still passes after a
// JSON round trip.
func TestFrameTxJSONSignatureIntegrity(t *testing.T) {
	inner := frameTxForSigning(nil)
	inner.Signatures = []FrameSignature{{Scheme: FrameSigSchemeSecp256k1}}
	digest := inner.computeSigHash()
	inner.Signatures[0].Signature = signK1ForFrame(t, frameK1Key, digest)

	out, err := json.Marshal(NewTx(inner))
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var decoded Transaction
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if err := ValidateFrameSignatures(&decoded); err != nil {
		t.Fatalf("signature validation failed after JSON round trip: %v", err)
	}
}

// TestFrameTxJSONGasDerivation checks the derived gas/value fields exposed
// over JSON.
func TestFrameTxJSONGasDerivation(t *testing.T) {
	inner := frameTxJSONFixture()
	tx := NewTx(inner)
	var enc struct {
		Gas   hexutil.Uint64 `json:"gas"`
		Value *hexutil.Big   `json:"value"`
	}
	out, err := json.Marshal(tx)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if err := json.Unmarshal(out, &enc); err != nil {
		t.Fatalf("re-decode failed: %v", err)
	}
	if uint64(enc.Gas) != tx.Gas() {
		t.Fatalf("json gas %d != derived gas %d", uint64(enc.Gas), tx.Gas())
	}
	want := new(big.Int).Add(big.NewInt(99), new(big.Int).Lsh(big.NewInt(1), 255))
	if (*big.Int)(enc.Value).Cmp(want) != 0 {
		t.Fatalf("json value %v != sum of sender frame values %v", (*big.Int)(enc.Value), want)
	}
}
