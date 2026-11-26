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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/holiman/uint256"
)

// Test fixture keys (deterministic, generated from fixed seeds — these are
// test keys only, never real private keys).

// frameK1Key is a fixed secp256k1 test key.
var frameK1Key, _ = crypto.HexToECDSA("c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3")

// frameK1KeyB is a second fixed secp256k1 test key, used to produce
// signer-mismatch cases. Derived from a fixed seed so no randomness or real
// key material is involved.
var frameK1KeyB = func() *ecdsa.PrivateKey {
	for i := byte(0); ; i++ {
		if key, err := crypto.ToECDSA(crypto.Keccak256([]byte("frame-test-k1-key-b"), []byte{i})); err == nil {
			return key
		}
	}
}()

// frameP256Key is a fixed P256 test key: D = sha256("frame-test-p256-key") mod N.
var frameP256Key = func() *ecdsa.PrivateKey {
	seed := crypto.Keccak256([]byte("frame-test-p256-key"))
	d := new(big.Int).SetBytes(seed)
	n := elliptic.P256().Params().N
	d.Mod(d, n)
	if d.Sign() == 0 {
		d.SetInt64(1)
	}
	x, y := elliptic.P256().ScalarBaseMult(d.Bytes())
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}
}()

// frameTestSender is the frame-tx sender used across the validation tests.
var frameTestSender = crypto.PubkeyToAddress(frameK1Key.PublicKey)

// signK1ForFrame signs digest with the repository secp256k1 signer and
// converts the produced [R || S || V] layout into the EIP-8141 v || r || s
// layout.
func signK1ForFrame(t *testing.T, key *ecdsa.PrivateKey, digest common.Hash) []byte {
	t.Helper()
	sig, err := crypto.Sign(digest.Bytes(), key)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	out := make([]byte, frameSecp256k1SigLen)
	out[0] = sig[64] // V
	copy(out[1:33], sig[0:32])
	copy(out[33:65], sig[32:64])
	return out
}

// signP256ForFrame produces a deterministic P256 signature entry payload of
// the form r || s || qx || qy.
func signP256ForFrame(t *testing.T, digest common.Hash) (payload []byte, signer common.Address) {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, frameP256Key, digest.Bytes())
	if err != nil {
		t.Fatalf("p256 sign failed: %v", err)
	}
	// Normalize to the canonical low-s form required by the EIP. ECDSA
	// signatures come in (r, s) / (r, N-s) pairs; only the low-s
	// representative is valid in a frame transaction.
	if s.Cmp(secp256R1HalfN) > 0 {
		s = new(big.Int).Sub(secp256R1N, s)
	}
	payload = make([]byte, frameP256SigLen)
	r.FillBytes(payload[0:32])
	s.FillBytes(payload[32:64])
	frameP256Key.X.FillBytes(payload[64:96])
	frameP256Key.Y.FillBytes(payload[96:128])
	// Signer address = keccak256(qx || qy)[12:].
	h := crypto.Keccak256(payload[64:96], payload[96:128])
	return payload, common.BytesToAddress(h[12:])
}

// p256TestAddr returns the address derived from the fixed P256 test key.
func p256TestAddr() common.Address {
	var buf [64]byte
	frameP256Key.X.FillBytes(buf[0:32])
	frameP256Key.Y.FillBytes(buf[32:64])
	h := crypto.Keccak256(buf[:])
	return common.BytesToAddress(h[12:])
}

// frameTxForSigning builds a minimal valid-in-structure frame transaction for
// signature validation tests.
func frameTxForSigning(sigs []FrameSignature) *FrameTx {
	return &FrameTx{
		ChainID: uint256.NewInt(20118),
		Nonce:   3,
		Sender:  frameTestSender,
		Frames: []Frame{
			{Mode: FrameModeSender, Limits: FrameLimits{Execution: 100000, State: 50000}, Value: uint256.NewInt(0), Data: []byte{0x01}},
		},
		Signatures: sigs,
		Fees: FrameFees{
			GasTipCap:  uint256.NewInt(1),
			GasFeeCap:  uint256.NewInt(100),
			BlobFeeCap: uint256.NewInt(0),
		},
	}
}

func TestFrameValidateSecp256k1(t *testing.T) {
	tx := frameTxForSigning(nil)

	// The canonical hash elides empty-msg signature bytes, so it must be
	// computed with the signature entries already present (nil signature
	// bytes encode identically to the elided final form).
	digestOf := func(sigs []FrameSignature) common.Hash {
		tx.Signatures = sigs
		return tx.computeSigHash()
	}
	signEntry := func(signer []byte, key *ecdsa.PrivateKey) FrameSignature {
		digest := digestOf([]FrameSignature{{Scheme: FrameSigSchemeSecp256k1, Signer: signer}})
		return FrameSignature{Scheme: FrameSigSchemeSecp256k1, Signer: signer, Signature: signK1ForFrame(t, key, digest)}
	}

	t.Run("valid omitted signer resolves to sender", func(t *testing.T) {
		tx.Signatures = []FrameSignature{signEntry(nil, frameK1Key)}
		if err := tx.ValidateSignatures(); err != nil {
			t.Fatalf("valid signature rejected: %v", err)
		}
	})

	t.Run("valid explicit signer", func(t *testing.T) {
		tx.Signatures = []FrameSignature{signEntry(frameTestSender.Bytes(), frameK1Key)}
		if err := tx.ValidateSignatures(); err != nil {
			t.Fatalf("valid explicit-signer signature rejected: %v", err)
		}
	})

	t.Run("corrupted signature rejected", func(t *testing.T) {
		entry := signEntry(nil, frameK1Key)
		entry.Signature[40] ^= 0xff // corrupt r
		tx.Signatures = []FrameSignature{entry}
		if err := tx.ValidateSignatures(); err == nil {
			t.Fatal("corrupted signature accepted")
		}
	})

	t.Run("wrong key rejected", func(t *testing.T) {
		tx.Signatures = []FrameSignature{signEntry(nil, frameK1KeyB)}
		if err := tx.ValidateSignatures(); err == nil {
			t.Fatal("signature from wrong key accepted")
		}
	})

	t.Run("explicit signer mismatch rejected", func(t *testing.T) {
		wrong := crypto.PubkeyToAddress(frameK1KeyB.PublicKey)
		tx.Signatures = []FrameSignature{signEntry(wrong.Bytes(), frameK1Key)}
		if err := tx.ValidateSignatures(); err == nil {
			t.Fatal("signer mismatch accepted")
		}
	})

	t.Run("bad lengths rejected", func(t *testing.T) {
		good := signEntry(nil, frameK1Key)
		for _, n := range []int{0, 64, 66, 130} {
			raw := make([]byte, n)
			copy(raw, good.Signature)
			tx.Signatures = []FrameSignature{{Scheme: FrameSigSchemeSecp256k1, Signature: raw}}
			if err := tx.ValidateSignatures(); err == nil {
				t.Fatalf("signature of length %d accepted", n)
			}
		}
	})

	t.Run("invalid recovery ids rejected", func(t *testing.T) {
		good := signEntry(nil, frameK1Key)
		for _, v := range []byte{2, 27, 28, 255} {
			raw := make([]byte, frameSecp256k1SigLen)
			copy(raw, good.Signature)
			raw[0] = v
			tx.Signatures = []FrameSignature{{Scheme: FrameSigSchemeSecp256k1, Signature: raw}}
			if err := tx.ValidateSignatures(); err == nil {
				t.Fatalf("recovery id %d accepted", v)
			}
		}
	})

	t.Run("out of range scalars rejected", func(t *testing.T) {
		good := signEntry(nil, frameK1Key)
		// r = 0
		raw := make([]byte, frameSecp256k1SigLen)
		copy(raw, good.Signature)
		copy(raw[1:33], make([]byte, 32))
		tx.Signatures = []FrameSignature{{Scheme: FrameSigSchemeSecp256k1, Signature: raw}}
		if err := tx.ValidateSignatures(); err == nil {
			t.Fatal("r = 0 accepted")
		}
		// s = 0
		raw = make([]byte, frameSecp256k1SigLen)
		copy(raw, good.Signature)
		copy(raw[33:65], make([]byte, 32))
		tx.Signatures = []FrameSignature{{Scheme: FrameSigSchemeSecp256k1, Signature: raw}}
		if err := tx.ValidateSignatures(); err == nil {
			t.Fatal("s = 0 accepted")
		}
	})
}

func TestFrameValidateExplicitMsg(t *testing.T) {
	// An explicit 32-byte digest must be signed instead of the canonical hash.
	explicit := common.BytesToHash(crypto.Keccak256([]byte("explicit digest")))

	t.Run("valid explicit digest", func(t *testing.T) {
		tx := frameTxForSigning(nil)
		tx.Signatures = []FrameSignature{
			{Scheme: FrameSigSchemeSecp256k1, Msg: explicit.Bytes(), Signature: signK1ForFrame(t, frameK1Key, explicit)},
		}
		if err := tx.ValidateSignatures(); err != nil {
			t.Fatalf("valid explicit-digest signature rejected: %v", err)
		}
	})

	t.Run("canonical hash signature does not satisfy explicit digest", func(t *testing.T) {
		tx := frameTxForSigning(nil)
		digest := tx.computeSigHash()
		tx.Signatures = []FrameSignature{
			{Scheme: FrameSigSchemeSecp256k1, Msg: explicit.Bytes(), Signature: signK1ForFrame(t, frameK1Key, digest)},
		}
		if err := tx.ValidateSignatures(); err == nil {
			t.Fatal("signature over canonical hash accepted for explicit digest")
		}
	})

	t.Run("bad msg lengths rejected", func(t *testing.T) {
		for _, n := range []int{1, 31, 33, 64} {
			tx := frameTxForSigning(nil)
			tx.Signatures = []FrameSignature{
				{Scheme: FrameSigSchemeSecp256k1, Msg: make([]byte, n), Signature: signK1ForFrame(t, frameK1Key, tx.computeSigHash())},
			}
			if err := tx.ValidateSignatures(); err == nil {
				t.Fatalf("msg of length %d accepted", n)
			}
		}
	})

	t.Run("zero explicit digest rejected", func(t *testing.T) {
		tx := frameTxForSigning(nil)
		tx.Signatures = []FrameSignature{
			{Scheme: FrameSigSchemeSecp256k1, Msg: make([]byte, 32), Signature: signK1ForFrame(t, frameK1Key, tx.computeSigHash())},
		}
		if err := tx.ValidateSignatures(); err == nil {
			t.Fatal("all-zero explicit digest accepted")
		}
	})
}

func TestFrameValidateArbitrary(t *testing.T) {
	t.Run("valid structural entry", func(t *testing.T) {
		tx := frameTxForSigning([]FrameSignature{
			{Scheme: FrameSigSchemeArbitrary, Signature: []byte{0x01, 0x02, 0x03}},
			{Scheme: FrameSigSchemeArbitrary, Msg: common.BytesToHash([]byte{0xaa}).Bytes(), Signature: nil},
		})
		if err := tx.ValidateSignatures(); err != nil {
			t.Fatalf("valid ARBITRARY entries rejected: %v", err)
		}
	})

	t.Run("signer metadata rejected", func(t *testing.T) {
		tx := frameTxForSigning([]FrameSignature{
			{Scheme: FrameSigSchemeArbitrary, Signer: frameTestSender.Bytes(), Signature: []byte{0x01}},
		})
		if err := tx.ValidateSignatures(); err == nil {
			t.Fatal("ARBITRARY entry with signer accepted")
		}
	})

	t.Run("signature bytes preserved unverified", func(t *testing.T) {
		raw := []byte{0xde, 0xad, 0xbe, 0xef}
		tx := frameTxForSigning([]FrameSignature{{Scheme: FrameSigSchemeArbitrary, Signature: raw}})
		if err := tx.ValidateSignatures(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(tx.Signatures[0].Signature) != string(raw) {
			t.Fatal("ARBITRARY signature bytes were modified by validation")
		}
	})
}

func TestFrameValidateP256(t *testing.T) {
	tx := frameTxForSigning(nil)

	// signP256Entry mirrors the elision rule: the digest must be taken with
	// the final entry in place, because both the signer field and (for
	// explicit-msg entries) the signature bytes are committed to the hash.
	signP256Entry := func(tx *FrameTx, signer []byte) (FrameSignature, common.Address) {
		tx.Signatures = []FrameSignature{{Scheme: FrameSigSchemeP256, Signer: signer}}
		digest := tx.computeSigHash()
		payload, addr := signP256ForFrame(t, digest)
		return FrameSignature{Scheme: FrameSigSchemeP256, Signer: signer, Signature: payload}, addr
	}

	t.Run("valid explicit signer", func(t *testing.T) {
		entry, _ := signP256Entry(tx, p256TestAddr().Bytes())
		tx.Signatures = []FrameSignature{entry}
		if err := tx.ValidateSignatures(); err != nil {
			t.Fatalf("valid P256 signature rejected: %v", err)
		}
	})

	t.Run("omitted signer resolves to sender", func(t *testing.T) {
		tx2 := frameTxForSigning(nil)
		tx2.Sender = p256TestAddr()
		entry, _ := signP256Entry(tx2, nil)
		tx2.Signatures = []FrameSignature{entry}
		if err := tx2.ValidateSignatures(); err != nil {
			t.Fatalf("valid P256 signature with omitted signer rejected: %v", err)
		}
	})

	t.Run("corrupted signature rejected", func(t *testing.T) {
		entry, _ := signP256Entry(tx, p256TestAddr().Bytes())
		entry.Signature[0] ^= 0xff // corrupt r (signature bytes are elided, digest stays valid)
		tx.Signatures = []FrameSignature{entry}
		if err := tx.ValidateSignatures(); err == nil {
			t.Fatal("corrupted P256 signature accepted")
		}
	})

	t.Run("signer address mismatch rejected", func(t *testing.T) {
		entry, _ := signP256Entry(tx, frameTestSender.Bytes())
		tx.Signatures = []FrameSignature{entry}
		if err := tx.ValidateSignatures(); err == nil {
			t.Fatal("P256 entry with mismatched signer accepted")
		}
	})

	t.Run("off-curve coordinates rejected", func(t *testing.T) {
		entry, _ := signP256Entry(tx, nil)
		// Replace the public key coordinates with the all-zero point, and set
		// the signer to the address that point derives to, so validation
		// reaches the curve/verification check rather than failing on the
		// address comparison.
		for i := 64; i < 128; i++ {
			entry.Signature[i] = 0
		}
		h := crypto.Keccak256(make([]byte, 64))
		entry.Signer = h[12:]
		tx.Signatures = []FrameSignature{entry}
		if err := tx.ValidateSignatures(); err == nil {
			t.Fatal("P256 entry with off-curve point accepted")
		}
	})

	t.Run("bad lengths rejected", func(t *testing.T) {
		addr := p256TestAddr()
		entry, _ := signP256Entry(tx, addr.Bytes())
		for _, n := range []int{0, 96, 127, 129, 256} {
			raw := make([]byte, n)
			copy(raw, entry.Signature)
			tx.Signatures = []FrameSignature{
				{Scheme: FrameSigSchemeP256, Signer: addr.Bytes(), Signature: raw},
			}
			if err := tx.ValidateSignatures(); err == nil {
				t.Fatalf("P256 signature of length %d accepted", n)
			}
		}
	})
}

func TestFrameValidateP256Scalars(t *testing.T) {
	// Build a valid low-s entry; the digest is stable under signature-byte
	// mutation because empty-msg signatures are elided from the hash.
	tx := frameTxForSigning(nil)
	tx.Signatures = []FrameSignature{{Scheme: FrameSigSchemeP256, Signer: p256TestAddr().Bytes()}}
	tx.computeSigHash()
	payload, _ := signP256ForFrame(t, tx.computeSigHash())
	base := FrameSignature{Scheme: FrameSigSchemeP256, Signer: p256TestAddr().Bytes(), Signature: payload}

	mutate := func(modify func(p []byte)) FrameSignature {
		sig := make([]byte, frameP256SigLen)
		copy(sig, base.Signature)
		modify(sig)
		return FrameSignature{Scheme: FrameSigSchemeP256, Signer: base.Signer, Signature: sig}
	}
	setScalar := func(p []byte, off int, v *big.Int) {
		for i := off; i < off+32; i++ {
			p[i] = 0
		}
		v.FillBytes(p[off : off+32])
	}

	t.Run("valid low-s passes", func(t *testing.T) {
		tx.Signatures = []FrameSignature{base}
		if err := tx.ValidateSignatures(); err != nil {
			t.Fatalf("valid low-s P256 signature rejected: %v", err)
		}
	})

	t.Run("mathematically valid high-s rejected", func(t *testing.T) {
		s := new(big.Int).SetBytes(base.Signature[32:64])
		if s.Cmp(secp256R1HalfN) >= 0 {
			t.Fatalf("test fixture is not low-s: %v", s)
		}
		sHigh := new(big.Int).Sub(secp256R1N, s)
		entry := mutate(func(p []byte) { setScalar(p, 32, sHigh) })
		tx.Signatures = []FrameSignature{entry}
		if err := tx.ValidateSignatures(); !errors.Is(err, errFrameTxP256HighS) {
			t.Fatalf("expected errFrameTxP256HighS, got %v", err)
		}
	})

	t.Run("zero r rejected", func(t *testing.T) {
		entry := mutate(func(p []byte) { setScalar(p, 0, new(big.Int)) })
		tx.Signatures = []FrameSignature{entry}
		if err := tx.ValidateSignatures(); !errors.Is(err, errFrameTxP256ScalarRange) {
			t.Fatalf("expected errFrameTxP256ScalarRange, got %v", err)
		}
	})

	t.Run("zero s rejected", func(t *testing.T) {
		entry := mutate(func(p []byte) { setScalar(p, 32, new(big.Int)) })
		tx.Signatures = []FrameSignature{entry}
		if err := tx.ValidateSignatures(); !errors.Is(err, errFrameTxP256ScalarRange) {
			t.Fatalf("expected errFrameTxP256ScalarRange, got %v", err)
		}
	})

	t.Run("r equal to group order rejected", func(t *testing.T) {
		entry := mutate(func(p []byte) { setScalar(p, 0, secp256R1N) })
		tx.Signatures = []FrameSignature{entry}
		if err := tx.ValidateSignatures(); !errors.Is(err, errFrameTxP256ScalarRange) {
			t.Fatalf("expected errFrameTxP256ScalarRange, got %v", err)
		}
	})

	t.Run("s equal to group order rejected", func(t *testing.T) {
		entry := mutate(func(p []byte) { setScalar(p, 32, secp256R1N) })
		tx.Signatures = []FrameSignature{entry}
		if err := tx.ValidateSignatures(); !errors.Is(err, errFrameTxP256ScalarRange) {
			t.Fatalf("expected errFrameTxP256ScalarRange, got %v", err)
		}
	})
}

func TestFrameValidateMultipleEntries(t *testing.T) {
	t.Run("one invalid entry fails all", func(t *testing.T) {
		tx := frameTxForSigning(nil)
		tx.Signatures = []FrameSignature{
			{Scheme: FrameSigSchemeSecp256k1},
			{Scheme: FrameSigSchemeArbitrary, Signature: []byte{0x01}},
			{Scheme: FrameSigSchemeSecp256k1},
		}
		digest := tx.computeSigHash()
		good := FrameSignature{Scheme: FrameSigSchemeSecp256k1, Signature: signK1ForFrame(t, frameK1Key, digest)}
		bad := make([]byte, frameSecp256k1SigLen)
		copy(bad, good.Signature)
		bad[0] = 2 // invalid recovery id
		tx.Signatures = []FrameSignature{
			good,
			{Scheme: FrameSigSchemeArbitrary, Signature: []byte{0x01}},
			{Scheme: FrameSigSchemeSecp256k1, Signature: bad},
		}
		if err := tx.ValidateSignatures(); err == nil {
			t.Fatal("transaction with one invalid signature entry accepted")
		}
	})

	t.Run("all valid entries pass", func(t *testing.T) {
		tx := frameTxForSigning(nil)
		// P256 digest depends on the full signature list, so fix the final
		// entry layout first (nil k1 signature bytes encode identically to
		// the elided form), then sign both protocol-validated entries.
		p256 := FrameSignature{Scheme: FrameSigSchemeP256, Signer: p256TestAddr().Bytes()}
		tx.Signatures = []FrameSignature{
			{Scheme: FrameSigSchemeSecp256k1},
			{Scheme: FrameSigSchemeSecp256k1, Signer: frameTestSender.Bytes()},
			p256,
			{Scheme: FrameSigSchemeArbitrary, Signature: []byte{0xaa, 0xbb}},
		}
		digest := tx.computeSigHash()
		tx.Signatures[0].Signature = signK1ForFrame(t, frameK1Key, digest)
		tx.Signatures[1].Signature = signK1ForFrame(t, frameK1Key, digest)
		payload, _ := signP256ForFrame(t, digest)
		tx.Signatures[2].Signature = payload
		if err := tx.ValidateSignatures(); err != nil {
			t.Fatalf("mixed valid entries rejected: %v", err)
		}
	})

	t.Run("error identifies entry index", func(t *testing.T) {
		tx := frameTxForSigning(nil)
		tx.Signatures = []FrameSignature{{Scheme: FrameSigSchemeSecp256k1}, {Scheme: FrameSigSchemeSecp256k1}}
		digest := tx.computeSigHash()
		good := FrameSignature{Scheme: FrameSigSchemeSecp256k1, Signature: signK1ForFrame(t, frameK1Key, digest)}
		bad := make([]byte, frameSecp256k1SigLen)
		copy(bad, good.Signature)
		bad[10] ^= 0xff
		tx.Signatures = []FrameSignature{
			good,
			{Scheme: FrameSigSchemeSecp256k1, Signature: bad},
		}
		err := tx.ValidateSignatures()
		if err == nil || !contains(err.Error(), "signature 1") {
			t.Fatalf("expected indexed error, got %v", err)
		}
	})
}

// TestValidateFrameSignaturesWrapper covers the *Transaction convenience
// wrapper and its rejection of non-frame transactions.
func TestValidateFrameSignaturesWrapper(t *testing.T) {
	tx := frameTxForSigning(nil)
	tx.Signatures = []FrameSignature{{Scheme: FrameSigSchemeSecp256k1}}
	digest := tx.computeSigHash()
	tx.Signatures[0].Signature = signK1ForFrame(t, frameK1Key, digest)
	wrapped := NewTx(tx.copy())
	if err := ValidateFrameSignatures(wrapped); err != nil {
		t.Fatalf("wrapper rejected valid frame tx: %v", err)
	}

	legacy := NewTx(&LegacyTx{Nonce: 1, Gas: 21000, GasPrice: big.NewInt(1)})
	if err := ValidateFrameSignatures(legacy); !errors.Is(err, ErrTxTypeNotSupported) {
		t.Fatalf("expected ErrTxTypeNotSupported for legacy tx, got %v", err)
	}
}

// TestFrameK1RecoveryRegression ties ValidateSignatures to the repository's
// standard recovery path: the same digest/key must reproduce the sender
// address through both the ordinary signer and the frame validator.
func TestFrameK1RecoveryRegression(t *testing.T) {
	key, _ := crypto.HexToECDSA("c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3")
	addr := crypto.PubkeyToAddress(key.PublicKey)

	tx := frameTxForSigning(nil)
	tx.Sender = addr
	tx.Signatures = []FrameSignature{{Scheme: FrameSigSchemeSecp256k1}}
	digest := tx.computeSigHash()

	sig := signK1ForFrame(t, key, digest)
	tx.Signatures[0].Signature = sig
	if err := tx.ValidateSignatures(); err != nil {
		t.Fatalf("frame validation failed: %v", err)
	}

	// Cross-check with the ordinary recovery helper: the elided canonical
	// hash must equal what crypto.SigToPub recovers from.
	rsv := make([]byte, 65)
	copy(rsv[0:64], sig[1:65])
	rsv[64] = sig[0]
	pub, err := crypto.SigToPub(digest.Bytes(), rsv)
	if err != nil {
		t.Fatalf("SigToPub failed: %v", err)
	}
	if crypto.PubkeyToAddress(*pub) != addr {
		t.Fatal("ordinary recovery produced a different address")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
