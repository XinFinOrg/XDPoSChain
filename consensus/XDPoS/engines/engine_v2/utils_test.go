package engine_v2

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/stretchr/testify/assert"
)

func addrOf(k *ecdsa.PrivateKey) common.Address {
	return crypto.PubkeyToAddress(k.PublicKey)
}

func signMsg(t *testing.T, k *ecdsa.PrivateKey, h common.Hash) types.Signature {
	t.Helper()
	sig, err := crypto.Sign(h.Bytes(), k)
	if err != nil {
		t.Fatalf("crypto.Sign: %v", err)
	}
	return sig
}

// flipSignature returns the malleable counterpart of sig: same r, s' = N - s, v' = v ^ 1.
// The result recovers the same public key as the input but is byte-distinct and
// has S in the upper half of the curve order.
func flipSignature(sig types.Signature) types.Signature {
	flipped := make(types.Signature, 65)
	copy(flipped, sig)
	s := new(big.Int).SetBytes(sig[32:64])
	sFlipped := new(big.Int).Sub(crypto.S256().Params().N, s)
	sFlipped.FillBytes(flipped[32:64])
	flipped[64] = sig[64] ^ 1
	return flipped
}

func TestVerifyAllSignatures_AllValidUnique(t *testing.T) {
	x := &XDPoS_v2{}
	msg := common.HexToHash("0xdeadbeef")

	k1, _ := crypto.GenerateKey()
	k2, _ := crypto.GenerateKey()
	k3, _ := crypto.GenerateKey()
	candidates := []common.Address{addrOf(k1), addrOf(k2), addrOf(k3)}
	sigs := []types.Signature{
		signMsg(t, k1, msg),
		signMsg(t, k2, msg),
		signMsg(t, k3, msg),
	}

	valid, signers, dups, err := x.verifyAllSignatures(msg, sigs, candidates)
	assert.NoError(t, err)
	assert.Empty(t, dups)
	assert.Len(t, valid, 3)
	assert.Equal(t, candidates, signers, "signers preserve input order")
	for i, sig := range sigs {
		assert.Equal(t, sig, valid[i], "validSignatures parallel to signers")
	}
}

func TestVerifyAllSignatures_EmptyInput(t *testing.T) {
	x := &XDPoS_v2{}
	candidates := []common.Address{common.HexToAddress("0x1")}

	valid, signers, dups, err := x.verifyAllSignatures(common.HexToHash("0x1"), nil, candidates)
	assert.NoError(t, err)
	assert.Empty(t, valid)
	assert.Empty(t, signers)
	assert.Empty(t, dups)
}

func TestVerifyAllSignatures_NonMasternodeFiltered(t *testing.T) {
	x := &XDPoS_v2{}
	msg := common.HexToHash("0xfeed")
	k1, _ := crypto.GenerateKey()
	kStranger, _ := crypto.GenerateKey() // not in candidates
	k3, _ := crypto.GenerateKey()
	candidates := []common.Address{addrOf(k1), addrOf(k3)}
	sigs := []types.Signature{
		signMsg(t, k1, msg),
		signMsg(t, kStranger, msg),
		signMsg(t, k3, msg),
	}

	valid, signers, dups, err := x.verifyAllSignatures(msg, sigs, candidates)
	assert.Error(t, err, "stranger signer should produce a joined error")
	assert.Empty(t, dups)
	assert.Len(t, valid, 2, "only valid signers kept")
	assert.Equal(t, []common.Address{addrOf(k1), addrOf(k3)}, signers)
}

func TestVerifyAllSignatures_DuplicateSignerDeduped(t *testing.T) {
	x := &XDPoS_v2{}
	msg := common.HexToHash("0xcafe")
	k1, _ := crypto.GenerateKey()
	k2, _ := crypto.GenerateKey()
	candidates := []common.Address{addrOf(k1), addrOf(k2)}
	sig1 := signMsg(t, k1, msg)
	sig2 := signMsg(t, k2, msg)

	// k1 represented twice — even byte-identical, dedup must catch it
	sigs := []types.Signature{sig1, sig1, sig2}

	valid, signers, dups, err := x.verifyAllSignatures(msg, sigs, candidates)
	assert.NoError(t, err, "duplicates are not verification errors")
	assert.Equal(t, []common.Address{addrOf(k1)}, dups, "k1 reported as duplicate exactly once")
	assert.Len(t, valid, 2, "first occurrence kept, second dropped")
	assert.Equal(t, []common.Address{addrOf(k1), addrOf(k2)}, signers)
}

func TestVerifyAllSignatures_DuplicateReportedOncePerAddress(t *testing.T) {
	x := &XDPoS_v2{}
	msg := common.HexToHash("0xbeef")
	k1, _ := crypto.GenerateKey()
	k2, _ := crypto.GenerateKey()
	candidates := []common.Address{addrOf(k1), addrOf(k2)}
	sig1 := signMsg(t, k1, msg)
	sig2 := signMsg(t, k2, msg)

	// k1 appears 4 times, k2 appears 3 times
	sigs := []types.Signature{sig1, sig1, sig1, sig1, sig2, sig2, sig2}

	_, _, dups, err := x.verifyAllSignatures(msg, sigs, candidates)
	assert.NoError(t, err)
	assert.Len(t, dups, 2, "each duplicated signer listed once, regardless of count")
	assert.ElementsMatch(t, []common.Address{addrOf(k1), addrOf(k2)}, dups)
}

func TestVerifyAllSignatures_EmptyCandidatesAllError(t *testing.T) {
	x := &XDPoS_v2{}
	msg := common.HexToHash("0xfade")
	k1, _ := crypto.GenerateKey()
	sigs := []types.Signature{signMsg(t, k1, msg)}

	valid, signers, dups, err := x.verifyAllSignatures(msg, sigs, nil)
	assert.Error(t, err, "empty masternodes makes every signature invalid")
	assert.Empty(t, valid)
	assert.Empty(t, signers)
	assert.Empty(t, dups)
}

func TestVerifyAllSignatures_GarbageSignatureKeepsValid(t *testing.T) {
	x := &XDPoS_v2{}
	msg := common.HexToHash("0xbabe")
	k1, _ := crypto.GenerateKey()
	candidates := []common.Address{addrOf(k1)}
	garbage := make(types.Signature, 65) // all zeros, ecrecover fails

	valid, signers, _, err := x.verifyAllSignatures(msg, []types.Signature{signMsg(t, k1, msg), garbage}, candidates)
	assert.Error(t, err, "garbage signature contributes an error")
	assert.Len(t, valid, 1, "valid signature still recovered")
	assert.Equal(t, addrOf(k1), signers[0])
}

func TestVerifyAllSignatures_OrderPreservedFirstOccurrence(t *testing.T) {
	x := &XDPoS_v2{}
	msg := common.HexToHash("0xface")
	k1, _ := crypto.GenerateKey()
	k2, _ := crypto.GenerateKey()
	k3, _ := crypto.GenerateKey()
	candidates := []common.Address{addrOf(k1), addrOf(k2), addrOf(k3)}

	// Ordering: k2, k1, k2 (dup), k3 — first-occurrence order is k2, k1, k3
	sigs := []types.Signature{
		signMsg(t, k2, msg),
		signMsg(t, k1, msg),
		signMsg(t, k2, msg), // duplicate of position 0
		signMsg(t, k3, msg),
	}
	_, signers, dups, err := x.verifyAllSignatures(msg, sigs, candidates)
	assert.NoError(t, err)
	assert.Equal(t, []common.Address{addrOf(k2)}, dups)
	assert.Equal(t, []common.Address{addrOf(k2), addrOf(k1), addrOf(k3)}, signers)
}

func TestHasLowS_AcceptsCanonicalSignature(t *testing.T) {
	k, _ := crypto.GenerateKey()
	sig := signMsg(t, k, common.HexToHash("0xab"))
	assert.True(t, hasLowS(sig), "crypto.Sign produces canonical low-S; should be accepted")
}

func TestHasLowS_RejectsMalleableCounterpart(t *testing.T) {
	k, _ := crypto.GenerateKey()
	sig := signMsg(t, k, common.HexToHash("0xab"))
	flipped := flipSignature(sig)
	assert.NotEqual(t, sig, flipped, "flipSignature must produce byte-distinct signature")
	assert.True(t, hasLowS(sig))
	assert.False(t, hasLowS(flipped), "high-S counterpart must be rejected")
}

func TestHasLowS_RejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 1, 32, 64, 66, 128} {
		assert.Falsef(t, hasLowS(make(types.Signature, n)), "length %d must be rejected", n)
	}
}

func TestHasLowS_BoundaryAtHalfN(t *testing.T) {
	// s == halfN: low-S is `s <= floor(N/2)`, so the midpoint must be accepted.
	atHalf := make(types.Signature, 65)
	secp256k1halfN.FillBytes(atHalf[32:64])
	assert.True(t, hasLowS(atHalf), "s == halfN must be accepted")

	// s == halfN + 1: just over the boundary, must be rejected.
	overHalf := make(types.Signature, 65)
	new(big.Int).Add(secp256k1halfN, big.NewInt(1)).FillBytes(overHalf[32:64])
	assert.False(t, hasLowS(overHalf), "s == halfN+1 must be rejected")

	// s == 1: minimum valid s, must be accepted.
	minS := make(types.Signature, 65)
	big.NewInt(1).FillBytes(minS[32:64])
	assert.True(t, hasLowS(minS))
}

func TestVerifyMsgSignature_RejectsMalleableSignature(t *testing.T) {
	x := &XDPoS_v2{}
	msg := common.HexToHash("0xabc1")
	k, _ := crypto.GenerateKey()
	flipped := flipSignature(signMsg(t, k, msg))

	verified, signer, err := x.verifyMsgSignature(msg, flipped, []common.Address{addrOf(k)})
	assert.False(t, verified)
	assert.Equal(t, common.Address{}, signer, "no signer recovered when low-S check fails first")
	assert.ErrorIs(t, err, utils.ErrInvalidSignature)
}

func TestRecoverUniqueSigners_RejectsBatchOnMalleableSignature(t *testing.T) {
	msg := common.HexToHash("0xabc2")
	k1, _ := crypto.GenerateKey()
	k2, _ := crypto.GenerateKey()
	good := signMsg(t, k1, msg)
	bad := flipSignature(signMsg(t, k2, msg))

	// Strict-by-design: one malleable signature fails the entire batch so that
	// peer-supplied TC/QC certs containing any malleable sig are rejected whole.
	unique, dups, err := RecoverUniqueSigners(msg, []types.Signature{good, bad})
	assert.ErrorIs(t, err, utils.ErrInvalidSignature)
	assert.Nil(t, unique)
	assert.Nil(t, dups)
}

func TestVerifyAllSignatures_DropsMalleableKeepsValid(t *testing.T) {
	x := &XDPoS_v2{}
	msg := common.HexToHash("0xabc3")
	k1, _ := crypto.GenerateKey()
	k2, _ := crypto.GenerateKey()
	candidates := []common.Address{addrOf(k1), addrOf(k2)}
	good := signMsg(t, k1, msg)
	bad := flipSignature(signMsg(t, k2, msg))

	// Tolerant-by-design: per-sig errors are aggregated, valid sigs survive so
	// a single bad pool entry cannot stall TC/QC generation.
	valid, signers, dups, err := x.verifyAllSignatures(msg, []types.Signature{good, bad}, candidates)
	assert.Error(t, err, "malleable sig contributes a per-sig error")
	assert.Empty(t, dups)
	assert.Len(t, valid, 1, "valid signature still recovered")
	assert.Equal(t, []common.Address{addrOf(k1)}, signers)
}
