package engine_v2

import (
	"crypto/ecdsa"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
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

func TestCountValidSignatures_AllValidReturnsCount(t *testing.T) {
	x := &XDPoS_v2{}
	msg := common.HexToHash("0xa")
	k1, _ := crypto.GenerateKey()
	k2, _ := crypto.GenerateKey()
	candidates := []common.Address{addrOf(k1), addrOf(k2)}
	sigs := []types.Signature{signMsg(t, k1, msg), signMsg(t, k2, msg)}

	n, err := x.countValidSignatures(msg, sigs, candidates)
	assert.NoError(t, err)
	assert.Equal(t, 2, n)
}

func TestCountValidSignatures_FailsOnNonMasternode(t *testing.T) {
	x := &XDPoS_v2{}
	msg := common.HexToHash("0xb")
	k1, _ := crypto.GenerateKey()
	kStranger, _ := crypto.GenerateKey()
	candidates := []common.Address{addrOf(k1)}
	sigs := []types.Signature{signMsg(t, k1, msg), signMsg(t, kStranger, msg)}

	n, err := x.countValidSignatures(msg, sigs, candidates)
	assert.Error(t, err)
	assert.Equal(t, 0, n, "strict adapter returns 0 on any verification failure")
}

func TestCountValidSignatures_FailsOnDuplicate(t *testing.T) {
	x := &XDPoS_v2{}
	msg := common.HexToHash("0xc")
	k1, _ := crypto.GenerateKey()
	k2, _ := crypto.GenerateKey()
	candidates := []common.Address{addrOf(k1), addrOf(k2)}
	sig1 := signMsg(t, k1, msg)
	sigs := []types.Signature{sig1, sig1, signMsg(t, k2, msg)}

	n, err := x.countValidSignatures(msg, sigs, candidates)
	assert.Error(t, err, "strict adapter rejects duplicates")
	assert.Equal(t, 0, n)
	assert.True(t, strings.Contains(err.Error(), "duplicate"), "error mentions duplicate: %v", err)
}

func TestCountValidSignatures_EmptyInputReturnsZero(t *testing.T) {
	x := &XDPoS_v2{}
	k1, _ := crypto.GenerateKey()
	candidates := []common.Address{addrOf(k1)}

	n, err := x.countValidSignatures(common.HexToHash("0xd"), nil, candidates)
	assert.NoError(t, err)
	assert.Equal(t, 0, n)
}

func TestCountValidSignatures_EmptyCandidatesErrors(t *testing.T) {
	x := &XDPoS_v2{}
	msg := common.HexToHash("0xe")
	k1, _ := crypto.GenerateKey()
	sigs := []types.Signature{signMsg(t, k1, msg)}

	n, err := x.countValidSignatures(msg, sigs, nil)
	assert.Error(t, err)
	assert.Equal(t, 0, n)
}
