// Copyright 2026 The XDPoSChain Authors
// This file is part of the XDPoSChain library.

package params

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/crypto"
)

var eip7997RuntimeCodeHash = common.HexToHash("0x2fa86add0aed31f33a762c9d88e807c475bd51d0f52bd0955754b2608f7e4989")

func TestDeterministicFactoryConstants(t *testing.T) {
	if have, want := DeterministicFactoryAddress, common.HexToAddress("0x4e59b44847b379578588920cA78FbF26c0B4956C"); have != want {
		t.Fatalf("factory address = %s, want %s", have, want)
	}
	if have, want := len(DeterministicFactoryCode), 69; have != want {
		t.Fatalf("runtime code length = %d, want %d", have, want)
	}
	if have := crypto.Keccak256Hash(DeterministicFactoryCode); have != eip7997RuntimeCodeHash {
		t.Fatalf("runtime code hash = %s, want %s", have, eip7997RuntimeCodeHash)
	}
}
