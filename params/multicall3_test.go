// Copyright 2026 The XDPoSChain Authors
// This file is part of the XDPoSChain library.

package params

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/crypto"
)

// multicall3RuntimeCodeHash is the keccak256 of the runtime code the canonical
// deployment left at the Multicall3 address. TestMulticall3RuntimeCode pins
// Multicall3RuntimeCode against it, so a corrupted constant never reaches a chain.
var multicall3RuntimeCodeHash = common.HexToHash("0xd5c15df687b16f2ff992fc8d767b4216323184a2bbc6ee2f9c398c318e770891")

// TestMulticall3RuntimeCode pins the bytecode installed at the Prague block to the code
// the canonical deployment produced, the code the chains sharing the address run.
func TestMulticall3RuntimeCode(t *testing.T) {
	if have, want := len(Multicall3RuntimeCode), 3808; have != want {
		t.Fatalf("runtime code length = %d, want %d", have, want)
	}
	if have := crypto.Keccak256Hash(Multicall3RuntimeCode); have != multicall3RuntimeCodeHash {
		t.Fatalf("runtime code hash = %s, want %s", have, multicall3RuntimeCodeHash)
	}
}
