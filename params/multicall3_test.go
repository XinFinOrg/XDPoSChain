// Copyright 2026 The XDPoSChain Authors
// This file is part of the XDPoSChain library.

package params

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/crypto"
)

// TestMulticall3RuntimeCode pins the bytecode installed at the Prague block: it
// has to be the runtime code the canonical deployment produced, otherwise the
// account would run different code than on the chains that share its address.
func TestMulticall3RuntimeCode(t *testing.T) {
	if have, want := len(Multicall3RuntimeCode), 3808; have != want {
		t.Fatalf("runtime code length = %d, want %d", have, want)
	}
	if have := crypto.Keccak256Hash(Multicall3RuntimeCode); have != Multicall3RuntimeCodeHash {
		t.Fatalf("runtime code hash = %s, want %s", have, Multicall3RuntimeCodeHash)
	}
}
