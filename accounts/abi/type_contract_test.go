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

package abi

import (
	"bytes"
	"strings"
	"testing"
)

// TestContractTypedArgumentStringKind checks that an argument whose ABI type is
// a contract name is described as an address, both on its own and inside an
// array or a slice. The ABI of such an argument carries the contract name in
// "type" and the contract keyword in "internalType", so the parser has to
// recognize it from "internalType" and rewrite the canonical string form.
func TestContractTypedArgumentStringKind(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		typ          string
		internalType string
		want         string
	}{
		{"INameService", "contract INameService", "address"},
		{"INameService[]", "contract INameService[]", "address[]"},
		{"INameService[2]", "contract INameService[2]", "address[2]"},
	} {
		typ, err := NewType(tt.typ, tt.internalType, nil)
		if err != nil {
			t.Fatalf("type %q: failed to parse: %v", tt.typ, err)
		}
		if typ.stringKind != tt.want {
			t.Errorf("type %q: stringKind mismatch: got %q, want %q", tt.typ, typ.stringKind, tt.want)
		}
		if got := typ.String(); got != tt.want {
			t.Errorf("type %q: String() mismatch: got %q, want %q", tt.typ, got, tt.want)
		}
	}
}

// TestContractTypedArgumentSignature checks that the same ABI spelled with a
// contract type and with an address yields the same method selector and the
// same event topic. The signature is derived from the canonical string form of
// the argument, so a contract-typed argument that keeps the contract name would
// make the selector and the topic differ from the ones Ethereum computes.
func TestContractTypedArgumentSignature(t *testing.T) {
	t.Parallel()

	const (
		contractForm = `[{"inputs":[{"internalType":"contract INameService","name":"nameService","type":"INameService"}],"name":"setName","outputs":[],"stateMutability":"nonpayable","type":"function"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"contract INameService","name":"nameService","type":"INameService"}],"name":"NameServiceSet","type":"event"}]`
		addressForm  = `[{"inputs":[{"internalType":"address","name":"nameService","type":"address"}],"name":"setName","outputs":[],"stateMutability":"nonpayable","type":"function"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"nameService","type":"address"}],"name":"NameServiceSet","type":"event"}]`
	)
	fromContract, err := JSON(strings.NewReader(contractForm))
	if err != nil {
		t.Fatalf("failed to parse the contract-typed ABI: %v", err)
	}
	fromAddress, err := JSON(strings.NewReader(addressForm))
	if err != nil {
		t.Fatalf("failed to parse the address-typed ABI: %v", err)
	}
	// The signature is enough to pin the canonical form down, but compare the
	// derived selector and topic as well, since those are what callers compare
	// against the chain.
	if got, want := fromContract.Methods["setName"].Sig, fromAddress.Methods["setName"].Sig; got != want {
		t.Errorf("method signature mismatch: got %q, want %q", got, want)
	}
	if got, want := fromContract.Methods["setName"].ID, fromAddress.Methods["setName"].ID; !bytes.Equal(got, want) {
		t.Errorf("method selector mismatch: got %x, want %x", got, want)
	}
	if got, want := fromContract.Events["NameServiceSet"].Sig, fromAddress.Events["NameServiceSet"].Sig; got != want {
		t.Errorf("event signature mismatch: got %q, want %q", got, want)
	}
	if got, want := fromContract.Events["NameServiceSet"].ID, fromAddress.Events["NameServiceSet"].ID; got != want {
		t.Errorf("event topic mismatch: got %s, want %s", got, want)
	}
}
