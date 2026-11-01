// Copyright 2026 The XDPoSChain Authors
// This file is part of the XDPoSChain library.
//
// The XDPoSChain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The XDPoSChain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the XDPoSChain library. If not, see <http://www.gnu.org/licenses/>.

package eth

import (
	"errors"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
)

func TestSignerGateFor(t *testing.T) {
	noEtherbase := errors.New("etherbase must be explicitly specified")

	tests := []struct {
		name     string
		etherErr error
		signer   bool
		want     bool
	}{
		{"no etherbase", noEtherbase, true, false},
		{"steady state, not a signer", nil, false, false},
		{"steady state, signer", nil, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gate := signerGateFor(
				func() (common.Address, error) { return common.Address{}, tt.etherErr },
				func(common.Address) bool { return tt.signer },
			)
			if got := gate(); got != tt.want {
				t.Fatalf("gate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSignerPredicate(t *testing.T) {
	syncing := false
	checked := 0
	authorised := func(common.Address) bool {
		checked++
		return true
	}
	isSigner := signerPredicate(func() bool { return syncing }, authorised)

	syncing = true
	if isSigner(common.Address{}) {
		t.Fatal("predicate reported a signer during a sync")
	}
	if checked != 0 {
		t.Fatalf("authorised check ran %d times during a sync, want 0", checked)
	}

	syncing = false
	if !isSigner(common.Address{}) {
		t.Fatal("predicate reported no signer after the sync")
	}
	if checked != 1 {
		t.Fatalf("authorised check ran %d times after the sync, want 1", checked)
	}

	notAuthorised := signerPredicate(func() bool { return false }, func(common.Address) bool { return false })
	if notAuthorised(common.Address{}) {
		t.Fatal("predicate reported an unauthorised address as a signer")
	}
}
