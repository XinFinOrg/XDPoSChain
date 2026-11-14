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

func TestSignerStatusFor(t *testing.T) {
	syncing := false
	checked := 0
	authorised := true
	status := signerStatusFor(func() bool { return syncing }, func(common.Address) bool {
		checked++
		return authorised
	})

	syncing = true
	if ok, known := status(common.Address{}); ok || known {
		t.Fatalf("status during a sync = (%v, %v), want (false, false)", ok, known)
	}
	if checked != 0 {
		t.Fatalf("authorised check ran %d times during a sync, want 0", checked)
	}

	syncing = false
	if ok, known := status(common.Address{}); !ok || !known {
		t.Fatalf("status after the sync = (%v, %v), want (true, true)", ok, known)
	}
	if checked != 1 {
		t.Fatalf("authorised check ran %d times after the sync, want 1", checked)
	}

	authorised = false
	if ok, known := status(common.Address{}); ok || !known {
		t.Fatalf("status of an unauthorised address = (%v, %v), want (false, true)", ok, known)
	}
}

// TestSignerChecksAdmitIgnoresSync pins the #3057 fix: the txpool's admission
// test answers for the sender, so a syncing node still admits a candidate's
// special transaction, while this node's own status stays unknown.
func TestSignerChecksAdmitIgnoresSync(t *testing.T) {
	candidate := common.HexToAddress("0x01")
	stranger := common.HexToAddress("0x02")
	isAuthorised := func(a common.Address) bool { return a == candidate }

	admit, status := signerChecks(func() bool { return true }, isAuthorised)

	if !admit(candidate) {
		t.Fatal("a syncing node rejected a candidate's special transaction")
	}
	if admit(stranger) {
		t.Fatal("a syncing node admitted a special transaction from a non-candidate")
	}
	if ok, known := status(candidate); ok || known {
		t.Fatalf("own status during a sync = (%v, %v), want (false, false)", ok, known)
	}
}

func TestCanSign(t *testing.T) {
	tests := []struct {
		name   string
		status func(common.Address) (bool, bool)
		want   bool
	}{
		{"no XDPoS", nil, false},
		{"syncing", func(common.Address) (bool, bool) { return false, false }, false},
		{"not a signer", func(common.Address) (bool, bool) { return false, true }, false},
		{"signer", func(common.Address) (bool, bool) { return true, true }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Ethereum{signerStatus: tt.status}
			if got := e.canSign(common.Address{}); got != tt.want {
				t.Fatalf("canSign() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateMasternode(t *testing.T) {
	etherbase := common.HexToAddress("0xb8e36187c560bd9c26272c2fcd9a603fe56d5514")

	tests := []struct {
		name           string
		status         func(common.Address) (bool, bool)
		wantAuthorised bool
		wantKnown      bool
		wantErr        bool
	}{
		{"no XDPoS", nil, false, false, true},
		{"syncing", func(common.Address) (bool, bool) { return false, false }, false, false, false},
		{"not a masternode", func(common.Address) (bool, bool) { return false, true }, false, true, false},
		{"masternode", func(common.Address) (bool, bool) { return true, true }, true, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var asked common.Address
			e := &Ethereum{etherbase: etherbase}
			if tt.status != nil {
				e.signerStatus = func(a common.Address) (bool, bool) {
					asked = a
					return tt.status(a)
				}
			}
			authorised, known, err := e.ValidateMasternode()
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if authorised != tt.wantAuthorised || known != tt.wantKnown {
				t.Fatalf("ValidateMasternode() = (%v, %v), want (%v, %v)", authorised, known, tt.wantAuthorised, tt.wantKnown)
			}
			if tt.status != nil && asked != etherbase {
				t.Fatalf("status asked about %s, want the etherbase %s", asked, etherbase)
			}
		})
	}
}
