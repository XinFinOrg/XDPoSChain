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

package abigen

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
)

// TestBindLibraryLinkingUsesPlainAddressHex checks the expression a generated
// binding uses to link the address of a deployed library into the bytecode of
// the contract that depends on it.
//
// common.Address.String() carries this repository's xdc prefix, so String()[2:]
// is 41 characters long while the __$<id>$__ placeholder it replaces is 40. The
// resulting bytecode has an odd number of hex digits, and common.FromHex pads it
// with a leading zero, which shifts the whole deployer bytecode by one nibble
// rather than producing an error. String0x() is the 0x-prefixed form, whose
// [2:] is the 40 digits the placeholder stands for.
func TestBindLibraryLinkingUsesPlainAddressHex(t *testing.T) {
	addr := common.HexToAddress("0x3a220f351252089d385b29beca14e27f204c296a")
	linked := addr.String0x()[2:]
	if len(linked) != 40 {
		t.Fatalf("linked address is %d hex digits long, want 40: %q", len(linked), linked)
	}
	if _, err := hex.DecodeString(linked); err != nil {
		t.Fatalf("linked address is not valid hex: %v", err)
	}

	libPattern := "deadbeefdeadbeefdeadbeefdeadbeefde"
	code, err := Bind(
		[]string{"Lib", "Main"},
		[]string{`[]`, `[]`},
		[]string{"0x6000", "0x6000__$" + libPattern + "$__6000"},
		nil, "bindtest", map[string]string{libPattern: "Lib"}, nil,
	)
	if err != nil {
		t.Fatalf("failed to generate binding: %v", err)
	}
	want := `MainBin = strings.ReplaceAll(MainBin, "__$` + libPattern + `$__", libAddr.String0x()[2:])`
	if !strings.Contains(code, want) {
		t.Errorf("generated binding does not contain %q\n%s", want, code)
	}
	if strings.Contains(code, "libAddr.String()[2:]") {
		t.Errorf("generated binding links the library address with the xdc-prefixed form\n%s", code)
	}
}
