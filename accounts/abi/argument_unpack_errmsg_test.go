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
	"math/big"
	"strings"
	"testing"
)

// TestUnpackIntoInterfaceWantCountSkipsIndexed checks the arity error reported
// when the decoded values do not fit into the destination. Only the non-indexed
// inputs of an event are decoded, so the "want" count has to be the number of
// decoded values, not the number of entries in the event ABI.
func TestUnpackIntoInterfaceWantCountSkipsIndexed(t *testing.T) {
	t.Parallel()

	const definition = `[{"name":"E","type":"event","anonymous":false,"inputs":[` +
		`{"indexed":true,"name":"a","type":"uint256"},` +
		`{"indexed":false,"name":"b","type":"uint256"},` +
		`{"indexed":false,"name":"c","type":"uint256"}]}]`
	eventABI, err := JSON(strings.NewReader(definition))
	if err != nil {
		t.Fatalf("cannot parse event ABI: %v", err)
	}
	data := make([]byte, 64)
	big.NewInt(1).FillBytes(data[:32])
	big.NewInt(2).FillBytes(data[32:])

	// The indexed input is skipped, so two values are decoded and a
	// one-element destination is exactly one short.
	short := []any{new(big.Int)}
	want := "abi: insufficient number of arguments for unpack, want 2, got 1"
	if err := eventABI.UnpackIntoInterface(&short, "E", data); err == nil || err.Error() != want {
		t.Fatalf("unpack into a one-element slice: error = %v, want %q", err, want)
	}

	// A destination with room for both decoded values still unpacks.
	fitted := make([]any, 2)
	if err := eventABI.UnpackIntoInterface(&fitted, "E", data); err != nil {
		t.Fatalf("unpack into a two-element slice failed: %v", err)
	}
	if got := fitted[0].(*big.Int); got.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("first unpacked value = %v, want 1", got)
	}
	if got := fitted[1].(*big.Int); got.Cmp(big.NewInt(2)) != 0 {
		t.Errorf("second unpacked value = %v, want 2", got)
	}
}
