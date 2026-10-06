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

// TestArrayUnpackBoundaryErrorMessage checks the argument order of the error
// reported when a fixed-size array does not fit into the output: the offset
// that goes over the boundary comes first, the length of the output second.
func TestArrayUnpackBoundaryErrorMessage(t *testing.T) {
	t.Parallel()

	const definition = `[{"name":"f","type":"function","outputs":[{"name":"x","type":"uint256[3]"}]}]`
	contractABI, err := JSON(strings.NewReader(definition))
	if err != nil {
		t.Fatalf("cannot parse ABI: %v", err)
	}

	// 64 bytes cannot hold the three 32 byte elements of the array.
	want := "abi: cannot marshal into go array: offset 96 would go over slice boundary (len=64)"
	if _, err := contractABI.Unpack("f", make([]byte, 64)); err == nil || err.Error() != want {
		t.Fatalf("unpack of 64 bytes: error = %v, want %q", err, want)
	}

	// An output that is large enough still unpacks.
	values, err := contractABI.Unpack("f", make([]byte, 96))
	if err != nil {
		t.Fatalf("unpack of 96 bytes failed: %v", err)
	}
	if len(values) != 1 {
		t.Fatalf("unpacked %d values, want 1", len(values))
	}
	arr, ok := values[0].([3]*big.Int)
	if !ok {
		t.Fatalf("unpacked value = %T, want [3]*big.Int", values[0])
	}
	for i, v := range arr {
		if v == nil || v.Sign() != 0 {
			t.Fatalf("unpacked element %d = %v, want 0", i, v)
		}
	}
}
