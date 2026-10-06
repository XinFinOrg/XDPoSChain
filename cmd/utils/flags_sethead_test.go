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

package utils

import (
	"math"
	"testing"
)

// TestParseSetHeadValid pins down the accepted --set-head inputs: an absolute
// block number in decimal or 0x-prefixed hexadecimal, and a negative offset
// (also accepted in hexadecimal) counting backwards from the current head.
func TestParseSetHeadValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		want  int64
	}{
		{name: "decimal block number", value: "1234", want: 1234},
		{name: "decimal one", value: "1", want: 1},
		{name: "decimal max int64", value: "9223372036854775807", want: math.MaxInt64},
		{name: "hex block number", value: "0x1f", want: 31},
		{name: "hex uppercase prefix", value: "0X1f", want: 31},
		{name: "hex as printed by eth_blockNumber", value: "0x6b7a1c", want: 7043612},
		{name: "hex with leading zeroes", value: "0x010", want: 16},
		{name: "hex max int64", value: "0x7fffffffffffffff", want: math.MaxInt64},
		{name: "negative offset", value: "-1", want: -1},
		{name: "negative offset of a thousand", value: "-1000", want: -1000},
		{name: "negative offset max int64", value: "-9223372036854775807", want: -math.MaxInt64},
		{name: "negative hex offset", value: "-0x10", want: -16},
		{name: "negative hex offset uppercase prefix", value: "-0X10", want: -16},
		{name: "zero", value: "0", want: 0},
		{name: "negative zero", value: "-0", want: 0},
		{name: "hex zero", value: "0x0", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseSetHead(tt.value)
			if err != nil {
				t.Fatalf("parseSetHead(%q) rejected a valid value: %v", tt.value, err)
			}
			if got != tt.want {
				t.Fatalf("parseSetHead(%q) = %d, want %d", tt.value, got, tt.want)
			}
		})
	}
}

// TestParseSetHeadInvalid pins down what --set-head must reject: octal and
// binary literals, leading zeroes, a "+" sign, signs inside a hexadecimal
// literal, and values that do not fit an int64. Before this change the flag was
// a cli.Uint64Flag, so Go's base-0 integer parsing let "010" through as 8 and
// "0b101" as 5.
func TestParseSetHeadInvalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
	}{
		{name: "empty", value: ""},
		{name: "minus only", value: "-"},
		{name: "double minus", value: "--5"},
		{name: "plus then minus", value: "+-5"},
		{name: "minus then plus", value: "-+5"},
		{name: "plus decimal", value: "+5"},
		{name: "plus hex", value: "+0x10"},
		{name: "leading zero", value: "010"},
		{name: "leading zero negative", value: "-010"},
		{name: "double zero", value: "00"},
		{name: "hex without digits", value: "0x"},
		{name: "hex without digits negative", value: "-0x"},
		{name: "plus inside hex", value: "0x+5"},
		{name: "minus inside hex", value: "0x-5"},
		{name: "negative offset with minus inside hex", value: "-0x-5"},
		{name: "negative offset with plus inside hex", value: "-0x+5"},
		{name: "hex with bad digit", value: "0x1g"},
		{name: "not a number", value: "abc"},
		{name: "float", value: "5.5"},
		{name: "exponent", value: "1e3"},
		{name: "underscores", value: "1_000"},
		{name: "binary literal", value: "0b101"},
		{name: "octal literal", value: "0o17"},
		{name: "leading space", value: " 12"},
		{name: "trailing space", value: "12 "},
		{name: "above int64", value: "9223372036854775808"},
		{name: "int64 min", value: "-9223372036854775808"},
		{name: "uint64 max", value: "18446744073709551615"},
		{name: "hex above int64", value: "0x8000000000000000"},
		{name: "negative hex above int64", value: "-0x8000000000000000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseSetHead(tt.value)
			if err == nil {
				t.Fatalf("parseSetHead(%q) = %d, want an error", tt.value, got)
			}
		})
	}
}
