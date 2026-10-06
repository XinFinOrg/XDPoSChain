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

// This file contains the EIP-2537 BLS12-381 precompile fuzzer, ported from
// go-ethereum tests/fuzzers/bls12381.
//
// Upstream splits its target in two: bls12381_fuzz.go fuzzes the gnark-crypto
// library itself (cross-curve consistency, subgroup membership) and is not
// ported here, because this repository does not own that library. What is
// ported is the precompile-level target, whose invariants are ours: the gas
// calculation must survive any input, the length gate, the gas ceiling, and
// the rule that a precompile must never modify the caller's input, whether it
// succeeds or fails.
//
// Two adaptations are forced on us. Upstream runs one target per precompile
// with the address hardcoded, while this file runs a single target that takes
// the address from the fuzzing engine, so any address outside EIP-2537 has to
// be dropped before the precompile table is consulted. And upstream reaches
// the precompiles through the exported PrecompiledContractsBLS alias; the test
// lives in the same package here, so it can index the Prague bucket directly
// and no production code has to grow an alias for it.

package vm

import (
	"bytes"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
)

// EIP-2537 precompile addresses.
const (
	bls12381G1AddAddr      = byte(0x0b)
	bls12381G1MultiExpAddr = byte(0x0c)
	bls12381G2AddAddr      = byte(0x0d)
	bls12381G2MultiExpAddr = byte(0x0e)
	bls12381PairingAddr    = byte(0x0f)
	bls12381MapG1Addr      = byte(0x10)
	bls12381MapG2Addr      = byte(0x11)
)

// bls12381Addrs lists the seven addresses in call order, matching the order the
// precompiles are declared in contracts.go.
var bls12381Addrs = []byte{
	bls12381G1AddAddr, bls12381G1MultiExpAddr,
	bls12381G2AddAddr, bls12381G2MultiExpAddr,
	bls12381PairingAddr, bls12381MapG1Addr, bls12381MapG2Addr,
}

// checkBLS12381Input reports whether data is a well-formed input length for the
// precompile at id. Anything else has to be rejected by the length gate, and
// ids outside EIP-2537 are rejected outright. The rule is upstream's, kept
// verbatim: the multi-exponentiations and the pairing accept any multiple of
// their stride, zero included, so that an empty input reaches Run and is turned
// away there instead of being filtered out before it.
func checkBLS12381Input(id byte, inputLen int) bool {
	switch id {
	case bls12381G1AddAddr:
		return inputLen == 256
	case bls12381G1MultiExpAddr:
		return inputLen%160 == 0
	case bls12381G2AddAddr:
		return inputLen == 512
	case bls12381G2MultiExpAddr:
		return inputLen%288 == 0
	case bls12381PairingAddr:
		return inputLen%384 == 0
	case bls12381MapG1Addr:
		return inputLen == 64
	case bls12381MapG2Addr:
		return inputLen == 128
	}
	return false
}

// FuzzPrecompiledBLS12381 runs the seven EIP-2537 precompiles over arbitrary
// input. Seeds come from the ported test vectors, so `go test` alone already
// exercises the successful and the rejected paths of every precompile; the
// fuzzer takes over from there under -fuzz.
//
// Upstream's fuzz() returns 1 on success to bias the corpus towards parseable
// inputs. Go's native fuzzing has no such priority, so only the invariants
// survive the port.
func FuzzPrecompiledBLS12381(f *testing.F) {
	for _, seed := range bls12381FuzzSeeds() {
		f.Add(seed.addr, seed.input)
	}
	f.Fuzz(func(t *testing.T, id byte, input []byte) {
		precompile, ok := PrecompiledContractsPrague[common.BytesToAddress([]byte{id})]
		if !ok {
			// The address comes from the fuzzing engine, so anything outside
			// EIP-2537 is simply not this target's business.
			return
		}
		// Even on bad input, it should not crash, so we still test the gas calc.
		gas := precompile.RequiredGas(input)
		if !checkBLS12381Input(id, len(input)) {
			return
		}
		// If the gas cost is too large (25M), bail out.
		if gas > 25*1000*1000 {
			return
		}
		cpy := make([]byte, len(input))
		copy(cpy, input)
		_, err := precompile.Run(cpy)
		if !bytes.Equal(cpy, input) {
			t.Fatalf("input data modified, precompile %#x: %x -> %x", id, input, cpy)
		}
		if err != nil {
			return
		}
	})
}

type bls12381FuzzSeed struct {
	addr  byte
	input []byte
}

// bls12381FuzzSeeds draws seeds from the ported vectors: a couple of successful
// cases and one rejected case per precompile, plus the off-length inputs that
// must survive the gas calculation and then be turned away by the length gate
// before any curve arithmetic starts.
//
// The G1Mul and G2Mul vector files are driven through the multi-exponentiation
// precompiles, matching how contracts_test.go addresses them. The names are
// bare in both tables: loadJsonFail adds the fail- prefix itself.
func bls12381FuzzSeeds() []bls12381FuzzSeed {
	vectors := []struct {
		name string
		addr byte
	}{
		{"blsG1Add", bls12381G1AddAddr},
		{"blsG1Mul", bls12381G1MultiExpAddr},
		{"blsG1MultiExp", bls12381G1MultiExpAddr},
		{"blsG2Add", bls12381G2AddAddr},
		{"blsG2Mul", bls12381G2MultiExpAddr},
		{"blsG2MultiExp", bls12381G2MultiExpAddr},
		{"blsPairing", bls12381PairingAddr},
		{"blsMapG1", bls12381MapG1Addr},
		{"blsMapG2", bls12381MapG2Addr},
	}
	rejects := []struct {
		name string
		addr byte
	}{
		{"blsG1Add", bls12381G1AddAddr},
		{"blsG1Mul", bls12381G1MultiExpAddr},
		{"blsG1MultiExp", bls12381G1MultiExpAddr},
		{"blsG2Add", bls12381G2AddAddr},
		{"blsG2Mul", bls12381G2MultiExpAddr},
		{"blsG2MultiExp", bls12381G2MultiExpAddr},
		{"blsPairing", bls12381PairingAddr},
		{"blsMapG1", bls12381MapG1Addr},
		{"blsMapG2", bls12381MapG2Addr},
	}
	var seeds []bls12381FuzzSeed
	for _, v := range vectors {
		cases, err := loadJson(v.name)
		if err != nil {
			continue // a missing vector file must not disable the whole target
		}
		for i, test := range cases {
			if i >= 2 {
				break
			}
			seeds = append(seeds, bls12381FuzzSeed{v.addr, common.Hex2Bytes(test.Input)})
		}
	}
	for _, v := range rejects {
		cases, err := loadJsonFail(v.name)
		if err != nil {
			continue // loadJsonFail owns the fail- prefix; a bare name is correct
		}
		if len(cases) > 0 {
			seeds = append(seeds, bls12381FuzzSeed{v.addr, common.Hex2Bytes(cases[0].Input)})
		}
	}
	// One below, one above and one far off every accepted length, so the gas
	// calculation is exercised and the gate has a seed on each side of it.
	// The zero length doubles as the empty-input case the failure vectors open
	// with, which is why those two sources produce the same pairs.
	for _, addr := range bls12381Addrs {
		for _, n := range []int{0, 1, 63, 65, 127, 129, 159, 161, 255, 257, 287, 289, 383, 385, 511, 513} {
			seeds = append(seeds, bls12381FuzzSeed{addr, make([]byte, n)})
		}
	}
	return seeds
}
