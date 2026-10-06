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
	"strings"
	"testing"
)

// TestBindingResolvesABIThroughMetaData pins the two halves of the v1 binding
// template that its ABI cache consists of:
//
//   - bind* takes the ABI from CacheMetaData.GetAbi(), which parses the ABI
//     JSON once and caches the result, instead of calling abi.JSON whenever a
//     Caller, Transactor or Filterer is constructed.
//   - the generated file keeps its "accounts/abi" import referenced even for a
//     contract that converts no output, where abi.ConvertType is not emitted
//     and the reference import list is the only remaining use of the package.
func TestBindingResolvesABIThroughMetaData(t *testing.T) {
	t.Parallel()

	// A single getter is enough for the template to emit the bind* wrapper. The
	// bytecode is empty, so no deploy function is generated either.
	code, err := Bind([]string{"Cache"}, []string{`[{"constant":true,"inputs":[],"name":"value","outputs":[{"name":"","type":"uint256"}],"type":"function"}]`}, []string{""}, nil, "bindtest", nil, nil)
	if err != nil {
		t.Fatalf("failed to generate binding: %v", err)
	}
	if !strings.Contains(code, "parsed, err := CacheMetaData.GetAbi()") {
		t.Error("generated binding does not resolve its ABI through the metadata cache")
	}
	if strings.Contains(code, "abi.JSON(strings.NewReader(") {
		t.Error("generated binding parses the ABI JSON itself instead of using the cached metadata ABI")
	}

	// A contract without calls converts no output, so nothing but the reference
	// import list keeps the generated file's "accounts/abi" import alive.
	empty, err := Bind([]string{"Empty"}, []string{`[]`}, []string{""}, nil, "bindtest", nil, nil)
	if err != nil {
		t.Fatalf("failed to generate binding: %v", err)
	}
	if !strings.Contains(empty, "_ = abi.ConvertType") {
		t.Error("generated binding of a contract without calls does not reference accounts/abi")
	}
}
