// Copyright 2024 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"errors"
	"testing"
)

func TestTimedExecBenchNondeterministicReturnsError(t *testing.T) {
	t.Parallel()

	var calls int
	execFunc := func() ([]byte, uint64, error) {
		calls++
		if calls == 1 {
			return []byte{0x01}, 7, nil
		}
		return []byte{0x02}, 7, nil
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("timedExec panicked instead of returning an error: %v", recovered)
		}
	}()

	_, _, err := timedExec(true, execFunc)
	if err == nil {
		t.Fatal("expected nondeterministic benchmark run to return an error")
	}
	if !errors.Is(err, errInconsistentBenchmarkResult) {
		t.Fatalf("expected errInconsistentBenchmarkResult, got %v", err)
	}
}
