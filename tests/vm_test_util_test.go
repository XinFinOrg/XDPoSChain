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

package tests

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestVMTestSlotNum pins EIP-7843 in the state test harness: the block context
// takes its slot number from the environment's block number (docs/adr/0006-define-slot-number-as-block-number.md).
func TestVMTestSlotNum(t *testing.T) {
	vmtest := &VMTest{
		json:        vmJSON{Env: stEnv{Number: 42}},
		chainConfig: params.TestChainConfig,
	}
	if got := vmtest.newEVM(nil, vm.Config{}).Context.SlotNum; got != 42 {
		t.Errorf("SlotNum = %d, want 42", got)
	}
}
