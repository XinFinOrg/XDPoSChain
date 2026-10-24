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

package live

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
)

// TestSupplySelfdestructBurn pins that the supply tracer accounts the
// selfdestruct burn from the BalanceDecreaseSelfdestructBurn event instead of
// the SELFDESTRUCT enter event: the enter event cannot tell a burn from a
// no-op, because a self-destruct to self keeps its balance from EIP-6780
// (Cancun) onwards and from EIP-8246 (Amsterdam) onwards.
func TestSupplySelfdestructBurn(t *testing.T) {
	var (
		addr  = common.HexToAddress("0x8246")
		value = big.NewInt(100)
		tests = []struct {
			name string
			// burn is the amount the balance hooks report as burnt.
			burn *big.Int
		}{
			{"enter-only", nil},
			{"balance-change", value},
		}
	)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			hooks, err := newSupply(json.RawMessage(fmt.Sprintf(`{"path":%q}`, dir)))
			if err != nil {
				t.Fatalf("failed to create the supply tracer: %v", err)
			}
			block := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(1)})
			hooks.OnBlockStart(tracing.BlockEvent{Block: block})
			hooks.OnTxStart(&tracing.VMContext{BlockNumber: block.Number()}, nil, addr)
			hooks.OnEnter(0, byte(vm.CALL), addr, addr, nil, 0, new(big.Int))
			hooks.OnEnter(1, byte(vm.SELFDESTRUCT), addr, addr, nil, 0, value)
			hooks.OnExit(1, nil, 0, nil, false)
			hooks.OnExit(0, nil, 0, nil, false)
			if tt.burn != nil {
				hooks.OnBalanceChange(addr, tt.burn, new(big.Int), tracing.BalanceDecreaseSelfdestructBurn)
			}
			hooks.OnBlockEnd(nil)
			hooks.OnClose()

			got := readSupplyBurn(t, dir)
			want := tt.burn
			if want == nil {
				want = new(big.Int)
			}
			if got.Cmp(want) != 0 {
				t.Errorf("reported burn = %v, want %v", got, want)
			}
		})
	}
}

// readSupplyBurn reads the produced supply log and returns the misc burn of
// its single block.
func readSupplyBurn(t *testing.T, dir string) *big.Int {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(dir, "supply.jsonl"))
	if err != nil {
		t.Fatalf("failed to read the supply log: %v", err)
	}
	var info supplyInfo
	if err := json.Unmarshal(bytes.TrimSpace(raw), &info); err != nil {
		t.Fatalf("failed to decode the supply log: %v", err)
	}
	if info.Burn == nil || info.Burn.Misc == nil {
		return new(big.Int)
	}
	return info.Burn.Misc
}
