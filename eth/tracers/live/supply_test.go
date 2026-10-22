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
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestSupplySelfdestructForkGate pins that the supply tracer only accounts a
// selfdestruct-to-self as burnt while the fork still burns the balance, and
// that it takes the fork from the chain configuration.
func TestSupplySelfdestructForkGate(t *testing.T) {
	var (
		addr  = common.HexToAddress("0x8246")
		value = big.NewInt(100)
		// The fork boundaries are checked at the block that starts the trace.
		tests = []struct {
			name      string
			amsterdam *big.Int
			number    int64
			reverted  bool
			skipInit  bool
			wantBurn  *big.Int
		}{
			{"pre-amsterdam", nil, 1, false, false, value},
			{"amsterdam", big.NewInt(0), 1, false, false, nil},
			{"before-fork-block", big.NewInt(10), 9, false, false, value},
			{"at-fork-block", big.NewInt(10), 10, false, false, nil},
			{"reverted", nil, 1, true, false, nil},
			{"no-chain-config", big.NewInt(0), 1, false, true, value},
		}
	)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := *params.AllEthashProtocolChanges
			config.AmsterdamBlock = tt.amsterdam

			dir := t.TempDir()
			hooks, err := newSupply(json.RawMessage(fmt.Sprintf(`{"path":%q}`, dir)))
			if err != nil {
				t.Fatalf("failed to create the supply tracer: %v", err)
			}
			// core.NewBlockChain invokes this hook when a live tracer is
			// attached; without it the tracer has no chain configuration.
			if !tt.skipInit {
				if hooks.OnBlockchainInit == nil {
					t.Fatal("supply tracer does not register OnBlockchainInit")
				}
				hooks.OnBlockchainInit(&config)
			}
			block := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(tt.number)})
			hooks.OnBlockStart(tracing.BlockEvent{Block: block})
			hooks.OnTxStart(&tracing.VMContext{BlockNumber: block.Number()}, nil, addr)
			hooks.OnEnter(0, byte(vm.CALL), addr, addr, nil, 0, new(big.Int))
			hooks.OnEnter(1, byte(vm.SELFDESTRUCT), addr, addr, nil, 0, value)
			hooks.OnExit(1, nil, 0, nil, tt.reverted)
			hooks.OnExit(0, nil, 0, nil, false)
			hooks.OnBlockEnd(nil)
			hooks.OnClose()

			got := readSupplyBurn(t, dir)
			if tt.wantBurn == nil {
				if got.Sign() != 0 {
					t.Errorf("reported burn = %v, want none", got)
				}
				return
			}
			if got.Cmp(tt.wantBurn) != 0 {
				t.Errorf("reported burn = %v, want %v", got, tt.wantBurn)
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
