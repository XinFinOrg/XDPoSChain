// Copyright 2023 The go-ethereum Authors
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

package forkid

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// trioStoredConfig re-encodes the built-in mainnet config without the trio keys,
// the way a binary that predates their declaration persisted it, then applies
// raw JSON overrides so a shape can declare an explicit null.
func trioStoredConfig(t *testing.T, mutate func(*params.ChainConfig), overrides map[string]json.RawMessage) *params.ChainConfig {
	t.Helper()
	cfg := params.XDCMainnetChainConfig.Clone()
	if mutate != nil {
		mutate(cfg)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal the stored config: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("failed to decode the stored config: %v", err)
	}
	for _, key := range []string{"constantinopleBlock", "petersburgBlock", "istanbulBlock"} {
		delete(fields, key)
	}
	for key, value := range overrides {
		fields[key] = value
	}
	raw, err = json.Marshal(fields)
	if err != nil {
		t.Fatalf("failed to marshal the stripped config: %v", err)
	}
	var stored params.ChainConfig
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatalf("failed to decode the stripped config: %v", err)
	}
	return &stored
}

func explicitNulls(fields ...string) map[string]json.RawMessage {
	overrides := make(map[string]json.RawMessage, len(fields))
	for _, field := range fields {
		overrides[field] = json.RawMessage("null")
	}
	return overrides
}

// TestForkIDUnchangedWhenTrioHydrationIsSkipped pins the property the hydration
// gate exists for: a stored override that does not accept the built-in trio
// keeps its fork set, so neither the fork id nor the EIP-2124 filter rejects a
// peer in either direction after the upgrade.
func TestForkIDUnchangedWhenTrioHydrationIsSkipped(t *testing.T) {
	genesis := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(0)})
	shapes := []struct {
		name      string
		mutate    func(*params.ChainConfig)
		overrides map[string]json.RawMessage
	}{
		{
			// The cancellation fee sits far below the built-in trio height, so
			// injecting 38383838 would add a boundary the schedule never had.
			name: "fee below the built-in trio",
			mutate: func(cfg *params.ChainConfig) {
				height := int64(3000000)
				cfg.TIPRandomizeBlock = big.NewInt(height)
				cfg.TIPIncreaseMasternodesBlock = big.NewInt(height)
				cfg.DenylistBlock = big.NewInt(height)
				cfg.TIPNoHalvingMNRewardBlock = big.NewInt(height)
				cfg.TIPXDCXBlock = big.NewInt(height)
				cfg.TIPXDCXLendingBlock = big.NewInt(height)
				cfg.TIPXDCXCancellationFeeBlock = big.NewInt(height)
				cfg.TIPTRC21FeeBlock = big.NewInt(90000000)
				cfg.BerlinBlock = big.NewInt(90000000)
				cfg.LondonBlock = big.NewInt(90000000)
				cfg.MergeBlock = big.NewInt(90000000)
				cfg.ShanghaiBlock = big.NewInt(90000000)
				cfg.Gas50xBlock = big.NewInt(90000000)
				cfg.TIPXDCXMinerDisableBlock = big.NewInt(90000000)
				cfg.TIPXDCXReceiverDisableBlock = big.NewInt(90000000)
			},
		},
		{
			// The cancellation fee is disabled, so the trio must stay unset
			// instead of activating Petersburg and Istanbul at the built-in
			// height. Every other field that would contribute 38383838 to the
			// fork set is moved away, so an injection would add a boundary and
			// the fork-id comparisons below have teeth for this shape too.
			name: "cancellation fee declared null",
			mutate: func(cfg *params.ChainConfig) {
				height := int64(5000000)
				cfg.DenylistBlock = big.NewInt(height)
				cfg.TIPNoHalvingMNRewardBlock = big.NewInt(height)
				cfg.TIPXDCXBlock = big.NewInt(height)
				cfg.TIPXDCXLendingBlock = big.NewInt(height)
				cfg.TIPTRC21FeeBlock = big.NewInt(60000000)
			},
			overrides: explicitNulls(
				"tipXDCXCancellationFeeBlock",
				"berlinBlock", "londonBlock", "mergeBlock", "shanghaiBlock",
				"cancunBlock", "eip1559Block", "pragueBlock", "osakaBlock", "amsterdamBlock",
			),
		},
	}
	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			stored := trioStoredConfig(t, shape.mutate, shape.overrides)
			hydrated := stored.BackfillMissingFieldsFrom(params.XDCMainnetChainConfig)

			for _, field := range []struct {
				name string
				got  *big.Int
			}{
				{name: "ConstantinopleBlock", got: hydrated.ConstantinopleBlock},
				{name: "PetersburgBlock", got: hydrated.PetersburgBlock},
				{name: "IstanbulBlock", got: hydrated.IstanbulBlock},
			} {
				if field.got != nil {
					t.Fatalf("%s must stay unset, have %v", field.name, field.got)
				}
			}
			for _, head := range []uint64{20_000_000, 40_000_000, 95_000_000} {
				if got, want := NewID(hydrated, genesis, head), NewID(stored, genesis, head); got != want {
					t.Fatalf("fork id at head %d: have %v want %v", head, got, want)
				}
			}
			head := uint64(40_000_000)
			idStored, idHydrated := NewID(stored, genesis, head), NewID(hydrated, genesis, head)
			if err := newFilter(hydrated, genesis.Hash(), func() uint64 { return head })(idStored); err != nil {
				t.Fatalf("upgraded node rejected the stored id: %v", err)
			}
			if err := newFilter(stored, genesis.Hash(), func() uint64 { return head })(idHydrated); err != nil {
				t.Fatalf("old node rejected the hydrated id: %v", err)
			}
		})
	}
}
