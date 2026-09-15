package core

import (
	"math/big"
	"sort"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/ethdb/memorydb"
)

func newHistoricalBypassStateDB(t *testing.T) *state.StateDB {
	t.Helper()

	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewDatabase(memorydb.New())))
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	return statedb
}

func TestHistoricalBalanceBypassApply(t *testing.T) {
	blocks := make([]uint64, 0, len(historicalBalanceBypassByBlock))
	for block := range historicalBalanceBypassByBlock {
		blocks = append(blocks, block)
	}
	sort.Slice(blocks, func(i, j int) bool {
		return blocks[i] < blocks[j]
	})

	for _, block := range blocks {
		block := block
		t.Run(new(big.Int).SetUint64(block).String(), func(t *testing.T) {
			statedb := newHistoricalBypassStateDB(t)
			rule := historicalBalanceBypassByBlock[block]

			statedb.SetBalance(rule.addr, big.NewInt(1), tracing.BalanceChangeUnspecified)
			applyHistoricalBalanceBypass(statedb, new(big.Int).SetUint64(block), rule.addr)

			if have := statedb.GetBalance(rule.addr); have.Cmp(rule.balance) != 0 {
				t.Fatalf("wrong balance after bypass: have %v want %v", have, rule.balance)
			}
		})
	}
}

func TestHistoricalBalanceBypassSkip(t *testing.T) {
	tests := []struct {
		name        string
		blockNumber *big.Int
		from        common.Address
	}{
		{
			name:        "nil block number",
			blockNumber: nil,
			from:        historicalBalanceBypassByBlock[9073579].addr,
		},
		{
			name:        "block above max",
			blockNumber: new(big.Int).SetUint64(maxHistoricalBalanceBypassBlock + 1),
			from:        historicalBalanceBypassByBlock[9073579].addr,
		},
		{
			name:        "block without rule",
			blockNumber: big.NewInt(1),
			from:        historicalBalanceBypassByBlock[9073579].addr,
		},
		{
			name:        "address mismatch",
			blockNumber: big.NewInt(9073579),
			from:        common.HexToAddress("0x1111111111111111111111111111111111111111"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statedb := newHistoricalBypassStateDB(t)
			rule := historicalBalanceBypassByBlock[9073579]
			original := big.NewInt(7)

			statedb.SetBalance(rule.addr, new(big.Int).Set(original), tracing.BalanceChangeUnspecified)
			applyHistoricalBalanceBypass(statedb, tt.blockNumber, tt.from)

			if have := statedb.GetBalance(rule.addr); have.Cmp(original) != 0 {
				t.Fatalf("balance changed unexpectedly: have %v want %v", have, original)
			}
		})
	}
}
