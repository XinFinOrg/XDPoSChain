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

package ethapi

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/hexutil"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/internal/ethapi/override"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/require"
)

// TestHistoryStorageWrittenSlots pins the arithmetic the guard shares with
// core.ProcessParentBlockHash: which slots of the EIP-2935 history contract the block
// writes, and therefore which slots a state override of the contract cannot set. A block
// below Prague writes nothing, a block that deploys the contract writes the ring window
// the serve window reaches, and a block that only finds the contract there writes the slot
// of its own parent hash.
func TestHistoryStorageWrittenSlots(t *testing.T) {
	t.Parallel()

	// ringSlot builds a storage key of the history contract the way core.historyStorageKey
	// does: the ring position in the low bytes of the key, zeroes above.
	ringSlot := func(position uint64) common.Hash {
		var key common.Hash
		binary.BigEndian.PutUint64(key[common.HashLength-8:], position)
		return key
	}
	// baseState builds the pre-state of the block being simulated, either without the
	// contract, the state a chain is in before a Prague block deploys it, or with its
	// canonical code, the state a chain reaches once one has.
	baseState := func(t *testing.T, withCode bool) *state.StateDB {
		t.Helper()
		statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
		require.NoError(t, err)
		if withCode {
			statedb.SetCode(params.HistoryStorageAddress, params.HistoryStorageCode)
		}
		return statedb
	}
	pragueConfig := func(prague int64) *params.ChainConfig {
		config := *params.MergedTestChainConfig
		config.PragueBlock = big.NewInt(prague)
		return &config
	}

	for _, tc := range []struct {
		name      string
		config    *params.ChainConfig
		withCode  bool
		number    int64
		written   []common.Hash
		unwritten []common.Hash
	}{
		{
			name:      "the first Prague block deploys the contract and writes the slot of its parent",
			config:    pragueConfig(0),
			number:    1,
			written:   []common.Hash{ringSlot(0)},
			unwritten: []common.Hash{ringSlot(1)},
		},
		{
			name:      "a later block writes the slot of its own parent hash",
			config:    pragueConfig(0),
			number:    3,
			written:   []common.Hash{ringSlot(2)},
			unwritten: []common.Hash{ringSlot(0), ringSlot(1), ringSlot(3)},
		},
		{
			name:      "a contract the state already holds only gets the slot of its own parent hash",
			config:    pragueConfig(0),
			withCode:  true,
			number:    3,
			written:   []common.Hash{ringSlot(2)},
			unwritten: []common.Hash{ringSlot(0), ringSlot(1), ringSlot(3)},
		},
		{
			name:      "a block below Prague writes nothing",
			config:    pragueConfig(10),
			number:    3,
			unwritten: []common.Hash{ringSlot(0), ringSlot(1), ringSlot(2)},
		},
		{
			name:      "a deploy past the serve window backfills every ring position",
			config:    pragueConfig(0),
			number:    8192,
			written:   []common.Hash{ringSlot(0), ringSlot(1), ringSlot(8190)},
			unwritten: nil,
		},
		{
			name:      "the backfill stops at the fork block and wraps around the ring",
			config:    pragueConfig(5000),
			number:    8193,
			written:   []common.Hash{ringSlot(4999), ringSlot(8190), ringSlot(0), ringSlot(1)},
			unwritten: []common.Hash{ringSlot(4998), ringSlot(2)},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			statedb := baseState(t, tc.withCode)
			number := big.NewInt(tc.number)
			for _, slot := range tc.written {
				require.True(t, historyStorageSlotIsWritten(tc.config, statedb, number, slot),
					"slot %v of block %d has to count as written", slot, tc.number)
			}
			for _, slot := range tc.unwritten {
				require.False(t, historyStorageSlotIsWritten(tc.config, statedb, number, slot),
					"slot %v of block %d has to count as left alone", slot, tc.number)
			}
		})
	}

	// A key the contract never reads, one with anything above the ring position, is left
	// alone whatever the block number is.
	statedb := baseState(t, false)
	require.False(t, historyStorageSlotIsWritten(pragueConfig(0), statedb, big.NewInt(8193), common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")))
}

// TestSimulateV1HistoryStorageStateOverride covers the account the EIP-2935 history
// contract lives in, the way TestSimulateV1Multicall3StateOverride covers Multicall3. The
// block writes the parent hash into the ring buffer after the caller's state overrides, so
// an override of the code, of the nonce of a contract the block deploys, or of a slot the
// block writes would either trip the consensus panic that guards a diverging contract or be
// silently undone by it. The fields the block does not write stay overridable.
func TestSimulateV1HistoryStorageStateOverride(t *testing.T) {
	t.Parallel()

	var (
		sender    = common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
		recipient = common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	)

	// newAPI builds a backend whose chain activates Prague at the genesis block, so the
	// first simulated block is one whose processing writes the history contract, over a
	// base state that either lacks the contract or already holds its canonical code.
	newAPI := func(t *testing.T, withCode bool) (*BlockChainAPI, *params.ChainConfig, *big.Int) {
		t.Helper()
		config := *params.MergedTestChainConfig
		alloc := types.GenesisAlloc{sender: {Balance: big.NewInt(params.Ether)}}
		if withCode {
			alloc[params.HistoryStorageAddress] = types.Account{Code: params.HistoryStorageCode}
		}
		genesis := &core.Genesis{Config: &config, Alloc: alloc}
		db := rawdb.NewMemoryDatabase()
		block := genesis.MustCommit(db)
		stateDB, err := state.New(block.Root(), state.NewDatabase(db))
		require.NoError(t, err)
		backend := &simulateBackendMock{
			estimateBackendMock: &estimateBackendMock{
				backendMock: newBackendMock(),
				stateDB:     stateDB,
				header:      block.Header(),
				engine:      ethash.NewFaker(),
			},
			gasCap: 30_000_000,
		}
		// The mock backend carries its own chain config, so Prague has to be scheduled
		// there too for the simulated block to take the block level Prague state changes.
		backend.config = &config
		return NewBlockChainAPI(backend, nil), &config, block.Number()
	}
	calls := []TransactionArgs{{From: &sender, To: &recipient, Value: (*hexutil.Big)(big.NewInt(1))}}
	simulate := func(t *testing.T, withCode bool, overrides override.StateOverride) error {
		t.Helper()
		api, config, base := newAPI(t, withCode)
		require.True(t, config.IsPrague(new(big.Int).Add(base, big.NewInt(1))),
			"the test chain must activate Prague at the first simulated block")
		_, err := api.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{{
			StateOverrides: &overrides,
			Calls:          calls,
		}}}, nil)
		return err
	}

	var (
		nonCanonicalCode = hexutil.Bytes(common.FromHex("0x60006000fd"))
		canonicalCode    = hexutil.Bytes(params.HistoryStorageCode)
		emptyCode        = hexutil.Bytes{}
		nonce            = (*hexutil.Uint64)(new(uint64))
		// The first simulated block writes the parent hash of the base block into the ring
		// position zero, the way the arithmetic in TestHistoryStorageWrittenSlots pins.
		writtenSlot   = common.Hash{}
		untouchedSlot = common.BigToHash(big.NewInt(1))
		slotValue     = common.BigToHash(big.NewInt(1))
	)
	for _, tc := range []struct {
		name     string
		withCode bool
		override override.OverrideAccount
	}{
		{"code diverging from the canonical runtime code", false, override.OverrideAccount{Code: &nonCanonicalCode}},
		{"empty code", false, override.OverrideAccount{Code: &emptyCode}},
		{"canonical code", false, override.OverrideAccount{Code: &canonicalCode}},
		{"nonce of a contract the block will deploy", false, override.OverrideAccount{Nonce: nonce}},
		{"the slot the block writes the parent hash into", false, override.OverrideAccount{StateDiff: map[common.Hash]common.Hash{writtenSlot: slotValue}}},
		{"a full storage replacement covering the slot the block writes", false, override.OverrideAccount{State: map[common.Hash]common.Hash{writtenSlot: slotValue}}},
	} {
		err := simulate(t, tc.withCode, override.StateOverride{params.HistoryStorageAddress: tc.override})
		var invalidReqErr *invalidParamsError
		require.ErrorAs(t, err, &invalidReqErr, tc.name)
		require.Contains(t, invalidReqErr.message, "history", tc.name)
	}

	// The block leaves the balance of the contract alone, it writes the slot of the parent
	// hash alone, and it does not touch an account it does not own.
	require.NoError(t, simulate(t, false, override.StateOverride{
		params.HistoryStorageAddress: override.OverrideAccount{Balance: (*hexutil.Big)(big.NewInt(1))},
	}), "the balance of the history contract stays overridable")
	require.NoError(t, simulate(t, false, override.StateOverride{
		params.HistoryStorageAddress: override.OverrideAccount{StateDiff: map[common.Hash]common.Hash{untouchedSlot: slotValue}},
	}), "a slot the block does not write stays overridable")
	require.NoError(t, simulate(t, false, override.StateOverride{
		recipient: override.OverrideAccount{Code: &nonCanonicalCode},
	}), "an account the block does not own stays overridable")

	// A contract the state already holds keeps its nonce: the block writes the slot of the
	// parent hash and leaves the account itself alone.
	require.NoError(t, simulate(t, true, override.StateOverride{
		params.HistoryStorageAddress: override.OverrideAccount{Nonce: nonce},
	}), "the nonce of a contract the state already holds stays overridable")
}

// TestSimulateV1BlockSignersStateOverride covers the account the TIPSigning activation
// owns. The block that activates TIPSigning removes the legacy block signers account after
// the caller's state overrides, so every field of an override of it at that block is undone
// and nothing in the response shows it. The removal happens at the activation block alone,
// so the account is overridable again from the block after it.
func TestSimulateV1BlockSignersStateOverride(t *testing.T) {
	t.Parallel()

	var (
		sender    = common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
		recipient = common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
		legacy    = common.BlockSignersBinary
	)

	// newAPI builds a backend whose chain activates TIPSigning in block #1 over a base
	// state that holds the legacy block signers account, the account the activation
	// removes. Every fork ordered after TIPSigning moves with it, because the config
	// rejects one taking effect before the forks that follow it, and they are all active
	// from the first block. Prague stays ahead of the simulated blocks so the EIP-2935
	// history contract, which the block level changes own as well, stays out of the way.
	newAPI := func(t *testing.T) (*BlockChainAPI, *params.ChainConfig) {
		t.Helper()
		config := *params.MergedTestChainConfig
		one := func() *big.Int { return big.NewInt(1) }
		config.TIPSigningBlock = one()
		config.TIPRandomizeBlock = one()
		config.TIPIncreaseMasternodesBlock = one()
		config.DenylistBlock = one()
		config.TIPNoHalvingMNRewardBlock = one()
		config.TIPXDCXBlock = one()
		config.TIPXDCXLendingBlock = one()
		config.TIPXDCXCancellationFeeBlock = one()
		config.TIPTRC21FeeBlock = one()
		config.Gas50xBlock = one()
		config.BerlinBlock = one()
		config.LondonBlock = one()
		config.MergeBlock = one()
		config.ShanghaiBlock = one()
		config.EIP1559Block = one()
		config.CancunBlock = one()
		// EIP-2935 stores the parent block hash in the state, which would put the history
		// contract in the picture as well, so the Prague forks stay ahead.
		config.PragueBlock = big.NewInt(10)
		config.OsakaBlock = big.NewInt(10)

		genesis := &core.Genesis{
			Config: &config,
			Alloc: types.GenesisAlloc{
				sender: {Balance: big.NewInt(params.Ether)},
				// The account comes from the genesis allocation so the base state is one
				// that holds it, the state the activation block runs on.
				legacy: {Balance: big.NewInt(1234)},
			},
		}
		db := rawdb.NewMemoryDatabase()
		block := genesis.MustCommit(db)
		stateDB, err := state.New(block.Root(), state.NewDatabase(db))
		require.NoError(t, err)
		backend := &simulateBackendMock{
			estimateBackendMock: &estimateBackendMock{
				backendMock: newBackendMock(),
				stateDB:     stateDB,
				header:      block.Header(),
				engine:      ethash.NewFaker(),
			},
			gasCap: 30_000_000,
		}
		backend.config = &config
		return NewBlockChainAPI(backend, nil), &config
	}
	calls := []TransactionArgs{{From: &sender, To: &recipient, Value: (*hexutil.Big)(big.NewInt(1))}}

	var (
		// Code that returns the word one, so a call to the account proves the override
		// landed: a removed account runs no code at all.
		code      = hexutil.Bytes{0x60, 0x01, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3}
		nonce     = (*hexutil.Uint64)(new(uint64))
		balance   = (*hexutil.Big)(big.NewInt(1))
		storage   = map[common.Hash]common.Hash{common.BigToHash(big.NewInt(1)): common.BigToHash(big.NewInt(1))}
		moved     = common.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")
		overrides = []struct {
			name     string
			override override.OverrideAccount
		}{
			{"code", override.OverrideAccount{Code: &code}},
			{"the nonce", override.OverrideAccount{Nonce: nonce}},
			{"the balance", override.OverrideAccount{Balance: balance}},
			{"storage", override.OverrideAccount{State: storage}},
			{"a storage diff", override.OverrideAccount{StateDiff: storage}},
			{"a precompile move", override.OverrideAccount{MovePrecompileTo: &moved}},
		}
	)
	for _, tc := range overrides {
		api, config := newAPI(t)
		require.Equal(t, big.NewInt(1), config.TIPSigningBlock, tc.name+" requires TIPSigning in the first simulated block")
		_, err := api.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{{
			StateOverrides: &override.StateOverride{legacy: tc.override},
			Calls:          calls,
		}}}, nil)
		var invalidReqErr *invalidParamsError
		require.ErrorAs(t, err, &invalidReqErr, tc.name)
		require.Contains(t, invalidReqErr.message, "TIPSigning", tc.name)
	}

	// The block after the activation one leaves the account alone, so the code the caller
	// sets there is the code a call to the account runs.
	api, _ := newAPI(t)
	results, err := api.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{{
		BlockOverrides: &override.BlockOverrides{Number: (*hexutil.Big)(big.NewInt(2))},
		StateOverrides: &override.StateOverride{legacy: override.OverrideAccount{Code: &code}},
		Calls:          []TransactionArgs{{From: &sender, To: &legacy}},
	}}}, nil)
	require.NoError(t, err)
	// The gap the jump to block #2 leaves is filled with an empty block #1, so the
	// activation runs before the block the override targets.
	require.Len(t, results, 2)

	type callSummary struct {
		Status      string `json:"status"`
		ReturnValue string `json:"returnData"`
	}
	type blockSummary struct {
		Calls []callSummary `json:"calls"`
	}
	enc, err := json.Marshal(results)
	require.NoError(t, err)
	var summary []blockSummary
	require.NoError(t, json.Unmarshal(enc, &summary))
	require.Len(t, summary[1].Calls, 1)
	require.Equal(t, "0x1", summary[1].Calls[0].Status)
	require.Equal(t, "0x0000000000000000000000000000000000000000000000000000000000000001", summary[1].Calls[0].ReturnValue)
}
