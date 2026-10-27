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
	"fmt"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/hexutil"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/internal/ethapi/override"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/require"
)

// TestHistoryStorageWrittenSlots pins the slot arithmetic against core.ProcessParentBlockHash.
func TestHistoryStorageWrittenSlots(t *testing.T) {
	t.Parallel()

	// ringSlot builds a key the way core.historyStorageKey does.
	ringSlot := func(position uint64) common.Hash {
		var key common.Hash
		binary.BigEndian.PutUint64(key[common.HashLength-8:], position)
		return key
	}
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
	coreWrote := func(t *testing.T, config *params.ChainConfig, withCode bool, number int64) map[uint64]bool {
		t.Helper()
		statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
		require.NoError(t, err)
		if withCode {
			statedb.SetCode(params.HistoryStorageAddress, params.HistoryStorageCode)
		}
		evm := vm.NewEVM(vm.BlockContext{
			CanTransfer: core.CanTransfer,
			Transfer:    core.Transfer,
			// A non-zero hash for every block, so the backfill resolves every slot.
			GetHash:     func(n uint64) common.Hash { return common.BigToHash(new(big.Int).SetUint64(n + 1)) },
			BlockNumber: big.NewInt(number),
			Difficulty:  big.NewInt(0),
			GasLimit:    30_000_000,
			BaseFee:     big.NewInt(0),
		}, statedb, nil, config, vm.Config{})
		core.ProcessParentBlockHash(common.BigToHash(big.NewInt(0xabc)), evm)

		written := make(map[uint64]bool)
		for ring := uint64(0); ring < params.HistoryServeWindow; ring++ {
			if statedb.GetState(params.HistoryStorageAddress, ringSlot(ring)) != (common.Hash{}) {
				written[ring] = true
			}
		}
		return written
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
			name:      "the first Prague block of a later fork writes the slot of its parent",
			config:    pragueConfig(10),
			number:    10,
			written:   []common.Hash{ringSlot(9)},
			unwritten: []common.Hash{ringSlot(0), ringSlot(10)},
		},
		{
			name:      "a deploy past the serve window backfills every ring position",
			config:    pragueConfig(0),
			number:    8192,
			written:   []common.Hash{ringSlot(0), ringSlot(1), ringSlot(8190)},
			unwritten: []common.Hash{ringSlot(params.HistoryServeWindow), ringSlot(100000)},
		},
		{
			name:      "the backfill stops at the fork block and wraps around the ring",
			config:    pragueConfig(5000),
			number:    8193,
			written:   []common.Hash{ringSlot(4999), ringSlot(8190), ringSlot(0), ringSlot(1)},
			unwritten: []common.Hash{ringSlot(4998), ringSlot(2), ringSlot(params.HistoryServeWindow)},
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
			// Read the ring positions back from core, which the guard has to agree with.
			written := coreWrote(t, tc.config, tc.withCode, tc.number)
			for ring := uint64(0); ring < params.HistoryServeWindow; ring++ {
				require.Equal(t, written[ring], historyStorageSlotIsWritten(tc.config, statedb, number, ringSlot(ring)),
					"ring position %d of block %d: the guard and core disagree", ring, tc.number)
			}
		})
	}

	statedb := baseState(t, false)
	require.False(t, historyStorageSlotIsWritten(pragueConfig(0), statedb, big.NewInt(8193), common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")))

	// A block below Prague runs no block level change, so go through the guard.
	t.Run("a block below Prague owns no slot", func(t *testing.T) {
		t.Parallel()
		config := pragueConfig(10)
		statedb := baseState(t, false)
		header := &types.Header{Number: big.NewInt(3)}
		precompiles := vm.ActivePrecompiledContracts(config.Rules(header.Number))
		for ring := uint64(0); ring < 3; ring++ {
			require.NoError(t, rejectOwnedAccountOverrides(config, statedb, precompiles, header, &override.StateOverride{
				params.HistoryStorageAddress: override.OverrideAccount{
					StateDiff: map[common.Hash]common.Hash{ringSlot(ring): common.BigToHash(big.NewInt(1))},
				},
			}), "ring position %d of a block below Prague has to stay overridable", ring)
		}
	})
}

// TestSimulateV1HistoryStorageStateOverride covers the EIP-2935 history account.
func TestSimulateV1HistoryStorageStateOverride(t *testing.T) {
	t.Parallel()

	var (
		sender    = common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
		recipient = common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	)

	// newAPI builds a chain that activates Prague at genesis.
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
		// The mock backend carries its own config, so Prague has to be scheduled there too.
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
		// The first simulated block writes its parent hash into ring position zero.
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
		// A full replacement sets every slot, so it cannot omit the one the block writes.
		{"a full storage replacement that omits the slot the block writes", false, override.OverrideAccount{State: map[common.Hash]common.Hash{untouchedSlot: slotValue}}},
		{"an empty storage replacement", false, override.OverrideAccount{State: map[common.Hash]common.Hash{}}},
	} {
		err := simulate(t, tc.withCode, override.StateOverride{params.HistoryStorageAddress: tc.override})
		var invalidReqErr *invalidParamsError
		require.ErrorAs(t, err, &invalidReqErr, tc.name)
		require.Contains(t, invalidReqErr.message, "history", tc.name)
	}

	// A move onto the contract shadows it, so the parent hash write is dropped. The move is
	// issued on the precompile's own address, so the guard looks at the destination.
	movedToHistory := params.HistoryStorageAddress
	err := simulate(t, false, override.StateOverride{
		common.BytesToAddress([]byte{1}): {MovePrecompileTo: &movedToHistory},
	})
	var invalidReqErr *invalidParamsError
	require.ErrorAs(t, err, &invalidReqErr, "a precompile moved onto the history contract")
	require.Contains(t, invalidReqErr.message, "history", "a precompile moved onto the history contract")

	// A source the EVM does not serve as a precompile cannot shadow the contract, so the
	// guard leaves the move to override.Apply, which reports the account as invalid.
	err = simulate(t, false, override.StateOverride{
		common.HexToAddress("0xdead"): {MovePrecompileTo: &movedToHistory},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a precompile")
	require.NotContains(t, err.Error(), "history write owns")

	// The balance, the other slots and foreign accounts stay overridable.
	require.NoError(t, simulate(t, false, override.StateOverride{
		params.HistoryStorageAddress: override.OverrideAccount{Balance: (*hexutil.Big)(big.NewInt(1))},
	}), "the balance of the history contract stays overridable")
	require.NoError(t, simulate(t, false, override.StateOverride{
		params.HistoryStorageAddress: override.OverrideAccount{StateDiff: map[common.Hash]common.Hash{untouchedSlot: slotValue}},
	}), "a slot the block does not write stays overridable")
	require.NoError(t, simulate(t, false, override.StateOverride{
		recipient: override.OverrideAccount{Code: &nonCanonicalCode},
	}), "an account the block does not own stays overridable")

	require.NoError(t, simulate(t, true, override.StateOverride{
		params.HistoryStorageAddress: override.OverrideAccount{Nonce: nonce},
	}), "the nonce of a contract the state already holds stays overridable")

	// Only a zero nonce is raised, so a nonzero one survives.
	nonzeroNonce := hexutil.Uint64(5)
	require.NoError(t, simulate(t, false, override.StateOverride{
		params.HistoryStorageAddress: override.OverrideAccount{Nonce: &nonzeroNonce},
	}), "a nonzero nonce of a contract the block deploys stays overridable")

	installedNonce := hexutil.Uint64(1)
	require.NoError(t, simulate(t, false, override.StateOverride{
		params.HistoryStorageAddress: override.OverrideAccount{Nonce: &installedNonce},
	}), "the nonce the install writes stays overridable when the caller sets it")
}

// TestSimulateV1BlockSignersStateOverride covers the account TIPSigning removes.
func TestSimulateV1BlockSignersStateOverride(t *testing.T) {
	t.Parallel()

	var (
		sender    = common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
		recipient = common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
		legacy    = common.BlockSignersBinary
	)

	// newAPI activates TIPSigning in block #1. Every later fork moves with it, since the
	// config rejects one taking effect earlier; Prague stays ahead to keep EIP-2935 out.
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
		config.ConstantinopleBlock = one()
		config.PetersburgBlock = one()
		config.IstanbulBlock = one()
		config.TIPTRC21FeeBlock = one()
		config.Gas50xBlock = one()
		config.BerlinBlock = one()
		config.LondonBlock = one()
		config.MergeBlock = one()
		config.ShanghaiBlock = one()
		config.EIP1559Block = one()
		config.CancunBlock = one()
		// EIP-2935 would write the history contract too, so Prague stays ahead.
		config.PragueBlock = big.NewInt(10)
		config.OsakaBlock = big.NewInt(10)
		config.AmsterdamBlock = big.NewInt(10)

		genesis := &core.Genesis{
			Config: &config,
			Alloc: types.GenesisAlloc{
				sender: {Balance: big.NewInt(params.Ether)},
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
		// Code returning the word one, so a call proves the override landed.
		code      = hexutil.Bytes{0x60, 0x01, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3}
		nonce     = (*hexutil.Uint64)(new(uint64))
		balance   = (*hexutil.Big)(big.NewInt(1))
		storage   = map[common.Hash]common.Hash{common.BigToHash(big.NewInt(1)): common.BigToHash(big.NewInt(1))}
		overrides = []struct {
			name     string
			override override.OverrideAccount
		}{
			{"code", override.OverrideAccount{Code: &code}},
			{"the nonce", override.OverrideAccount{Nonce: nonce}},
			{"the balance", override.OverrideAccount{Balance: balance}},
			{"storage", override.OverrideAccount{State: storage}},
			{"a storage diff", override.OverrideAccount{StateDiff: storage}},
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

	// A move from the account is not a field the block removes: the account is not a
	// precompile, so override.Apply rejects the move itself and the guard leaves it there.
	moveAPI, _ := newAPI(t)
	moved := common.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")
	_, err := moveAPI.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{{
		StateOverrides: &override.StateOverride{legacy: override.OverrideAccount{MovePrecompileTo: &moved}},
		Calls:          calls,
	}}}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a precompile")
	require.NotContains(t, err.Error(), "TIPSigning")

	// An empty map sets no field, so these go through.
	for _, empty := range []override.OverrideAccount{
		{State: map[common.Hash]common.Hash{}},
		{StateDiff: map[common.Hash]common.Hash{}},
	} {
		api, _ := newAPI(t)
		_, err := api.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{{
			StateOverrides: &override.StateOverride{legacy: empty},
			Calls:          calls,
		}}}, nil)
		require.NoError(t, err, "an empty map sets no field")
	}

	// The block after the activation one leaves the account alone, so its code runs.
	api, _ := newAPI(t)
	results, err := api.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{{
		BlockOverrides: &override.BlockOverrides{Number: (*hexutil.Big)(big.NewInt(2))},
		StateOverrides: &override.StateOverride{legacy: override.OverrideAccount{Code: &code}},
		Calls:          []TransactionArgs{{From: &sender, To: &legacy}},
	}}}, nil)
	require.NoError(t, err)
	// The jump to block #2 fills the gap with an empty block #1, so the activation runs first.
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

// TestPrecompileMoveGuardIsStable pins the address order the move rule reports in.
func TestPrecompileMoveGuardIsStable(t *testing.T) {
	t.Parallel()

	config := *params.MergedTestChainConfig
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
	require.NoError(t, err)
	header := &types.Header{Number: big.NewInt(1)}
	precompiles := vm.ActivePrecompiledContracts(config.Rules(header.Number))
	history := params.HistoryStorageAddress
	low, high := common.BytesToAddress([]byte{1}), common.BytesToAddress([]byte{2})
	overrides := override.StateOverride{
		low:  {MovePrecompileTo: &history},
		high: {MovePrecompileTo: &history},
	}
	// The error renders the source with %v (0x form), not Address.Hex() (xdc-prefixed).
	source := fmt.Sprintf("%v", low)
	for i := 0; i < 50; i++ {
		err := rejectOwnedAccountOverrides(&config, statedb, precompiles, header, &overrides)
		require.Error(t, err)
		require.Contains(t, err.Error(), source, "the lowest source address has to be named every time")
	}
}

// TestStateDiffGuardIsStable pins the slot the stateDiff rule names: when the diff lists
// more than one slot the block writes, the error has to name the lowest one every time.
func TestStateDiffGuardIsStable(t *testing.T) {
	t.Parallel()

	config := *params.MergedTestChainConfig
	config.PragueBlock = big.NewInt(5000)
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
	require.NoError(t, err)
	// Block 8193 deploys the contract over a state without code, so the backfill covers
	// blocks 4999..8192 and writes both ring positions 0 and 1.
	header := &types.Header{Number: big.NewInt(8193)}
	ringSlot := func(position uint64) common.Hash {
		var key common.Hash
		binary.BigEndian.PutUint64(key[common.HashLength-8:], position)
		return key
	}
	low, high := ringSlot(0), ringSlot(1)
	overrides := override.StateOverride{
		params.HistoryStorageAddress: override.OverrideAccount{
			StateDiff: map[common.Hash]common.Hash{
				high: common.BigToHash(big.NewInt(1)),
				low:  common.BigToHash(big.NewInt(1)),
			},
		},
	}
	precompiles := vm.ActivePrecompiledContracts(config.Rules(header.Number))
	for i := 0; i < 50; i++ {
		err := rejectOwnedAccountOverrides(&config, statedb, precompiles, header, &overrides)
		require.Error(t, err)
		require.Contains(t, err.Error(), fmt.Sprintf("storage slot %v", low), "the lowest written slot has to be named every time")
	}
}
