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

// ringSlot builds a history storage key the way core.historyStorageKey does.
func ringSlot(position uint64) common.Hash {
	var key common.Hash
	binary.BigEndian.PutUint64(key[common.HashLength-8:], position)
	return key
}

// TestHistoryStorageWrittenSlots pins the slot arithmetic against core.ProcessParentBlockHash.
func TestHistoryStorageWrittenSlots(t *testing.T) {
	t.Parallel()

	baseState := func(t *testing.T, withCode bool) *state.StateDB {
		t.Helper()
		statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
		require.NoError(t, err)
		if withCode {
			statedb.SetCode(params.HistoryStorageAddress, params.HistoryStorageCode)
		}
		return statedb
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
			config:    pragueAt(0),
			number:    1,
			written:   []common.Hash{ringSlot(0)},
			unwritten: []common.Hash{ringSlot(1)},
		},
		{
			name:      "a later block writes the slot of its own parent hash",
			config:    pragueAt(0),
			number:    3,
			written:   []common.Hash{ringSlot(2)},
			unwritten: []common.Hash{ringSlot(0), ringSlot(1), ringSlot(3)},
		},
		{
			name:      "a contract the state already holds only gets the slot of its own parent hash",
			config:    pragueAt(0),
			withCode:  true,
			number:    3,
			written:   []common.Hash{ringSlot(2)},
			unwritten: []common.Hash{ringSlot(0), ringSlot(1), ringSlot(3)},
		},
		{
			name:      "the first Prague block of a later fork writes the slot of its parent",
			config:    pragueAt(10),
			number:    10,
			written:   []common.Hash{ringSlot(9)},
			unwritten: []common.Hash{ringSlot(0), ringSlot(10)},
		},
		{
			name:      "a deploy past the serve window backfills every ring position",
			config:    pragueAt(0),
			number:    8192,
			written:   []common.Hash{ringSlot(0), ringSlot(1), ringSlot(8190)},
			unwritten: []common.Hash{ringSlot(params.HistoryServeWindow), ringSlot(100000)},
		},
		{
			name:      "the backfill stops at the fork block and wraps around the ring",
			config:    pragueAt(5000),
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
	require.False(t, historyStorageSlotIsWritten(pragueAt(0), statedb, big.NewInt(8193), common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")))

	// A block below Prague runs no block level change, so go through the guard.
	t.Run("a block below Prague owns no slot", func(t *testing.T) {
		t.Parallel()
		config := pragueAt(10)
		statedb := baseState(t, false)
		header := &types.Header{Number: big.NewInt(3)}
		precompiles := vm.ActivePrecompiledContracts(config.Rules(header.Number))
		for ring := uint64(0); ring < 3; ring++ {
			require.NoError(t, rejectOwnedAccountOverrides(config, statedb, precompiles, header, requestSpan{lastBlock: big.NewInt(3)}, &override.StateOverride{
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
	newAPI := func(t *testing.T, withCode bool) (*BlockChainAPI, *params.ChainConfig) {
		t.Helper()
		config := *params.MergedTestChainConfig
		alloc := types.GenesisAlloc{sender: {Balance: big.NewInt(params.Ether)}}
		if withCode {
			alloc[params.HistoryStorageAddress] = types.Account{Code: params.HistoryStorageCode}
		}
		api, _ := newSimulateChain(t, &config, alloc)
		return api, &config
	}
	calls := []TransactionArgs{{From: &sender, To: &recipient, Value: (*hexutil.Big)(big.NewInt(1))}}
	simulate := func(t *testing.T, withCode bool, overrides override.StateOverride) error {
		t.Helper()
		api, config := newAPI(t, withCode)
		require.True(t, config.IsPrague(big.NewInt(1)),
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

	// newAPI activates TIPSigning in block #1.
	newAPI := func(t *testing.T) (*BlockChainAPI, *params.ChainConfig) {
		t.Helper()
		config := tipSigningAt(1)
		alloc := types.GenesisAlloc{
			sender: {Balance: big.NewInt(params.Ether)},
			legacy: {Balance: big.NewInt(1234)},
		}
		api, _ := newSimulateChain(t, config, alloc)
		return api, config
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

	enc, err := json.Marshal(results)
	require.NoError(t, err)
	var summary []simulateBlockSummary
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
		err := rejectOwnedAccountOverrides(&config, statedb, precompiles, header, requestSpan{lastBlock: header.Number}, &overrides)
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
		err := rejectOwnedAccountOverrides(&config, statedb, precompiles, header, requestSpan{lastBlock: header.Number}, &overrides)
		require.Error(t, err)
		require.Contains(t, err.Error(), fmt.Sprintf("storage slot %v", low), "the lowest written slot has to be named every time")
	}
}

// tipSigningAt returns a config that activates TIPSigning at the given block and moves every
// later fork with it, since the config rejects one taking effect earlier. Prague stays ahead
// at 10 to keep EIP-2935 out: it would write the history contract too.
func tipSigningAt(block int64) *params.ChainConfig {
	config := *params.MergedTestChainConfig
	at := func() *big.Int { return big.NewInt(block) }
	config.TIPSigningBlock = at()
	config.TIPRandomizeBlock = at()
	config.TIPIncreaseMasternodesBlock = at()
	config.DenylistBlock = at()
	config.TIPNoHalvingMNRewardBlock = at()
	config.TIPXDCXBlock = at()
	config.TIPXDCXLendingBlock = at()
	config.TIPXDCXCancellationFeeBlock = at()
	config.ConstantinopleBlock = at()
	config.PetersburgBlock = at()
	config.IstanbulBlock = at()
	config.TIPTRC21FeeBlock = at()
	config.Gas50xBlock = at()
	config.BerlinBlock = at()
	config.LondonBlock = at()
	config.MergeBlock = at()
	config.ShanghaiBlock = at()
	config.EIP1559Block = at()
	config.CancunBlock = at()
	config.PragueBlock = big.NewInt(10)
	config.OsakaBlock = big.NewInt(10)
	config.AmsterdamBlock = big.NewInt(10)
	return &config
}

// pragueAt returns a config that activates Prague and every later fork at the given
// block, since the config rejects one taking effect earlier.
func pragueAt(block int64) *params.ChainConfig {
	config := *params.MergedTestChainConfig
	config.PragueBlock = big.NewInt(block)
	config.OsakaBlock = big.NewInt(block)
	config.AmsterdamBlock = big.NewInt(block)
	return &config
}

// simulateCallSummary and simulateBlockSummary decode the response fields the tests assert on.
type simulateCallSummary struct {
	Status      string `json:"status"`
	ReturnValue string `json:"returnData"`
}

type simulateBlockSummary struct {
	Calls []simulateCallSummary `json:"calls"`
}

// newSimulateChain commits a genesis carrying alloc and returns an API whose simulated
// request starts at the block after it, together with the state the request runs on.
func newSimulateChain(t *testing.T, config *params.ChainConfig, alloc types.GenesisAlloc) (*BlockChainAPI, *state.StateDB) {
	t.Helper()
	genesis := &core.Genesis{Config: config, Alloc: alloc}
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
	// The mock backend carries its own config, so every fork has to be scheduled there too.
	backend.config = config
	return NewBlockChainAPI(backend, nil), stateDB
}

// threeBlockRequest builds a request over three blocks with the same calls everywhere and the
// given override on the block at index, if any.
func threeBlockRequest(calls []TransactionArgs, index int, overrides *override.StateOverride) simOpts {
	blocks := make([]simBlock, 3)
	for i := range blocks {
		blocks[i] = simBlock{Calls: calls}
	}
	blocks[index].StateOverrides = overrides
	return simOpts{BlockStateCalls: blocks}
}

// TestSimulateV1CrossBlockPragueOverride covers an override the request carries from a
// block before the Prague activation into the block that runs the Prague block level hooks.
func TestSimulateV1CrossBlockPragueOverride(t *testing.T) {
	t.Parallel()

	var (
		sender    = common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
		recipient = common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
		// Code diverging from the canonical runtime code trips the consensus check.
		diverging = hexutil.Bytes(common.FromHex("0x60006000fd"))
		calls     = []TransactionArgs{{From: &sender, To: &recipient, Value: (*hexutil.Big)(big.NewInt(1))}}
		alloc     = types.GenesisAlloc{sender: {Balance: big.NewInt(params.Ether)}}
	)

	// The request spans blocks #1 and #2 and Prague activates in #2: the override lands on
	// a block that does not own the account, and the shared state carries it into the one
	// that does. Every field the install at #2 overwrites is refused.
	zeroNonce := (*hexutil.Uint64)(new(uint64))
	for _, tc := range []struct {
		name     string
		address  common.Address
		override override.OverrideAccount
		field    string
	}{
		{"history code", params.HistoryStorageAddress, override.OverrideAccount{Code: &diverging}, "code"},
		{"multicall code", params.Multicall3Address, override.OverrideAccount{Code: &diverging}, "code"},
		{"history nonce of the contract the block deploys", params.HistoryStorageAddress, override.OverrideAccount{Nonce: zeroNonce}, "the nonce"},
		{"history storage replacement", params.HistoryStorageAddress, override.OverrideAccount{State: map[common.Hash]common.Hash{common.BigToHash(big.NewInt(1)): common.BigToHash(big.NewInt(1))}}, "a state replacement"},
		{"multicall nonce of the contract the block installs", params.Multicall3Address, override.OverrideAccount{Nonce: zeroNonce}, "the nonce"},
	} {
		api, _ := newSimulateChain(t, pragueAt(2), alloc)
		overrides := override.StateOverride{tc.address: tc.override}
		_, err := api.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{
			{StateOverrides: &overrides, Calls: calls},
			{Calls: calls},
		}}, nil)
		var invalidReqErr *invalidParamsError
		require.ErrorAs(t, err, &invalidReqErr, "%s: the install panic has to become a parameter error", tc.name)
		require.Contains(t, invalidReqErr.message, fmt.Sprintf("%v", tc.address), tc.name)
		require.Contains(t, invalidReqErr.message, tc.field, tc.name)
		require.Contains(t, invalidReqErr.message, "block 2 of the request writes it", tc.name)
	}

	// With no Prague block inside the request nothing carries the override into a block
	// level change, so the same override stays accepted.
	api, _ := newSimulateChain(t, pragueAt(10), alloc)
	overrides := override.StateOverride{params.HistoryStorageAddress: override.OverrideAccount{Code: &diverging}}
	_, err := api.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{
		{StateOverrides: &overrides, Calls: calls},
		{Calls: calls},
	}}, nil)
	require.NoError(t, err, "a request below Prague holds no block level change")

	// The precompile move rule stays with the block that runs the parent hash write: at an
	// earlier block the move only shadows the precompile for that block, so the write of a
	// later block still lands. Ring position 1 cannot show it: the activation block
	// backfills that slot with a state write, which survives the shadowing. Position 2 is
	// written by the parent hash call of block 3 alone, so it proves the write ran.
	shadows := params.HistoryStorageAddress
	moveAPI, moveState := newSimulateChain(t, pragueAt(2), alloc)
	_, err = moveAPI.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{
		{StateOverrides: &override.StateOverride{common.BytesToAddress([]byte{1}): {MovePrecompileTo: &shadows}}, Calls: calls},
		{Calls: calls},
		{Calls: calls},
	}}, nil)
	require.NoError(t, err, "a move before the activation block drops no parent hash write")
	require.NotEqual(t, common.Hash{}, moveState.GetState(params.HistoryStorageAddress, ringSlot(2)),
		"a move before the activation block must not shadow the parent hash write of block 3")

	// The Multicall3 install writes code and a nonce only, so a whole State replacement
	// survives it: unlike the history contract, there is no slot for it to wipe.
	stateAPI, _ := newSimulateChain(t, pragueAt(2), alloc)
	_, err = stateAPI.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{
		{StateOverrides: &override.StateOverride{params.Multicall3Address: override.OverrideAccount{
			State: map[common.Hash]common.Hash{common.BigToHash(big.NewInt(1)): common.BigToHash(big.NewInt(1))},
		}}, Calls: calls},
		{Calls: calls},
	}}, nil)
	require.NoError(t, err, "the Multicall3 install fills no storage slot, so a state replacement survives it")

	// The install leaves an account that already carries the canonical code alone, so an
	// override of a nonce no block writes lands instead of being refused.
	nonceAPI, nonceState := newSimulateChain(t, pragueAt(1), alloc)
	nonce := hexutil.Uint64(7)
	_, err = nonceAPI.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{
		{Calls: calls},
		{StateOverrides: &override.StateOverride{params.Multicall3Address: override.OverrideAccount{Nonce: &nonce}}, Calls: calls},
		{Calls: calls},
	}}, nil)
	require.NoError(t, err, "the install leaves the nonce of an account that already carries code")
	require.Equal(t, uint64(nonce), nonceState.GetNonce(params.Multicall3Address),
		"the override of a nonce no block writes has to land")
}

// TestSimulateV1CrossBlockBlockSignersOverride covers an override the request plants before
// the block that activates TIPSigning removes the block signers account.
func TestSimulateV1CrossBlockBlockSignersOverride(t *testing.T) {
	t.Parallel()

	var (
		sender    = common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
		recipient = common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
		legacy    = common.BlockSignersBinary
		// Code returning the word one, so a call proves the override landed.
		code  = hexutil.Bytes{0x60, 0x01, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3}
		calls = []TransactionArgs{{From: &sender, To: &recipient, Value: (*hexutil.Big)(big.NewInt(1))}}
		alloc = types.GenesisAlloc{
			sender: {Balance: big.NewInt(params.Ether)},
			legacy: {Balance: big.NewInt(1234)},
		}
	)
	storage := map[common.Hash]common.Hash{common.BigToHash(big.NewInt(1)): common.BigToHash(big.NewInt(1))}
	for _, tc := range []struct {
		name     string
		override override.OverrideAccount
	}{
		{"code", override.OverrideAccount{Code: &code}},
		{"the nonce", override.OverrideAccount{Nonce: (*hexutil.Uint64)(new(uint64))}},
		{"the balance", override.OverrideAccount{Balance: (*hexutil.Big)(big.NewInt(1))}},
		{"storage", override.OverrideAccount{State: storage}},
		// A replacement clears the slots the account holds before the activation block
		// removes it, so unlike at the activation block an empty map is not a no-op.
		{"an empty storage replacement", override.OverrideAccount{State: map[common.Hash]common.Hash{}}},
		{"a storage diff", override.OverrideAccount{StateDiff: storage}},
	} {
		api, _ := newSimulateChain(t, tipSigningAt(2), alloc)
		_, err := api.SimulateV1(context.Background(), threeBlockRequest(calls, 0, &override.StateOverride{legacy: tc.override}), nil)
		var invalidReqErr *invalidParamsError
		require.ErrorAs(t, err, &invalidReqErr, tc.name)
		require.Contains(t, invalidReqErr.message, "the block that activates TIPSigning at 2 removes the account with it", tc.name)
	}

	// The block that holds the activation itself keeps its wording and its rules: there the
	// same block removes the account, so an empty map sets no field that survives.
	api, _ := newSimulateChain(t, tipSigningAt(2), alloc)
	_, err := api.SimulateV1(context.Background(), threeBlockRequest(calls, 1, &override.StateOverride{
		legacy: override.OverrideAccount{State: map[common.Hash]common.Hash{}},
	}), nil)
	require.NoError(t, err, "the activation block removes the account before an empty map can matter")

	// The last block of the request can be the activation block itself: the shared state
	// still carries the override into the account removal, so the span is refused.
	api, _ = newSimulateChain(t, tipSigningAt(3), alloc)
	_, err = api.SimulateV1(context.Background(), threeBlockRequest(calls, 0, &override.StateOverride{
		legacy: override.OverrideAccount{Code: &code},
	}), nil)
	var boundaryErr *invalidParamsError
	require.ErrorAs(t, err, &boundaryErr, "an override on the first block of a request activating TIPSigning in its last block")
	require.Contains(t, boundaryErr.message, "the block that activates TIPSigning at 3 removes the account with it")

	// An activation block outside the request drops nothing: the account removal happens
	// after the last simulated block, so the override the request plants still lands.
	api, outsideState := newSimulateChain(t, tipSigningAt(4), alloc)
	_, err = api.SimulateV1(context.Background(), threeBlockRequest(calls, 0, &override.StateOverride{
		legacy: override.OverrideAccount{Code: &code},
	}), nil)
	require.NoError(t, err, "the activation block is outside the request, so the override survives it")
	require.Equal(t, []byte(code), outsideState.GetCode(legacy), "the override must still be in the state the request ran on")

	// The block after the activation one leaves the account alone, so the override lands.
	api, _ = newSimulateChain(t, tipSigningAt(2), alloc)
	results, err := api.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{
		{Calls: calls},
		{Calls: calls},
		{StateOverrides: &override.StateOverride{legacy: override.OverrideAccount{Code: &code}}, Calls: []TransactionArgs{{From: &sender, To: &legacy}}},
	}}, nil)
	require.NoError(t, err, "the block after the activation one leaves the account alone")

	enc, err := json.Marshal(results)
	require.NoError(t, err)
	var summary []simulateBlockSummary
	require.NoError(t, json.Unmarshal(enc, &summary))
	require.Len(t, summary, 3)
	require.Len(t, summary[2].Calls, 1)
	require.Equal(t, "0x1", summary[2].Calls[0].Status)
	require.Equal(t, "0x0000000000000000000000000000000000000000000000000000000000000001", summary[2].Calls[0].ReturnValue)
}

// TestSimulateV1CrossBlockHistorySlotOverride covers the ring positions the request writes
// after the block an override lands on. The request runs one state, so a later block's
// parent hash write replaces whatever the override put in the same ring position.
func TestSimulateV1CrossBlockHistorySlotOverride(t *testing.T) {
	t.Parallel()

	var (
		sender    = common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
		recipient = common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
		calls     = []TransactionArgs{{From: &sender, To: &recipient, Value: (*hexutil.Big)(big.NewInt(1))}}
		slotValue = common.BigToHash(big.NewInt(1))
	)
	// Prague activates in block #2, so a request over blocks #1..#3 holds the deploy and
	// backfill in #2 (ring position 1) and the parent hash write of #3 (ring position 2).
	alloc := types.GenesisAlloc{sender: {Balance: big.NewInt(params.Ether)}}

	for _, tc := range []struct {
		name  string
		index int
		slot  common.Hash
		want  string
	}{
		{
			name:  "a slot the activation block writes",
			index: 0,
			slot:  ringSlot(1),
			want:  "block 2 of the request writes it",
		},
		{
			name:  "a slot a later block writes",
			index: 0,
			slot:  ringSlot(2),
			want:  "block 3 of the request writes it",
		},
		{
			// The activation block owns the account but not this slot: a later block writes
			// it, which the single block guard could not see before the request view.
			name:  "a slot owned by a block later than the one holding the override",
			index: 1,
			slot:  ringSlot(2),
			want:  "block 3 of the request writes it",
		},
		{
			name:  "a slot no block of the request writes",
			index: 0,
			slot:  ringSlot(0),
			want:  "",
		},
	} {
		api, _ := newSimulateChain(t, pragueAt(2), alloc)
		_, err := api.SimulateV1(context.Background(), threeBlockRequest(calls, tc.index, &override.StateOverride{
			params.HistoryStorageAddress: override.OverrideAccount{StateDiff: map[common.Hash]common.Hash{tc.slot: slotValue}},
		}), nil)
		if tc.want == "" {
			require.NoError(t, err, tc.name)
			continue
		}
		var invalidReqErr *invalidParamsError
		require.ErrorAs(t, err, &invalidReqErr, tc.name)
		require.Contains(t, invalidReqErr.message, tc.want, tc.name)
		require.Contains(t, invalidReqErr.message, fmt.Sprintf("%v", params.HistoryStorageAddress), tc.name)
	}
}
