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
)

// TestSimulateV1AppliesTIPSigningActivation verifies that eth_simulateV1 runs the block
// level state changes block processing performs before the first transaction of a block.
// TIPSigning removes the legacy block signers account at the block that activates it, and a
// simulation that starts from the parent state without removing it reports calls and a state
// root for a pre-state the chain never had.
//
// The fixture pins its premise by simulating the same block over base states that differ
// only in where the legacy account comes from: absent, part of the base state, or supplied
// by a state override. With the removal in place all three land on the same state root;
// without it the runs that hold the account keep it and land elsewhere. The override run
// matters because the override is applied to the base state before the block level removal,
// so DeleteAddress evicts the overridden account from the session cache as well.
func TestSimulateV1AppliesTIPSigningActivation(t *testing.T) {
	t.Parallel()

	var (
		sender    = common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
		recipient = common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
		legacy    = common.BlockSignersBinary
	)

	// legacySource says where the legacy block signers account comes from in a run.
	type legacySource int
	const (
		legacyAbsent legacySource = iota
		legacyInState
		legacyOverridden
	)

	// simulateBlock traces block #1 over a base state that optionally holds the legacy block
	// signers account. TIPSigning is activated in block #1, which makeHeaders numbers one
	// above the base block, so the simulation goes through the activation path.
	simulateBlock := func(t *testing.T, source legacySource) common.Hash {
		t.Helper()

		config := *params.MergedTestChainConfig
		// TIPSigning is activated in block #1. Every fork ordered after it moves with it,
		// because the config rejects one taking effect before the forks that follow it, and
		// they are all active from the first block.
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
		// Prague stays off: EIP-2935 stores the parent block hash in the state, and the two
		// runs have different base blocks (their state roots differ), which would land in the
		// roots compared below for a reason that has nothing to do with TIPSigning.
		config.PragueBlock = big.NewInt(10)
		config.OsakaBlock = big.NewInt(10)
		// Amsterdam stays unset as well: it adds no state writes, so scheduling it
		// would only extend the run to a fork it does not exercise.
		config.AmsterdamBlock = nil

		// The base state carries the legacy account only for the in-state run; the override
		// run supplies it through the request instead, so the two paths stay apart and the
		// override run can show that an in-memory account is removed too.
		alloc := types.GenesisAlloc{
			sender: {Balance: big.NewInt(params.Ether)},
		}
		if source == legacyInState {
			alloc[legacy] = types.Account{Balance: big.NewInt(1234)}
		}
		genesis := &core.Genesis{Config: &config, Alloc: alloc}
		db := rawdb.NewMemoryDatabase()
		block := genesis.MustCommit(db)
		statedb, err := state.New(block.Root(), state.NewDatabase(db))
		if err != nil {
			t.Fatalf("failed to create state db: %v", err)
		}
		backend := &simulateBackendMock{
			estimateBackendMock: &estimateBackendMock{
				backendMock: newBackendMock(),
				stateDB:     statedb,
				header:      block.Header(),
				engine:      ethash.NewFaker(),
			},
			gasCap: 30_000_000,
		}
		backend.config = &config
		api := NewBlockChainAPI(backend, nil)

		var stateOverrides *override.StateOverride
		if source == legacyOverridden {
			overrides := override.StateOverride{
				legacy: {Balance: (*hexutil.Big)(big.NewInt(1234))},
			}
			stateOverrides = &overrides
		}
		result, err := api.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{{
			StateOverrides: stateOverrides,
			Calls: []TransactionArgs{{
				From:  &sender,
				To:    &recipient,
				Value: (*hexutil.Big)(big.NewInt(1)),
			}},
		}}}, nil)
		if err != nil {
			t.Fatalf("failed to simulate the TIPSigning activation block: %v", err)
		}
		if len(result) != 1 {
			t.Fatalf("expected 1 simulated block, got %d", len(result))
		}
		root, ok := result[0]["stateRoot"].(common.Hash)
		if !ok {
			t.Fatalf("unexpected simulated state root type %T", result[0]["stateRoot"])
		}
		return root
	}

	withAccount := simulateBlock(t, legacyInState)
	withoutAccount := simulateBlock(t, legacyAbsent)
	if withAccount != withoutAccount {
		t.Fatalf("simulating the TIPSigning activation block over a base state holding the legacy block signers account ended on %x, want the same root as over one without it (%x): the block level removal was not applied", withAccount, withoutAccount)
	}
	// The override is applied to the base state before the block level removal runs, and
	// DeleteAddress evicts the account from the session cache, so an account that only the
	// override put in memory is removed as well.
	overridden := simulateBlock(t, legacyOverridden)
	if overridden != withoutAccount {
		t.Fatalf("simulating the TIPSigning activation block with the legacy block signers account supplied by a state override ended on %x, want the same root as over a base state without it (%x): the block level removal did not drop the overridden account", overridden, withoutAccount)
	}
}
