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
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestSimulateV1AppliesTIPSigningActivation verifies that eth_simulateV1 runs the block
// level state changes block processing performs before the first transaction of a block.
// TIPSigning removes the legacy block signers account at the block that activates it, and a
// simulation that starts from the parent state without removing it reports calls and a state
// root for a pre-state the chain never had.
//
// The fixture pins its premise by simulating the same block twice, once over a base state
// that holds the legacy account and once over one that does not: with the removal in place
// both simulations land on the same state root, and without it the first one keeps the
// account and lands elsewhere.
func TestSimulateV1AppliesTIPSigningActivation(t *testing.T) {
	t.Parallel()

	var (
		sender    = common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
		recipient = common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
		legacy    = common.BlockSignersBinary
	)

	// simulateBlock traces block #1 over a base state that optionally holds the legacy block
	// signers account. TIPSigning is activated in block #1, which makeHeaders numbers one
	// above the base block, so the simulation goes through the activation path.
	simulateBlock := func(t *testing.T, withLegacyAccount bool) common.Hash {
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

		// The legacy account has to come from the genesis allocation rather than from a state
		// override: DeleteAddress removes the account from the trie only, so an account the
		// overrides created in memory would be written back by the block finalisation.
		alloc := types.GenesisAlloc{
			sender: {Balance: big.NewInt(params.Ether)},
		}
		if withLegacyAccount {
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

		result, err := api.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{{
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

	withAccount := simulateBlock(t, true)
	withoutAccount := simulateBlock(t, false)
	if withAccount != withoutAccount {
		t.Fatalf("simulating the TIPSigning activation block over a base state holding the legacy block signers account ended on %x, want the same root as over one without it (%x): the block level removal was not applied", withAccount, withoutAccount)
	}
}
