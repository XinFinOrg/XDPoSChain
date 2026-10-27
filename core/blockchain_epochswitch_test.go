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

package core

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// newChainOnMockSchedule opens a chain for a fixture whose schedule is outside
// the bound startup accepts: the chain is opened on the mock 900/450 schedule
// and switched over before the first insert. Only bc.chainConfig and the engine
// take the out-of-bound config; the header chain, validator and processor keep
// the mock schedule they were built with. Returns the chain and the mock
// genesis it was opened on.
func newChainOnMockSchedule(t *testing.T, cfg *params.ChainConfig, engine consensus.Engine, extraData []byte) (*BlockChain, *Genesis) {
	t.Helper()
	genesis := &Genesis{BaseFee: big.NewInt(params.InitialBaseFee), Config: params.TestXDPoSMockChainConfig.Clone(), ExtraData: extraData}
	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	chain.SetChainConfig(cfg)
	return chain, genesis
}

// TestNotifyEpochSwitchDoesNotReportABadBlock pins the policy of the notify path: a header whose
// epoch switch the engine cannot read is logged, never reported. The failure is unreachable through
// the import paths - engine_v2 decodes the same extra fields in verifyHeader, and engine_v1 never
// fails it - so the case is driven with a header of a block this node never verified, which is
// exactly the entry reportBlock used to write.
func TestNotifyEpochSwitchDoesNotReportABadBlock(t *testing.T) {
	cfg := params.TestXDPoSMockChainConfig.Clone()
	xdpos := *cfg.XDPoS
	xdpos.Epoch = 3
	xdpos.Gap = 0
	xdpos.SkipV1Validation = true
	cfg.XDPoS = &xdpos

	engine := XDPoS.NewFaker(rawdb.NewMemoryDatabase(), cfg)
	if engine == nil {
		t.Fatal("failed to create the XDPoS faker engine")
	}
	// An XDPoS genesis has to name signers, and the faker engine never reads them.
	extraData := make([]byte, 32)
	for _, signer := range []common.Address{{1}, {2}, {3}, {4}} {
		extraData = append(extraData, signer.Bytes()...)
	}
	chain, genesis := newChainOnMockSchedule(t, cfg, engine, extraData)
	defer chain.Stop()

	// Vanity only: no quorum certificate for the engine to read the epoch switch out of. The
	// number sits above the mock config's v2 switch, so the epoch switch is read out of the
	// extra, and is not the switch block itself, which is answered without reading anything.
	block := types.NewBlockWithHeader(&types.Header{
		ParentHash: genesis.ToBlock().Hash(),
		Number:     big.NewInt(901),
		Difficulty: big.NewInt(1),
		GasLimit:   genesis.GasLimit,
		Extra:      make([]byte, 32),
	})
	if _, _, err := engine.IsEpochSwitch(block.Header()); err == nil {
		t.Fatal("the fixture header has to be one the engine cannot read the epoch switch out of")
	}
	chain.notifyEpochSwitchBlock(block)

	if bad := rawdb.ReadBadBlock(chain.ChainDb(), block.Hash()); bad != nil {
		t.Fatalf("an epoch switch this node cannot read was written into the bad-block table: #%d", bad.NumberU64())
	}
}
