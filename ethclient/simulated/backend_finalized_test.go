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

package simulated

import (
	"context"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rpc"
)

// The simulated backend's own constructor panics on a chain that is v2 from the
// genesis block, so the chain is set up here directly and the filter backend is
// assembled from it, the same way eth.TestFinalizedBlockNumberWithoutCommittedBlock
// covers the same guard on the production backend.
func TestFilterBackendHeaderByNumberWithoutCommittedBlock(t *testing.T) {
	// The mock config switches to v2 after block 900. Below the genesis block the
	// engine is v2 from block 0, so the v2 branch needs no generated chain.
	cfg := params.TestXDPoSMockChainConfig.Clone()
	cfg.XDPoS.Epoch = 1
	cfg.XDPoS.V2.SwitchBlock = big.NewInt(-1)

	gspec := &core.Genesis{
		Config:     cfg,
		Alloc:      types.GenesisAlloc{},
		Difficulty: common.Big0,
		BaseFee:    big.NewInt(params.InitialBaseFee),
		ExtraData:  append(make([]byte, 32), make([]byte, crypto.SignatureLength)...),
	}
	db := rawdb.NewMemoryDatabase()
	engine := XDPoS.NewFaker(db, cfg)
	chain, err := core.NewBlockChain(db, nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	t.Cleanup(chain.Stop)

	if got := chain.Config().XDPoS.BlockConsensusVersion(chain.CurrentBlock().Number); got != params.ConsensusEngineVersion2 {
		t.Fatalf("test setup needs an active v2 engine, have consensus version %q", got)
	}
	if info := engine.EngineV2.GetLatestCommittedBlockInfo(); info != nil {
		t.Fatalf("test setup needs an engine without committed block info, have %v", info)
	}

	const wantErr = "no committed block info available yet"
	fb := &filterBackend{bc: chain}
	header, err := fb.HeaderByNumber(context.Background(), rpc.FinalizedBlockNumber)
	if header != nil || err == nil || err.Error() != wantErr {
		t.Fatalf("HeaderByNumber on the finalized tag: have (%v, %v), want (nil, %q)", header, err, wantErr)
	}
}
