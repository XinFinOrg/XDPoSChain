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

package gasestimator

import (
	"context"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

type testChainContext struct {
	engine consensus.Engine
}

func (c *testChainContext) Engine() consensus.Engine {
	return c.engine
}

func (c *testChainContext) GetHeader(common.Hash, uint64) *types.Header {
	return nil
}

func TestEstimateCapsHiAtMaxTxGasOnOsaka(t *testing.T) {
	t.Parallel()

	from := common.HexToAddress("0x1001")
	to := common.HexToAddress("0x1002")

	genesis := &core.Genesis{
		Config: params.MergedTestChainConfig,
		Alloc: types.GenesisAlloc{
			from: {Balance: big.NewInt(params.Ether)},
		},
	}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)

	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}

	header := types.CopyHeader(block.Header())
	header.GasLimit = params.MaxTxGas + 100000

	opts := &Options{
		Config: params.MergedTestChainConfig,
		Chain:  &testChainContext{engine: ethash.NewFaker()},
		Header: header,
		State:  stateDB,
	}
	msg := &core.Message{
		From:                  from,
		To:                    &to,
		Nonce:                 0,
		Value:                 new(big.Int),
		GasLimit:              header.GasLimit,
		GasPrice:              new(big.Int),
		GasFeeCap:             new(big.Int),
		GasTipCap:             new(big.Int),
		SkipNonceChecks:       false,
		SkipTransactionChecks: false,
	}

	estimate, _, err := Estimate(context.Background(), msg, opts, 0)
	if err != nil {
		t.Fatalf("estimate should not fail when hi is capped at maxTxGas: %v", err)
	}
	if estimate > params.MaxTxGas {
		t.Fatalf("estimate exceeds maxTxGas: got %d, max %d", estimate, params.MaxTxGas)
	}
}
