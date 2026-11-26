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

// RED-first test for EIP-8131 §Backwards Compatibility / §Security
// Considerations: eth_estimateGas MUST compute the transaction content floor
// and never return an estimate below tx_floor (approved design assumption 4).
// Under the proposed Bogotá gate a 1,000-byte payload has
// tx_floor = 21,000 + 64×1,000 = 85,000, while execution needs only
// 21,000 + 16×1,000 = 37,000. RED today: the estimator has no floor logic and
// returns the execution-level estimate.

package gasestimator

import (
	"bytes"
	"context"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/types/bal"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

// eip8131ChainContext is a minimal core.ChainContext: headers are never
// looked up (the payload issues no BLOCKHASH) and the engine only serves
// coinbase resolution in NewEVMBlockContext.
type eip8131ChainContext struct {
	cfg *params.ChainConfig
}

func (c *eip8131ChainContext) Config() *params.ChainConfig { return c.cfg }
func (c *eip8131ChainContext) CurrentHeader() *types.Header {
	return &types.Header{Number: big.NewInt(0)}
}
func (c *eip8131ChainContext) GetHeader(common.Hash, uint64) *types.Header { return nil }
func (c *eip8131ChainContext) GetHeaderByNumber(uint64) *types.Header      { return nil }
func (c *eip8131ChainContext) GetHeaderByHash(common.Hash) *types.Header   { return nil }
func (c *eip8131ChainContext) GetBlock(common.Hash, uint64) *types.Block   { return nil }
func (c *eip8131ChainContext) Engine() consensus.Engine                    { return eip8131Engine{} }

type eip8131Engine struct{}

func (eip8131Engine) Author(*types.Header) (common.Address, error) { return common.Address{}, nil }
func (eip8131Engine) VerifyHeader(consensus.ChainHeaderReader, *types.Header) error {
	return nil
}
func (eip8131Engine) VerifyHeaders(consensus.ChainHeaderReader, []*types.Header) (chan<- struct{}, <-chan error) {
	return nil, nil
}
func (eip8131Engine) VerifyUncles(consensus.ChainReader, *types.Block) error { return nil }
func (eip8131Engine) Prepare(consensus.ChainHeaderReader, *types.Header) error {
	return nil
}
func (eip8131Engine) Finalize(consensus.ChainHeaderReader, *types.Header, vm.StateDB, *types.Body, uint32, *bal.ConstructionBlockAccessList) {
}
func (eip8131Engine) Seal(consensus.ChainHeaderReader, *types.Block, chan<- *types.Block, <-chan struct{}) error {
	return nil
}
func (eip8131Engine) SealHash(*types.Header) common.Hash { return common.Hash{} }
func (eip8131Engine) CalcDifficulty(consensus.ChainHeaderReader, uint64, *types.Header) *big.Int {
	return big.NewInt(0)
}
func (eip8131Engine) Close() error { return nil }

func TestEIP8131R3EstimateGasCoversFloor(t *testing.T) {
	cfg := *params.MergedTestChainConfig
	cfg.PragueTime, cfg.PragueBlock = nil, nil
	cfg.BogotaTime = new(uint64) // zero time → Bogotá active
	cfg.AmsterdamTime = nil

	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	to := common.HexToAddress("0x00000000000000000000000000000000000dead1")
	call := &core.Message{
		From:                  common.HexToAddress("0x00000000000000000000000000000000000beef1"),
		To:                    &to,
		Value:                 uint256.NewInt(0),
		GasFeeCap:             uint256.NewInt(0),
		GasTipCap:             uint256.NewInt(0),
		GasPrice:              uint256.NewInt(0),
		Data:                  bytes.Repeat([]byte{1}, 1000),
		SkipNonceChecks:       true,
		SkipTransactionChecks: true,
	}
	header := &types.Header{
		Number:        big.NewInt(1),
		Time:          0,
		GasLimit:      10_000_000,
		Difficulty:    big.NewInt(1),
		BaseFee:       big.NewInt(0),
		ExcessBlobGas: new(uint64), // Cancun is active on the test config
		BlobGasUsed:   new(uint64),
	}
	// RED: the estimate carries no floor logic — the binary search converges
	// on the execution requirement (~37,000), below the spec floor of 79,000
	// (A1: 15,000 anchor).
	est, _, err := Estimate(context.Background(), call, &Options{
		Config:     &cfg,
		Chain:      &eip8131ChainContext{cfg: &cfg},
		Header:     header,
		State:      statedb,
		ErrorRatio: 0.0,
	}, 10_000_000)
	if err != nil {
		t.Fatalf("Estimate failed: %v", err)
	}
	const floor = uint64(15_000) + 64*1000
	if est < floor {
		t.Fatalf("estimate = %d, want >= spec floor %d (estimator ignores the EIP-8131 floor)", est, floor)
	}
}
