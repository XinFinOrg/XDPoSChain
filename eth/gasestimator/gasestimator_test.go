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
	"errors"
	"fmt"
	"math/big"
	"strings"
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

	// Amsterdam replaces the EIP-7825 cap with the EIP-8037 total cap, so pin
	// the Osaka-only rules this test is about.
	osaka := params.MergedTestChainConfig.Clone()
	osaka.AmsterdamBlock = nil

	genesis := &core.Genesis{
		Config: osaka,
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
		Config: osaka,
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

// TestEstimateHonoursBaseGasCap checks that the caller's gas cap is measured
// against the transaction base of the active fork: on Amsterdam a 14,000 cap is
// above the EIP-2780 base and therefore honoured, so a call needing 15,000 fails
// instead of being re-estimated against the header limit; before Amsterdam the
// same cap is below the flat 21,000 and raised to the header limit.
func TestEstimateHonoursBaseGasCap(t *testing.T) {
	t.Parallel()

	from := common.HexToAddress("0x1001")
	to := common.HexToAddress("0x1002")

	preAmsterdam := params.MergedTestChainConfig.Clone()
	preAmsterdam.AmsterdamBlock = nil

	for _, tt := range []struct {
		name    string
		config  *params.ChainConfig
		wantErr string
	}{
		{"amsterdam", params.MergedTestChainConfig, "gas required exceeds allowance (14000)"},
		{"pre-amsterdam", preAmsterdam, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			genesis := &core.Genesis{
				Config: tt.config,
				Alloc:  types.GenesisAlloc{from: {Balance: big.NewInt(params.Ether)}},
			}
			db := rawdb.NewMemoryDatabase()
			block := genesis.MustCommit(db)

			stateDB, err := state.New(block.Root(), state.NewDatabase(db))
			if err != nil {
				t.Fatalf("failed to create state db: %v", err)
			}
			header := types.CopyHeader(block.Header())
			header.GasLimit = 8_000_000

			opts := &Options{
				Config: tt.config,
				Chain:  &testChainContext{engine: ethash.NewFaker()},
				Header: header,
				State:  stateDB,
			}
			msg := &core.Message{
				From:      from,
				To:        &to,
				Value:     new(big.Int),
				GasLimit:  14_000,
				GasPrice:  new(big.Int),
				GasFeeCap: new(big.Int),
				GasTipCap: new(big.Int),
			}
			estimate, _, err := Estimate(context.Background(), msg, opts, 0)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if estimate != params.TxGas {
				t.Fatalf("estimate = %d, want %d", estimate, params.TxGas)
			}
		})
	}
}

// TestEstimateGasCapAcrossAmsterdam checks that Amsterdam lifts the EIP-7825
// cap on the initial high bound. The loop contract below never halts, so the
// error reports the bound the estimator started from: the EIP-7825 cap before
// Amsterdam, the caller's own gas limit after it.
func TestEstimateGasCapAcrossAmsterdam(t *testing.T) {
	t.Parallel()

	var (
		from = common.HexToAddress("0x1001")
		to   = common.HexToAddress("0x1002")
		loop = []byte{0x5b, 0x60, 0x00, 0x56} // JUMPDEST PUSH1 0x00 JUMP
		gas  = params.MaxTxGas + 100000
	)
	osaka := params.MergedTestChainConfig.Clone()
	osaka.AmsterdamBlock = nil
	amsterdam := params.MergedTestChainConfig.Clone()

	for _, tt := range []struct {
		name   string
		config *params.ChainConfig
		want   string
	}{
		{"osaka", osaka, fmt.Sprintf("gas required exceeds allowance (%d)", params.MaxTxGas)},
		{"amsterdam", amsterdam, fmt.Sprintf("gas required exceeds allowance (%d)", gas)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			genesis := &core.Genesis{
				Config: tt.config,
				Alloc: types.GenesisAlloc{
					from: {Balance: big.NewInt(params.Ether)},
					to:   {Code: loop},
				},
			}
			db := rawdb.NewMemoryDatabase()
			block := genesis.MustCommit(db)

			stateDB, err := state.New(block.Root(), state.NewDatabase(db))
			if err != nil {
				t.Fatalf("failed to create state db: %v", err)
			}
			header := types.CopyHeader(block.Header())
			header.GasLimit = gas

			msg := &core.Message{
				From:      from,
				To:        &to,
				GasLimit:  gas,
				GasPrice:  new(big.Int),
				GasFeeCap: new(big.Int),
				GasTipCap: new(big.Int),
				Value:     new(big.Int),
			}
			opts := &Options{
				Config: tt.config,
				Chain:  &testChainContext{engine: ethash.NewFaker()},
				Header: header,
				State:  stateDB,
			}
			_, _, err = Estimate(context.Background(), msg, opts, 0)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

// TestEstimateAboveTotalCap checks that a gas limit above the EIP-8037 total cap
// is still estimated when the transaction checks are skipped, as eth_estimateGas
// does, while the same limit is rejected when the checks run. Amsterdam must not
// clamp the initial high bound to the total cap, otherwise the checks-enabled
// case would silently succeed.
func TestEstimateAboveTotalCap(t *testing.T) {
	t.Parallel()

	var (
		from = common.HexToAddress("0x1001")
		to   = common.HexToAddress("0x1002")
		gas  = params.MaxTxTotalGas + 1
	)
	amsterdam := params.MergedTestChainConfig.Clone()

	for _, tt := range []struct {
		name    string
		skip    bool
		wantErr bool
	}{
		{"checks-skipped", true, false},
		{"checks-enabled", false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			genesis := &core.Genesis{
				Config: amsterdam,
				Alloc:  types.GenesisAlloc{from: {Balance: big.NewInt(params.Ether)}},
			}
			db := rawdb.NewMemoryDatabase()
			block := genesis.MustCommit(db)

			stateDB, err := state.New(block.Root(), state.NewDatabase(db))
			if err != nil {
				t.Fatalf("failed to create state db: %v", err)
			}
			header := types.CopyHeader(block.Header())
			header.GasLimit = 8_000_000

			msg := &core.Message{
				From:                  from,
				To:                    &to,
				GasLimit:              gas,
				GasPrice:              new(big.Int),
				GasFeeCap:             new(big.Int),
				GasTipCap:             new(big.Int),
				Value:                 new(big.Int),
				SkipTransactionChecks: tt.skip,
			}
			opts := &Options{
				Config: amsterdam,
				Chain:  &testChainContext{engine: ethash.NewFaker()},
				Header: header,
				State:  stateDB,
			}
			estimate, _, err := Estimate(context.Background(), msg, opts, 0)
			if tt.wantErr {
				if !errors.Is(err, core.ErrGasLimitTooHigh) {
					t.Fatalf("error = %v, want ErrGasLimitTooHigh", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("estimate failed: %v", err)
			}
			if estimate > params.MaxTxTotalGas {
				t.Fatalf("estimate = %d, want at most %d", estimate, params.MaxTxTotalGas)
			}
		})
	}
}
