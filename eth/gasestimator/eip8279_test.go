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

// RED-first estimator test for EIP-8279 §Gas estimation: eth_estimateGas
// MUST simulate floor_gas_used (static seed AND runtime metered BAL bytes).
// A call to a contract doing 3 warm SLOADs on a 1,000-byte payload has
// static EIP-8131 floor 15,000 + 64×(1000+20+96) = 86,424 (A1: the anchor
// is the EIP-2780 base, not 21,000) and, with the
// EIP-8279 runtime meter, +3×32×64 = +6,144 ⇒ estimate must be ≥ 92,568.
// RED today: the estimator has only the static clamp and returns 86,424.
// Reuses the eip8131ChainContext/eip8131Engine fixtures from
// eip8131_test.go (same package).

package gasestimator

import (
	"bytes"
	"context"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

func TestEIP8279R4EstimateGasRuntimeFloor(t *testing.T) {
	cfg := *params.MergedTestChainConfig
	cfg.PragueTime, cfg.PragueBlock = nil, nil
	cfg.BogotaTime = new(uint64) // zero time → Bogotá active
	cfg.AmsterdamTime = nil

	// Fixture contract: SLOAD slots 0,1,2, STOP (mirrors the core harness).
	code := []byte{0x60, 0x00, 0x54, 0x60, 0x01, 0x54, 0x60, 0x02, 0x54, 0x00}
	contract := common.HexToAddress("0x00000000000000000000000000000000000c0de1")
	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	statedb.SetCode(contract, code, tracing.CodeChangeGenesis)

	call := &core.Message{
		From:                  common.HexToAddress("0x00000000000000000000000000000000000beef1"),
		To:                    &contract,
		Value:                 uint256.NewInt(0),
		GasFeeCap:             uint256.NewInt(0),
		GasTipCap:             uint256.NewInt(0),
		GasPrice:              uint256.NewInt(0),
		Data:                  bytes.Repeat([]byte{1}, 1000),
		AccessList:            types.AccessList{{Address: contract, StorageKeys: []common.Hash{{0x00}, {0x01}, {0x02}}}},
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

	// EIP-8131 static floor: 15,000 + 64×(1000 + 20 + 3×32) = 86,424 (A1).
	staticFloor := uint64(15_000 + 64*(1000+20+96))
	// EIP-8279 runtime tail: 3 first storage-key touches × 32 B × 64.
	want := staticFloor + 3*32*64

	// RED: the estimate carries only the static clamp — the binary search
	// result (~45,700 execution) is clamped to 86,424, missing the 6,144
	// runtime tail.
	est, _, err := Estimate(context.Background(), call, &Options{
		Config:     &cfg,
		Chain:      &eip8131ChainContext{cfg: &cfg},
		Header:     header,
		State:      statedb,
		ErrorRatio: 0.0,
	}, 10_000_000)
	if err != nil {
		t.Fatalf("estimate failed: %v", err)
	}
	if est < staticFloor {
		t.Fatalf("estimate %d below even the EIP-8131 static floor %d (regression in the 8131 clamp)", est, staticFloor)
	}
	if est < want {
		t.Fatalf("estimate = %d, want ≥ %d (missing runtime BAL metering tail 3×32 B×64 = %d gas)",
			est, want, want-est)
	}
}
