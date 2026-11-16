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
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/XDCx"
	"github.com/XinFinOrg/XDPoSChain/XDCx/tradingstate"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// xdcxGateBackendMock counts the XDCx service lookups the call paths make.
type xdcxGateBackendMock struct {
	*backendMock
	service  *XDCx.XDCX
	svcCalls int
}

func (b *xdcxGateBackendMock) XDCxService() *XDCx.XDCX {
	b.svcCalls++
	return b.service
}

// TestXDCXTradingStateFollowsReceiverFork pins that the call paths stop reading
// the XDCx trading state once the receiver fork is off, and that no service is
// touched on a chain where XDCx never activated.
func TestXDCXTradingStateFollowsReceiverFork(t *testing.T) {
	cfg := func(minerDisable, receiverDisable *big.Int) *params.ChainConfig {
		return &params.ChainConfig{
			XDPoS:                       &params.XDPoSConfig{},
			TIPXDCXBlock:                big.NewInt(0),
			TIPXDCXMinerDisableBlock:    minerDisable,
			TIPXDCXReceiverDisableBlock: receiverDisable,
		}
	}
	tests := []struct {
		name      string
		cfg       *params.ChainConfig
		effNumber *big.Int
		noService bool
		wantState bool
		wantCalls bool
	}{
		{name: "receiver active", cfg: cfg(nil, nil), wantState: true, wantCalls: true},
		{name: "miner off, receiver on", cfg: cfg(big.NewInt(50), big.NewInt(200)), wantState: true, wantCalls: true},
		{name: "receiver off", cfg: cfg(big.NewInt(50), big.NewInt(100)), wantState: false, wantCalls: false},
		{name: "receiver off at the block, on at the execution height", cfg: cfg(big.NewInt(50), big.NewInt(100)), effNumber: big.NewInt(50), wantState: true, wantCalls: true},
		{name: "receiver on at the block, off at the execution height", cfg: cfg(nil, big.NewInt(150)), effNumber: big.NewInt(150), wantState: false, wantCalls: false},
		{name: "receiver active without a service", cfg: cfg(nil, nil), noService: true, wantState: false, wantCalls: true},
		{name: "no XDCx fork", cfg: &params.ChainConfig{XDPoS: &params.XDPoSConfig{}}, wantState: false, wantCalls: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &xdcxGateBackendMock{backendMock: newBackendMock()}
			if !tt.noService {
				b.service = &XDCx.XDCX{StateCache: tradingstate.NewDatabase(rawdb.NewMemoryDatabase())}
			}
			b.config = tt.cfg
			block := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(100)})
			executionNumber := block.Number()
			if tt.effNumber != nil {
				executionNumber = tt.effNumber
			}

			state, err := xdcxTradingState(b, block, common.Address{}, executionNumber)
			if err != nil {
				t.Fatalf("xdcxTradingState: %v", err)
			}
			if (state != nil) != tt.wantState {
				t.Fatalf("state nil = %v, want nil = %v", state == nil, !tt.wantState)
			}
			if (b.svcCalls > 0) != tt.wantCalls {
				t.Fatalf("service calls = %d, want calls = %v", b.svcCalls, tt.wantCalls)
			}
		})
	}
}
