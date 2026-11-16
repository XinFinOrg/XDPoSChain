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

package types

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestIsSpecialTx checks that the randomize contract stops being special at
// TIPRandomizeDisable while BlockSigners stays special.
func TestIsSpecialTx(t *testing.T) {
	const fork = 10
	forked := params.TestChainConfig.Clone()
	forked.TIPRandomizeDisableBlock = big.NewInt(fork)
	unscheduled := params.TestChainConfig.Clone()
	unscheduled.TIPRandomizeDisableBlock = nil

	signers, randomize, other := common.BlockSignersBinary, common.RandomizeSMCBinary, common.HexToAddress("0x01")

	for _, tt := range []struct {
		name   string
		config *params.ChainConfig
		number int64
		to     *common.Address
		want   bool
	}{
		{"block signers before the fork", forked, fork - 1, &signers, true},
		{"block signers at the fork", forked, fork, &signers, true},
		{"randomize before the fork", forked, fork - 1, &randomize, true},
		{"randomize at the fork", forked, fork, &randomize, false},
		{"randomize after the fork", forked, fork + 1, &randomize, false},
		{"randomize, fork unscheduled", unscheduled, fork, &randomize, true},
		{"randomize, nil config", nil, fork, &randomize, true},
		{"other address", forked, fork - 1, &other, false},
		{"contract creation", forked, fork - 1, nil, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSpecialTx(tt.config, big.NewInt(tt.number), tt.to); got != tt.want {
				t.Fatalf("IsSpecialTx = %v, want %v", got, tt.want)
			}
		})
	}
}
