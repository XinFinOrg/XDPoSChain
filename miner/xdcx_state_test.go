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

package miner

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestXDCXStateEnabled pins when the miner still loads XDCx state: while either
// the root producer or the receiver consumer is active.
func TestXDCXStateEnabled(t *testing.T) {
	tests := []struct {
		name string
		cfg  *params.ChainConfig
		want map[int64]bool
	}{
		{
			name: "receiver disabled while the miner still writes roots",
			cfg: &params.ChainConfig{
				XDPoS:                       &params.XDPoSConfig{},
				TIPXDCXBlock:                big.NewInt(0),
				TIPXDCXReceiverDisableBlock: big.NewInt(100),
			},
			want: map[int64]bool{99: true, 100: true, 1000: true},
		},
		{
			name: "miner disabled before the receiver",
			cfg: &params.ChainConfig{
				XDPoS:                       &params.XDPoSConfig{},
				TIPXDCXBlock:                big.NewInt(0),
				TIPXDCXMinerDisableBlock:    big.NewInt(100),
				TIPXDCXReceiverDisableBlock: big.NewInt(200),
			},
			want: map[int64]bool{99: true, 100: true, 199: true, 200: false},
		},
		{
			name: "both disabled at the same block",
			cfg: &params.ChainConfig{
				XDPoS:                       &params.XDPoSConfig{},
				TIPXDCXBlock:                big.NewInt(0),
				TIPXDCXMinerDisableBlock:    big.NewInt(100),
				TIPXDCXReceiverDisableBlock: big.NewInt(100),
			},
			want: map[int64]bool{99: true, 100: false},
		},
		{
			name: "no XDPoS",
			cfg:  &params.ChainConfig{},
			want: map[int64]bool{0: false},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &worker{chainConfig: tt.cfg}
			for number, want := range tt.want {
				if got := w.xdcxStateEnabled(&types.Header{Number: big.NewInt(number)}); got != want {
					t.Fatalf("xdcxStateEnabled(%d) = %v, want %v", number, got, want)
				}
			}
		})
	}
}
