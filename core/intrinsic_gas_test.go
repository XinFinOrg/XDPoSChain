// Copyright 2026 The XDPoSChain Authors
// This file is part of the XDPoSChain library.

package core

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestIntrinsicGasCalldataPricing pins the calldata byte pricing of IntrinsicGas.
// XDC prices non-zero calldata bytes at 68 gas (the pre-EIP-2028 rate) and moves
// to the EIP-2028 rate of 16 gas on the Prague fork, while zero bytes stay at 4.
func TestIntrinsicGasCalldataPricing(t *testing.T) {
	// A clone of the test config with a Prague block above the blocks used below,
	// so the reduced price must stay off there.
	pragueAt1000 := params.TestChainConfig.Clone()
	pragueAt1000.PragueBlock = big.NewInt(1000)

	// 3502 non-zero and 338 zero bytes, matching the byte mix of the canonical
	// Multicall3 creation transaction whose fixed 1,000,000 gas limit runs out of
	// gas under the XDC calldata price.
	multicall3Like := make([]byte, 3840)
	for i := 0; i < 3502; i++ {
		multicall3Like[i] = 0x01
	}

	for _, tt := range []struct {
		name             string
		config           *params.ChainConfig
		block            int64
		contractCreation bool
		data             []byte
		wantPrague       bool
		want             uint64
	}{
		{
			name:   "mainnet before Prague",
			config: params.XDCMainnetChainConfig,
			block:  71542788,
			data:   []byte{0x01, 0x02, 0x03, 0x00, 0x00},
			want:   21212, // 21000 + 3*68 + 2*4
		},
		{
			name:             "mainnet before Prague, contract creation",
			config:           params.XDCMainnetChainConfig,
			block:            71542788,
			data:             []byte{0x01, 0x02, 0x03, 0x00, 0x00},
			want:             53212, // 53000 + 3*68 + 2*4, EIP-3860 is not active on mainnet there
			contractCreation: true,
		},
		{
			name:       "before the Prague block",
			config:     pragueAt1000,
			block:      999,
			data:       []byte{0x01, 0x02, 0x03, 0x00, 0x00},
			wantPrague: false,
			want:       21212, // 21000 + 3*68 + 2*4
		},
		{
			name:       "at the Prague block",
			config:     pragueAt1000,
			block:      1000,
			wantPrague: true,
			data:       []byte{0x01, 0x02, 0x03, 0x00, 0x00},
			want:       21056, // 21000 + 3*16 + 2*4
		},
		{
			name:             "at the Prague block, contract creation",
			config:           params.TestChainConfig,
			block:            1,
			contractCreation: true,
			data:             []byte{0x01, 0x02, 0x03, 0x00, 0x00},
			wantPrague:       true,
			want:             53058, // 53000 + 3*16 + 2*4 + 1*2 (EIP-3860 word cost)
		},
		{
			name:       "zero bytes keep their price",
			config:     params.TestChainConfig,
			block:      1,
			data:       []byte{0x00, 0x00, 0x00, 0x00, 0x00},
			wantPrague: true,
			want:       21020, // 21000 + 5*4
		},
		{
			name:             "mainnet before Prague, Multicall3 sized initcode",
			config:           params.XDCMainnetChainConfig,
			block:            71542788,
			contractCreation: true,
			data:             multicall3Like,
			want:             292488, // 53000 + 3502*68 + 338*4
		},
		{
			name:             "at the Prague block, Multicall3 sized initcode",
			config:           params.TestChainConfig,
			block:            1,
			contractCreation: true,
			data:             multicall3Like,
			wantPrague:       true,
			want:             110624, // 53000 + 3502*16 + 338*4 + 120*2 (EIP-3860 word cost)
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rules := tt.config.Rules(big.NewInt(tt.block))
			if rules.IsPrague != tt.wantPrague {
				t.Fatalf("IsPrague at block %d = %v, want %v", tt.block, rules.IsPrague, tt.wantPrague)
			}
			got, err := IntrinsicGas(tt.data, nil, nil, tt.contractCreation, rules.IsHomestead, rules.IsPrague, rules.IsEIP1559)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("intrinsic gas = %d, want %d (IsPrague=%v)", got, tt.want, rules.IsPrague)
			}
		})
	}
}
