// Copyright 2026 The XDPoSChain Authors
// This file is part of the XDPoSChain library.

package core

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/holiman/uint256"
)

// TestIntrinsicGasCalldataPricing pins the calldata byte pricing of IntrinsicGas.
// XDC prices non-zero calldata bytes at 68 gas (the pre-EIP-2028 rate) and moves
// to the EIP-2028 rate of 16 gas on the Prague fork, while zero bytes stay at 4.
func TestIntrinsicGasCalldataPricing(t *testing.T) {
	// Clones of the test config with a Prague block above or at the blocks used
	// below, so the reduced price must stay off there. Amsterdam is cleared so
	// the EIP-2780 base cost does not enter the calldata expectations.
	pragueAt1000 := params.TestChainConfig.Clone()
	pragueAt1000.PragueBlock = big.NewInt(1000)
	pragueAt1000.AmsterdamBlock = nil
	pragueAt0 := params.TestChainConfig.Clone()
	pragueAt0.AmsterdamBlock = nil

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
			config:           pragueAt0,
			block:            1,
			contractCreation: true,
			data:             []byte{0x01, 0x02, 0x03, 0x00, 0x00},
			wantPrague:       true,
			want:             53058, // 53000 + 3*16 + 2*4 + 1*2 (EIP-3860 word cost)
		},
		{
			name:       "zero bytes keep their price",
			config:     pragueAt0,
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
			config:           pragueAt0,
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
			to := &testReceiver
			if tt.contractCreation {
				to = nil
			}
			got, err := IntrinsicGas(tt.data, nil, nil, testSender, to, nil, rules)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("intrinsic gas = %d, want %d (IsPrague=%v)", got, tt.want, rules.IsPrague)
			}
		})
	}
}

// TestIntrinsicGasAccessListAmsterdam pins the EIP-7981 access list data charge.
// On top of the EIP-2930 per-entry cost, Amsterdam charges the access list as
// calldata tokens: 20 bytes per address and 32 bytes per storage key, four
// tokens per byte at the EIP-7976 rate.
func TestIntrinsicGasAccessListAmsterdam(t *testing.T) {
	t.Parallel()

	var (
		from = common.HexToAddress("0x1111111111111111111111111111111111111111")
		to   = common.HexToAddress("0x2222222222222222222222222222222222222222")
		key1 = common.HexToHash("0xaa")
		key2 = common.HexToHash("0xbb")

		accessList = types.AccessList{
			{Address: from, StorageKeys: []common.Hash{key1, key2}},
			{Address: to, StorageKeys: []common.Hash{key1}},
		}
		// 2 addresses and 3 storage keys under EIP-2930.
		berlinBase    = params.TxGas + 2*params.TxAccessListAddressGas + 3*params.TxAccessListStorageKeyGas
		amsterdamBase = params.TxBaseCost2780 + params.ColdAccountAccessAmsterdam + 2*params.TxAccessListAddressGas + 3*params.TxAccessListStorageKeyGas
		// EIP-7981 adds (2*20 + 3*32) bytes * 4 tokens * 16 gas.
		amsterdamExtra = (2*common.AddressLength + 3*common.HashLength) * params.TxTokenPerNonZeroByte * params.TxCostFloorPerToken7976

		data5 = []byte{0x01, 0x02, 0x03, 0x00, 0x00} // 3 non-zero and 2 zero bytes

		berlin    = params.Rules{IsHomestead: true, IsPrague: true, IsEIP1559: true}
		amsterdam = params.Rules{IsHomestead: true, IsPrague: true, IsEIP1559: true, IsAmsterdam: true}
	)
	tests := []struct {
		name       string
		data       []byte
		accessList types.AccessList
		rules      params.Rules
		want       uint64
	}{
		{"berlin pricing", nil, accessList, berlin, berlinBase},
		{"amsterdam pricing", nil, accessList, amsterdam, amsterdamBase + amsterdamExtra},
		{"empty access list", nil, types.AccessList{}, amsterdam, params.TxBaseCost2780 + params.ColdAccountAccessAmsterdam},
		{"nil access list", nil, nil, amsterdam, params.TxBaseCost2780 + params.ColdAccountAccessAmsterdam},
		// Calldata and the access list together: 3*16 + 2*4 = 56 gas on top.
		{"berlin pricing with calldata", data5, accessList, berlin, berlinBase + 56},
		{"amsterdam pricing with calldata", data5, accessList, amsterdam, amsterdamBase + amsterdamExtra + 56},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IntrinsicGas(tt.data, tt.accessList, nil, from, &to, nil, tt.rules)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("intrinsic gas = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestAccessListTokenPrice pins the EIP-7981 access list price shared by
// IntrinsicGas and FloorDataGas. Both charge an address as 20 bytes and a
// storage key as 32 bytes of calldata tokens, so the per-entry charge each
// function adds under Amsterdam must agree even though they derive it from
// different constants.
func TestAccessListTokenPrice(t *testing.T) {
	t.Parallel()

	var (
		amsterdam = params.Rules{IsPrague: true, IsAmsterdam: true}
		berlin    = params.Rules{IsPrague: true}
		addr1     = common.HexToAddress("0x1111111111111111111111111111111111111111")
		addr2     = common.HexToAddress("0x2222222222222222222222222222222222222222")
		key1      = common.HexToHash("0xaa")
		key2      = common.HexToHash("0xbb")
	)
	floorBase, err := FloorDataGas(amsterdam, common.Address{}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	intrinsicBase, err := IntrinsicGas(nil, nil, nil, common.Address{}, nil, nil, amsterdam)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	berlinBase, err := IntrinsicGas(nil, nil, nil, common.Address{}, nil, nil, berlin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, tt := range []struct {
		name       string
		accessList types.AccessList
	}{
		{"nil", nil},
		{"empty", types.AccessList{}},
		{"one address", types.AccessList{{Address: addr1}}},
		{"address with storage keys", types.AccessList{{Address: addr1, StorageKeys: []common.Hash{key1, key2}}}},
		{"two addresses", types.AccessList{
			{Address: addr1, StorageKeys: []common.Hash{key1}},
			{Address: addr2},
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			berlinGas, err := IntrinsicGas(nil, tt.accessList, nil, common.Address{}, nil, nil, berlin)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			amsterdamGas, err := IntrinsicGas(nil, tt.accessList, nil, common.Address{}, nil, nil, amsterdam)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			floor, err := FloorDataGas(amsterdam, common.Address{}, nil, nil, nil, tt.accessList)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			// The Berlin run also pays the EIP-2930 base charge, and the two
			// runs differ in their base cost, so both cancel out here.
			charge := (amsterdamGas - berlinGas) - (intrinsicBase - berlinBase)
			if want := floor - floorBase; charge != want {
				t.Fatalf("access list charge = %d in intrinsic gas, %d in floor data gas", charge, want)
			}
		})
	}
}

// TestIntrinsicGasEIP2780 pins the resource-based intrinsic base: 12,000 for
// the sender, a cold recipient touch (or CREATE_ACCESS for a creation), and
// 6,000 when value moves to a different, non-created account.
func TestIntrinsicGasEIP2780(t *testing.T) {
	t.Parallel()

	var (
		from   = common.HexToAddress("0x1111111111111111111111111111111111111111")
		to     = common.HexToAddress("0x2222222222222222222222222222222222222222")
		rules  = params.Rules{IsHomestead: true, IsPrague: true, IsEIP1559: true, IsAmsterdam: true}
		noVal  = uint256.NewInt(0)
		oneWei = uint256.NewInt(1)
	)
	for _, tt := range []struct {
		name  string
		to    *common.Address
		value *uint256.Int
		want  uint64
	}{
		{
			name:  "self-transfer",
			to:    &from,
			value: oneWei,
			want:  params.TxBaseCost2780,
		},
		{
			name:  "self-transfer, zero value",
			to:    &from,
			value: noVal,
			want:  params.TxBaseCost2780,
		},
		{
			name:  "zero-value call",
			to:    &to,
			value: noVal,
			want:  params.TxBaseCost2780 + params.ColdAccountAccessAmsterdam,
		},
		{
			name:  "value transfer",
			to:    &to,
			value: oneWei,
			want:  params.TxBaseCost2780 + params.ColdAccountAccessAmsterdam + params.TxValueCost2780,
		},
		{
			name:  "contract creation, zero value",
			to:    nil,
			value: noVal,
			want:  params.TxBaseCost2780 + params.CreateAccessAmsterdam,
		},
		{
			name:  "contract creation, value > 0",
			to:    nil,
			value: oneWei,
			want:  params.TxBaseCost2780 + params.CreateAccessAmsterdam,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IntrinsicGas(nil, nil, nil, from, tt.to, tt.value, rules)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("intrinsic gas = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestFloorDataGasEIP2780 checks that the EIP-7623 floor sits on the EIP-2780
// base, so it never undercuts the intrinsic base of the same transaction.
func TestFloorDataGasEIP2780(t *testing.T) {
	t.Parallel()

	var (
		from  = common.HexToAddress("0x1111111111111111111111111111111111111111")
		to    = common.HexToAddress("0x2222222222222222222222222222222222222222")
		rules = params.Rules{IsHomestead: true, IsPrague: true, IsEIP1559: true, IsAmsterdam: true}
		data  = []byte{0x01, 0x02, 0x03, 0x00, 0x00}
		// 3 non-zero and 2 zero bytes, all charged four tokens at 16 gas.
		dataCost = uint64(len(data)) * params.TxTokenPerNonZeroByte * params.TxCostFloorPerToken7976
		noVal    = uint256.NewInt(0)
		oneWei   = uint256.NewInt(1)
	)
	for _, tt := range []struct {
		name  string
		to    *common.Address
		value *uint256.Int
		base  uint64
	}{
		{"self-transfer", &from, oneWei, params.TxBaseCost2780},
		{"zero-value call", &to, noVal, params.TxBaseCost2780 + params.ColdAccountAccessAmsterdam},
		{"value transfer", &to, oneWei, params.TxBaseCost2780 + params.ColdAccountAccessAmsterdam + params.TxValueCost2780},
		{"contract creation", nil, noVal, params.TxBaseCost2780 + params.CreateAccessAmsterdam},
	} {
		t.Run(tt.name, func(t *testing.T) {
			floor, err := FloorDataGas(rules, from, tt.to, tt.value, data, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if want := tt.base + dataCost; floor != want {
				t.Fatalf("floor = %d, want %d", floor, want)
			}
			intrinsic, err := IntrinsicGas(data, nil, nil, from, tt.to, tt.value, rules)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if floor < intrinsic {
				t.Fatalf("floor %d undercuts intrinsic gas %d", floor, intrinsic)
			}
		})
	}
}
