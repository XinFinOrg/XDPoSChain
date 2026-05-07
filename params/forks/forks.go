// Copyright 2023 The go-ethereum Authors
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

package forks

import "fmt"

// Fork is a numerical identifier of specific network upgrades (forks).
type Fork int

const (
	Frontier Fork = iota
	FrontierThawing
	Homestead
	DAO
	TIP2019
	TangerineWhistle // a.k.a. the EIP150 fork
	SpuriousDragon   // a.k.a. the EIP155 fork
	EIP158
	Byzantium
	Constantinople
	Petersburg
	Istanbul
	TIPSigning
	TIPRandomize
	TIPIncreaseMasternodes
	Denylist
	TIPNoHalvingMNReward
	TIPXDCX
	TIPXDCXLending
	TIPXDCXCancellationFee
	TIPTRC21Fee
	Berlin
	London
	Merge
	Shanghai
	Gas50x
	XDPoSV2
	TIPXDCXMiner
	TIPXDCXReceiver
	XDCxDisable
	EIP1559
	Cancun
	DynamicGasLimit
	TIPUpgradeReward
	TIPUpgradePenalty
	TIPEpochHalving
	Prague
	Osaka
)

// String implements fmt.Stringer.
func (f Fork) String() string {
	s, ok := forkToString[f]
	if !ok {
		return fmt.Sprintf("Unknown fork (%d)", f)
	}
	return s
}

var forkToString = map[Fork]string{
	Frontier:               "Frontier",
	FrontierThawing:        "Frontier Thawing",
	Homestead:              "Homestead",
	DAO:                    "DAO",
	TIP2019:                "TIP2019",
	TangerineWhistle:       "Tangerine Whistle",
	SpuriousDragon:         "Spurious Dragon",
	EIP158:                 "EIP158",
	Byzantium:              "Byzantium",
	Constantinople:         "Constantinople",
	Petersburg:             "Petersburg",
	Istanbul:               "Istanbul",
	TIPSigning:             "TIPSigning",
	TIPRandomize:           "TIPRandomize",
	TIPIncreaseMasternodes: "TIPIncreaseMasternodes",
	Denylist:               "Denylist",
	TIPNoHalvingMNReward:   "TIPNoHalvingMNReward",
	TIPXDCX:                "TIPXDCX",
	TIPXDCXLending:         "TIPXDCXLending",
	TIPXDCXCancellationFee: "TIPXDCXCancellationFee",
	TIPTRC21Fee:            "TIPTRC21Fee",
	Berlin:                 "Berlin",
	London:                 "London",
	Merge:                  "Merge",
	Shanghai:               "Shanghai",
	Gas50x:                 "Gas50x",
	XDPoSV2:                "XDPoS V2",
	TIPXDCXMiner:           "TIPXDCXMiner",
	TIPXDCXReceiver:        "TIPXDCXReceiver",
	XDCxDisable:            "XDCxDisable",
	EIP1559:                "EIP1559",
	Cancun:                 "Cancun",
	DynamicGasLimit:        "DynamicGasLimit",
	TIPUpgradeReward:       "TIPUpgradeReward",
	TIPUpgradePenalty:      "TIPUpgradePenalty",
	TIPEpochHalving:        "TIPEpochHalving",
	Prague:                 "Prague",
	Osaka:                  "Osaka",
}
