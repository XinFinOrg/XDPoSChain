// Copyright 2017 The go-ethereum Authors
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

package params

import (
	"math"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestForkActivationIgnoresCommonFallbacks(t *testing.T) {
	const zeroAddress0x = "0x0000000000000000000000000000000000000000"
	config := &ChainConfig{}
	block := big.NewInt(1)

	assert.False(t, config.IsTIP2019(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsTIPSigning(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsTIPRandomize(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsTIPIncreaseMasternodes(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsDenylist(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsTIPNoHalvingMNReward(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsTIPXDCX(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsTIPXDCXLending(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsTIPXDCXCancellationFee(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsBerlin(block))
	assert.False(t, config.IsLondon(block))
	assert.False(t, config.IsMerge(block))
	assert.False(t, config.IsShanghai(block))
	assert.False(t, config.IsTIPXDCXMiner(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsTIPXDCXReceiver(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsXDCxDisable(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsCancun(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsPrague(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsOsaka(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsDynamicGasLimit(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsTIPUpgradeReward(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsTIPUpgradePenalty(big.NewInt(math.MaxInt64)))
	assert.False(t, config.IsTIPEpochHalving(big.NewInt(math.MaxInt64)))

	description := config.Description()
	assertDescriptionLineValue := func(t *testing.T, label, value string) {
		t.Helper()
		for _, line := range strings.Split(description, "\n") {
			if strings.Contains(line, label) {
				assert.Contains(t, line, value, "description line for %s should contain %s", label, value)
				return
			}
		}
		assert.Failf(t, "missing description line", "description must contain a line for %s", label)
	}

	assertDescriptionLineValue(t, "TIP2019:", "<nil>")
	assertDescriptionLineValue(t, "TIPSigning:", "<nil>")
	assertDescriptionLineValue(t, "TIPRandomize:", "<nil>")
	assertDescriptionLineValue(t, "TIPIncreaseMasternodes:", "<nil>")
	assertDescriptionLineValue(t, "Denylist:", "<nil>")
	assertDescriptionLineValue(t, "TIPNoHalvingMNReward:", "<nil>")
	assertDescriptionLineValue(t, "TIPXDCX:", "<nil>")
	assertDescriptionLineValue(t, "TIPXDCXLending:", "<nil>")
	assertDescriptionLineValue(t, "TIPXDCXCancellationFee:", "<nil>")
	assertDescriptionLineValue(t, "TIPTRC21Fee:", "<nil>")
	assertDescriptionLineValue(t, "Berlin:", "<nil>")
	assertDescriptionLineValue(t, "London:", "<nil>")
	assertDescriptionLineValue(t, "Merge:", "<nil>")
	assertDescriptionLineValue(t, "Shanghai:", "<nil>")
	assertDescriptionLineValue(t, "TIPXDCXMinerDisable:", "<nil>")
	assertDescriptionLineValue(t, "TIPXDCXReceiverDisable:", "<nil>")
	assertDescriptionLineValue(t, "Cancun:", "<nil>")
	assertDescriptionLineValue(t, "Prague:", "<nil>")
	assertDescriptionLineValue(t, "Osaka:", "<nil>")
	assertDescriptionLineValue(t, "DynamicGasLimit:", "<nil>")
	assertDescriptionLineValue(t, "TIPUpgradeReward:", "<nil>")
	assertDescriptionLineValue(t, "TIPUpgradePenalty:", "<nil>")
	assertDescriptionLineValue(t, "TIPEpochHalving:", "<nil>")
	assertDescriptionLineValue(t, "TRC21IssuerSMC:", zeroAddress0x)
	assertDescriptionLineValue(t, "XDCXListingSMC:", zeroAddress0x)
	assertDescriptionLineValue(t, "RelayerRegistrationSMC:", zeroAddress0x)
	assertDescriptionLineValue(t, "LendingRegistrationSMC:", zeroAddress0x)
}
