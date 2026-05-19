// Copyright 2016 The go-ethereum Authors
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
	"math/big"
)

func (c *ChainConfig) IsHomestead(num *big.Int) bool {
	return isForked(c.HomesteadBlock, num)
}

// IsTIP2019 returns whether num is at or past the TIP2019 fork block.
func (c *ChainConfig) IsTIP2019(num *big.Int) bool {
	return isForked(c.TIP2019Block, num)
}

// IsDAO returns whether num is either equal to the DAO fork block or greater.
func (c *ChainConfig) IsDAOFork(num *big.Int) bool {
	return isForked(c.DAOForkBlock, num)
}

func (c *ChainConfig) IsEIP150(num *big.Int) bool {
	return isForked(c.EIP150Block, num)
}

func (c *ChainConfig) IsEIP155(num *big.Int) bool {
	return isForked(c.EIP155Block, num)
}

func (c *ChainConfig) IsEIP158(num *big.Int) bool {
	return isForked(c.EIP158Block, num)
}

func (c *ChainConfig) IsByzantium(num *big.Int) bool {
	return isForked(c.ByzantiumBlock, num)
}

func (c *ChainConfig) IsConstantinople(num *big.Int) bool {
	return isForked(c.ConstantinopleBlock, num)
}

// IsPetersburg returns whether num is at or past the effective Petersburg activation.
//
// Backward compatibility note: legacy XDC chain configs may leave PetersburgBlock
// unset and rely on TIPXDCXCancellationFeeBlock as the effective cutoff instead.
// That is the case for the built-in XDC mainnet/testnet/devnet configs, which
// historically encoded the XDC-specific cancellation-fee fork but still reuse
// Ethereum fork helpers in downstream callers. Non-XDC or upstream-style configs
// should set PetersburgBlock directly; if TIPXDCXCancellationFeeBlock is nil, the
// fallback path is inert.
func (c *ChainConfig) IsPetersburg(num *big.Int) bool {
	return isForked(c.TIPXDCXCancellationFeeBlock, num) || isForked(c.PetersburgBlock, num)
}

// IsIstanbul returns whether num is at or past the effective Istanbul activation.
//
// Backward compatibility note: legacy XDC chain configs may leave IstanbulBlock
// unset and rely on TIPXDCXCancellationFeeBlock as the effective cutoff instead.
// That is the case for the built-in XDC mainnet/testnet/devnet configs, which
// historically encoded the XDC-specific cancellation-fee fork but still reuse
// Ethereum fork helpers in downstream callers. Non-XDC or upstream-style configs
// should set IstanbulBlock directly; if TIPXDCXCancellationFeeBlock is nil, the
// fallback path is inert.
func (c *ChainConfig) IsIstanbul(num *big.Int) bool {
	return isForked(c.TIPXDCXCancellationFeeBlock, num) || isForked(c.IstanbulBlock, num)
}

// IsTIPTRC21Fee returns whether num is either equal to the TIPTRC21Fee fork block or greater.
func (c *ChainConfig) IsTIPTRC21Fee(num *big.Int) bool {
	return isForked(c.TIPTRC21FeeBlock, num)
}

// IsDenylist returns whether num is at or past the denylist fork block.
func (c *ChainConfig) IsDenylist(num *big.Int) bool {
	return isForked(c.DenylistBlock, num)
}

// IsBerlin returns whether num is either equal to the Berlin fork block or greater.
func (c *ChainConfig) IsBerlin(num *big.Int) bool {
	return isForked(c.BerlinBlock, num)
}

// IsLondon returns whether num is either equal to the London fork block or greater.
func (c *ChainConfig) IsLondon(num *big.Int) bool {
	return isForked(c.LondonBlock, num)
}

// IsMerge returns whether num is either equal to the Merge fork block or greater.
// Different from Geth which uses `block.difficulty != nil`
func (c *ChainConfig) IsMerge(num *big.Int) bool {
	return isForked(c.MergeBlock, num)
}

// IsShanghai returns whether num is either equal to the Shanghai fork block or greater.
func (c *ChainConfig) IsShanghai(num *big.Int) bool {
	return isForked(c.ShanghaiBlock, num)
}

// IsGas50x returns whether num is either equal to the Gas50x fork block or greater.
func (c *ChainConfig) IsGas50x(num *big.Int) bool {
	return isForked(c.Gas50xBlock, num)
}

// IsEIP1559 returns whether num is either equal to the EIP1559 fork block or greater.
func (c *ChainConfig) IsEIP1559(num *big.Int) bool {
	return isForked(c.EIP1559Block, num)
}

// IsCancun returns whether num is either equal to the Cancun fork block or greater.
func (c *ChainConfig) IsCancun(num *big.Int) bool {
	return isForked(c.CancunBlock, num)
}

// IsPrague returns whether num is either equal to the Prague fork block or greater.
func (c *ChainConfig) IsPrague(num *big.Int) bool {
	return isForked(c.PragueBlock, num)
}

// IsOsaka returns whether num is either equal to the Osaka fork block or greater.
func (c *ChainConfig) IsOsaka(num *big.Int) bool {
	return isForked(c.OsakaBlock, num)
}

// IsDynamicGasLimit returns whether num is either equal to the DynamicGasLimitBlock fork block or greater.
func (c *ChainConfig) IsDynamicGasLimit(num *big.Int) bool {
	return isForked(c.DynamicGasLimitBlock, num)
}

func (c *ChainConfig) IsTIPSigning(num *big.Int) bool {
	return isForked(c.TIPSigningBlock, num)
}

func (c *ChainConfig) IsTIPRandomize(num *big.Int) bool {
	return isForked(c.TIPRandomizeBlock, num)
}

// IsTIPIncreaseMasternodes using for increase masternodes from 18 to 40
func (c *ChainConfig) IsTIPIncreaseMasternodes(num *big.Int) bool {
	return isForked(c.TIPIncreaseMasternodesBlock, num)
}

func (c *ChainConfig) IsTIPNoHalvingMNReward(num *big.Int) bool {
	return isForked(c.TIPNoHalvingMNRewardBlock, num)
}

func (c *ChainConfig) IsTIPXDCX(num *big.Int) bool {
	return isForked(c.TIPXDCXBlock, num)
}

// IsTIPXDCXMiner reports whether XDCX miner handling is active at num, taking
// the later miner-disable fork into account.
func (c *ChainConfig) IsTIPXDCXMiner(num *big.Int) bool {
	return isForked(c.TIPXDCXBlock, num) && !isForked(c.TIPXDCXMinerDisableBlock, num)
}

// IsTIPXDCXReceiver reports whether XDCX receiver handling is active at num,
// taking the later receiver-disable fork into account.
func (c *ChainConfig) IsTIPXDCXReceiver(num *big.Int) bool {
	return isForked(c.TIPXDCXBlock, num) && !isForked(c.TIPXDCXReceiverDisableBlock, num)
}

func (c *ChainConfig) IsXDCxDisable(num *big.Int) bool {
	return isForked(c.TIPXDCXMinerDisableBlock, num)
}

func (c *ChainConfig) IsTIPXDCXLending(num *big.Int) bool {
	return isForked(c.TIPXDCXLendingBlock, num)
}

func (c *ChainConfig) IsTIPXDCXCancellationFee(num *big.Int) bool {
	return isForked(c.TIPXDCXCancellationFeeBlock, num)
}

func (c *ChainConfig) IsTIPUpgradeReward(num *big.Int) bool {
	return isForked(c.TIPUpgradeRewardBlock, num)
}

func (c *ChainConfig) IsTIPUpgradePenalty(num *big.Int) bool {
	return isForked(c.TIPUpgradePenaltyBlock, num)
}

func (c *ChainConfig) IsTIPEpochHalving(num *big.Int) bool {
	return isForked(c.TIPEpochHalvingBlock, num)
}

// GasTable returns the gas table corresponding to the current phase (homestead or homestead reprice).
//
// The returned GasTable's fields shouldn't, under any circumstances, be changed.
func (c *ChainConfig) GasTable(num *big.Int) GasTable {
	if num == nil {
		return GasTableHomestead
	}
	switch {
	case c.IsEIP158(num):
		return GasTableEIP158
	case c.IsEIP150(num):
		return GasTableEIP150
	default:
		return GasTableHomestead
	}
}

func isForked(s, head *big.Int) bool {
	if s == nil || head == nil {
		return false
	}
	return s.Cmp(head) <= 0
}

type Rules struct {
	ChainId          *big.Int
	IsHomestead      bool
	IsEIP150         bool
	IsEIP155         bool
	IsEIP158         bool
	IsByzantium      bool
	IsConstantinople bool
	IsPetersburg     bool
	IsIstanbul       bool
	IsBerlin         bool
	IsLondon         bool
	IsMerge          bool
	IsShanghai       bool
	IsXDCxDisable    bool
	IsEIP1559        bool
	IsCancun         bool
	IsPrague         bool
	IsOsaka          bool
}

func (c *ChainConfig) Rules(num *big.Int) Rules {
	chainId := c.ChainID
	if chainId == nil {
		chainId = new(big.Int)
	}
	return Rules{
		ChainId:          new(big.Int).Set(chainId),
		IsHomestead:      c.IsHomestead(num),
		IsEIP150:         c.IsEIP150(num),
		IsEIP155:         c.IsEIP155(num),
		IsEIP158:         c.IsEIP158(num),
		IsByzantium:      c.IsByzantium(num),
		IsConstantinople: c.IsConstantinople(num),
		IsPetersburg:     c.IsPetersburg(num),
		IsIstanbul:       c.IsIstanbul(num),
		IsBerlin:         c.IsBerlin(num),
		IsLondon:         c.IsLondon(num),
		IsMerge:          c.IsMerge(num),
		IsShanghai:       c.IsShanghai(num),
		IsXDCxDisable:    c.IsXDCxDisable(num),
		IsEIP1559:        c.IsEIP1559(num),
		IsCancun:         c.IsCancun(num),
		IsPrague:         c.IsPrague(num),
		IsOsaka:          c.IsOsaka(num),
	}
}
