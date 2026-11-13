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

package params

import (
	"errors"
	"fmt"
	"math/big"
)

// ErrInvalidSubnetConfig reports a subnet chain config the subnet consensus
// rules cannot run on.
var ErrInvalidSubnetConfig = errors.New("invalid XDPoS subnet config")

// IsSubnet reports whether the chain runs the XDC subnet consensus rules.
func (c *ChainConfig) IsSubnet() bool {
	return c != nil && c.XDPoS != nil && c.XDPoS.IsSubnet
}

// checkSubnetConfig enforces the shape the subnet rules assume. It is a no-op
// for chains that do not set XDPoS.IsSubnet.
//
//   - The v2 engine runs from genesis: V2.SwitchBlock and V2.SwitchEpoch are 0,
//     since subnet epochs are numbered by block (epoch = number / Epoch).
//   - Gap is at least 2, so the block after the gap block (which carries the
//     next-epoch candidates and penalties) is never the epoch switch block.
//   - EIP-1559 stays off: the subnet header layout has no base fee field, so a
//     base fee could be neither hashed nor sent to peers.
//   - The masternode reward is the flat legacy one: no halving
//     (TIPNoHalvingMNRewardBlock is 0) and none of the tiered reward forks.
//   - Every v2 config caps the masternodes (maxMasternodes > 0), which the
//     subnet applies to its candidates at each epoch switch.
func (c *ChainConfig) checkSubnetConfig() error {
	if !c.IsSubnet() {
		return nil
	}
	x := c.XDPoS
	if x.V2 == nil || x.V2.SwitchBlock == nil || x.V2.SwitchBlock.Sign() != 0 {
		return fmt.Errorf("%w: XDPoS.V2.SwitchBlock must be 0, the subnet runs the v2 engine from genesis", ErrInvalidSubnetConfig)
	}
	if x.V2.SwitchEpoch != 0 {
		return fmt.Errorf("%w: XDPoS.V2.SwitchEpoch must be 0, subnet epochs are numbered by block", ErrInvalidSubnetConfig)
	}
	if x.Gap < 2 {
		return fmt.Errorf("%w: XDPoS.Gap %d must be at least 2, so the block after the gap block is not the epoch switch block", ErrInvalidSubnetConfig, x.Gap)
	}
	if c.EIP1559Block != nil {
		return fmt.Errorf("%w: EIP1559Block must be unset, the subnet header has no base fee field", ErrInvalidSubnetConfig)
	}
	if c.TIPNoHalvingMNRewardBlock == nil || c.TIPNoHalvingMNRewardBlock.Sign() != 0 {
		return fmt.Errorf("%w: TIPNoHalvingMNRewardBlock must be 0, the subnet reward does not halve", ErrInvalidSubnetConfig)
	}
	for _, fork := range []struct {
		name  string
		block *big.Int
	}{
		{"TIPFixedRewardBlock", c.TIPFixedRewardBlock},
		{"TIPProportionalRewardBlock", c.TIPProportionalRewardBlock},
		{"TIPEpochHalvingBlock", c.TIPEpochHalvingBlock},
	} {
		if fork.block != nil {
			return fmt.Errorf("%w: %s must be unset, the subnet pays the flat masternode reward", ErrInvalidSubnetConfig, fork.name)
		}
	}
	for round, cfg := range x.V2.AllConfigs {
		if cfg != nil && cfg.MaxMasternodes <= 0 {
			return fmt.Errorf("%w: XDPoS.V2.AllConfigs[%d].MaxMasternodes must be positive", ErrInvalidSubnetConfig, round)
		}
	}
	return nil
}
