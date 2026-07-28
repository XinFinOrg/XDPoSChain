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

package core

import (
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// The denylist is split into versions, each with its own activation height in
// the chain config. Resolving an address to its version and then gating on that
// version's height means adding addresses never changes the verdict of an
// already-sealed block: a node replaying history from genesis reaches the same
// result as the node that first validated the chain.
//
// Nothing here needs to change to introduce a version. Tag the new addresses
// with the next version in common.denylist and schedule that version in
// ChainConfig.DenylistActivations.

// IsDeniedSender reports whether from is denied as a transaction sender at block
// num, under whichever denylist version lists it.
func IsDeniedSender(config *params.ChainConfig, num *big.Int, from *common.Address) bool {
	return isDenied(config, num, from)
}

// IsDeniedReceiver reports whether to is denied as a transaction recipient at
// block num, under whichever denylist version lists it.
func IsDeniedReceiver(config *params.ChainConfig, num *big.Int, to *common.Address) bool {
	return isDenied(config, num, to)
}

// isDenied resolves address to its denylist version and reports whether that
// version is active at num. A nil num means the height is unknown, for example
// a transaction being admitted to the pool before any head exists, in which case
// every version is treated as active.
func isDenied(config *params.ChainConfig, num *big.Int, address *common.Address) bool {
	version, listed := common.DenylistVersion(address)
	if !listed {
		return false
	}
	if num == nil {
		return true
	}
	return config.IsDenylistVersion(version, num)
}
