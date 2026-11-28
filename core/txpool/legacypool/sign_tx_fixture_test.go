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

package legacypool

import (
	"github.com/XinFinOrg/XDPoSChain/common"
)

// signTxData is a well-formed sign(uint256,bytes32) call that signs block 0,
// valid for every block the test pools build on. tag varies the signed hash,
// so two calls with different tags give different transactions.
func signTxData(tag byte) []byte {
	data := common.Hex2Bytes(common.HexSignMethod)
	data = append(data, make([]byte, 32)...)
	hash := common.Hash{tag, 0x01}
	return append(data, hash.Bytes()...)
}
