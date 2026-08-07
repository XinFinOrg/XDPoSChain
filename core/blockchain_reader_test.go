// Copyright 2015 The go-ethereum Authors
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

package core

import (
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/engines/engine_v2"
)

// BlockChain must keep satisfying the v2 engine's GapStateReader, otherwise
// Initial's startup repair silently skips a missing gap snapshot on
// production nodes. The check lives in a test file so that production core
// does not depend on a consensus engine implementation; engine_v2 must
// therefore never import core itself (only its subpackages), or an import
// cycle would result.
var _ engine_v2.GapStateReader = (*BlockChain)(nil)
