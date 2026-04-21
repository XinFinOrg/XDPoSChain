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

package forkid

import (
	"hash/crc32"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

func TestNewID(t *testing.T) {
	genesis := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(0)})
	config := &params.ChainConfig{
		BerlinBlock:  big.NewInt(1000),
		EIP1559Block: big.NewInt(1000),
		XDPoS: &params.XDPoSConfig{V2: &params.V2{
			SwitchBlock: big.NewInt(1500),
		}},
	}

	genesisChecksum := crc32.ChecksumIEEE(genesis.Hash().Bytes())
	after1000 := checksumUpdate(genesisChecksum, 1000)
	after1500 := checksumUpdate(after1000, 1500)

	tests := []struct {
		name string
		head uint64
		want ID
	}{
		{
			name: "before first fork",
			head: 999,
			want: ID{Hash: checksumToBytes(genesisChecksum), Next: 1000},
		},
		// Duplicate fork heights are deduplicated by GatherForks; this case asserts
		// that NewID observes the deduplicated list returned by the chain config.
		{
			name: "at duplicated block fork only updates once",
			head: 1000,
			want: ID{Hash: checksumToBytes(after1000), Next: 1500},
		},
		{
			name: "before xdpos v2 switch keeps next boundary",
			head: 1499,
			want: ID{Hash: checksumToBytes(after1000), Next: 1500},
		},
		{
			name: "at xdpos v2 switch consumes final fork",
			head: 1500,
			want: ID{Hash: checksumToBytes(after1500), Next: 0},
		},
		{
			name: "after all forks stays final",
			head: 2000,
			want: ID{Hash: checksumToBytes(after1500), Next: 0},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, NewID(config, genesis, test.head))
		})
	}
}

func TestNewIDWithoutForks(t *testing.T) {
	genesis := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(0)})
	checksum := crc32.ChecksumIEEE(genesis.Hash().Bytes())

	assert.Equal(t, ID{Hash: checksumToBytes(checksum), Next: 0}, NewID(&params.ChainConfig{}, genesis, 0))
}

func TestNewIDIncludesDAOForkBlockInChecksum(t *testing.T) {
	genesis := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(0)})
	config := &params.ChainConfig{
		HomesteadBlock: big.NewInt(0),
		DAOForkBlock:   big.NewInt(5),
		EIP150Block:    big.NewInt(9),
	}

	genesisChecksum := crc32.ChecksumIEEE(genesis.Hash().Bytes())
	afterDAO := checksumUpdate(genesisChecksum, 5)
	afterEIP150 := checksumUpdate(afterDAO, 9)

	assert.Equal(t, ID{Hash: checksumToBytes(afterDAO), Next: 9}, NewID(config, genesis, 5))
	assert.Equal(t, ID{Hash: checksumToBytes(afterEIP150), Next: 0}, NewID(config, genesis, 9))
}
