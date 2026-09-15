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
	"bytes"
	"hash/crc32"
	"math"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rlp"
	"github.com/stretchr/testify/assert"
)

// newIDFromHash is a test helper that calculates fork ID from a genesis hash instead of block
func newIDFromHash(config *params.ChainConfig, genesisHash common.Hash, head uint64) ID {
	// Calculate the starting checksum from the genesis hash
	hash := crc32.ChecksumIEEE(genesisHash.Bytes())

	// Calculate the current fork checksum and the next fork block
	forksByBlock := config.GatherForks()
	for _, fork := range forksByBlock {
		if fork <= head {
			// Fork already passed, checksum the previous hash and the fork number
			hash = checksumUpdate(hash, fork)
			continue
		}
		return ID{Hash: checksumToBytes(hash), Next: fork}
	}
	return ID{Hash: checksumToBytes(hash), Next: 0}
}

// TestCreation tests that different genesis and fork rule combinations result in
// the correct fork ID.
func TestCreation(t *testing.T) {
	type testcase struct {
		head uint64
		want ID
	}
	tests := []struct {
		config *params.ChainConfig
		hash   common.Hash
		cases  []testcase
	}{
		// Mainnet test cases - XDPoSChain specific fork checksums (BigEndian)
		{
			params.MainnetChainConfig,
			params.MainnetGenesisHash,
			[]testcase{
				// Genesis and early blocks
				{0, ID{Hash: checksumToBytes(0x0f331419), Next: 1150000}},       // Genesis block
				{100000, ID{Hash: checksumToBytes(0x0f331419), Next: 1150000}},  // Early block before first fork
				{1000000, ID{Hash: checksumToBytes(0x0f331419), Next: 1150000}}, // Block approaching first fork
				// First fork (1150000)
				{1149999, ID{Hash: checksumToBytes(0x0f331419), Next: 1150000}}, // Last block before first fork
				{1150000, ID{Hash: checksumToBytes(0x39f281ca), Next: 1920000}}, // First block after first fork
				{1500000, ID{Hash: checksumToBytes(0x39f281ca), Next: 1920000}}, // Block between first and second fork
				// Second fork (1920000)
				{1919999, ID{Hash: checksumToBytes(0x39f281ca), Next: 1920000}}, // Last block before second fork
				{1920000, ID{Hash: checksumToBytes(0x1c7c371f), Next: 2463000}}, // First block after second fork
				{2000000, ID{Hash: checksumToBytes(0x1c7c371f), Next: 2463000}}, // Block between second and third fork
				// Third fork (2463000)
				{2462999, ID{Hash: checksumToBytes(0x1c7c371f), Next: 2463000}}, // Last block before third fork
				{2463000, ID{Hash: checksumToBytes(0x5551b209), Next: 2675000}}, // First block after third fork
				{2500000, ID{Hash: checksumToBytes(0x5551b209), Next: 2675000}}, // Block between third and fourth fork
				// Fourth fork (2675000)
				{2674999, ID{Hash: checksumToBytes(0x5551b209), Next: 2675000}}, // Last block before fourth fork
				{2675000, ID{Hash: checksumToBytes(0x7cd95aba), Next: 4370000}}, // First block after fourth fork
				{3000000, ID{Hash: checksumToBytes(0x7cd95aba), Next: 4370000}}, // Block between fourth and final fork
				// Final fork (4370000)
				{4369999, ID{Hash: checksumToBytes(0x7cd95aba), Next: 4370000}}, // Last block before final fork
				{4370000, ID{Hash: checksumToBytes(0x84537aeb), Next: 0}},       // First block after final fork
				{5000000, ID{Hash: checksumToBytes(0x84537aeb), Next: 0}},       // Future block after all forks
				{10000000, ID{Hash: checksumToBytes(0x84537aeb), Next: 0}},      // Far future block
			},
		},
		// Testnet (Apothem) test cases
		{
			params.TestnetChainConfig,
			params.TestnetGenesisHash,
			[]testcase{
				// Genesis block
				{0, ID{Hash: checksumToBytes(0x6627b1ab), Next: 1}}, // Genesis
				// Fork at block 1
				{1, ID{Hash: checksumToBytes(0x6fdbe752), Next: 2}}, // After fork 1
				// Fork at block 2
				{2, ID{Hash: checksumToBytes(0x39b3de17), Next: 3}}, // After fork 2
				// Fork at block 3
				{3, ID{Hash: checksumToBytes(0x41c675d5), Next: 4}}, // After fork 3
				// Fork at block 4
				{4, ID{Hash: checksumToBytes(0x30c010d4), Next: 3000000}}, // After fork 4
				// Fork at block 3000000
				{2500000, ID{Hash: checksumToBytes(0x30c010d4), Next: 3000000}}, // Before fork 3000000
				{2999999, ID{Hash: checksumToBytes(0x30c010d4), Next: 3000000}}, // Just before fork 3000000
				{3000000, ID{Hash: checksumToBytes(0x0633fab8), Next: 3464000}}, // After fork 3000000
				{3200000, ID{Hash: checksumToBytes(0x0633fab8), Next: 3464000}}, // Between fork 3000000 and 3464000
				// Fork at block 3464000
				{3463999, ID{Hash: checksumToBytes(0x0633fab8), Next: 3464000}}, // Just before fork 3464000
				{3464000, ID{Hash: checksumToBytes(0x9ae3e747), Next: 5000000}}, // After fork 3464000
				// Fork at block 5000000
				{4000000, ID{Hash: checksumToBytes(0x9ae3e747), Next: 5000000}},  // Before fork 5000000
				{4999999, ID{Hash: checksumToBytes(0x9ae3e747), Next: 5000000}},  // Just before fork 5000000
				{5000000, ID{Hash: checksumToBytes(0x97ca7963), Next: 23779191}}, // After fork 5000000
				// Fork at block 23779191
				{23000000, ID{Hash: checksumToBytes(0x97ca7963), Next: 23779191}}, // Before fork 23779191
				{23779190, ID{Hash: checksumToBytes(0x97ca7963), Next: 23779191}}, // Just before fork 23779191
				{23779191, ID{Hash: checksumToBytes(0x6c07b5cf), Next: 56828700}}, // After fork 23779191
				// Fork at block 56828700
				{50000000, ID{Hash: checksumToBytes(0x6c07b5cf), Next: 56828700}}, // Before fork 56828700
				{56828699, ID{Hash: checksumToBytes(0x6c07b5cf), Next: 56828700}}, // Just before fork 56828700
				{56828700, ID{Hash: checksumToBytes(0x07a2b1b8), Next: 61290000}}, // After fork 56828700
				// Fork at block 61290000
				{60000000, ID{Hash: checksumToBytes(0x07a2b1b8), Next: 61290000}}, // Before fork 61290000
				{61289999, ID{Hash: checksumToBytes(0x07a2b1b8), Next: 61290000}}, // Just before fork 61290000
				{61290000, ID{Hash: checksumToBytes(0x5aee5f80), Next: 66825000}}, // After fork 61290000
				// Fork at block 66825000
				{66824999, ID{Hash: checksumToBytes(0x5aee5f80), Next: 66825000}}, // Just before fork 66825000
				{66825000, ID{Hash: checksumToBytes(0x6e0b9072), Next: 71550000}}, // After fork 66825000
				// Fork at block 71550000
				{71549999, ID{Hash: checksumToBytes(0x6e0b9072), Next: 71550000}}, // Just before fork 71550000
				{71550000, ID{Hash: checksumToBytes(0x5cab807f), Next: 71551800}}, // After fork 71550000
				// Fork at block 71551800
				{71551799, ID{Hash: checksumToBytes(0x5cab807f), Next: 71551800}}, // Just before fork 71551800
				{71551800, ID{Hash: checksumToBytes(0xebce6795), Next: 83600000}}, // After fork 71551800
				// Final fork at block 83600000
				{83599999, ID{Hash: checksumToBytes(0xebce6795), Next: 83600000}}, // Just before final fork
				{83600000, ID{Hash: checksumToBytes(0x7fcfc8b0), Next: 0}},        // After final fork
				{90000000, ID{Hash: checksumToBytes(0x7fcfc8b0), Next: 0}},        // Future block after all forks
			},
		},
	}
	for i, tt := range tests {
		for j, ttt := range tt.cases {
			if have := newIDFromHash(tt.config, tt.hash, ttt.head); have != ttt.want {
				t.Errorf("test %d, case %d: fork ID mismatch: have %x, want %x", i, j, have, ttt.want)
			}
		}
	}
}

// TestValidation tests that a local peer correctly validates and accepts a remote
// fork ID.
func TestValidation(t *testing.T) {
	// Config for mainnet with XDPoSChain fork values
	config := params.MainnetChainConfig

	tests := []struct {
		config *params.ChainConfig
		head   uint64
		id     ID
		err    error
	}{
		//-----------------------------------
		// Local and remote at same state
		//-----------------------------------

		// Local is mainnet after final fork, remote announces the same. No future fork is announced.
		{config, 4370000, ID{Hash: checksumToBytes(0x84537aeb), Next: 0}, nil},

		// Local is mainnet after final fork, remote announces the same. Remote also announces a next fork
		// at block 0xffffffff, but that is uncertain.
		{config, 4370000, ID{Hash: checksumToBytes(0x84537aeb), Next: math.MaxUint64}, nil},

		//-----------------------------------
		// Local and remote before first fork
		//-----------------------------------

		// Local is mainnet currently before any fork, remote announces the same. No future fork is announced.
		{config, 0, ID{Hash: checksumToBytes(0x0f331419), Next: 0}, nil},

		// Local is mainnet currently before any fork, remote announces also before fork, but with future fork
		{config, 100000, ID{Hash: checksumToBytes(0x0f331419), Next: 1150000}, nil},

		// Local is mainnet before fork, remote announces before fork but without awareness of future fork
		{config, 100000, ID{Hash: checksumToBytes(0x0f331419), Next: 0}, nil},

		//-----------------------------------
		// Local and remote between forks
		//-----------------------------------

		// Local is mainnet at first fork (1150000), remote announces genesis + knowledge about first fork.
		// Remote is simply out of sync, accept.
		{config, 1150000, ID{Hash: checksumToBytes(0x0f331419), Next: 1150000}, nil},

		// Local is mainnet between first and second fork, remote announces same block-based state
		{config, 1500000, ID{Hash: checksumToBytes(0x39f281ca), Next: 1920000}, nil},

		// Local is mainnet after first fork, remote announces genesis state - remote is behind but compatible
		{config, 1500000, ID{Hash: checksumToBytes(0x0f331419), Next: 1150000}, nil},

		// Local is mainnet between forks, remote announces prior fork state - remote is far behind
		{config, 2000000, ID{Hash: checksumToBytes(0x39f281ca), Next: 1920000}, nil},

		//-----------------------------------
		// Remote stale cases
		//-----------------------------------

		// Local is mainnet after second fork, remote announces first fork state without next boundary.
		// Remote needs software update.
		{config, 2000000, ID{Hash: checksumToBytes(0x39f281ca), Next: 0}, ErrRemoteStale},

		// Local is mainnet at third fork, remote announces second fork state without awareness of further forks.
		// Remote needs software update.
		{config, 2463000, ID{Hash: checksumToBytes(0x1c7c371f), Next: 0}, ErrRemoteStale},

		// Local is mainnet after final fork, remote announces genesis state without any next fork awareness.
		// Remote is severely outdated.
		{config, 4370000, ID{Hash: checksumToBytes(0x0f331419), Next: 0}, ErrRemoteStale},

		// Local is mainnet after final fork, remote announces first fork without higher fork awareness.
		// Remote needs software update.
		{config, 4370000, ID{Hash: checksumToBytes(0x39f281ca), Next: 0}, ErrRemoteStale},

		//-----------------------------------
		// Local out of sync cases (future forks unknown to local)
		//-----------------------------------

		// Local is mainnet before first fork, remote announces after first fork.
		// Local is out of sync, accept.
		{config, 100000, ID{Hash: checksumToBytes(0x39f281ca), Next: 1920000}, nil},

		// Local is mainnet at first fork, remote announces after second fork.
		// Local is out of sync, accept.
		{config, 1150000, ID{Hash: checksumToBytes(0x1c7c371f), Next: 2463000}, nil},

		// Local is mainnet between forks, remote announces state we haven't reached yet
		{config, 1500000, ID{Hash: checksumToBytes(0x1c7c371f), Next: 2463000}, nil},

		//-----------------------------------
		// Incompatible fork cases
		//-----------------------------------

		// Remote has unknown checksum - should reject
		{config, 0, ID{Hash: checksumToBytes(0xffffffff), Next: 0}, ErrLocalIncompatibleOrStale},

		// Local is mainnet between forks, remote has completely different checksum
		{config, 1500000, ID{Hash: checksumToBytes(0xdeadbeef), Next: 1920000}, ErrLocalIncompatibleOrStale},

		// Remote is showing incompatible intermediate state
		{config, 2000000, ID{Hash: checksumToBytes(0x12345678), Next: 2463000}, ErrLocalIncompatibleOrStale},

		// Local is mainnet at final fork, remote is on incompatible chain
		{config, 4370000, ID{Hash: checksumToBytes(0xabcdef00), Next: 0}, ErrLocalIncompatibleOrStale},

		// Local is mainnet between forks, remote has fake future fork
		{config, 2000000, ID{Hash: checksumToBytes(0x39f281ca), Next: 1920000}, nil},

		// Local is mainnet far in the future. Remote announces fake fork at some future block,
		// but past block for local. Remote's checksum matches our final state, so it's acceptable.
		{config, 10000000, ID{Hash: checksumToBytes(0x84537aeb), Next: 5000000}, nil},

		// Local is mainnet between forks. Remote announces same state but with invalid next fork.
		// This is tricky - same checksum means same fork history, but next differs
		{config, 1500000, ID{Hash: checksumToBytes(0x39f281ca), Next: 1900000}, nil}, // Close enough, might be syncing

		// Remote has higher fork awareness but wrong checksum - definitely incompatible
		{config, 1500000, ID{Hash: checksumToBytes(0xffffffff), Next: 1920000}, ErrLocalIncompatibleOrStale},

		//-----------------------------------
		// Edge cases
		//-----------------------------------

		// Local is at genesis, remote at genesis - perfect match
		{config, 0, ID{Hash: checksumToBytes(0x0f331419), Next: 1150000}, nil},

		// Local way ahead of any forks, remote at genesis but aware of first fork
		{config, 100000000, ID{Hash: checksumToBytes(0x0f331419), Next: 1150000}, nil},

		// Local and remote both at final fork with same state
		{config, 10000000, ID{Hash: checksumToBytes(0x84537aeb), Next: 0}, nil},
	}
	for i, tt := range tests {
		filter := newFilter(tt.config, params.MainnetGenesisHash, func() uint64 { return tt.head })
		if err := filter(tt.id); err != tt.err {
			t.Errorf("test %d: validation error mismatch: have %v, want %v", i, err, tt.err)
		}
	}
}

// TestEncoding tests that IDs are properly RLP encoded (specifically important because we
// use uint32 to store the hash, but we need to encode it as [4]byte).
func TestEncoding(t *testing.T) {
	tests := []struct {
		id   ID
		want []byte
	}{
		{ID{Hash: checksumToBytes(0), Next: 0}, common.Hex2Bytes("c6840000000080")},
		{ID{Hash: checksumToBytes(0xdeadbeef), Next: 0xBADDCAFE}, common.Hex2Bytes("ca84deadbeef84baddcafe")},
		{ID{Hash: checksumToBytes(math.MaxUint32), Next: math.MaxUint64}, common.Hex2Bytes("ce84ffffffff88ffffffffffffffff")},
	}
	for i, tt := range tests {
		have, err := rlp.EncodeToBytes(tt.id)
		if err != nil {
			t.Errorf("test %d: failed to encode forkid: %v", i, err)
			continue
		}
		if !bytes.Equal(have, tt.want) {
			t.Errorf("test %d: RLP mismatch: have %x, want %x", i, have, tt.want)
		}
	}
}

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
