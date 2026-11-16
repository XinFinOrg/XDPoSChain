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

package hooks

import (
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/log"
)

// newSubnetPenaltyHook returns the subnet HookPenalty. The engine calls it when
// it derives the snapshot of a gap block, with number the gap block and
// parentHash its parent; candidates are not used. It follows the penalty rules
// of the subnet clients (Nethermind's SubnetPenaltyHandler, the XDC-Subnet
// HookPenalty):
//
//  1. Walk back from the parent of the gap block to the previous gap block
//     (block 1 for the first epochs), counting the blocks of each miner. At
//     every epoch switch block, and at the end of the walk, the masternodes of
//     that block's epoch that mined fewer than MinimunMinerBlockPerEpoch blocks
//     of the segment just counted are penalized, and the count restarts.
//  2. The penalties published by the previous block after a gap block are
//     carried over.
//  3. A penalized node comes back if it sent a signing transaction for one of
//     the MergeSignRange blocks among the last RangeReturnSigner blocks, scanning
//     upwards so a signing transaction only counts for a block seen before it.
//  4. The result is deduplicated and sorted by EIP-55 hex address.
func newSubnetPenaltyHook(adaptor *XDPoS.XDPoS) func(consensus.ChainReader, *big.Int, common.Hash, []common.Address) ([]common.Address, error) {
	return func(chain consensus.ChainReader, number *big.Int, parentHash common.Hash, _ []common.Address) ([]common.Address, error) {
		start := time.Now()
		epoch := chain.Config().XDPoS.Epoch
		gapNumber := number.Uint64()
		if gapNumber == 0 {
			return []common.Address{}, nil
		}
		stopNumber := uint64(1)
		if gapNumber > epoch+1 {
			stopNumber = gapNumber - epoch
		}

		var (
			penalties    = make(map[common.Address]struct{})
			minedBlocks  = make(map[common.Address]int)
			blockHashes  []common.Hash
			blockNumbers []uint64
		)
		for number, hash := gapNumber-1, parentHash; ; number-- {
			header := chain.GetHeader(hash, number)
			if header == nil {
				return nil, fmt.Errorf("subnet penalty: missing header %d (%s)", number, hash.Hex())
			}
			// The block after the previous gap block published the penalties
			// still in force, which carry over to the next epoch.
			if number == stopNumber+1 {
				for _, p := range common.ExtractAddressFromBytes(header.Penalties) {
					penalties[p] = struct{}{}
				}
			}
			blockHashes = append(blockHashes, hash)
			blockNumbers = append(blockNumbers, number)
			minedBlocks[header.Coinbase]++

			isEpochSwitch, _, err := adaptor.EngineV2.IsEpochSwitch(header)
			if err != nil {
				return nil, err
			}
			if isEpochSwitch || number <= stopNumber {
				for _, masternode := range adaptor.EngineV2.GetMasternodes(chain, header) {
					if minedBlocks[masternode] < common.MinimunMinerBlockPerEpoch {
						log.Info("[HookPenalty] subnet masternode did not mine enough blocks", "addr", masternode, "mined", minedBlocks[masternode], "segmentEnd", number)
						penalties[masternode] = struct{}{}
					}
				}
				clear(minedBlocks)
				if number <= stopNumber {
					break
				}
			}
			hash = header.ParentHash
		}

		// Comeback: scan the walked blocks upwards from the start of the range.
		startRange := uint64(1)
		if gapNumber+1 > common.RangeReturnSigner {
			startRange = gapNumber - common.RangeReturnSigner + 1
		}
		signedBlocks := make(map[common.Hash]struct{})
		for i := len(blockNumbers) - 1; i >= 0; i-- {
			blockNumber, blockHash := blockNumbers[i], blockHashes[i]
			if blockNumber < startRange {
				continue
			}
			if blockNumber%common.MergeSignRange == 0 {
				signedBlocks[blockHash] = struct{}{}
			}
			signingTxs, ok := adaptor.GetCachedSigningTxs(blockHash)
			if !ok {
				block := chain.GetBlock(blockHash, blockNumber)
				if block == nil {
					return nil, fmt.Errorf("subnet penalty: missing block %d (%s)", blockNumber, blockHash.Hex())
				}
				signingTxs = adaptor.CacheSigningTxs(blockHash, block.Transactions())
			}
			for _, tx := range signingTxs {
				if _, ok := signedBlocks[signedBlockHash(tx)]; !ok {
					continue
				}
				if from := tx.From(); from != nil {
					delete(penalties, *from)
				}
			}
		}

		result := make([]common.Address, 0, len(penalties))
		for p := range penalties {
			result = append(result, p)
		}
		slices.SortFunc(result, func(a, b common.Address) int {
			return strings.Compare(a.String0x(), b.String0x())
		})
		for i, p := range result {
			log.Info("[HookPenalty] subnet penalty", "gapNumber", gapNumber, "index", i, "addr", p)
		}
		log.Info("[HookPenalty] subnet penalties calculated", "gapNumber", gapNumber, "count", len(result), "elapsed", common.PrettyDuration(time.Since(start)))
		return result, nil
	}
}

// signedBlockHash returns the block hash a signing transaction signs, which is
// the last 32 bytes of its data.
func signedBlockHash(tx *types.Transaction) common.Hash {
	data := tx.Data()
	return common.BytesToHash(data[len(data)-32:])
}
