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

package eth

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

// AdminAPI is the collection of Ethereum full node related APIs for node
// administration.
type AdminAPI struct {
	eth *Ethereum
}

// NewAdminAPI creates a new instance of AdminAPI.
func NewAdminAPI(eth *Ethereum) *AdminAPI {
	return &AdminAPI{eth: eth}
}

// ExportChain exports the current blockchain into a local file.
func (api *AdminAPI) ExportChain(file string) (bool, error) {
	// Make sure we can create the file to export into
	out, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return false, err
	}
	defer out.Close()

	var writer io.Writer = out
	if strings.HasSuffix(file, ".gz") {
		writer = gzip.NewWriter(writer)
		defer writer.(*gzip.Writer).Close()
	}

	// Export the blockchain
	if err := api.eth.BlockChain().Export(writer); err != nil {
		return false, err
	}
	return true, nil
}

// missingBlocks returns the suffix of the batch that still has to be run, starting at the first
// block this node cannot answer for - the same line, and the same shape, cmd/utils.missingBlocks
// draws over the same batch. That line lives in core (see BlockChain.FirstMissingImportedBlock,
// which carries the reasoning), so this importer and the CLI one cannot drift apart.
//
// The suffix is what this importer runs, and the shape matters: the blocks before the first missing
// one are ones this node already holds, so handing the batch over whole would run it through the
// batch verifiers again and let it adopt them, where this precheck only decides what is skipped.
//
// A batch this node executed above a head that stops below it is answered as imported too: this
// precheck decides what the import skips, not where the head ends up. That shape is recovered by
// the sync paths, which do not come through here.
func missingBlocks(chain *core.BlockChain, bs []*types.Block) []*types.Block {
	if first := chain.FirstMissingImportedBlock(bs); first >= 0 {
		return bs[first:]
	}
	return nil
}

// ImportChain imports a blockchain from a local file.
func (api *AdminAPI) ImportChain(file string) (bool, error) {
	// Make sure the can access the file to import
	in, err := os.Open(file)
	if err != nil {
		return false, err
	}
	defer in.Close()

	var reader io.Reader = in
	if strings.HasSuffix(file, ".gz") {
		if reader, err = gzip.NewReader(reader); err != nil {
			return false, err
		}
	}

	// Run actual the import in pre-configured batches
	stream := rlp.NewStream(reader, 0)

	blocks, index := make([]*types.Block, 0, 2500), 0
	for batch := 0; ; batch++ {
		// Load a batch of blocks from the input file
		for len(blocks) < cap(blocks) {
			block := new(types.Block)
			if err := stream.Decode(block); err == io.EOF {
				break
			} else if err != nil {
				return false, fmt.Errorf("block %d: failed to parse: %v", index, err)
			}
			// Count the block before the genesis skip below: index names a position in the input
			// stream, and a malformed block has to be reported there.
			index++
			// The first block of an export is the exporting node's genesis block, which never has
			// to be imported: the insertion paths answer this node's own by its hash, and a block
			// 0 of another chain is rejected by the batch verifiers that resolve the parent of
			// block 0 (ethash's does, XDPoS's does not) before ValidateBody can answer it. The CLI
			// importer drops it the same way, as does upstream go-ethereum.
			if block.NumberU64() == 0 {
				continue
			}
			blocks = append(blocks, block)
		}
		if len(blocks) == 0 {
			break
		}

		missing := missingBlocks(api.eth.BlockChain(), blocks)
		if len(missing) == 0 {
			blocks = blocks[:0]
			continue
		}
		// Import the batch and reset the buffer. A batch can end on a block this node already
		// has, but only in the one shape insertChain hands the sentinel out from (a future tail
		// stopping on an executed block). Reaching that tail takes a block dated ahead of this
		// node's clock, which the file importers replaying historical blocks do not meet, so
		// the branch is defensive; a batch that does land there reports "already imported"
		// below, not a failed insert.
		if _, err := api.eth.BlockChain().InsertChain(missing); err != nil {
			// A local condition says nothing about the blocks in the file: blaming them would
			// report this node's own state as a failed import. core owns the classification, so
			// this importer and cmd/utils cannot drift apart.
			if reason, ok := core.DescribeLocalInsertFailure(err); ok {
				return false, fmt.Errorf("batch %d: %s: %v", batch, reason, err)
			}
			return false, fmt.Errorf("batch %d: failed to insert: %v", batch, err)
		}
		blocks = blocks[:0]
	}
	return true, nil
}
