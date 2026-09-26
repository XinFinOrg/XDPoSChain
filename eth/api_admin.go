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

// hasAllBlocks answers whether this node already imported every block of the batch, with the
// same line cmd/utils.missingBlocks draws over the same batch: below the head the state is
// available at the head, so a body on disk is what says the block was imported, while at or
// above it the block has to have been executed by this node (see HasExecutedBlock). Answering
// on bodies alone would report blocks this node only wrote as side entries - stored without
// their receipts and state by writeBlockWithoutState - as an import that needs no running, and
// the batch would be skipped with the head left where it was.
//
// That line is a second copy rather than a shared helper - each importer asks the question in
// its own package - so a change to one has to be made to the other as well. What the two do
// share is the reason they report: see core.DescribeLocalInsertFailure.
//
// The two sides are the same split the CLI importer makes, so a block below the head is still
// answered on its body: making that side stricter would change where missingBlocks starts an
// import from as well, which is a behaviour change rather than this fix. The shape the
// executed-block question ends is the one above the head.
//
// A chain that reports no head has imported nothing, so it is answered the way a missing body
// is: core reports the same condition of this node as a local insert condition (see its
// headTd), and a batch cannot have been imported into a chain that has no head.
//
// A batch this node executed above a head that stops below it is answered as imported too:
// this precheck decides what the import skips, not where the head ends up. Recovering that
// shape is left to the sync paths, which do not come through here.
func hasAllBlocks(chain *core.BlockChain, bs []*types.Block) bool {
	head := chain.CurrentBlock()
	if head == nil {
		return false
	}
	for _, b := range bs {
		if head.Number.Uint64() > b.NumberU64() {
			if !chain.HasBlock(b.Hash(), b.NumberU64()) {
				return false
			}
			continue
		}
		if !chain.HasExecutedBlock(b.Hash(), b.NumberU64()) {
			return false
		}
	}

	return true
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
			blocks = append(blocks, block)
			index++
		}
		if len(blocks) == 0 {
			break
		}

		if hasAllBlocks(api.eth.BlockChain(), blocks) {
			blocks = blocks[:0]
			continue
		}
		// Import the batch and reset the buffer. A batch can still end on a block this
		// node already has, but only in the one shape insertChain hands the sentinel out
		// from - a future tail stopping on an executed block, see the note there - and that
		// needs no retry here: from anywhere else insertChain consumes every known block
		// itself - adopting it, or skipping it when it does not beat the head - and carries
		// on with the rest of the batch.
		if _, err := api.eth.BlockChain().InsertChain(blocks); err != nil {
			// A local condition says nothing about the blocks in the file: blaming them would
			// report this node's own state as a failed import. core owns the classification
			// and the reason, so this importer and cmd/utils cannot drift apart.
			if reason, ok := core.DescribeLocalInsertFailure(err); ok {
				return false, fmt.Errorf("batch %d: %s: %v", batch, reason, err)
			}
			return false, fmt.Errorf("batch %d: failed to insert: %v", batch, err)
		}
		blocks = blocks[:0]
	}
	return true, nil
}
