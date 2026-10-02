// Copyright 2026 The go-ethereum Authors
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
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
)

// TestInsertChainReportsFarFutureBlockAsLocal pins the classification of a block whose
// timestamp is past the future queue's window: the node cannot place it yet, but the block
// itself is not wrong, so the failure has to be recognisable as a local condition and the
// downloader must not drop the peer that served it.
func TestInsertChainReportsFarFutureBlockAsLocal(t *testing.T) {
	engine := &failFromEngine{Engine: ethash.NewFaker(), fromNumber: 1, failErr: consensus.ErrFutureBlock}
	chain, blocks := newFarFutureChain(t, engine)

	_, err := chain.InsertChain(blocks)
	if err == nil {
		t.Fatal("expected the block past the future window to be reported")
	}
	if !IsLocalInsertError(err) {
		t.Fatalf("a block this node's clock cannot place yet is a local condition: %v", err)
	}
	if chain.futureBlocks.Contains(blocks[0].Hash()) {
		t.Fatal("a block the queue refused must not be parked")
	}
}
