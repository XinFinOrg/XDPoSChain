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

package downloader

import (
	"errors"
	"fmt"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// TestImportBlockResultsKeepsPeerOnInterruption guards the local-interruption path of
// importBlockResults: an insertion cut short by InterruptInsert says nothing about the peer that
// served the blocks, so it must not become the errInvalidChain that Synchronise drops the peer for.
func TestImportBlockResultsKeepsPeerOnInterruption(t *testing.T) {
	tester := newTester()
	defer tester.terminate()

	block := testChainBase.shorten(2).headBlock()
	tester.insertChainHook = func(types.Blocks) error { return core.ErrInsertionInterrupted }

	err := tester.downloader.importBlockResults([]*fetchResult{{
		Header:       block.Header(),
		Uncles:       block.Uncles(),
		Transactions: block.Transactions(),
	}})
	if err == nil {
		t.Fatal("expected the interruption to be reported")
	}
	if errors.Is(err, errInvalidChain) {
		t.Fatalf("a locally interrupted insertion must not be an invalid chain: %v", err)
	}
	if !errors.Is(err, errLocalInsertFailure) {
		t.Fatalf("unexpected error: have %v want %v", err, errLocalInsertFailure)
	}
	// The sentinel has to carry the cause: telling a stop from a cancel and from a refused
	// reorg is what the operator has to act on.
	if !errors.Is(err, core.ErrInsertionInterrupted) {
		t.Fatalf("the local condition must keep its cause: have %v want %v", err, core.ErrInsertionInterrupted)
	}
}

// TestImportBlockResultsKeepsPeerOnStoppedChain covers the other local condition InsertChain can
// report: the chain is stopping, so the batch was never even looked at. That is just as local as an
// interruption, so the peer must be kept here too instead of being dropped through errInvalidChain.
func TestImportBlockResultsKeepsPeerOnStoppedChain(t *testing.T) {
	tester := newTester()
	defer tester.terminate()

	block := testChainBase.shorten(2).headBlock()
	tester.insertChainHook = func(types.Blocks) error { return core.ErrChainStopped }

	err := tester.downloader.importBlockResults([]*fetchResult{{
		Header:       block.Header(),
		Uncles:       block.Uncles(),
		Transactions: block.Transactions(),
	}})
	if err == nil {
		t.Fatal("expected the stopped chain to be reported")
	}
	if errors.Is(err, errInvalidChain) {
		t.Fatalf("a locally stopped insertion must not be an invalid chain: %v", err)
	}
	if !errors.Is(err, errLocalInsertFailure) {
		t.Fatalf("unexpected error: have %v want %v", err, errLocalInsertFailure)
	}
	if !errors.Is(err, core.ErrChainStopped) {
		t.Fatalf("the local condition must keep its cause: have %v want %v", err, core.ErrChainStopped)
	}
}

// TestImportBlockResultsKeepsPeerOnKnownBlock covers the batch that stops on a block this node
// already stores with its state: the peer served exactly the range it was asked for, so it must not
// be dropped through errInvalidChain. ErrKnownBlock is one of the local conditions
// IsLocalInsertError enumerates; the error is injected through a hook, so this pins the
// classification rather than proving insertChain still produces it.
func TestImportBlockResultsKeepsPeerOnKnownBlock(t *testing.T) {
	tester := newTester()
	defer tester.terminate()

	block := testChainBase.shorten(2).headBlock()
	tester.insertChainHook = func(types.Blocks) error { return core.ErrKnownBlock }

	err := tester.downloader.importBlockResults([]*fetchResult{{
		Header:       block.Header(),
		Uncles:       block.Uncles(),
		Transactions: block.Transactions(),
	}})
	if err == nil {
		t.Fatal("expected the known block to be reported")
	}
	if errors.Is(err, errInvalidChain) {
		t.Fatalf("a batch stopping on a known block must not be an invalid chain: %v", err)
	}
	if !errors.Is(err, errLocalInsertFailure) {
		t.Fatalf("unexpected error: have %v want %v", err, errLocalInsertFailure)
	}
	if !errors.Is(err, core.ErrKnownBlock) {
		t.Fatalf("the local condition must keep its cause: have %v want %v", err, core.ErrKnownBlock)
	}
}

// TestImportBlockResultsKeepsPeerOnPrunedAncestor covers the local condition that needs an ancestor
// whose state this node no longer holds: the peer served a valid range this node cannot link, so it
// must not become errInvalidChain. As above, the error is injected through a hook, so this pins the
// classification rather than proving insertChain still produces it.
func TestImportBlockResultsKeepsPeerOnPrunedAncestor(t *testing.T) {
	tester := newTester()
	defer tester.terminate()

	block := testChainBase.shorten(2).headBlock()
	tester.insertChainHook = func(types.Blocks) error { return consensus.ErrPrunedAncestor }

	err := tester.downloader.importBlockResults([]*fetchResult{{
		Header:       block.Header(),
		Uncles:       block.Uncles(),
		Transactions: block.Transactions(),
	}})
	if err == nil {
		t.Fatal("expected the pruned ancestor to be reported")
	}
	if errors.Is(err, errInvalidChain) {
		t.Fatalf("a batch whose ancestor state is gone must not be an invalid chain: %v", err)
	}
	if !errors.Is(err, errLocalInsertFailure) {
		t.Fatalf("unexpected error: have %v want %v", err, errLocalInsertFailure)
	}
	if !errors.Is(err, consensus.ErrPrunedAncestor) {
		t.Fatalf("the local condition must keep its cause: have %v want %v", err, consensus.ErrPrunedAncestor)
	}
}

// TestCommitPivotBlockKeepsPeerOnLocalInsertError covers the pivot commit of fast sync, the other
// insertion call the downloader makes: an import cut short or a chain stopping says nothing about the
// pivot the peer served, so it must end the cycle instead of dropping the peer.
func TestCommitPivotBlockKeepsPeerOnLocalInsertError(t *testing.T) {
	tester := newTester()
	defer tester.terminate()

	block := testChainBase.shorten(2).headBlock()
	tester.insertReceiptChainHook = func(types.Blocks, []types.Receipts) error {
		return core.ErrInsertionInterrupted
	}
	err := tester.downloader.commitPivotBlock(&fetchResult{Header: block.Header()})
	if err == nil {
		t.Fatal("expected the interrupted pivot commit to be reported")
	}
	if errors.Is(err, errInvalidChain) {
		t.Fatalf("a locally interrupted insertion must not be an invalid chain: %v", err)
	}
	if !errors.Is(err, errLocalInsertFailure) {
		t.Fatalf("unexpected error: have %v want %v", err, errLocalInsertFailure)
	}
	if !errors.Is(err, core.ErrInsertionInterrupted) {
		t.Fatalf("the local condition must keep its cause: have %v want %v", err, core.ErrInsertionInterrupted)
	}
}

// TestImportBlockResultsKeepsPeerOnReorgRefusal covers the local condition that adopting an already
// stored block can raise: a reorg this node refuses (a missing ancestor chain, or the XDPoS
// committed-block guard) says nothing about the blocks, so it must not become errInvalidChain.
func TestImportBlockResultsKeepsPeerOnReorgRefusal(t *testing.T) {
	tester := newTester()
	defer tester.terminate()

	block := testChainBase.shorten(2).headBlock()
	tester.insertChainHook = func(types.Blocks) error {
		return fmt.Errorf("%w: stop reorg, blockchain is under forking attack", core.ErrLocalInsertRefused)
	}

	err := tester.downloader.importBlockResults([]*fetchResult{{
		Header:       block.Header(),
		Uncles:       block.Uncles(),
		Transactions: block.Transactions(),
	}})
	if err == nil {
		t.Fatal("expected the refused reorg to be reported")
	}
	if errors.Is(err, errInvalidChain) {
		t.Fatalf("a locally refused reorg must not be an invalid chain: %v", err)
	}
	if !errors.Is(err, errLocalInsertFailure) {
		t.Fatalf("unexpected error: have %v want %v", err, errLocalInsertFailure)
	}
	if !errors.Is(err, core.ErrLocalInsertRefused) {
		t.Fatalf("the local condition must keep its cause: have %v want %v", err, core.ErrLocalInsertRefused)
	}
}

// TestCommitFastSyncDataKeepsPeerOnStoppedChain is the fast sync counterpart of
// TestImportBlockResultsKeepsPeerOnStoppedChain: InsertReceiptChain reports the same local conditions
// as InsertChain, and commitFastSyncData must exempt them too instead of blaming the peer.
func TestCommitFastSyncDataKeepsPeerOnStoppedChain(t *testing.T) {
	tester := newTester()
	defer tester.terminate()

	block := testChainBase.shorten(2).headBlock()
	tester.insertReceiptChainHook = func(types.Blocks, []types.Receipts) error { return core.ErrChainStopped }

	err := tester.downloader.commitFastSyncData([]*fetchResult{{
		Header:       block.Header(),
		Uncles:       block.Uncles(),
		Transactions: block.Transactions(),
	}}, &stateSync{done: make(chan struct{})})
	if err == nil {
		t.Fatal("expected the stopped chain to be reported")
	}
	if errors.Is(err, errInvalidChain) {
		t.Fatalf("a locally stopped insertion must not be an invalid chain: %v", err)
	}
	if !errors.Is(err, errLocalInsertFailure) {
		t.Fatalf("unexpected error: have %v want %v", err, errLocalInsertFailure)
	}
	if !errors.Is(err, core.ErrChainStopped) {
		t.Fatalf("the local condition must keep its cause: have %v want %v", err, core.ErrChainStopped)
	}
}
