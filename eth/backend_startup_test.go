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

package eth

import (
	"math/big"
	"path/filepath"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/XDCx"
	"github.com/XinFinOrg/XDPoSChain/XDCxlending"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/eth/ethconfig"
	"github.com/XinFinOrg/XDPoSChain/node"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// newSetHeadGenesis returns a genesis whose startup repair is decided by state
// availability alone: without the XDPoS engine the XDCX and lending state
// checks in loadLastState and repair are skipped.
func newSetHeadGenesis() *core.Genesis {
	key, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	return &core.Genesis{
		Alloc:   types.GenesisAlloc{crypto.PubkeyToAddress(key.PublicKey): {Balance: big.NewInt(1000000000000000)}},
		BaseFee: big.NewInt(params.InitialBaseFee),
		Config:  params.TestChainConfig,
	}
}

// bootSetHeadNode starts a node carrying an eth service on dataDir. The caller
// closes the returned node to release the chaindata lock.
func bootSetHeadNode(t *testing.T, dataDir string, gspec *core.Genesis) (*node.Node, *Ethereum, error) {
	t.Helper()

	n, err := node.New(&node.Config{Name: "geth", DataDir: dataDir})
	if err != nil {
		t.Fatalf("can't create node: %v", err)
	}
	xdcx := XDCx.New(n, &XDCx.Config{DataDir: filepath.Join(dataDir, "XDCx")})
	lending := XDCxlending.New(n, xdcx)

	ethservice, err := New(n, &ethconfig.Config{Genesis: gspec}, xdcx, lending)
	if err != nil {
		n.Close()
		return nil, nil, err
	}
	if err := n.Start(); err != nil {
		n.Close()
		return nil, nil, err
	}
	return n, ethservice, nil
}

// TestNewResolvesSetHeadAgainstTheHeadRecordedOnDisk pins the startup ordering
// that eth.New depends on: a relative --set-head request is counted from the
// head recorded on disk, and it is resolved before core.NewBlockChainExResolved
// opens the chain, which runs repair and may rewind a head whose state is
// missing. TestResolveRollbackTarget covers the arithmetic; what these cases add
// is that the order of the two steps in eth.New is observable. Moving the
// resolution below the chain construction keeps every helper test green, but the
// request is then counted from the repaired head, which both cases reject.
//
// Every case persists a six block chain and deletes the state of its head, so
// that reopening has to repair. A clean shutdown writes the state of the head
// and of its parent, so the repair falls back to block five, and block four and
// below carry no state at all: the recorded head six is the only base a relative
// request can be counted from.
func TestNewResolvesSetHeadAgainstTheHeadRecordedOnDisk(t *testing.T) {
	tests := []struct {
		name     string
		request  int64
		wantHead uint64
		wantErr  string
	}{
		{
			// The request means 6-1=5, which is where repair already landed.
			// Counted from the repaired head it would mean 5-1=4, rewind one
			// block too far.
			name:     "offset counts from the recorded head, not the repaired one",
			request:  -1,
			wantHead: 5,
		},
		{
			// The request means 6-2=4, a block without state. Repair, bounded by
			// that resolved target, cannot stop there and ends up at the genesis
			// block, so the rollback is refused. Losing the resolved target would
			// leave repair unbounded, land it on block five instead, and turn the
			// same request into a silent rollback to genesis.
			name:    "the resolved target bounds the repair and is enforced",
			request: -2,
			wantErr: "can't rollback to 4 which is greater than current 0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// RollbackNumber is a package level global; keep the subtests
			// sequential and restore it for the rest of the package.
			prev := common.RollbackNumber
			common.RollbackNumber = 0
			t.Cleanup(func() { common.RollbackNumber = prev })

			dataDir := t.TempDir()
			gspec := newSetHeadGenesis()
			_, blocks, _ := core.GenerateChainWithGenesis(gspec, ethash.NewFaker(), 6, nil)

			// Persist a full chain first, then delete the state of its head so
			// that reopening the datadir has to repair.
			n1, ethservice, err := bootSetHeadNode(t, dataDir, gspec)
			if err != nil {
				t.Fatalf("can't boot the preparing node: %v", err)
			}
			if _, err := ethservice.BlockChain().InsertChain(blocks); err != nil {
				n1.Close()
				t.Fatalf("can't insert the test chain: %v", err)
			}
			dbPath := n1.ResolvePath("chaindata")
			if err := n1.Close(); err != nil {
				t.Fatalf("can't close the preparing node: %v", err)
			}
			db, err := rawdb.NewLevelDBDatabase(dbPath, 0, 0, "", false)
			if err != nil {
				t.Fatalf("can't open the persisted chaindata: %v", err)
			}
			rawdb.DeleteLegacyTrieNode(db, blocks[len(blocks)-1].Root())
			if err := db.Close(); err != nil {
				t.Fatalf("can't close the persisted chaindata: %v", err)
			}

			common.RollbackNumber = tt.request
			n2, ethservice, err := bootSetHeadNode(t, dataDir, gspec)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("New() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("can't boot the reopening node: %v", err)
			}
			defer n2.Close()

			if got := ethservice.BlockChain().CurrentBlock().Number.Uint64(); got != tt.wantHead {
				t.Fatalf("head after rollback = %d, want %d", got, tt.wantHead)
			}
		})
	}
}
