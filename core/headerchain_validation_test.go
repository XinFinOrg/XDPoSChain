package core

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
)

func TestValidateHeaderChain_EmptyChain(t *testing.T) {
	testdb := rawdb.NewMemoryDatabase()
	gspec := &Genesis{Config: params.TestChainConfig}
	if _, err := gspec.Commit(testdb); err != nil {
		t.Fatalf("failed to commit genesis: %v", err)
	}

	bc, err := NewBlockChain(testdb, nil, gspec, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	defer bc.Stop()

	if idx, err := bc.hc.ValidateHeaderChain(nil, 1); err != nil || idx != 0 {
		t.Fatalf("empty chain should pass, idx=%d err=%v", idx, err)
	}
}
