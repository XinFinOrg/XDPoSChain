package ethapi

import (
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
)

func TestAttachStateChainConfig(t *testing.T) {
	t.Parallel()

	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	config := &params.ChainConfig{TRC21IssuerSMC: common.HexToAddress("0x1000000000000000000000000000000000000001")}

	got, err := AttachStateChainConfig(statedb, config)
	if err != nil {
		t.Fatalf("expected attach to succeed: %v", err)
	}
	if got != statedb {
		t.Fatal("expected helper to return the original state db")
	}
	if statedb.ChainConfig() != config {
		t.Fatal("expected helper to attach chain config to fresh state db")
	}

	existing := &params.ChainConfig{TRC21IssuerSMC: common.HexToAddress("0x2000000000000000000000000000000000000002")}
	statedb.SetChainConfig(existing)
	_, err = AttachStateChainConfig(statedb, config)
	if err != nil {
		t.Fatalf("expected attach to preserve existing config without error: %v", err)
	}
	if statedb.ChainConfig() != existing {
		t.Fatal("expected helper not to override existing chain config")
	}
}

func TestAttachStateChainConfigRejectsMissingConfig(t *testing.T) {
	t.Parallel()

	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	_, err = AttachStateChainConfig(statedb, nil)
	if err == nil || err.Error() != "state: missing chain config for state access" {
		t.Fatalf("unexpected error: %v", err)
	}
}
