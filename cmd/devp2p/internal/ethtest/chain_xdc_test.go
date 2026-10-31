package ethtest

import (
	"math/big"
	"path/filepath"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
)

// xdcFixtureDir is the committed XDC-compatible fixture chain. The live
// regression surface (devp2p rlpx eth-test) and a local devnet share it, so
// the suite's chain model and the node's chain stay byte-for-byte identical.
var xdcFixtureDir = filepath.Join("testdata", "xdc")

// TestXDCFixtureGenesisMatchesNodeSetup pins the genesis hash parity between
// the suite's loader (plain json.Unmarshal + ToBlock) and the node's own setup
// path (SetupGenesisBlockWithOverride). The node resolves and hydrates the
// chain config before committing, and the config is hash-relevant input
// (EIP-1559 activation injects the initial BaseFee), so a fixture the suite
// hashes differently from what the node commits fails every dialing test at
// the status exchange. This is the regression for that failure mode.
func TestXDCFixtureGenesisMatchesNodeSetup(t *testing.T) {
	gen, err := loadGenesis(filepath.Join(xdcFixtureDir, "genesis.json"))
	if err != nil {
		t.Fatalf("failed to load fixture genesis: %v", err)
	}
	if gen.Config == nil {
		t.Fatal("fixture genesis carries no chain config")
	}
	if gen.Config.XDPoS == nil {
		t.Fatal("fixture genesis is not XDPoS-enabled")
	}
	if gen.Config.XDPoS.V2 == nil {
		t.Fatal("fixture genesis carries no XDPoS v2 config")
	}
	if gen.Config.ChainID.Cmp(big.NewInt(5152)) != 0 {
		t.Fatalf("fixture chain id drifted: have %s want 5152", gen.Config.ChainID)
	}
	// The senders are the suite's transaction fuel: they must carry funds in
	// the genesis alloc, which is the authoritative funding source (the node's
	// head-state dump keys genesis-only accounts by their secure key, since the
	// sealing DB records no preimages for them).
	senderFunds := new(big.Int).Exp(big.NewInt(10), big.NewInt(24), nil) // 1M XDC
	for _, addr := range fixtureSenderAddresses(t) {
		alloc, ok := gen.Alloc[addr]
		if !ok {
			t.Fatalf("fixture sender %s missing from genesis alloc", addr)
		}
		if alloc.Balance == nil || alloc.Balance.Cmp(senderFunds) != 0 {
			t.Fatalf("fixture sender %s is underfunded: have %v want 1M XDC", addr, alloc.Balance)
		}
	}

	suiteBlock := gen.ToBlock()
	db := rawdb.NewMemoryDatabase()
	_, nodeHash, _, err := core.SetupGenesisBlockWithOverride(db, &gen, false)
	if err != nil {
		t.Fatalf("node setup path rejected the fixture genesis: %v", err)
	}
	if have, want := suiteBlock.Hash(), nodeHash; have != want {
		t.Fatalf("suite and node disagree on the genesis hash: suite %s, node %s", have, want)
	}
}

// TestXDCFixtureLoadsFullChain pins that the fixture loads as a full chain
// model, not the genesis-only fallback: the fallback silently degrades every
// fixture-anchored assertion while the suite keeps running.
func TestXDCFixtureLoadsFullChain(t *testing.T) {
	chain, err := NewChain(xdcFixtureDir)
	if err != nil {
		t.Fatalf("failed to load XDC fixture: %v", err)
	}
	if chain.Len() != 601 {
		t.Fatalf("fixture chain length drifted: have %d want 601 (genesis + 600 blocks)", chain.Len())
	}
	if head := chain.Head(); head.NumberU64() != 600 {
		t.Fatalf("fixture head drifted: have %d want 600", head.NumberU64())
	}
	if block := chain.GetBlock(1); block.NumberU64() != 1 {
		t.Fatalf("fixture block 1 drifted: have %d", block.NumberU64())
	}

	addr, nonce := chain.GetSender(0)
	if nonce != 0 {
		t.Fatalf("fixture sender nonce is not fresh: have %d want 0", nonce)
	}
	if _, err := chain.SignTx(addr, types.NewTransaction(0, common.HexToAddress("0xaa"), big.NewInt(1), 21000, big.NewInt(1), nil)); err != nil {
		t.Fatalf("fixture sender cannot sign: %v", err)
	}
}

// fixtureSenderAddresses returns the sender addresses the fixture commits for
// the suite's transaction smoke cases.
func fixtureSenderAddresses(t *testing.T) []common.Address {
	t.Helper()
	chain, err := NewChain(xdcFixtureDir)
	if err != nil {
		t.Fatalf("failed to load XDC fixture: %v", err)
	}
	addrs := make([]common.Address, 0, len(chain.senders))
	for addr := range chain.senders {
		addrs = append(addrs, addr)
	}
	return addrs
}
