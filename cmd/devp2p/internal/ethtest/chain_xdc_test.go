package ethtest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
)

// xdcFixtureDir is the committed XDC-compatible fixture chain. The live
// regression surface (devp2p rlpx eth-test) and a local devnet load the same
// genesis and block sequence, so the suite's chain model and the node's chain
// agree block for block.
var xdcFixtureDir = filepath.Join("testdata", "xdc")

// loadXDCFixture loads the committed XDC fixture, failing the test on error.
func loadXDCFixture(t *testing.T) *Chain {
	t.Helper()
	chain, err := NewChain(xdcFixtureDir)
	if err != nil {
		t.Fatalf("failed to load XDC fixture: %v", err)
	}
	return chain
}

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
	chain := loadXDCFixture(t)
	if len(chain.senders) == 0 {
		t.Fatal("fixture carries no sender accounts")
	}
	for _, addr := range fixtureSenderAddresses(chain) {
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
	chain := loadXDCFixture(t)
	if chain.Len() != 601 {
		t.Fatalf("fixture chain length drifted: have %d want 601 (genesis + 600 blocks)", chain.Len())
	}
	if head := chain.Head(); head.NumberU64() != 600 {
		t.Fatalf("fixture head drifted: have %d want 600", head.NumberU64())
	}
	// The chain must descend from the committed genesis. A chain.rlp paired with
	// a stale or hand-edited genesis.json still loads as 601 sequential blocks
	// (blocksFromFile only checks the numbering), while the node treats every
	// imported block as an orphan and the whole suite silently mismatches.
	genesisHash := chain.genesis.ToBlock().Hash()
	if parent := chain.GetBlock(1).ParentHash(); parent != genesisHash {
		t.Fatalf("fixture chain does not descend from the committed genesis: block 1 parent %s, genesis %s", parent, genesisHash)
	}
	// blocksFromFile only checks the block numbers, so an orphaned or spliced
	// tail would load and then mismatch every chain-anchored assertion against
	// the node. Walk the parent links to keep the whole 600-block chain pinned.
	if err := checkBlockLinks(chain.blocks); err != nil {
		t.Fatalf("fixture chain is not canonical: %v", err)
	}

	// readAccounts trusts the addresses keying accounts.json; a key belonging to
	// another address would keep this loader green while every transaction smoke
	// case failed against a live node, so pin the binding here.
	if len(chain.senders) == 0 {
		t.Fatal("fixture carries no sender accounts")
	}
	for _, addr := range fixtureSenderAddresses(chain) {
		if have := crypto.PubkeyToAddress(chain.senders[addr].Key.PublicKey); have != addr {
			t.Fatalf("fixture sender key mismatch: %s derives %s", addr, have)
		}
	}
	addr, _ := chain.GetSender(0)
	signed, err := chain.SignTx(addr, types.NewTransaction(0, common.HexToAddress("0xaa"), big.NewInt(1), 21000, big.NewInt(1), nil))
	if err != nil {
		t.Fatalf("fixture sender cannot sign: %v", err)
	}
	if from, err := types.Sender(types.LatestSigner(chain.config), signed); err != nil || from != addr {
		t.Fatalf("signed transaction does not recover the fixture sender: have %v want %s (err %v)", from, addr, err)
	}
}

// checkBlockLinks verifies every block names its predecessor as parent.
func checkBlockLinks(blocks []*types.Block) error {
	for i := 1; i < len(blocks); i++ {
		if parent := blocks[i].ParentHash(); parent != blocks[i-1].Hash() {
			return fmt.Errorf("block %d parent %s, previous block %s", i, parent, blocks[i-1].Hash())
		}
	}
	return nil
}

// fixtureSenderAddresses returns the sender addresses the fixture commits for
// the suite's transaction smoke cases, in ascending address order so failure
// messages stay reproducible.
func fixtureSenderAddresses(chain *Chain) []common.Address {
	addrs := make([]common.Address, 0, len(chain.senders))
	for addr := range chain.senders {
		addrs = append(addrs, addr)
	}
	sort.Slice(addrs, func(i, j int) bool {
		return bytes.Compare(addrs[i][:], addrs[j][:]) < 0
	})
	return addrs
}

// TestXDCFixtureSenderBalances pins the funding contract the suite's
// transaction cases rely on. The committed dump cannot resolve the senders
// (the sealing DB recorded no preimages for accounts it never touched), so
// Balance has to fall back to the genesis allocation for them.
func TestXDCFixtureSenderBalances(t *testing.T) {
	chain := loadXDCFixture(t)
	if len(chain.senders) == 0 {
		t.Fatal("fixture carries no sender accounts")
	}
	funds := new(big.Int).Exp(big.NewInt(10), big.NewInt(24), nil) // 1M XDC
	for _, addr := range fixtureSenderAddresses(chain) {
		if got := chain.Balance(addr); got.Cmp(funds) != 0 {
			t.Fatalf("fixture sender %s has balance %s, want %s (1M XDC)", addr, got, funds)
		}
	}
	// Exercise the fallback directly, so the assertion keeps covering it once
	// a regenerated dump happens to resolve the senders.
	addr, _ := chain.GetSender(0)
	delete(chain.state, addr)
	if got := chain.Balance(addr); got.Cmp(funds) != 0 {
		t.Fatalf("genesis fallback returned %s for %s, want %s", got, addr, funds)
	}
	unknown := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	if got := chain.Balance(unknown); got.Sign() != 0 {
		t.Fatalf("unknown account balance should be zero, have %s", got)
	}
}

// TestXDCFixtureBalanceMalformedDump pins that an unparsable dump balance
// falls through to the genesis allocation instead of returning nil (which
// would panic every Balance caller), and that a valid dump balance still wins.
func TestXDCFixtureBalanceMalformedDump(t *testing.T) {
	chain := loadXDCFixture(t)
	if len(chain.senders) == 0 {
		t.Fatal("fixture carries no sender accounts")
	}
	addr, _ := chain.GetSender(0)
	chain.state[addr] = state.DumpAccount{Balance: "12345"}
	if got := chain.Balance(addr); got == nil || got.Cmp(big.NewInt(12345)) != 0 {
		t.Fatalf("valid dump balance not honored: have %v want 12345", got)
	}
	chain.state[addr] = state.DumpAccount{Balance: "not-a-decimal"}
	funds := new(big.Int).Exp(big.NewInt(10), big.NewInt(24), nil) // 1M XDC
	if got := chain.Balance(addr); got == nil || got.Cmp(funds) != 0 {
		t.Fatalf("malformed dump balance returned %v for %s, want the genesis allocation %s", got, addr, funds)
	}
}

// TestXDCFixtureHeadStateMatchesHead pins the dump to the chain it was
// exported from: a stale or hand-edited headstate.json still loads (its
// address map is independent of chain.rlp) while every head-state read
// silently returns another block's state.
func TestXDCFixtureHeadStateMatchesHead(t *testing.T) {
	chain := loadXDCFixture(t)
	data, err := os.ReadFile(filepath.Join(xdcFixtureDir, "headstate.json"))
	if err != nil {
		t.Fatalf("failed to read head-state dump: %v", err)
	}
	var dump struct {
		Root string `json:"root"`
	}
	if err := json.Unmarshal(data, &dump); err != nil {
		t.Fatalf("failed to decode head-state dump: %v", err)
	}
	have := strings.TrimPrefix(strings.ToLower(dump.Root), "0x")
	want := strings.TrimPrefix(chain.Head().Root().Hex(), "0x") // Hex is lowercase already
	if have != want {
		t.Fatalf("headstate.json was dumped from another block: have root %s want %s", have, want)
	}
}

// TestXDCFixtureGenesisAllocUnique pins that genesis.json does not carry the
// same account under two key spellings: the alloc decodes into
// common.UnprefixedAddress, so "654b…" and "0x654b…" would collapse into one
// account and the later entry would win, making the effective genesis (and its
// hash) depend on the JSON key order.
func TestXDCFixtureGenesisAllocUnique(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(xdcFixtureDir, "genesis.json"))
	if err != nil {
		t.Fatalf("failed to read fixture genesis: %v", err)
	}
	var spec struct {
		Alloc map[string]json.RawMessage `json:"alloc"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("failed to decode fixture genesis: %v", err)
	}
	if len(spec.Alloc) == 0 {
		t.Fatal("fixture genesis carries no alloc")
	}
	seen := make(map[string]string, len(spec.Alloc))
	for key := range spec.Alloc {
		norm := strings.ToLower(key)
		norm = strings.TrimPrefix(norm, "0x")
		norm = strings.TrimPrefix(norm, "xdc")
		if prev, ok := seen[norm]; ok {
			t.Fatalf("genesis alloc carries %s twice: %q and %q", norm, prev, key)
		}
		seen[norm] = key
	}
}
