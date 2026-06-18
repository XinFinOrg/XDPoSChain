package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
)

// TestMakeGenesisDeploysSystemContracts runs the full makeGenesis flow via the
// non-interactive input-file path and asserts that every XDC system contract is
// deployed with real bytecode (not just a balance). This is a regression test for
// the puppeth bug where all contract deployments failed silently, producing a
// genesis with balances but no contract code/storage.
func TestMakeGenesisDeploysSystemContracts(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "input.yaml")
	outPath := filepath.Join(dir, "out.json")

	const inputYAML = `name: xdc-test
chainid: 19420
period: 2
epoch: 900
gap: 450
timeoutperiod: 10
timeoutsyncthreshold: 3
v2switchblock: 0
tiptrc21feeblock: 0
gas50xblock: 0
certthreshold: 0.667
masternodesowner: "0xa4477b9b3dcfffb71db9e2aba579975ac756dade"
masternodes:
  - "0x7e7d7b438abd152af3753bdc01512d2208305397"
  - "0xd3350aaba9e8468e263eb7d197d6805b20e2918f"
  - "0xdb6552adc538e39b4f2a58aea3cd365def1be89b"
stakingthreshold: 10000000
rewardyield: 10
foundationwalletaddress: "0xd7a4209ec6952ca456407fe96740a381391751a0"
`
	if err := os.WriteFile(inPath, []byte(inputYAML), 0644); err != nil {
		t.Fatal(err)
	}

	w := &wizard{
		network: "xdc-test",
		in:      bufio.NewReader(strings.NewReader("")),
	}
	w.conf.path = outPath
	w.conf.inpath = inPath

	w.makeGenesis()

	g := w.conf.Genesis
	if g == nil {
		t.Fatal("makeGenesis produced no genesis")
	}

	systemContracts := map[string]common.Address{
		"MasternodeVotingSMC (0x88)": common.MasternodeVotingSMCBinary,
		"FoundationMultiSig (0x68)":  common.FoundationAddrBinary,
		"BlockSigners (0x89)":        common.BlockSignersBinary,
		"Randomize (0x90)":           common.RandomizeSMCBinary,
		"TeamMultiSig (0x99)":        common.TeamAddrBinary,
	}
	for name, addr := range systemContracts {
		acc, ok := g.Alloc[addr]
		if !ok {
			t.Errorf("%s: not present in alloc", name)
			continue
		}
		if len(acc.Code) == 0 {
			t.Errorf("%s: empty code (deployment failed silently)", name)
			continue
		}
		t.Logf("%s: codeLen=%d storageEntries=%d", name, len(acc.Code), len(acc.Storage))
	}

	// The validator contract must carry candidate storage, otherwise the chain
	// has no masternode set to read at the first epoch switch.
	if v := g.Alloc[common.MasternodeVotingSMCBinary]; len(v.Storage) == 0 {
		t.Error("MasternodeVotingSMC has no storage (no candidates registered)")
	}
}
