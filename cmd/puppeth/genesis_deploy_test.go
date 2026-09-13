package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/params"
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
masternodesowner: "0xa4477b9b3dcfffb71db9e2aba579975ac756dade"
masternodes:
  - "0x7e7d7b438abd152af3753bdc01512d2208305397"
  - "0xd3350aaba9e8468e263eb7d197d6805b20e2918f"
  - "0xdb6552adc538e39b4f2a58aea3cd365def1be89b"
stakingthreshold: 10000000
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

	// The input-file path carries no schedule of its own, so this file has to carry
	// none either (a schedule key would be refused by checkGenesisInputScheduleKeys,
	// which TestCheckGenesisInputScheduleKeys pins): the schedule is the cloned
	// Localnet template's, used as written.
	if g.Config.XDPoS == nil {
		t.Fatal("generated genesis has no XDPoS config")
	}
	if got, want := g.Config.XDPoS.Epoch, params.LocalnetChainConfig.XDPoS.Epoch; got != want {
		t.Errorf("XDPoS.Epoch = %d, want the Localnet template value %d", got, want)
	}
	// The switch epoch has to be derived from the schedule that was stored rather
	// than copied from the template, so that what this path generates is what the
	// validation accepts.
	if g.Config.XDPoS.V2 == nil {
		t.Fatal("generated genesis has no XDPoS V2 config")
	}
	if got, want := g.Config.XDPoS.V2.SwitchEpoch, xdposSwitchEpoch(g.Config.XDPoS.V2.SwitchBlock, g.Config.XDPoS.Epoch); got != want {
		t.Errorf("XDPoS.V2.SwitchEpoch = %d, want the derived value %d", got, want)
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
