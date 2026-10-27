// Copyright 2017 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

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
epoch: 600
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

	// The input file carries the epoch, which makeGenesis applies on top of the
	// cloned Localnet template; the gap stays the template's, and checkXDPoSSchedule
	// validates the resulting pair. The throwaway deploy chain is a separate clone of
	// the template, so deployChainV2SwitchBlock stays a whole number of epochs whatever
	// epoch the file asks for.
	if g.Config.XDPoS == nil {
		t.Fatal("generated genesis has no XDPoS config")
	}
	const wantEpoch = 600
	if got := g.Config.XDPoS.Epoch; got != wantEpoch {
		t.Errorf("XDPoS.Epoch = %d, want the value from the input file %d", got, wantEpoch)
	}
	if got, want := g.Config.XDPoS.Gap, params.LocalnetChainConfig.XDPoS.Gap; got != want {
		t.Errorf("XDPoS.Gap = %d, want the Localnet template value %d", got, want)
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
