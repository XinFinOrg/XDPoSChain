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
	"encoding/json"
	"errors"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/params"
	"gopkg.in/yaml.v3"
)

// TestCheckGenesisInputScheduleKeys pins the refusal and its canonical, fixed-order key list.
func TestCheckGenesisInputScheduleKeys(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string // canonical key list, empty when the file carries no refused key
	}{
		{
			name: "no schedule keys",
			yaml: "name: xdc-test\nchainid: 19420\n",
		},
		{
			name: "unrelated keys stay accepted",
			yaml: "epochLength: 900\nmygap: 1\nswitchblocksize: 2\n",
		},
		{
			name: "epoch has a field and is accepted",
			yaml: "epoch: 600\n",
		},
		{
			name: "gap",
			yaml: "gap: 450\n",
			want: "gap",
		},
		{
			name: "case and underscores are folded",
			yaml: "Switch_Block: 900\nswitchepoch: 1\n",
			want: "switchBlock, switchEpoch",
		},
		{
			name: "the three without a field are reported in a fixed order",
			yaml: "switchEpoch: 1\nswitchBlock: 900\ngap: 450\n",
			want: "gap, switchBlock, switchEpoch",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var raw map[string]yaml.Node
			if err := yaml.Unmarshal([]byte(tt.yaml), &raw); err != nil {
				t.Fatalf("failed to decode test input: %v", err)
			}
			err := checkGenesisInputScheduleKeys(raw)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("checkGenesisInputScheduleKeys = %v, want no error", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("checkGenesisInputScheduleKeys = nil, want a refusal naming %q", tt.want)
			}
			if want := "input file carries " + tt.want + ","; !strings.HasPrefix(err.Error(), want) {
				t.Errorf("refusal = %q, want it to start with %q", err, want)
			}
		})
	}
}

// TestCheckXDPoSSchedule pins the schedule an interactive run is allowed to store:
// an epoch of at least two and a gap that designates a block strictly inside it.
func TestCheckXDPoSSchedule(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *params.XDPoSConfig
		wantErr bool
		wantMsg string // substring the refusal must carry, empty when the schedule is accepted
	}{
		{name: "missing config", cfg: nil, wantErr: true, wantMsg: "missing XDPoS config"},
		{name: "unset epoch", cfg: &params.XDPoSConfig{Epoch: 0, Gap: 0}, wantErr: true, wantMsg: "epoch must be greater than 0"},
		{name: "epoch of one with a zero gap", cfg: &params.XDPoSConfig{Epoch: 1, Gap: 0}, wantErr: true, wantMsg: "epoch must be at least 2"},
		{name: "epoch of one with a positive gap", cfg: &params.XDPoSConfig{Epoch: 1, Gap: 1}, wantErr: true, wantMsg: "epoch must be at least 2"},
		{name: "zero gap", cfg: &params.XDPoSConfig{Epoch: 900, Gap: 0}, wantErr: true, wantMsg: "1 <= gap < 900"},
		{name: "gap equal to the epoch", cfg: &params.XDPoSConfig{Epoch: 900, Gap: 900}, wantErr: true, wantMsg: "1 <= gap < 900"},
		{name: "gap beyond the epoch", cfg: &params.XDPoSConfig{Epoch: 900, Gap: 901}, wantErr: true, wantMsg: "1 <= gap < 900"},
		{name: "epoch above the int64 range is still a uint64 schedule", cfg: &params.XDPoSConfig{Epoch: math.MaxUint64, Gap: 450}},
		{name: "default schedule", cfg: &params.XDPoSConfig{Epoch: 900, Gap: 450}},
		{name: "smallest usable schedule", cfg: &params.XDPoSConfig{Epoch: 2, Gap: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkXDPoSSchedule(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("checkXDPoSSchedule = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantMsg == "" {
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("checkXDPoSSchedule = %v, want it to mention %q", err, tt.wantMsg)
			}
		})
	}
}

// TestInteractiveGapDefault pins half the epoch for every epoch the prompt accepts.
func TestInteractiveGapDefault(t *testing.T) {
	for _, tt := range []struct {
		epoch uint64
		want  uint64
	}{
		{epoch: 900, want: 450},
		{epoch: 100, want: 50},
		{epoch: 3, want: 1},
		{epoch: 2, want: 1},
	} {
		if got := interactiveGapDefault(tt.epoch); got != tt.want {
			t.Errorf("interactiveGapDefault(%d) = %d, want %d", tt.epoch, got, tt.want)
		}
	}
	for epoch := uint64(2); epoch <= 3000; epoch++ {
		if gap := interactiveGapDefault(epoch); gap == 0 || gap >= epoch {
			t.Errorf("interactiveGapDefault(%d) = %d, want 0 < gap < %d", epoch, gap, epoch)
		}
	}
}

// TestInteractiveGapDefaultReachesGenesis: an empty gap after epoch 100 must store 50,
// not the template's 450; the child form is needed because a failure ends in log.Crit.
func TestInteractiveGapDefaultReachesGenesis(t *testing.T) {
	if outPath := os.Getenv("PUPPETH_INTERACTIVE_OUT"); outPath != "" {
		w := &wizard{
			network: "xdc-test",
			in:      bufio.NewReader(strings.NewReader(interactiveAnswers)),
		}
		w.conf.path = outPath
		w.makeGenesis()
		return
	}
	outPath := filepath.Join(t.TempDir(), "genesis.json")
	cmd := exec.Command(os.Args[0], "-test.run=^TestInteractiveGapDefaultReachesGenesis$")
	cmd.Env = append(os.Environ(), "PUPPETH_INTERACTIVE_OUT="+outPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("interactive makeGenesis exited with %v; output:\n%s", err, out)
	}
	blob, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("interactive run wrote no genesis: %v; output:\n%s", err, out)
	}
	var disk struct {
		Config struct {
			XDPoS struct {
				Epoch uint64 `json:"epoch"`
				Gap   uint64 `json:"gap"`
			} `json:"XDPoS"`
		} `json:"config"`
	}
	if err := json.Unmarshal(blob, &disk); err != nil {
		t.Fatalf("failed to decode the generated genesis: %v", err)
	}
	if got := disk.Config.XDPoS.Epoch; got != 100 {
		t.Errorf("XDPoS.Epoch = %d, want the answered 100", got)
	}
	if got := disk.Config.XDPoS.Gap; got != 50 {
		t.Errorf("XDPoS.Gap = %d, want the interactive default epoch/2 = 50", got)
	}
}

// scheduleAnswers is one line per prompt, in order; a blank gap line takes the default.
func scheduleAnswers(epoch, gap string) string {
	return "3\n" + // consensus engine: XDPoS
		"\n\n\n\n\n" + // block time, v2 switch block, timeout, sync threshold, cert threshold
		"a4477b9b3dcfffb71db9e2aba579975ac756dade\n" + // masternodes owner
		"7e7d7b438abd152af3753bdc01512d2208305397\n" + // first masternode
		"\n" + // end of the masternode list
		epoch + "\n" + // epoch
		gap + "\n" + // gap, blank takes the default
		"\n\n" + // staking threshold, reward yield
		"\n" + // foundation wallet
		"a4477b9b3dcfffb71db9e2aba579975ac756dade\n" + // foundation multisig signer
		"\n" + // end of the foundation signer list
		"\n" + // confirmations required by the foundation wallet
		"a4477b9b3dcfffb71db9e2aba579975ac756dade\n" + // team multisig signer
		"\n" + // end of the team signer list
		"\n" + // confirmations required by the team wallet
		"\n" + // prefunded accounts
		"\n" // chain id
}

// interactiveAnswers answers every prompt with epoch 100 and an empty gap answer.
var interactiveAnswers = scheduleAnswers("100", "")

// TestInteractiveScheduleValidation pins how the answers are judged where they are read:
// an epoch below 2, a negative gap, a zero gap (default) and a gap outside the epoch.
func TestInteractiveScheduleValidation(t *testing.T) {
	if outPath := os.Getenv("PUPPETH_SCHEDULE_OUT"); outPath != "" {
		w := &wizard{
			network: "xdc-test",
			in:      bufio.NewReader(strings.NewReader(scheduleAnswers(os.Getenv("PUPPETH_SCHEDULE_EPOCH"), os.Getenv("PUPPETH_SCHEDULE_GAP")))),
		}
		w.conf.path = outPath
		w.makeGenesis()
		return
	}
	tests := []struct {
		name    string
		epoch   string
		gap     string
		wantMsg string // empty when the run is expected to write a genesis
		wantGap uint64 // stored gap on success
	}{
		{name: "negative epoch", epoch: "-1", wantMsg: "Epoch must be at least 2"},
		{name: "zero epoch", epoch: "0", wantMsg: "Epoch must be at least 2"},
		{name: "epoch of one", epoch: "1", wantMsg: "Epoch must be at least 2 so that a gap block exists inside it"},
		{name: "zero gap falls back to the default", epoch: "100", gap: "0", wantGap: 50},
		{name: "negative gap", epoch: "100", gap: "-1", wantMsg: "Gap must not be negative"},
		{name: "gap equal to the epoch", epoch: "100", gap: "100", wantMsg: "epoch must be greater than gap"},
		{name: "gap beyond the epoch", epoch: "100", gap: "200", wantMsg: "epoch must be greater than gap"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outPath := filepath.Join(t.TempDir(), "genesis.json")
			cmd := exec.Command(os.Args[0], "-test.run=^TestInteractiveScheduleValidation$")
			cmd.Env = append(os.Environ(),
				"PUPPETH_SCHEDULE_OUT="+outPath,
				"PUPPETH_SCHEDULE_EPOCH="+tt.epoch,
				"PUPPETH_SCHEDULE_GAP="+tt.gap,
			)
			out, err := cmd.CombinedOutput()
			if tt.wantMsg != "" {
				if err == nil {
					t.Fatalf("interactive makeGenesis accepted epoch %q gap %q; output:\n%s", tt.epoch, tt.gap, out)
				}
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
					t.Fatalf("child exited with %v, want exit status 1; output:\n%s", err, out)
				}
				if !strings.Contains(string(out), tt.wantMsg) {
					t.Errorf("child output does not report %q:\n%s", tt.wantMsg, out)
				}
				if _, statErr := os.Stat(outPath); statErr == nil {
					t.Error("refused run still wrote the genesis output file")
				}
				return
			}
			if err != nil {
				t.Fatalf("interactive makeGenesis exited with %v; output:\n%s", err, out)
			}
			blob, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatalf("interactive run wrote no genesis: %v; output:\n%s", err, out)
			}
			var disk struct {
				Config struct {
					XDPoS struct {
						Gap uint64 `json:"gap"`
					} `json:"XDPoS"`
				} `json:"config"`
			}
			if err := json.Unmarshal(blob, &disk); err != nil {
				t.Fatalf("failed to decode the generated genesis: %v", err)
			}
			if disk.Config.XDPoS.Gap != tt.wantGap {
				t.Errorf("XDPoS.Gap = %d, want %d", disk.Config.XDPoS.Gap, tt.wantGap)
			}
		})
	}
}

// TestMakeGenesisRefusesUnusableSchedule: epoch 100 leaves the template gap outside the
// epoch, so the run must refuse before writing and say the file cannot set gap. An epoch
// below 2 is refused for its own reason, without that hint.
func TestMakeGenesisRefusesUnusableSchedule(t *testing.T) {
	if path := os.Getenv("PUPPETH_UNUSABLE_INPUT"); path != "" {
		w := &wizard{
			network: "xdc-test",
			in:      bufio.NewReader(strings.NewReader("")),
		}
		w.conf.path = path + ".out"
		w.conf.inpath = path
		w.makeGenesis()
		return
	}
	tests := []struct {
		name     string
		epoch    string
		wantMsgs []string
		notWants []string // substrings the refusal must not carry
	}{
		{
			name:     "gap outside the epoch",
			epoch:    "100",
			wantMsgs: []string{"Unusable XDPoS schedule", "the input file cannot set gap"},
			// Nothing may be derived from the pair before it is judged.
			notWants: []string{"Calculated Total Masternode rewards"},
		},
		{
			name:     "epoch below two",
			epoch:    "1",
			wantMsgs: []string{"Unusable XDPoS schedule", "epoch must be at least 2"},
			notWants: []string{"the input file cannot set gap", "Calculated Total Masternode rewards"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			inPath := filepath.Join(dir, "input.yaml")
			inputYAML := `name: xdc-test
chainid: 19420
epoch: ` + tt.epoch + `
masternodesowner: "0xa4477b9b3dcfffb71db9e2aba579975ac756dade"
masternodes:
  - "0x7e7d7b438abd152af3753bdc01512d2208305397"
stakingthreshold: 10000000
`
			if err := os.WriteFile(inPath, []byte(inputYAML), 0644); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestMakeGenesisRefusesUnusableSchedule$")
			cmd.Env = append(os.Environ(), "PUPPETH_UNUSABLE_INPUT="+inPath)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("makeGenesis accepted epoch %s against the template gap; output:\n%s", tt.epoch, out)
			}
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
				t.Fatalf("child exited with %v, want exit status 1; output:\n%s", err, out)
			}
			for _, want := range tt.wantMsgs {
				if !strings.Contains(string(out), want) {
					t.Errorf("child output does not report %q:\n%s", want, out)
				}
			}
			for _, notWant := range tt.notWants {
				if strings.Contains(string(out), notWant) {
					t.Errorf("child output carries %q for an unrelated cause:\n%s", notWant, out)
				}
			}
			if _, statErr := os.Stat(inPath + ".out"); statErr == nil {
				t.Error("refused run still wrote the genesis output file")
			}
		})
	}
}

// TestMakeGenesisRefusesScheduleKeysInInputFile: loadGenesisInput must refuse a file that
// names a key it cannot apply, before anything is deployed or written.
func TestMakeGenesisRefusesScheduleKeysInInputFile(t *testing.T) {
	if path := os.Getenv("PUPPETH_SCHEDULE_KEYS_INPUT"); path != "" {
		w := &wizard{
			network: "xdc-test",
			in:      bufio.NewReader(strings.NewReader("")),
		}
		w.conf.path = path + ".out"
		w.conf.inpath = path
		w.makeGenesis()
		return
	}
	dir := t.TempDir()
	inPath := filepath.Join(dir, "input.yaml")
	const inputYAML = `name: xdc-test
chainid: 19420
epoch: 900
gap: 450
masternodesowner: "0xa4477b9b3dcfffb71db9e2aba579975ac756dade"
masternodes:
  - "0x7e7d7b438abd152af3753bdc01512d2208305397"
stakingthreshold: 10000000
`
	if err := os.WriteFile(inPath, []byte(inputYAML), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMakeGenesisRefusesScheduleKeysInInputFile$")
	cmd.Env = append(os.Environ(), "PUPPETH_SCHEDULE_KEYS_INPUT="+inPath)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("makeGenesis accepted an input file carrying gap; output:\n%s", out)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("child exited with %v, want exit status 1; output:\n%s", err, out)
	}
	if !strings.Contains(string(out), "input file carries gap") {
		t.Errorf("child output does not name the refused key:\n%s", out)
	}
	if _, statErr := os.Stat(inPath + ".out"); statErr == nil {
		t.Error("refused run still wrote the genesis output file")
	}
}

// TestMakeGenesisRefusesEmptyInputFile: a file with no fields at all - empty, only
// comments, or an explicitly empty mapping - used to reach the wizard as a set of
// template defaults. It must be refused instead of quietly producing a Localnet-shaped
// genesis.
func TestMakeGenesisRefusesEmptyInputFile(t *testing.T) {
	if path := os.Getenv("PUPPETH_EMPTY_INPUT"); path != "" {
		w := &wizard{
			network: "xdc-test",
			in:      bufio.NewReader(strings.NewReader("")),
		}
		w.conf.path = path + ".out"
		w.conf.inpath = path
		w.makeGenesis()
		return
	}
	for _, tt := range []struct {
		name    string
		content string
	}{
		{name: "empty file", content: ""},
		{name: "only comments", content: "# nothing here yet\n# epoch: 900\n"},
		{name: "empty mapping {}", content: "{}\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			inPath := filepath.Join(dir, "input.yaml")
			if err := os.WriteFile(inPath, []byte(tt.content), 0644); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestMakeGenesisRefusesEmptyInputFile$")
			cmd.Env = append(os.Environ(), "PUPPETH_EMPTY_INPUT="+inPath)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("makeGenesis accepted an input file with no fields; output:\n%s", out)
			}
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
				t.Fatalf("child exited with %v, want exit status 1; output:\n%s", err, out)
			}
			if !strings.Contains(string(out), "no fields in it") {
				t.Errorf("child output does not say the file carries no fields:\n%s", out)
			}
			if _, statErr := os.Stat(inPath + ".out"); statErr == nil {
				t.Error("refused run still wrote the genesis output file")
			}
		})
	}
}

// TestMakeGenesisAcceptsEpochAboveInt64: the BlockSigner takes uint256, so 2^63 must reach it unwrapped.
func TestMakeGenesisAcceptsEpochAboveInt64(t *testing.T) {
	if path := os.Getenv("PUPPETH_BIG_EPOCH_INPUT"); path != "" {
		w := &wizard{
			network: "xdc-test",
			in:      bufio.NewReader(strings.NewReader("")),
		}
		w.conf.path = path + ".out"
		w.conf.inpath = path
		w.makeGenesis()
		return
	}
	dir := t.TempDir()
	inPath := filepath.Join(dir, "big-epoch.yaml")
	const bigEpochYAML = `name: xdc-test
chainid: 19420
epoch: 9223372036854775808
masternodesowner: "0xa4477b9b3dcfffb71db9e2aba579975ac756dade"
masternodes:
  - "0x7e7d7b438abd152af3753bdc01512d2208305397"
stakingthreshold: 10000000
`
	if err := os.WriteFile(inPath, []byte(bigEpochYAML), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMakeGenesisAcceptsEpochAboveInt64$")
	cmd.Env = append(os.Environ(), "PUPPETH_BIG_EPOCH_INPUT="+inPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("makeGenesis refused an epoch above int64: %v; output:\n%s", err, out)
	}
	blob, err := os.ReadFile(inPath + ".out")
	if err != nil {
		t.Fatalf("run wrote no genesis: %v; output:\n%s", err, out)
	}
	var disk struct {
		Config struct {
			XDPoS struct {
				Epoch uint64 `json:"epoch"`
			} `json:"XDPoS"`
		} `json:"config"`
	}
	if err := json.Unmarshal(blob, &disk); err != nil {
		t.Fatalf("failed to decode the generated genesis: %v", err)
	}
	if got, want := disk.Config.XDPoS.Epoch, uint64(9223372036854775808); got != want {
		t.Errorf("XDPoS.Epoch = %d, want %d", got, want)
	}
}
