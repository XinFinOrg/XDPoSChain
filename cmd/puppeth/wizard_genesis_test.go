package main

import (
	"bufio"
	"io"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/params"
	"gopkg.in/yaml.v3"
)

// newPromptWizard returns a wizard whose stdin carries the given lines. Every
// line has to end in a newline: readDefaultInt treats a read error as fatal, so
// an exhausted reader would exit the test process instead of failing the test.
func newPromptWizard(input string) *wizard {
	return &wizard{in: bufio.NewReader(strings.NewReader(input))}
}

// TestCheckGenesisInputScheduleKeys pins that an input file asking for a schedule
// is refused instead of decoded and dropped. The input-file path stores the cloned
// Localnet template schedule, so a schedule in the file cannot be applied, and yaml
// would drop the keys silently - including the spellings that match no field at all
// (switchBlock, switchblock, switch_block) - leaving the operator with a genesis
// that describes a schedule the file does not.
func TestCheckGenesisInputScheduleKeys(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantList string // the key list the refusal has to name, empty when nothing is refused
	}{
		{name: "no schedule keys", yaml: "name: xdc-test\nchainid: 19420\nstakingthreshold: 10000000\n"},
		{name: "empty document", yaml: ""},
		{name: "epoch only", yaml: "epoch: 2\n", wantList: "carries epoch,"},
		{name: "mixed case epoch", yaml: "Epoch: 900\n", wantList: "carries epoch,"},
		{name: "gap only", yaml: "gap: 1\n", wantList: "carries gap,"},
		{name: "switch block camel case", yaml: "switchBlock: 0\n", wantList: "carries switchBlock,"},
		{name: "switch block lower case", yaml: "switchblock: 0\n", wantList: "carries switchBlock,"},
		{name: "switch block upper case", yaml: "SWITCHBLOCK: 0\n", wantList: "carries switchBlock,"},
		{name: "switch block snake case", yaml: "switch_block: 0\n", wantList: "carries switchBlock,"},
		{name: "switch epoch camel case", yaml: "switchEpoch: 3\n", wantList: "carries switchEpoch,"},
		{name: "switch epoch snake case", yaml: "switch_epoch: 3\n", wantList: "carries switchEpoch,"},
		{name: "written out of order", yaml: "switchBlock: 0\ngap: 450\nepoch: 900\n", wantList: "carries epoch, gap, switchBlock,"},
		{name: "every schedule key in fixed order", yaml: "switchEpoch: 3\nswitchBlock: 0\ngap: 450\nepoch: 900\n", wantList: "carries epoch, gap, switchBlock, switchEpoch,"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var doc yaml.Node
			if tt.yaml != "" {
				if err := yaml.Unmarshal([]byte(tt.yaml), &doc); err != nil {
					t.Fatalf("decoding the test input: %v", err)
				}
			}

			err := checkGenesisInputScheduleKeys(&doc)
			if tt.wantList == "" {
				if err != nil {
					t.Fatalf("unexpected refusal: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected the input file to be refused")
			}
			if !strings.Contains(err.Error(), tt.wantList) {
				t.Errorf("refusal does not name %q: %v", tt.wantList, err)
			}
			// The operator needs the recovery too: the stored template schedule is
			// what the file cannot override.
			if !strings.Contains(err.Error(), "Localnet template") {
				t.Errorf("refusal does not name the stored schedule: %v", err)
			}
		})
	}

	// A missing document cannot carry a key either, and the helper stays total for a
	// direct caller.
	if err := checkGenesisInputScheduleKeys(nil); err != nil {
		t.Errorf("nil document should not be refused: %v", err)
	}
}

// TestReadXDPoSEpochRejectsAnEpochWithoutGapRoom pins that the epoch question
// cannot hand the gap question an epoch it has no answer for. 0 and 1 both make
// 1 <= gap < epoch unsatisfiable, so a wizard that accepted either used to spin
// the gap loop forever with no way out but Ctrl-C.
func TestReadXDPoSEpochRejectsAnEpochWithoutGapRoom(t *testing.T) {
	w := newPromptWizard("0\n1\n900\n")

	if got := w.readXDPoSEpoch(); got != 900 {
		t.Fatalf("readXDPoSEpoch() = %d, want 900", got)
	}
}

// TestReadXDPoSEpochKeepsTheDefault pins that a bare enter still accepts the
// engine default the prompt advertises.
func TestReadXDPoSEpochKeepsTheDefault(t *testing.T) {
	w := newPromptWizard("\n")

	if got := w.readXDPoSEpoch(); got != params.DefaultXDPoSEpoch {
		t.Fatalf("readXDPoSEpoch() = %d, want %d", got, params.DefaultXDPoSEpoch)
	}
}

// TestXDPoSGapDefaultNeverUnderflows pins the offer for every epoch shape the
// prompt can print for, including the unset epoch the non-interactive path still
// prints the question with.
func TestXDPoSGapDefaultNeverUnderflows(t *testing.T) {
	tests := []struct {
		epoch uint64
		want  uint64
	}{
		{epoch: 0, want: defaultXDPoSGap},
		{epoch: 1, want: defaultXDPoSGap},
		{epoch: 2, want: 1},
		{epoch: defaultXDPoSGap, want: defaultXDPoSGap - 1},
		{epoch: defaultXDPoSGap + 1, want: defaultXDPoSGap},
		{epoch: params.DefaultXDPoSEpoch, want: defaultXDPoSGap},
	}
	for _, tt := range tests {
		if got := xdposGapDefault(tt.epoch); got != tt.want {
			t.Errorf("xdposGapDefault(%d) = %d, want %d", tt.epoch, got, tt.want)
		}
	}
}

// TestXDPoSAlignedSwitchBlockKeepsAnUnsetEpochTotal pins the guard that keeps the
// modulo and the division off an epoch of zero. The interactive path refuses such an
// epoch before it asks, so this is only about a direct caller not panicking; the
// answer names no boundary, which is what the wizard templates carry as well.
func TestXDPoSAlignedSwitchBlockKeepsAnUnsetEpochTotal(t *testing.T) {
	for _, block := range []*big.Int{nil, new(big.Int), big.NewInt(1), big.NewInt(900)} {
		if got := xdposAlignedSwitchBlock(block, 0); got == nil || got.Sign() != 0 {
			t.Errorf("xdposAlignedSwitchBlock(%v, 0) = %v, want 0", block, got)
		}
	}
	// A usable epoch still normalizes to the nearest boundary below the height.
	if got := xdposAlignedSwitchBlock(big.NewInt(1850), 900); got.Uint64() != 1800 {
		t.Errorf("xdposAlignedSwitchBlock(1850, 900) = %v, want 1800", got)
	}
	// The question itself is total for the same reason: with no epoch it answers
	// from the normalized default instead of asking a question no answer could end,
	// which is what keeps the loop below off a zero divisor.
	if got := (&wizard{}).readXDPoSSwitchBlock(0, nil); got == nil || got.Sign() != 0 {
		t.Errorf("readXDPoSSwitchBlock(0, nil) = %v, want 0", got)
	}
}

// TestXDPoSSwitchBlockAlignmentUsesBigIntSemantics pins that the wizard judges the
// alignment rule on the big.Int, the way CheckSwitchBlockAlignment and
// CheckV2SwitchEpochAlignment do. SwitchBlock.Uint64() folds every bit above 2^64
// away, so a height above that limit whose low 64 bits look aligned used to be
// accepted by the question while the config validation refused the value init would
// read - the two definitions of one rule disagreeing about the same genesis.
func TestXDPoSSwitchBlockAlignmentUsesBigIntSemantics(t *testing.T) {
	aboveUint64 := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(900))

	if xdposSwitchBlockAligned(aboveUint64, 900) {
		t.Fatal("a height above 2^64 must not be judged by its low 64 bits")
	}
	want := new(big.Int).Mul(new(big.Int).Div(aboveUint64, big.NewInt(900)), big.NewInt(900))
	if got := xdposAlignedSwitchBlock(aboveUint64, 900); got.Cmp(want) != 0 {
		t.Fatalf("xdposAlignedSwitchBlock(%v, 900) = %v, want %v", aboveUint64, got, want)
	}
	if want.IsUint64() {
		t.Fatalf("the fixture has to exercise the path the uint64 form cannot hold, low 64 bits: %v", want.Uint64())
	}
}

// TestReadXDPoSGapAcceptsTheOfferedDefault pins the loop exit for a small epoch:
// the offer is clamped to what the epoch can hold, so a bare enter is always a
// legal gap instead of re-asking the same unanswerable question.
func TestReadXDPoSGapAcceptsTheOfferedDefault(t *testing.T) {
	tests := []struct {
		name  string
		epoch uint64
		want  uint64
	}{
		{name: "default gap fits", epoch: params.DefaultXDPoSEpoch, want: defaultXDPoSGap},
		{name: "smallest usable epoch", epoch: 2, want: 1},
		{name: "epoch just above the default gap", epoch: defaultXDPoSGap + 1, want: defaultXDPoSGap},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newPromptWizard("\n")

			if got := w.readXDPoSGap(tt.epoch); got != tt.want {
				t.Fatalf("readXDPoSGap(%d) = %d, want %d", tt.epoch, got, tt.want)
			}
		})
	}
}

// TestReadXDPoSGapRejectsIllegalValues pins that the re-ask still covers what the
// old loop covered, plus the negative values readDefaultInt parses as integers:
// uint64(-1) compares as a gap larger than any epoch, so it has to be judged
// before the conversion.
func TestReadXDPoSGapRejectsIllegalValues(t *testing.T) {
	w := newPromptWizard("0\n-1\n900\n450\n")

	if got := w.readXDPoSGap(900); got != 450 {
		t.Fatalf("readXDPoSGap(900) = %d, want 450", got)
	}
}

// TestReadXDPoSGapRefusesAnEpochWithoutGapRoom pins the guard that keeps a direct
// caller from entering the loop the epoch question exists to prevent.
func TestReadXDPoSGapRefusesAnEpochWithoutGapRoom(t *testing.T) {
	w := newPromptWizard("")

	if got := w.readXDPoSGap(1); got != 0 {
		t.Fatalf("readXDPoSGap(1) = %d, want 0", got)
	}
}

// TestReadXDPoSSwitchBlockRejectsAnUnalignedHeight pins that the v2 switch block
// question re-asks until the answer lands on an epoch boundary: makeGenesis
// collects the switch block before the epoch, so a later epoch change can leave
// the two inconsistent, and the genesis commit refuses that shape.
func TestReadXDPoSSwitchBlockRejectsAnUnalignedHeight(t *testing.T) {
	w := newPromptWizard("901\n1800\n")

	got := w.readXDPoSSwitchBlock(900, big.NewInt(900))
	if got.Cmp(big.NewInt(1800)) != 0 {
		t.Fatalf("readXDPoSSwitchBlock(900) = %v, want 1800", got)
	}
}

// TestReadXDPoSSwitchBlockKeepsAnAlignedHeight pins that the question still takes
// its default when the switch block and the epoch already agree.
func TestReadXDPoSSwitchBlockKeepsAnAlignedHeight(t *testing.T) {
	w := newPromptWizard("\n")

	got := w.readXDPoSSwitchBlock(900, big.NewInt(900))
	if got.Cmp(big.NewInt(900)) != 0 {
		t.Fatalf("readXDPoSSwitchBlock(900) = %v, want 900", got)
	}
}

// TestReadXDPoSSwitchBlockFallsBackToTheOfferedDefaultAfterARefusal pins that a
// refusal does not leave the question without an answer: "901" is rejected, the
// bare enter that follows takes the boundary the re-ask offers, and the reader is
// already drained at that point, so the loop ended on the second answer instead of
// asking a third time. The rejected height itself is never offered again, because
// what a bare enter returns is the default rather than the previous answer.
func TestReadXDPoSSwitchBlockFallsBackToTheOfferedDefaultAfterARefusal(t *testing.T) {
	w := newPromptWizard("901\n\n")

	got := w.readXDPoSSwitchBlock(900, big.NewInt(900))
	if got.Cmp(big.NewInt(900)) != 0 {
		t.Fatalf("readXDPoSSwitchBlock(900) = %v, want the offered default 900", got)
	}
	if _, err := w.in.ReadString('\n'); err == nil {
		t.Fatal("the question asked again after the bare enter took the offered default")
	}
}

// TestReadXDPoSSwitchBlockOffersAnAlignedDefault pins that whatever the question
// offers is an answer the rule accepts, so the bare enter always ends it: a
// template that carries no boundary (missing, negative or unaligned) is answered
// with the nearest boundary below it, and 0 - the value the templates write - when
// there is no non-negative height to align.
func TestReadXDPoSSwitchBlockOffersAnAlignedDefault(t *testing.T) {
	tests := []struct {
		name string
		def  *big.Int
		want int64
	}{
		{name: "no default at all", def: nil, want: 0},
		{name: "a negative default", def: big.NewInt(-900), want: 0},
		{name: "a default below one epoch", def: big.NewInt(1), want: 0},
		{name: "an unaligned default", def: big.NewInt(901), want: 900},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newPromptWizard("\n")

			got := w.readXDPoSSwitchBlock(900, tt.def)
			if got.Cmp(big.NewInt(tt.want)) != 0 {
				t.Fatalf("readXDPoSSwitchBlock(900, %v) = %v, want %d", tt.def, got, tt.want)
			}
		})
	}
}

// TestReadXDPoSSwitchBlockRejectsNegativeHeights pins that readDefaultBigInt's
// signed parse is judged before the modulo. Uint64() reports the magnitude of a
// negative big.Int, so -900 would otherwise pass the alignment test and be stored
// as the switch block.
func TestReadXDPoSSwitchBlockRejectsNegativeHeights(t *testing.T) {
	w := newPromptWizard("-900\n900\n")

	got := w.readXDPoSSwitchBlock(900, big.NewInt(900))
	if got.Cmp(big.NewInt(900)) != 0 {
		t.Fatalf("readXDPoSSwitchBlock(900) = %v, want 900", got)
	}
}

// TestXDPoSSwitchEpochPairsWithTheSwitchBlock pins the derivation that keeps the
// v2 switch epoch naming the epoch its switch block falls on. makeGenesis collects
// the switch block before the epoch and starts from the template's SwitchEpoch, so
// without this step an interactive run could store two fields that describe
// different schedules - the config validation refuses that shape, which would leave
// the wizard unable to store what it just collected.
func TestXDPoSSwitchEpochPairsWithTheSwitchBlock(t *testing.T) {
	tests := []struct {
		name        string
		switchBlock *big.Int
		epoch       uint64
		want        uint64
	}{
		{name: "the localnet template pair", switchBlock: big.NewInt(0), epoch: params.DefaultXDPoSEpoch, want: 0},
		{name: "a block the operator moved onto the template epoch", switchBlock: big.NewInt(int64(params.DefaultXDPoSEpoch)), epoch: params.DefaultXDPoSEpoch, want: 1},
		{name: "the same block under a shortened epoch", switchBlock: big.NewInt(900), epoch: 2, want: 450},
		{name: "an unset epoch names no epoch", switchBlock: big.NewInt(900), epoch: 0, want: 0},
		{name: "a missing block names no epoch", switchBlock: nil, epoch: params.DefaultXDPoSEpoch, want: 0},
		{name: "a negative block names no epoch", switchBlock: big.NewInt(-900), epoch: params.DefaultXDPoSEpoch, want: 0},
		{name: "a height above 2^64 is divided as a big.Int", switchBlock: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(900)), epoch: params.DefaultXDPoSEpoch, want: 20496382304121725},
		{name: "a quotient no uint64 names answers 0", switchBlock: new(big.Int).Lsh(big.NewInt(1), 80), epoch: 2, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := xdposSwitchEpoch(tt.switchBlock, tt.epoch); got != tt.want {
				t.Fatalf("xdposSwitchEpoch(%v, %d) = %d, want %d", tt.switchBlock, tt.epoch, got, tt.want)
			}
		})
	}
}

// TestWizardScheduleAgreesWithConfigValidation pins that the rules the wizard judges
// its answers by reach the same verdict the config validation does, so a schedule the
// questions accept is a schedule CheckConfigForkOrderWithEpochDefault accepts. The
// check is one-directional on purpose: the validation treats an unset epoch as "wait
// for the engine default" and skips, while the question treats it as "no boundary", so
// the two are not required to answer the same for every input - only to agree wherever
// the wizard stores a value. A boundary added on the validation side without one in
// params.SwitchBlockAligned turns this red.
//
// The last assertion is why the end-of-run gate never discards an interactive run:
// every field that gate reads was already settled by the questions, so there is
// nothing left for it to refuse.
func TestWizardScheduleAgreesWithConfigValidation(t *testing.T) {
	aboveUint64 := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(900))
	// The nearest multiple of the epoch at or below it: the height the question can
	// actually accept, whose low 64 bits (884) are not themselves a multiple.
	alignedAboveUint64 := new(big.Int).Mul(new(big.Int).Div(aboveUint64, big.NewInt(900)), big.NewInt(900))
	tests := []struct {
		name        string
		epoch       uint64
		switchBlock *big.Int
	}{
		{name: "the localnet template pair", epoch: params.DefaultXDPoSEpoch, switchBlock: big.NewInt(0)},
		{name: "an aligned height", epoch: params.DefaultXDPoSEpoch, switchBlock: big.NewInt(1800)},
		{name: "an aligned height above 2^64", epoch: params.DefaultXDPoSEpoch, switchBlock: alignedAboveUint64},
		{name: "the smallest usable epoch", epoch: 2, switchBlock: big.NewInt(2)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The question only accepts a height the shared alignment rule accepts.
			if !xdposSwitchBlockAligned(tt.switchBlock, tt.epoch) {
				t.Fatalf("xdposSwitchBlockAligned(%v, %d) = false, want true", tt.switchBlock, tt.epoch)
			}
			cfg := params.LocalnetChainConfig.Clone()
			cfg.XDPoS.Epoch = tt.epoch
			cfg.XDPoS.Gap = tt.epoch / 2
			cfg.XDPoS.V2.SwitchBlock = tt.switchBlock
			// makeGenesis re-points CurrentConfig at AllConfigs[0] after cloning; the
			// gate checks the same identity, so the fixture has to as well.
			cfg.XDPoS.V2.CurrentConfig = cfg.XDPoS.V2.AllConfigs[0]
			cfg.XDPoS.V2.SwitchEpoch = xdposSwitchEpoch(tt.switchBlock, tt.epoch)

			if err := cfg.CheckSwitchBlockAlignment(); err != nil {
				t.Fatalf("the alignment rule the question accepted refuses the config: %v", err)
			}
			if err := cfg.CheckV2SwitchEpochAlignment(); err != nil {
				t.Fatalf("the derived switch epoch does not pair with the switch block: %v", err)
			}
			// The end-of-run gate reads exactly the fields the questions settled, so a
			// collected answer is never refused after the operator has given it.
			if err := cfg.CheckConfigForkOrderWithEpochDefault(); err != nil {
				t.Fatalf("the end-of-run gate refuses a schedule the questions accepted: %v", err)
			}
		})
	}
}

// captureStdout runs fn with os.Stdout redirected to a pipe and returns what it
// wrote. The wizard emits its prompts and notes through fmt.Printf, so this is how
// the text a question is expected to print gets asserted.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating a stdout pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = original }()

	fn()
	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading captured stdout: %v", err)
	}
	r.Close()
	return string(out)
}

// TestReadXDPoSSwitchBlockAnnouncesALoweredDefault pins that the question does not
// silently replace the height it was offered. The value a template carries is
// normalized to the nearest boundary below it so the bare enter always ends the
// question, and an operator whose template held a height the rule cannot accept has
// to be told that the offered default is no longer the value they wrote.
func TestReadXDPoSSwitchBlockAnnouncesALoweredDefault(t *testing.T) {
	tests := []struct {
		name string
		def  *big.Int
		want []string
	}{
		{name: "an unaligned default", def: big.NewInt(950), want: []string{"950", "900"}},
		{name: "a negative default", def: big.NewInt(-900), want: []string{"-900", "0"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := captureStdout(t, func() {
				w := newPromptWizard("\n")
				got := w.readXDPoSSwitchBlock(900, tt.def)
				if got.Uint64()%900 != 0 {
					t.Fatalf("readXDPoSSwitchBlock(900, %v) = %v, want an aligned height", tt.def, got)
				}
			})

			if !strings.Contains(out, "not a non-negative multiple of the epoch") {
				t.Fatalf("the question did not announce the lowered default: %q", out)
			}
			for _, want := range tt.want {
				if !strings.Contains(out, want) {
					t.Fatalf("the announcement %q does not name %q", out, want)
				}
			}
		})
	}
}

// TestReadXDPoSSwitchBlockKeepsAnAlignedDefaultQuiet is the control: an aligned
// default is offered as it stands, so the operator is not told about a change that
// did not happen.
func TestReadXDPoSSwitchBlockKeepsAnAlignedDefaultQuiet(t *testing.T) {
	out := captureStdout(t, func() {
		w := newPromptWizard("\n")
		if got := w.readXDPoSSwitchBlock(900, big.NewInt(900)); got.Cmp(big.NewInt(900)) != 0 {
			t.Fatalf("readXDPoSSwitchBlock(900, 900) = %v, want 900", got)
		}
	})

	if strings.Contains(out, "not a non-negative multiple of the epoch") {
		t.Fatalf("an aligned default was announced as lowered: %q", out)
	}
}
