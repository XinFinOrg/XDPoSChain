package utils

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/params"
)

func TestFormatChainConfigErrorNil(t *testing.T) {
	if got := FormatChainConfigError(nil); got != "" {
		t.Fatalf("expected an empty string for a nil error, have %q", got)
	}
}

// TestFormatChainConfigError pins which hint each rejection path carries. The
// branches are ordered, so a newly recognised sentinel must not inherit the hint
// of the branch it was added next to: an unusable gap schedule has its own
// recovery path (fix the schedule, re-init the data directory), a chain opened
// with an unset epoch and a gap lookup handed no config have hints that name the
// constructor instead, a switch epoch that does not name its block's epoch has an
// arithmetic one, and a sparse fork config keeps the migration hint that lists the
// missing fields.
func TestFormatChainConfigError(t *testing.T) {
	gapErr := fmt.Errorf("invalid chain config: %w: XDPoS.Gap 0 designates no gap block inside XDPoS.Epoch 900 (want 1 <= Gap < Epoch)", params.ErrUnusableGapSchedule)
	unsetEpochErr := fmt.Errorf("invalid chain config: %w: XDPoS.Epoch is unset; this constructor resolves the config from the database or the supplied genesis, so it never sees the default the XDPoS engine fills in (%d). Build the engine on this config first and open through NewBlockChainResolved/NewBlockChainReadOnlyResolved with the config that engine resolved (XDPoS.ChainConfig()); those constructors also take the genesis hash, the compatibility error and the mismatch policy that core.SetupGenesisBlock* and core.LoadChainConfigWithCompat* return", params.ErrUnsetXDPoSEpoch, params.DefaultXDPoSEpoch)

	tests := []struct {
		name    string
		err     error
		want    []string
		notWant []string
	}{
		{
			name:    "gap schedule keeps its own recovery path",
			err:     gapErr,
			want:    []string{gapErr.Error(), UnusableGapScheduleHint, "re-run init on the data directory", "only while the directory has produced no blocks", "has to be resynchronised"},
			notWant: []string{"Migration hint", UnsetXDPoSEpochHint},
		},
		{
			name:    "unset epoch gets the constructor hint instead of the schedule one",
			err:     unsetEpochErr,
			want:    []string{unsetEpochErr.Error(), UnsetXDPoSEpochHint, "NewBlockChainResolved"},
			notWant: []string{UnusableGapScheduleHint, "Migration hint"},
		},
		{
			// The engine gap paths report an unset epoch through the same sentinel,
			// so an operator reading one of their messages still gets the hint that
			// names the caller-side defect rather than the schedule one.
			name:    "unset epoch from an engine gap path keeps the constructor hint",
			err:     fmt.Errorf("[getSnapshot] XDPoS.Epoch is unset, number: 1350, gap: 450: %w", params.ErrUnsetXDPoSEpoch),
			want:    []string{"[getSnapshot] XDPoS.Epoch is unset, number: 1350, gap: 450", UnsetXDPoSEpochHint, "XDPoS.New"},
			notWant: []string{UnusableGapScheduleHint, "Migration hint"},
		},
		{
			// A missing config is not a schedule defect and no genesis field can fix it,
			// so the operator must not be sent to the gap schedule recovery path.
			name:    "missing xdpos config gets the constructor hint instead of the schedule one",
			err:     fmt.Errorf("[getSnapshot] gap lookup was called with a nil config, number: 1350: %w", params.ErrMissingXDPoSConfig),
			want:    []string{"[getSnapshot] gap lookup was called with a nil config, number: 1350", MissingXDPoSConfigHint, "XDPoS.New"},
			notWant: []string{UnusableGapScheduleHint, UnsetXDPoSEpochHint, "Migration hint"},
		},
		{
			// The fork order is intact; the arithmetic is what has to change, so this
			// must not inherit the unaligned-switch-block or fork-order hint. A config
			// that spells its epoch out is not judged against the default, so the
			// default-epoch hint belongs to the other branch.
			name:    "switch epoch mismatch gets the arithmetic hint",
			err:     fmt.Errorf("invalid chain config: %w: XDPoS.V2.SwitchEpoch 1 does not name the epoch XDPoS.V2.SwitchBlock 900 falls on (want 450 = XDPoS.V2.SwitchBlock / XDPoS.Epoch 2)", params.ErrSwitchEpochMismatch),
			want:    []string{"XDPoS.V2.SwitchEpoch", SwitchEpochMismatchHint, "SwitchBlock / XDPoS.Epoch"},
			notWant: []string{UnusableGapScheduleHint, UnusableGapScheduleDefaultEpochHint, UnalignedSwitchBlockDefaultEpochHint, SwitchEpochMismatchAgainstDefaultEpochHint, "Migration hint"},
		},
		{
			// The field list below this branch belongs to ErrMissingForkSwitch, so a
			// gap rejection whose text happens to name a fork field must not fall into it.
			name:    "gap schedule is judged before the fork field list",
			err:     fmt.Errorf("invalid chain config: %w: Gas50xBlock", params.ErrUnusableGapSchedule),
			want:    []string{"Gas50xBlock", UnusableGapScheduleHint},
			notWant: []string{"Migration hint"},
		},
		{
			// The alignment hint belongs to the alignment rule only: the same sentinel
			// carries the fork order, the switch round and the exp timeout rejections,
			// so sending those operators to fix a switch block would be wrong.
			name:    "other wrong fork switch order rejections keep no hint",
			err:     fmt.Errorf("invalid chain config: %w: XDPoS.V2.CurrentConfig", params.ErrWrongForkSwitchOrder),
			want:    []string{"XDPoS.V2.CurrentConfig"},
			notWant: []string{"Hint:", UnalignedSwitchBlockHint, UnalignedSwitchBlockDefaultEpochHint},
		},
		{
			name:    "sparse fork config keeps the migration hint",
			err:     fmt.Errorf("invalid chain config: %w: TRC21IssuerSMC", params.ErrMissingForkSwitch),
			want:    []string{"Migration hint: ensure the persisted chain config"},
			notWant: []string{UnusableGapScheduleHint},
		},
		{
			name:    "unrelated error is passed through",
			err:     errors.New("some other failure"),
			want:    []string{"some other failure"},
			notWant: []string{"Hint:"},
		},
		{
			name:    "bare exit policy error gets its hint",
			err:     core.ErrConfigMismatchPolicyExit,
			want:    []string{ChainConfigMismatchPolicyExitHint},
			notWant: []string{UnusableGapScheduleHint},
		},
		{
			name:    "exit policy detail keeps the hint on its own line",
			err:     fmt.Errorf("%w: %s", core.ErrConfigMismatchPolicyExit, "config mismatch detail"),
			want:    []string{"config mismatch detail.\n" + ChainConfigMismatchPolicyExitHint},
			notWant: []string{UnusableGapScheduleHint},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatChainConfigError(tt.err)
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Fatalf("formatted error %q does not contain %q", got, want)
				}
			}
			for _, notWant := range tt.notWant {
				if strings.Contains(got, notWant) {
					t.Fatalf("formatted error %q must not contain %q", got, notWant)
				}
			}
		})
	}
}

// TestUnsetXDPoSEpochHintNamesTheAccessor pins the recovery path the hint names
// against the contract the engine actually implements: XDPoS.New resolves an
// omitted epoch onto its own copy and exposes it as XDPoS.ChainConfig(), so the
// hint must not claim the engine writes the default into the config it was given.
// That claim described the removed write-back and would send an operator looking
// for an update on their own object that never happens.
func TestUnsetXDPoSEpochHintNamesTheAccessor(t *testing.T) {
	for _, want := range []string{"XDPoS.ChainConfig()", "so the config it was given is left untouched"} {
		if !strings.Contains(UnsetXDPoSEpochHint, want) {
			t.Fatalf("UnsetXDPoSEpochHint does not contain %q: %s", want, UnsetXDPoSEpochHint)
		}
	}
	if stale := "writes that default into the config it is given"; strings.Contains(UnsetXDPoSEpochHint, stale) {
		t.Fatalf("UnsetXDPoSEpochHint still claims the removed write-back %q: %s", stale, UnsetXDPoSEpochHint)
	}
}

// TestFormatChainConfigErrorUnalignedSwitchBlock pins the hint for the alignment
// rejection of a config that writes its epoch out. It is the same rule the
// default-epoch variant pins, but the epoch here is a number the genesis contains,
// so the formatted text has to select the sibling hint - the one that names the
// arithmetic to fix - instead of the one that explains where a default came from.
// The error is built through the operator-facing API rather than assembled here, so
// the test also pins that the sentinel the validator attaches survives unwrapping and
// that the ordering sentinel callers already match keeps working.
func TestFormatChainConfigErrorUnalignedSwitchBlock(t *testing.T) {
	cfg := params.TestnetChainConfig.Clone()
	cfg.XDPoS = cfg.XDPoS.Clone()
	unaligned := new(big.Int).SetUint64(cfg.XDPoS.Epoch + 1)
	cfg.XDPoS.V2.SwitchBlock = unaligned

	err := cfg.CheckConfigForkOrder()
	if err == nil {
		t.Fatal("expected the written epoch to reject an unaligned switch block")
	}
	if !errors.Is(err, params.ErrSwitchBlockUnalignedToEpoch) {
		t.Fatalf("unexpected error: have %v want %v", err, params.ErrSwitchBlockUnalignedToEpoch)
	}
	if !errors.Is(err, params.ErrWrongForkSwitchOrder) {
		t.Fatalf("unexpected error: have %v want %v", err, params.ErrWrongForkSwitchOrder)
	}

	got := FormatChainConfigError(err)
	for _, want := range []string{
		fmt.Sprintf("XDPoS.V2.SwitchBlock %v not aligned to XDPoS.Epoch %d", unaligned, cfg.XDPoS.Epoch),
		UnalignedSwitchBlockHint,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("formatted error %q does not contain %q", got, want)
		}
	}
	for _, notWant := range []string{"Migration hint", UnalignedSwitchBlockDefaultEpochHint, UnusableGapScheduleHint, UnusableGapScheduleDefaultEpochHint, SwitchEpochMismatchHint, SwitchEpochMismatchAgainstDefaultEpochHint} {
		if strings.Contains(got, notWant) {
			t.Fatalf("formatted error %q must not contain %q", got, notWant)
		}
	}
}

// TestFormatChainConfigErrorUnalignedSwitchBlockDefaultEpoch pins the hint for the
// rejection only the filled-in default epoch produces: the alignment message names
// an epoch the genesis never wrote, so the formatted text has to say where that
// number came from instead of leaving the operator to guess.
//
// The error is built through the operator-facing API rather than assembled here, so
// the test also pins that the sentinel the validator attaches survives unwrapping.
func TestFormatChainConfigErrorUnalignedSwitchBlockDefaultEpoch(t *testing.T) {
	cfg := params.TestnetChainConfig.Clone()
	cfg.XDPoS = cfg.XDPoS.Clone()
	cfg.XDPoS.Epoch = 0
	unaligned := new(big.Int).SetUint64(cfg.XDPoS.V2.SwitchBlock.Uint64() + 1)
	cfg.XDPoS.V2.SwitchBlock = unaligned

	// An unset epoch defers the alignment rule, so the config is only refused once
	// the default the engine would fill in is applied.
	if err := cfg.CheckConfigForkOrder(); err != nil {
		t.Fatalf("CheckConfigForkOrder rejected an unset epoch: %v", err)
	}
	err := cfg.CheckConfigForkOrderWithEpochDefault()
	if err == nil {
		t.Fatal("expected the default epoch to reject an unaligned switch block")
	}
	if !errors.Is(err, params.ErrSwitchBlockUnalignedToDefaultEpoch) {
		t.Fatalf("unexpected error: have %v want %v", err, params.ErrSwitchBlockUnalignedToDefaultEpoch)
	}

	got := FormatChainConfigError(err)
	for _, want := range []string{
		fmt.Sprintf("XDPoS.V2.SwitchBlock %v not aligned to XDPoS.Epoch %d", unaligned, params.DefaultXDPoSEpoch),
		UnalignedSwitchBlockDefaultEpochHint,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("formatted error %q does not contain %q", got, want)
		}
	}
	// The neighbouring hints belong to other rejections, so this branch must not
	// inherit either of them.
	for _, notWant := range []string{"Migration hint", UnusableGapScheduleHint, UnusableGapScheduleDefaultEpochHint, SwitchEpochMismatchHint, SwitchEpochMismatchAgainstDefaultEpochHint} {
		if strings.Contains(got, notWant) {
			t.Fatalf("formatted error %q must not contain %q", got, notWant)
		}
	}
}

// TestFormatChainConfigErrorSwitchEpochMismatchAgainstDefaultEpoch pins the hint
// for the switch-epoch rejection that only the filled-in default epoch activates.
// The message divides by an epoch the genesis never wrote, so the formatted text
// has to say where that number came from - and the fix may be the switch epoch or
// the omitted epoch, which is what the hint has to name. The error is built through
// the operator-facing API rather than assembled here, so the test also pins that
// the tag the validator attaches survives unwrapping.
func TestFormatChainConfigErrorSwitchEpochMismatchAgainstDefaultEpoch(t *testing.T) {
	cfg := params.TestnetChainConfig.Clone()
	cfg.XDPoS = cfg.XDPoS.Clone()
	cfg.XDPoS.Epoch = 0
	cfg.XDPoS.V2.SwitchEpoch++

	// An unset epoch defers the rule, so the config is only refused once the default
	// the engine would fill in is applied.
	if err := cfg.CheckConfigForkOrder(); err != nil {
		t.Fatalf("CheckConfigForkOrder rejected an unset epoch: %v", err)
	}
	err := cfg.CheckConfigForkOrderWithEpochDefault()
	if err == nil {
		t.Fatal("expected the default epoch to reject a mismatched switch epoch")
	}
	if !errors.Is(err, params.ErrSwitchEpochMismatchAgainstDefaultEpoch) {
		t.Fatalf("unexpected error: have %v want %v", err, params.ErrSwitchEpochMismatchAgainstDefaultEpoch)
	}
	// Callers that only know the rule this sentinel refines keep matching.
	if !errors.Is(err, params.ErrSwitchEpochMismatch) {
		t.Fatalf("unexpected error: have %v want %v", err, params.ErrSwitchEpochMismatch)
	}

	got := FormatChainConfigError(err)
	for _, want := range []string{
		fmt.Sprintf("/ XDPoS.Epoch %d", params.DefaultXDPoSEpoch),
		SwitchEpochMismatchAgainstDefaultEpochHint,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("formatted error %q does not contain %q", got, want)
		}
	}
	// The arithmetic hint belongs to a config that spells its epoch out, and the
	// neighbouring schedule, alignment and constructor hints belong to other
	// rejections, so this branch must not inherit any of them.
	for _, notWant := range []string{
		"Migration hint",
		SwitchEpochMismatchHint,
		UnusableGapScheduleHint,
		UnusableGapScheduleDefaultEpochHint,
		UnalignedSwitchBlockDefaultEpochHint,
		UnsetXDPoSEpochHint,
	} {
		if strings.Contains(got, notWant) {
			t.Fatalf("formatted error %q must not contain %q", got, notWant)
		}
	}
}

// TestFormatChainConfigErrorGapScheduleAgainstDefaultEpoch pins the hint for the
// gap rejection that only the filled-in default epoch activates. The message names
// an epoch the genesis never wrote, so the formatted text has to say where that
// number came from - and the recovery path is still the schedule, so the generic
// schedule hint must not be the one an operator sees here.
//
// The error is built through the operator-facing API rather than assembled here, so
// the test also pins that the tag the validator attaches survives unwrapping.
func TestFormatChainConfigErrorGapScheduleAgainstDefaultEpoch(t *testing.T) {
	cfg := params.TestnetChainConfig.Clone()
	cfg.XDPoS = cfg.XDPoS.Clone()
	cfg.XDPoS.Epoch = 0
	cfg.XDPoS.Gap = 0

	// An unset epoch defers the gap rule, so the config is only refused once the
	// default the engine would fill in is applied.
	if err := cfg.CheckConfigForkOrder(); err != nil {
		t.Fatalf("CheckConfigForkOrder rejected an unset epoch: %v", err)
	}
	err := cfg.CheckConfigForkOrderWithEpochDefault()
	if !errors.Is(err, params.ErrUnusableGapSchedule) {
		t.Fatalf("unexpected error: have %v want %v", err, params.ErrUnusableGapSchedule)
	}

	got := FormatChainConfigError(err)
	for _, want := range []string{
		fmt.Sprintf("XDPoS.Gap 0 designates no gap block inside XDPoS.Epoch %d", params.DefaultXDPoSEpoch),
		UnusableGapScheduleDefaultEpochHint,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("formatted error %q does not contain %q", got, want)
		}
	}
	// The generic hint belongs to a schedule the config wrote itself, so this branch
	// must not inherit it, and neither hint of the other default-epoch rejection.
	for _, notWant := range []string{
		"Migration hint",
		UnusableGapScheduleHint,
		UnalignedSwitchBlockDefaultEpochHint,
		SwitchEpochMismatchAgainstDefaultEpochHint,
		UnsetXDPoSEpochHint,
	} {
		if strings.Contains(got, notWant) {
			t.Fatalf("formatted error %q must not contain %q", got, notWant)
		}
	}
}

// TestFormatChainConfigErrorNegativeSwitchBlock pins the hint for a switch block
// that carries a negative height. The error is built through the operator-facing
// API rather than assembled here, so the test also pins that the sentinel survives
// unwrapping, and it asserts the neighbouring hints are not inherited: a schedule
// without a gap block or an alignment failure is a different defect with a
// different recovery path, and a negative height is a defect of the config itself
// rather than an artifact of the default epoch.
func TestFormatChainConfigErrorNegativeSwitchBlock(t *testing.T) {
	cfg := params.TestnetChainConfig.Clone()
	cfg.XDPoS = cfg.XDPoS.Clone()
	cfg.XDPoS.V2 = cfg.XDPoS.V2.Clone()
	cfg.XDPoS.V2.SwitchBlock = big.NewInt(-900)

	err := cfg.CheckConfigForkOrder()
	if !errors.Is(err, params.ErrNegativeSwitchBlock) {
		t.Fatalf("unexpected error: have %v want %v", err, params.ErrNegativeSwitchBlock)
	}
	got := FormatChainConfigError(err)
	for _, want := range []string{
		"XDPoS.V2.SwitchBlock -900 must be non-negative",
		NegativeSwitchBlockHint,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("formatted error %q does not contain %q", got, want)
		}
	}
	for _, notWant := range []string{
		"Migration hint",
		UnusableGapScheduleHint,
		UnsetXDPoSEpochHint,
		UnalignedSwitchBlockDefaultEpochHint,
		SwitchEpochMismatchAgainstDefaultEpochHint,
	} {
		if strings.Contains(got, notWant) {
			t.Fatalf("formatted error %q must not contain %q", got, notWant)
		}
	}
}

// TestFormatChainConfigErrorPrefersTheDefaultEpochVariant pins the ordering the hint
// selection depends on: each *DefaultEpoch wrapping error identifies both its own
// sentinel and the base sentinel it refines, so the variant has to win. Keeping the
// pairs in one table makes the order data rather than control flow, and this test is
// what makes a future row appended at the end fail loudly instead of silently
// selecting the base hint.
func TestFormatChainConfigErrorPrefersTheDefaultEpochVariant(t *testing.T) {
	tests := []struct {
		name    string
		build   func() error
		want    string
		notWant []string
	}{
		{
			name: "gap schedule judged against the default epoch",
			build: func() error {
				cfg := params.TestnetChainConfig.Clone()
				cfg.XDPoS = cfg.XDPoS.Clone()
				cfg.XDPoS.Epoch = 0
				cfg.XDPoS.Gap = 0
				return cfg.CheckConfigForkOrderWithEpochDefault()
			},
			want:    UnusableGapScheduleDefaultEpochHint,
			notWant: []string{UnusableGapScheduleHint, UnalignedSwitchBlockDefaultEpochHint},
		},
		{
			name: "unaligned switch block judged against the default epoch",
			build: func() error {
				cfg := params.TestnetChainConfig.Clone()
				cfg.XDPoS = cfg.XDPoS.Clone()
				cfg.XDPoS.Epoch = 0
				cfg.XDPoS.V2.SwitchBlock = new(big.Int).SetUint64(cfg.XDPoS.V2.SwitchBlock.Uint64() + 1)
				return cfg.CheckConfigForkOrderWithEpochDefault()
			},
			want:    UnalignedSwitchBlockDefaultEpochHint,
			notWant: []string{UnusableGapScheduleHint, UnusableGapScheduleDefaultEpochHint},
		},
		{
			name: "switch epoch mismatch judged against the default epoch",
			build: func() error {
				cfg := params.TestnetChainConfig.Clone()
				cfg.XDPoS = cfg.XDPoS.Clone()
				cfg.XDPoS.Epoch = 0
				cfg.XDPoS.V2.SwitchEpoch++
				return cfg.CheckConfigForkOrderWithEpochDefault()
			},
			want:    SwitchEpochMismatchAgainstDefaultEpochHint,
			notWant: []string{SwitchEpochMismatchHint, UnusableGapScheduleDefaultEpochHint},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.build()
			if err == nil {
				t.Fatal("expected the default-epoch judgement to refuse the config")
			}

			got := FormatChainConfigError(err)
			if !strings.Contains(got, tt.want) {
				t.Fatalf("formatted error %q does not carry the variant hint %q", got, tt.want)
			}
			for _, notWant := range tt.notWant {
				if strings.Contains(got, notWant) {
					t.Fatalf("formatted error %q carries %q, so the variant lost to the base sentinel", got, notWant)
				}
			}
		})
	}
}

// multiSentinelError identifies more than one sentinel at once, the shape the
// *DefaultEpoch variants use to keep both the refined and the base sentinel
// recognisable. Nothing in this package builds a cross-family error today, so this
// is how the second half of the table order is pinned: a future compound error must
// resolve by the listed order instead of by which sentinel happened to be checked
// first.
type multiSentinelError struct {
	message   string
	sentinels []error
}

func (e multiSentinelError) Error() string { return e.message }

func (e multiSentinelError) Unwrap() []error { return e.sentinels }

// TestFormatChainConfigErrorOrdersTheSentinelFamilies pins the priority between
// families, which the variant test above does not cover: it only checks a variant
// against the base sentinel it refines. An unset epoch and a missing config are
// caller-side defects - there is no genesis field that fixes either, and the schedule
// may be perfectly usable - so they are listed before every schedule row and win when
// an error identifies both. Without this, a compound error would silently pick
// whichever row was listed first, and an operator would be sent to repair a schedule
// that is not the defect.
func TestFormatChainConfigErrorOrdersTheSentinelFamilies(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		want    string
		notWant []string
	}{
		{
			name: "unset epoch outranks an unusable schedule",
			err: multiSentinelError{
				message:   "invalid chain config: XDPoS.Epoch is unset and the gap schedule designates no gap block",
				sentinels: []error{params.ErrUnsetXDPoSEpoch, params.ErrUnusableGapSchedule},
			},
			want:    UnsetXDPoSEpochHint,
			notWant: []string{UnusableGapScheduleHint, MissingXDPoSConfigHint},
		},
		{
			name: "missing config outranks an unusable schedule",
			err: multiSentinelError{
				message:   "gap lookup was called with a nil config",
				sentinels: []error{params.ErrMissingXDPoSConfig, params.ErrUnusableGapSchedule},
			},
			want:    MissingXDPoSConfigHint,
			notWant: []string{UnusableGapScheduleHint, UnsetXDPoSEpochHint},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatChainConfigError(tt.err)
			if !strings.Contains(got, tt.err.Error()) {
				t.Fatalf("formatted error %q does not carry the message it formats", got)
			}
			if !strings.Contains(got, tt.want) {
				t.Fatalf("formatted error %q does not carry the caller-side hint %q", got, tt.want)
			}
			for _, notWant := range tt.notWant {
				if strings.Contains(got, notWant) {
					t.Fatalf("formatted error %q carries %q, so the family order was not honoured", got, notWant)
				}
			}
		})
	}
}
