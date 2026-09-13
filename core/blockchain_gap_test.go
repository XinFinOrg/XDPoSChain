package core

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestShouldUpdateM1 pins the shared gap-trigger predicate: GapOffset owns the
// judgement of whether the schedule designates a gap block at all, so no
// schedule below can divide by an unset epoch or fire on a height the trigger
// never selects.
func TestShouldUpdateM1(t *testing.T) {
	tests := []struct {
		name   string
		config *params.XDPoSConfig
		number uint64
		want   bool
	}{
		{name: "gap block of a usable schedule", config: &params.XDPoSConfig{Epoch: 900, Gap: 450}, number: 1350, want: true},
		{name: "epoch start is not the gap block", config: &params.XDPoSConfig{Epoch: 900, Gap: 450}, number: 1800, want: false},
		{name: "height before any gap block", config: &params.XDPoSConfig{Epoch: 900, Gap: 450}, number: 1000, want: false},
		{name: "zero gap never fires", config: &params.XDPoSConfig{Epoch: 900, Gap: 0}, number: 900, want: false},
		{name: "gap equal to epoch never fires", config: &params.XDPoSConfig{Epoch: 900, Gap: 900}, number: 900, want: false},
		{name: "gap above epoch never fires", config: &params.XDPoSConfig{Epoch: 900, Gap: 1200}, number: 1350, want: false},
		{name: "unset epoch never fires", config: &params.XDPoSConfig{Epoch: 0, Gap: 450}, number: 1350, want: false},
		{name: "missing config never fires", config: nil, number: 1350, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bc := &BlockChain{chainConfig: &params.ChainConfig{XDPoS: tt.config}}

			if got := bc.shouldUpdateM1(tt.number); got != tt.want {
				t.Fatalf("shouldUpdateM1(%d) = %v, want %v", tt.number, got, tt.want)
			}
		})
	}

	// A BlockChain built directly inside this package may carry no chain config at
	// all (SetHead runs on one), so the predicate has to stay total there the way
	// its siblings do instead of dereferencing a nil config.
	if (&BlockChain{}).shouldUpdateM1(1350) {
		t.Fatal("shouldUpdateM1 must answer false for a nil chain config")
	}
}

// TestGapPredicatesAreTotal pins that the two open-coded division sites left in
// core judge the schedule before dividing. A BlockChain can be built directly in
// this package (TestShouldUpdateM1 does), bypassing the newBlockChain refusal, so
// neither predicate may panic on an unset epoch or a missing config.
//
// The rows also pin that the v1 checkpoint predicate is deliberately independent
// of gap usability: unlike the v2 trigger, (number+Gap)%Epoch == 0 stays defined
// when Gap == 0 or Gap == Epoch, which is why it does not go through GapOffset.
func TestGapPredicatesAreTotal(t *testing.T) {
	tests := []struct {
		name   string
		config *params.ChainConfig
		number uint64
		// wantCheckpoint and wantLiquidation are the answers of
		// isV1SnapshotCheckpointBlock and isLendingLiquidationBlock.
		wantCheckpoint  bool
		wantLiquidation bool
	}{
		{name: "missing chain config", config: nil, number: 900},
		{name: "missing xdpos config", config: &params.ChainConfig{}, number: 900},
		{name: "unset epoch", config: &params.ChainConfig{XDPoS: &params.XDPoSConfig{Epoch: 0, Gap: 450}}, number: 1350},
		{name: "genesis is neither", config: &params.ChainConfig{XDPoS: &params.XDPoSConfig{Epoch: 900, Gap: 450}}, number: 0},
		{name: "zero gap is a v1 checkpoint at the epoch start", config: &params.ChainConfig{XDPoS: &params.XDPoSConfig{Epoch: 900, Gap: 0}}, number: 900, wantCheckpoint: true},
		{name: "gap equal to the epoch is a v1 checkpoint too", config: &params.ChainConfig{XDPoS: &params.XDPoSConfig{Epoch: 900, Gap: 900}}, number: 900, wantCheckpoint: true},
		{name: "v1 checkpoint one gap after the epoch start", config: &params.ChainConfig{XDPoS: &params.XDPoSConfig{Epoch: 900, Gap: 450}}, number: 1350, wantCheckpoint: true},
		{name: "liquidation block", config: &params.ChainConfig{XDPoS: &params.XDPoSConfig{Epoch: 900, Gap: 450}}, number: 1000, wantLiquidation: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bc := &BlockChain{chainConfig: tt.config}

			if got := bc.isV1SnapshotCheckpointBlock(tt.number); got != tt.wantCheckpoint {
				t.Fatalf("isV1SnapshotCheckpointBlock(%d) = %v, want %v", tt.number, got, tt.wantCheckpoint)
			}
			if got := bc.isLendingLiquidationBlock(tt.number); got != tt.wantLiquidation {
				t.Fatalf("isLendingLiquidationBlock(%d) = %v, want %v", tt.number, got, tt.wantLiquidation)
			}
		})
	}
}

// TestNewBlockChainRejectsUnsetXDPoSEpoch pins that a chain config with an
// unset epoch cannot be opened: the config validation deliberately judges an
// omitted epoch against params.DefaultXDPoSEpoch, a default only the XDPoS
// engine fills in, while the gap trigger divides by the stored value. The
// schedule stays otherwise valid (gap inside the default epoch, switch block
// aligned to it) so nothing but the invariant under test can reject it, which is
// also why the refusal carries the unset-epoch sentinel and not the gap one.
func TestNewBlockChainRejectsUnsetXDPoSEpoch(t *testing.T) {
	genesis := newCustomXDPoSGenesis(4545, 0)
	genesis.Config.XDPoS.Epoch = 0
	genesis.Config.XDPoS.Gap = 450
	genesis.Config.XDPoS.V2.SwitchBlock = big.NewInt(900)
	genesis.Config.XDPoS.V2.SwitchEpoch = 1

	_, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, genesis, ethash.NewFaker(), vm.Config{})
	if !errors.Is(err, params.ErrUnsetXDPoSEpoch) {
		t.Fatalf("unexpected error: have %v want %v", err, params.ErrUnsetXDPoSEpoch)
	}
	if errors.Is(err, params.ErrUnusableGapSchedule) {
		t.Fatalf("an unset epoch must not be reported as a gap schedule defect: %v", err)
	}
	if !strings.Contains(err.Error(), "XDPoS.Epoch is unset") {
		t.Fatalf("error %q does not report the unset epoch", err)
	}
	// The message has to name the way out: this constructor resolved its own config,
	// so the caller's engine-resolved one is invisible here and only the resolved
	// constructors accept it. Those constructors also take the genesis hash, the
	// compatibility error and the mismatch policy, so the message has to name where a
	// caller that only used this one gets them from.
	for _, want := range []string{"NewBlockChainResolved", "NewBlockChainReadOnlyResolved", "SetupGenesisBlock", "LoadChainConfigWithCompat"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not point at %s", err, want)
		}
	}
	// This is the path that cannot hand the engine's config over, so the message must
	// not read as if it could.
	if strings.Contains(err.Error(), "not the object the engine was built from") {
		t.Fatalf("the resolving constructor is given the resolved-constructor wording: %q", err)
	}
}

// TestNewBlockChainAcceptsFilledInXDPoSEpoch is the control for the invariant:
// the same schedule with the epoch filled in opens normally, so the guard only
// refuses the state that would divide by zero.
func TestNewBlockChainAcceptsFilledInXDPoSEpoch(t *testing.T) {
	genesis := newCustomXDPoSGenesis(4545, 0)
	genesis.Config.XDPoS.Epoch = 900
	genesis.Config.XDPoS.Gap = 450
	genesis.Config.XDPoS.V2.SwitchBlock = big.NewInt(900)
	genesis.Config.XDPoS.V2.SwitchEpoch = 1

	chain, err := NewBlockChain(rawdb.NewMemoryDatabase(), nil, genesis, ethash.NewFaker(), vm.Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer chain.Stop()

	if got := chain.Config().XDPoS.Epoch; got == 0 {
		t.Fatal("opened chain carries an unset epoch")
	}
}

// TestNewBlockChainResolvedRejectsUnsetXDPoSEpoch pins the same guard on the
// resolved constructor, which is the entry point the node startup path and the
// XDCx wrappers use. Its doc states the XDPoS.Epoch precondition; this is the
// refusal that precondition exists for, so the documented contract cannot drift
// away from the code silently.
func TestNewBlockChainResolvedRejectsUnsetXDPoSEpoch(t *testing.T) {
	genesis := newCustomXDPoSGenesis(4545, 0)
	genesis.Config.XDPoS.Epoch = 0
	genesis.Config.XDPoS.Gap = 450
	genesis.Config.XDPoS.V2.SwitchBlock = big.NewInt(900)
	genesis.Config.XDPoS.V2.SwitchEpoch = 1

	_, err := NewBlockChainResolved(rawdb.NewMemoryDatabase(), nil, genesis, ethash.NewFaker(), vm.Config{},
		genesis.Config, genesis.ToBlock().Hash(), nil, DefaultChainConfigMismatchPolicy)
	if !errors.Is(err, params.ErrUnsetXDPoSEpoch) {
		t.Fatalf("unexpected error: have %v want %v", err, params.ErrUnsetXDPoSEpoch)
	}
	if errors.Is(err, params.ErrUnusableGapSchedule) {
		t.Fatalf("an unset epoch must not be reported as a gap schedule defect: %v", err)
	}
	// This caller already used a resolved constructor, so pointing it back at one
	// would be a loop: the message has to name the object it should have passed
	// instead.
	if !strings.Contains(err.Error(), "XDPoS.ChainConfig()") {
		t.Fatalf("error %q does not name the config this constructor expects", err)
	}
	if strings.Contains(err.Error(), "NewBlockChainResolved") {
		t.Fatalf("the resolved constructor is sent back to itself: %q", err)
	}
}

// TestNewBlockChainResolvedRejectsUnusableGapSchedule pins the second half of the
// open precondition: the resolved constructors judge the caller's config as given,
// so a schedule that designates no gap block has to be refused here too. The engine
// constructors refuse it earlier on the node startup path, but a library caller can
// hand this constructor a config no engine validated, and such a chain would then
// run with shouldUpdateM1 never firing while every gap lookup errors - a divergence
// that surfaces as a state-root mismatch rather than as an error.
func TestNewBlockChainResolvedRejectsUnusableGapSchedule(t *testing.T) {
	tests := []struct {
		name    string
		epoch   uint64
		gap     uint64
		wantMsg string
	}{
		{name: "zero gap", epoch: 900, gap: 0, wantMsg: "XDPoS.Gap 0 designates no gap block inside XDPoS.Epoch 900"},
		{name: "gap equal to epoch", epoch: 900, gap: 900, wantMsg: "designates no gap block of its own"},
		{name: "gap above epoch", epoch: 900, gap: 1200, wantMsg: "XDPoS.Gap 1200 designates no gap block inside XDPoS.Epoch 900"},
		{name: "epoch one leaves no gap", epoch: 1, gap: 0, wantMsg: "Epoch >= 2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			genesis := newCustomXDPoSGenesis(4545, 0)
			db := rawdb.NewMemoryDatabase()
			// The genesis has to be committed with a schedule the commit path accepts,
			// so the helper's usable one is written first and the config under test is
			// applied to the object handed to the open afterwards.
			genesis.MustCommit(db)

			genesis.Config.XDPoS.Epoch = test.epoch
			genesis.Config.XDPoS.Gap = test.gap
			// A height every epoch divides, paired with its epoch, so nothing but the
			// gap rule can refuse this config.
			genesis.Config.XDPoS.V2.SwitchBlock = new(big.Int)
			genesis.Config.XDPoS.V2.SwitchEpoch = 0

			_, err := NewBlockChainResolved(db, nil, genesis, ethash.NewFaker(), vm.Config{},
				genesis.Config, genesis.ToBlock().Hash(), nil, DefaultChainConfigMismatchPolicy)
			if !errors.Is(err, params.ErrUnusableGapSchedule) {
				t.Fatalf("unexpected error: have %v want %v", err, params.ErrUnusableGapSchedule)
			}
			if errors.Is(err, params.ErrUnsetXDPoSEpoch) {
				t.Fatalf("a schedule with an epoch must not be reported as an unset epoch: %v", err)
			}
			if !strings.Contains(err.Error(), test.wantMsg) {
				t.Fatalf("error %q does not carry %q", err, test.wantMsg)
			}
		})
	}

	// Control: the same genesis with its usable schedule still opens, so the guard only
	// refuses what the schedule rule refuses.
	genesis := newCustomXDPoSGenesis(4545, 0)
	db := rawdb.NewMemoryDatabase()
	genesis.MustCommit(db)

	chain, err := NewBlockChainResolved(db, nil, genesis, ethash.NewFaker(), vm.Config{},
		genesis.Config, genesis.ToBlock().Hash(), nil, DefaultChainConfigMismatchPolicy)
	if err != nil {
		t.Fatalf("a usable schedule must still open: %v", err)
	}
	defer chain.Stop()
}
