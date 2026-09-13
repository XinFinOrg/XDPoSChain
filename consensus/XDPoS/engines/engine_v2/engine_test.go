package engine_v2

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/lru"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

func TestNewRequiresStartupValidatedV2Config(t *testing.T) {
	chainConfig := params.TestnetChainConfig.Clone()
	chainConfig.XDPoS = chainConfig.XDPoS.Clone()
	chainConfig.XDPoS.V2 = nil

	engine, err := New(chainConfig, rawdb.NewMemoryDatabase(), make(chan int), make(chan types.Round, 1))
	assert.Nil(t, engine)
	assert.EqualError(t, err, "engine_v2.New requires startup-validated XDPoS V2 config")
}

// TestNewRejectsUnsetEpoch pins the guard that keeps an unset epoch out of every
// round/epoch conversion in this package. Config validation deliberately leaves an
// omitted epoch for XDPoS.New to fill, so a caller that builds the engine directly
// - the same caller the isEpochSwitchAtRound guard exists for - has to be refused
// here instead of dividing by zero on the first conversion it reaches. The
// gap-schedule fixtures build the engine struct directly, so they still cover the
// on-demand guards. The refusal is not a schedule defect, so it carries the
// unset-epoch sentinel rather than the gap one.
func TestNewRejectsUnsetEpoch(t *testing.T) {
	chainConfig := params.TestnetChainConfig.Clone()
	chainConfig.XDPoS = chainConfig.XDPoS.Clone()
	chainConfig.XDPoS.Epoch = 0

	engine, err := New(chainConfig, rawdb.NewMemoryDatabase(), make(chan int), make(chan types.Round, 1))
	assert.Nil(t, engine)
	assert.ErrorIs(t, err, params.ErrUnsetXDPoSEpoch)
}

// TestNewRejectsUnalignedSwitchBlock pins the rule initial's first-epoch gap step
// relies on. That step steps back from the switch block by Gap, which resolves to
// GapBlockNumber's answer only while the switch block sits on an epoch boundary.
// CheckConfigForkOrder judges the rule for every resolved config, but a directly
// constructed engine never goes through it, and a silent disagreement there would
// be read by block production and by block import as different gap blocks.
func TestNewRejectsUnalignedSwitchBlock(t *testing.T) {
	chainConfig := params.TestnetChainConfig.Clone()
	chainConfig.XDPoS = chainConfig.XDPoS.Clone()
	// The pairing rule passes on these values, which is why the alignment has to be
	// judged on its own: 56828750 / 900 == 63143, and the remainder is 50.
	chainConfig.XDPoS.V2.SwitchBlock = big.NewInt(56828750)
	chainConfig.XDPoS.V2.SwitchEpoch = 63143

	engine, err := New(chainConfig, rawdb.NewMemoryDatabase(), make(chan int), make(chan types.Round, 1))
	assert.Nil(t, engine)
	assert.ErrorIs(t, err, params.ErrWrongForkSwitchOrder)
}

// TestNewRejectsMismatchedSwitchEpoch pins the other half of the switch schedule:
// SwitchEpoch has to name the epoch its block falls on, or the v2 round arithmetic
// renumbers every epoch the engine reports while every other rule still passes. A
// directly constructed engine never goes through CheckConfigForkOrder, which is why
// the rule is exported and this constructor judges it as well.
func TestNewRejectsMismatchedSwitchEpoch(t *testing.T) {
	chainConfig := params.TestnetChainConfig.Clone()
	chainConfig.XDPoS = chainConfig.XDPoS.Clone()
	chainConfig.XDPoS.V2 = chainConfig.XDPoS.V2.Clone()
	// The switch block stays on its epoch boundary, so the alignment rule passes and
	// only the pairing rule can refuse this config.
	chainConfig.XDPoS.V2.SwitchEpoch = chainConfig.XDPoS.V2.SwitchBlock.Uint64()/chainConfig.XDPoS.Epoch + 1

	engine, err := New(chainConfig, rawdb.NewMemoryDatabase(), make(chan int), make(chan types.Round, 1))
	assert.Nil(t, engine)
	assert.ErrorIs(t, err, params.ErrSwitchEpochMismatch)
}

// TestNewRejectsNegativeSwitchBlock pins that the constructor inherited the sign
// judgement CheckSwitchBlockAlignment gained. A negative multiple of the epoch looks
// aligned to SwitchBlock.Uint64(), so before that judgement this constructor built an
// engine whose gap lookups compared a height that can never match.
func TestNewRejectsNegativeSwitchBlock(t *testing.T) {
	for _, block := range []int64{-900, -1800} {
		chainConfig := params.TestnetChainConfig.Clone()
		chainConfig.XDPoS = chainConfig.XDPoS.Clone()
		chainConfig.XDPoS.V2 = chainConfig.XDPoS.V2.Clone()
		chainConfig.XDPoS.V2.SwitchBlock = big.NewInt(block)

		engine, err := New(chainConfig, rawdb.NewMemoryDatabase(), make(chan int), make(chan types.Round, 1))
		assert.Nil(t, engine)
		assert.ErrorIs(t, err, params.ErrNegativeSwitchBlock, "switch block %d", block)
	}
}

// TestNewRejectsUnusableGapSchedule pins the third rule this constructor judges on
// the config it is handed. Every gap lookup in this package - UpdateMasternodes,
// getSnapshot, verifyQC, sendVote, sendTimeout - resolves its height through the
// schedule, and a directly constructed engine goes through neither
// CheckConfigForkOrder nor the chain open path, so a schedule that designates no gap
// block used to build an engine whose every gap path failed at runtime. That is the
// asymmetry the two switch rules above are already judged for. The switch schedule
// is kept self-consistent in every row, so only the gap rule can refuse the config,
// and the refusal stays a gap-schedule defect: it must not be reported as an unset
// epoch or as a switch defect.
func TestNewRejectsUnusableGapSchedule(t *testing.T) {
	tests := []struct {
		name  string
		epoch uint64
		gap   uint64
	}{
		{"zero gap", 900, 0},
		{"gap equal to epoch", 900, 900},
		{"gap above epoch", 900, 1200},
		{"epoch one leaves no gap", 1, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chainConfig := params.TestnetChainConfig.Clone()
			chainConfig.XDPoS = chainConfig.XDPoS.Clone()
			chainConfig.XDPoS.Epoch = tt.epoch
			chainConfig.XDPoS.Gap = tt.gap
			chainConfig.XDPoS.V2.SwitchEpoch = chainConfig.XDPoS.V2.SwitchBlock.Uint64() / tt.epoch

			engine, err := New(chainConfig, rawdb.NewMemoryDatabase(), make(chan int), make(chan types.Round, 1))
			assert.Nil(t, engine)
			assertUnusableGapSchedule(t, err, []string{"engine_v2.New requires a usable XDPoS gap schedule"})
			assert.NotErrorIs(t, err, params.ErrUnsetXDPoSEpoch)
			assert.NotErrorIs(t, err, params.ErrSwitchEpochMismatch)
		})
	}
}

// TestNewReportsTheSwitchScheduleBeforeTheGapSchedule pins the judgement order the
// three exported rules are judged in. A config can fail more than one of them, and
// the two switch rules are the ones the engine's first-epoch step and its round
// arithmetic read directly, so they have to keep being reported as the defect they
// name instead of being masked by the gap rule judged after them.
func TestNewReportsTheSwitchScheduleBeforeTheGapSchedule(t *testing.T) {
	chainConfig := params.TestnetChainConfig.Clone()
	chainConfig.XDPoS = chainConfig.XDPoS.Clone()
	// Both defects at once: the switch epoch does not name the epoch its block falls
	// on, and the gap designates no gap block.
	chainConfig.XDPoS.V2.SwitchEpoch++
	chainConfig.XDPoS.Gap = 0

	engine, err := New(chainConfig, rawdb.NewMemoryDatabase(), make(chan int), make(chan types.Round, 1))
	assert.Nil(t, engine)
	assert.ErrorIs(t, err, params.ErrSwitchEpochMismatch)
	assert.NotErrorIs(t, err, params.ErrUnusableGapSchedule)
}

// TestNewCopiesScalarsAndSharesV2 pins the copy contract New makes about the config
// it is handed. The scalar consensus parameters are copied, so the engine never
// writes one back through the caller's XDPoSConfig pointer; V2 is deliberately
// shared, because it carries the live state the engine updates in place
// (BuildConfigIndex fills configIndex, UpdateParams repoints CurrentConfig) and
// callers read that state back through blockchain.Config().XDPoS.V2. Cloning V2 here
// would move that state to a private copy without failing anything.
func TestNewCopiesScalarsAndSharesV2(t *testing.T) {
	chainConfig := params.TestnetChainConfig.Clone()
	chainConfig.XDPoS = chainConfig.XDPoS.Clone()

	engine, err := New(chainConfig, rawdb.NewMemoryDatabase(), make(chan int), make(chan types.Round, 1))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if engine == nil {
		t.Fatal("expected an engine for a startup-validated config")
	}

	if engine.config == chainConfig.XDPoS {
		t.Fatal("the engine must not run on the caller's XDPoSConfig")
	}
	if engine.config.V2 != chainConfig.XDPoS.V2 {
		t.Fatal("V2 has to stay shared with the caller's config, because the engine updates it in place")
	}
	// The in-place update has to be visible through the caller's config: that is what
	// the readers of blockchain.Config().XDPoS.V2 rely on.
	if chainConfig.XDPoS.V2.ConfigIndex() == nil {
		t.Fatal("BuildConfigIndex did not fill the shared V2")
	}
}

// TestSendTimeoutUnusableGapSchedule has to put its chain head at this height:
// isEpochSwitchAtRound treats a head at the switch block as an epoch switch
// before it decodes any extra fields, which is what routes sendTimeout into its
// gap-number lookup.
const gapScheduleSwitchBlock uint64 = 900

// assertGuardError requires err to carry every fragment the caller names. The
// fragments are what identifies the rejection - the path prefix that names the call
// site and the height the lookup was for - rather than the whole sentence, so a
// wording change does not rewrite every table while the defect the guard reports
// stays pinned.
func assertGuardError(t *testing.T, err error, want []string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error carrying %q, got nil", want)
	}
	for _, fragment := range want {
		if !strings.Contains(err.Error(), fragment) {
			t.Fatalf("error %q does not carry %q", err, fragment)
		}
	}
}

// assertGapPathError requires err to carry want plus the sentinel that names the
// defect. Every shape gapPathError reports identifies a params sentinel with
// errors.Is: ErrUnusableGapSchedule for a height that resolves to no gap block,
// ErrUnsetXDPoSEpoch for an epoch the engine was never given, whose schedule may
// well be usable, and ErrMissingXDPoSConfig for a caller that handed the lookup no
// config at all. A caller that formats the error picks its recovery hint by that
// sentinel, so none of the three may identify another.
func assertGapPathError(t *testing.T, err error, want []string, sentinel error) {
	t.Helper()
	assertGuardError(t, err, want)
	if !errors.Is(err, sentinel) {
		t.Fatalf("error %q does not identify %v", err, sentinel)
	}
	if sentinel == params.ErrUnsetXDPoSEpoch && errors.Is(err, params.ErrUnusableGapSchedule) {
		t.Fatalf("error %q identifies %v, but an unset epoch is not a schedule defect", err, params.ErrUnusableGapSchedule)
	}
	if sentinel == params.ErrMissingXDPoSConfig && errors.Is(err, params.ErrUnusableGapSchedule) {
		t.Fatalf("error %q identifies %v, but a missing config is not a schedule defect", err, params.ErrUnusableGapSchedule)
	}
}

// assertUnusableGapSchedule requires err to identify
// params.ErrUnusableGapSchedule, so the engine paths that name this defect can be
// branched on with errors.Is just like the config validation paths.
func assertUnusableGapSchedule(t *testing.T, err error, want []string) {
	t.Helper()
	assertGapPathError(t, err, want, params.ErrUnusableGapSchedule)
}

// assertUnsetEpochInGapPath requires err to identify params.ErrUnsetXDPoSEpoch
// instead: the schedule may be perfectly usable, so the defect is the caller's and
// the hint that fits it is the unset-epoch one.
func assertUnsetEpochInGapPath(t *testing.T, err error, want []string) {
	t.Helper()
	assertGapPathError(t, err, want, params.ErrUnsetXDPoSEpoch)
}

// assertMissingXDPoSConfig requires err to identify params.ErrMissingXDPoSConfig
// instead: there is no schedule to repair at all, so the defect is the caller's and
// the hint that fits it names the constructor rather than a genesis field.
func assertMissingXDPoSConfig(t *testing.T, err error, want []string) {
	t.Helper()
	assertGapPathError(t, err, want, params.ErrMissingXDPoSConfig)
}

// gapScheduleEngine builds the smallest engine the gap-schedule guards need. The
// rejected paths never touch the database, but the epoch-switch cache has to
// exist: getEpochSwitchInfo looks there before it reads the chain.
func gapScheduleEngine(config *params.XDPoSConfig) *XDPoS_v2 {
	return &XDPoS_v2{
		config:        config,
		epochSwitches: lru.NewCache[common.Hash, *types.EpochSwitchInfo](int(utils.InMemoryEpochs)),
	}
}

// gapScheduleConfig returns a schedule that designates no gap block of its own, together
// with the V2 block the guard paths read before they reach the gap lookup:
// verifyQC reads the round-0 cert threshold there, and isEpochSwitchAtRound
// compares the chain head against SwitchBlock. Keep SwitchBlock in step with the
// head TestSendTimeoutUnusableGapSchedule sets.
func gapScheduleConfig(epoch, gap uint64) *params.XDPoSConfig {
	return &params.XDPoSConfig{
		Epoch: epoch,
		Gap:   gap,
		V2: &params.V2{
			SwitchBlock:   new(big.Int).SetUint64(gapScheduleSwitchBlock),
			CurrentConfig: &params.V2Config{CertThreshold: 0.5},
			AllConfigs:    map[uint64]*params.V2Config{0: {CertThreshold: 0.5}},
		},
	}
}

// seedEpochSwitch caches epoch switch info under hash, so getEpochSwitchInfo
// answers from the cache and the guards under test become reachable without a
// chain fixture.
func seedEpochSwitch(x *XDPoS_v2, hash common.Hash, number uint64) {
	x.epochSwitches.Add(hash, &types.EpochSwitchInfo{
		Masternodes:    []common.Address{{1}},
		MasternodesLen: 1,
		EpochSwitchBlockInfo: &types.BlockInfo{
			Hash:   hash,
			Number: new(big.Int).SetUint64(number),
			Round:  0,
		},
	})
}

// TestUpdateMasternodesUnusableGapSchedule pins the guard that separates a
// schedule designating no gap block from a height that is not the gap block.
// Both share one return statement otherwise, which reports a config defect as a
// timing mismatch on the UpdateM1 path. The guard returns before the snapshot is
// stored, so no database is needed and chain is unused on every case.
func TestUpdateMasternodesUnusableGapSchedule(t *testing.T) {
	tests := []struct {
		name   string
		config *params.XDPoSConfig
		number uint64
		want   []string
		// gapDefect marks the rows that must identify params.ErrUnusableGapSchedule:
		// a height that is merely not the gap block is a different defect, which is
		// exactly what this guard separates.
		gapDefect bool
		// unsetEpoch marks the one row that must identify params.ErrUnsetXDPoSEpoch
		// instead: an epoch the engine was never given leaves the schedule unknown
		// rather than unusable, and the two sentinels pick different hints.
		unsetEpoch bool
	}{
		{"zero gap", &params.XDPoSConfig{Epoch: 900, Gap: 0}, 1350, []string{"[UpdateMasternodes]", "XDPoS.Gap 0 designates no gap block inside XDPoS.Epoch 900", "number: 1350"}, true, false},
		{"gap equal to epoch", &params.XDPoSConfig{Epoch: 900, Gap: 900}, 1350, []string{"[UpdateMasternodes]", "XDPoS.Gap 900 designates no gap block of its own inside XDPoS.Epoch 900", "number: 1350"}, true, false},
		{"gap above epoch", &params.XDPoSConfig{Epoch: 900, Gap: 1200}, 1350, []string{"[UpdateMasternodes]", "XDPoS.Gap 1200 designates no gap block inside XDPoS.Epoch 900", "number: 1350"}, true, false},
		{"unset epoch", &params.XDPoSConfig{Epoch: 0, Gap: 0}, 1350, []string{"[UpdateMasternodes]", "XDPoS.Epoch is unset", "number: 1350", "gap: 0"}, false, true},
		{"epoch one leaves no usable gap", &params.XDPoSConfig{Epoch: 1, Gap: 0}, 1350, []string{"[UpdateMasternodes]", "XDPoS.Epoch 1 designates no gap block", "number: 1350"}, true, false},
		{"missing config", nil, 1350, []string{"[UpdateMasternodes]", "nil config", "number: 1350"}, false, false},
		{"usable schedule at a non gap height", &params.XDPoSConfig{Epoch: 900, Gap: 450}, 1000, []string{"[UpdateMasternodes]", "not gap block", "number: 1000", "epoch: 900", "gap: 450"}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := &XDPoS_v2{config: tt.config}
			header := &types.Header{Number: new(big.Int).SetUint64(tt.number)}

			err := x.UpdateMasternodes(nil, header, nil)
			switch {
			case tt.unsetEpoch:
				assertUnsetEpochInGapPath(t, err, tt.want)
			case tt.config == nil:
				assertMissingXDPoSConfig(t, err, tt.want)
			case tt.gapDefect:
				assertUnusableGapSchedule(t, err, tt.want)
			default:
				assertGuardError(t, err, tt.want)
			}
		})
	}
}

// TestVerifyQCUnusableGapSchedule pins the verifyQC guard. A round-0 QC without
// signatures reaches it: the cert threshold check only applies to rounds above
// zero and the signature loop has nothing to verify. A missing config is not a
// shape here: verifyQC reads the round-0 cert threshold from x.config.V2 before
// the gap lookup, so it fails earlier for a different reason.
func TestVerifyQCUnusableGapSchedule(t *testing.T) {
	blockHash := common.HexToHash("0x1")
	tests := []struct {
		name   string
		config *params.XDPoSConfig
		want   []string
		// unsetEpoch marks the row whose defect is the caller's, not the schedule's.
		unsetEpoch bool
	}{
		{"zero gap", gapScheduleConfig(900, 0), []string{"[verifyQC]", "XDPoS.Gap 0 designates no gap block inside XDPoS.Epoch 900", "number: 900"}, false},
		{"gap equal to epoch", gapScheduleConfig(900, 900), []string{"[verifyQC]", "XDPoS.Gap 900 designates no gap block of its own inside XDPoS.Epoch 900", "number: 900"}, false},
		{"gap above epoch", gapScheduleConfig(900, 1200), []string{"[verifyQC]", "XDPoS.Gap 1200 designates no gap block inside XDPoS.Epoch 900", "number: 900"}, false},
		{"unset epoch", gapScheduleConfig(0, 450), []string{"[verifyQC]", "XDPoS.Epoch is unset", "number: 900", "gap: 450"}, true},
		{"epoch one leaves no usable gap", gapScheduleConfig(1, 0), []string{"[verifyQC]", "XDPoS.Epoch 1 designates no gap block", "number: 900"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := gapScheduleEngine(tt.config)
			seedEpochSwitch(x, blockHash, 900)
			quorumCert := &types.QuorumCert{
				ProposedBlockInfo: &types.BlockInfo{Hash: blockHash, Number: big.NewInt(901), Round: 0},
			}

			err := x.verifyQC(nil, quorumCert, nil)
			if tt.unsetEpoch {
				assertUnsetEpochInGapPath(t, err, tt.want)
				return
			}
			assertUnusableGapSchedule(t, err, tt.want)
		})
	}
}
