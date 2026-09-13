package XDPoS

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

func TestAdaptorShouldShareDbWithV1Engine(t *testing.T) {
	database := rawdb.NewMemoryDatabase()
	config := params.TestXDPoSMockChainConfig
	engine, err := New(config, database)
	assert.NoError(t, err)

	assert := assert.New(t)
	assert.Equal(engine.EngineV1.GetDb(), engine.GetDb())
}

func TestNewRejectsMissingV2Config(t *testing.T) {
	database := rawdb.NewMemoryDatabase()
	config := params.TestnetChainConfig.Clone()
	config.XDPoS = config.XDPoS.Clone()
	config.XDPoS.V2 = nil

	engine, err := New(config, database)
	assert.Nil(t, engine)
	assert.ErrorIs(t, err, params.ErrMissingForkSwitch)
}

// TestNewRejectsMissingXDPoSConfig pins that a config with no XDPoS section is
// reported as such instead of as whatever the fork-order validation happens to
// find first: the bare config below lacks ChainID and every fork block, and the
// old ordering let the validation run first, so it failed as a missing fork
// switch. The other cases are shapes the validation either passes (a node that
// names another engine, or a built-in test network) or would judge as something
// else, and the missing section has to be the reported defect for all of them.
func TestNewRejectsMissingXDPoSConfig(t *testing.T) {
	tests := []struct {
		name   string
		config *params.ChainConfig
	}{
		{name: "bare config", config: &params.ChainConfig{}},
		{name: "config with a chain id", config: &params.ChainConfig{ChainID: big.NewInt(5151)}},
		{name: "config naming another engine", config: &params.ChainConfig{ChainID: big.NewInt(5151), Ethash: new(params.EthashConfig)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database := rawdb.NewMemoryDatabase()

			engine, err := New(tt.config, database)
			assert.Nil(t, engine)
			// The message is the sentinel's own text, so the rejection stays quotable
			// while cmd/utils.FormatChainConfigError can recognise it and append the
			// hint that names the constructor contract.
			assert.EqualError(t, err, "missing XDPoS config")
			assert.ErrorIs(t, err, params.ErrMissingXDPoSConfig)
		})
	}
}

// Replacing AllConfigs without the round-0 entry fails the "AllConfigs[0]"
// requirement before validation ever reaches the gap schedule, so this only
// pins the config-shape rejection, not a gap schedule.
func TestNewRejectsMissingAllConfigsZeroRound(t *testing.T) {
	database := rawdb.NewMemoryDatabase()
	config := params.TestnetChainConfig.Clone()
	config.XDPoS = config.XDPoS.Clone()
	config.XDPoS.V2 = config.XDPoS.V2.Clone()
	config.XDPoS.V2.CurrentConfig = config.XDPoS.V2.CurrentConfig.Clone()
	config.XDPoS.V2.AllConfigs = map[uint64]*params.V2Config{
		9: {SwitchRound: 9, MinePeriod: 2, TimeoutPeriod: 10},
	}

	engine, err := New(config, database)
	assert.Nil(t, engine)
	assert.ErrorIs(t, err, params.ErrMissingForkSwitch)
}

// TestNewRejectsUnusableGapSchedule pins the fallback where New fills the
// default epoch before re-running CheckConfigForkOrder. params cannot see that
// default when it validates a genesis, so an omitted epoch plus a gap that can
// never designate a gap block has to be refused here. A rejected config must not
// be left with the default epoch written into it, because the caller cannot tell
// the config it still owns from the one that was refused.
func TestNewRejectsUnusableGapSchedule(t *testing.T) {
	tests := []struct {
		name  string
		epoch uint64
		gap   uint64
		// defaultEpoch marks the rows whose epoch is unset, so the rejection is
		// judged against params.DefaultXDPoSEpoch and tagged as such. An epoch the
		// config writes out is judged against itself and must not carry the tag.
		defaultEpoch bool
	}{
		{name: "zero epoch and zero gap", epoch: 0, gap: 0, defaultEpoch: true},
		{name: "zero epoch and gap equal to the default epoch", epoch: 0, gap: 900, defaultEpoch: true},
		{name: "zero epoch and gap above the default epoch", epoch: 0, gap: 1200, defaultEpoch: true},
		{name: "gap equal to the epoch", epoch: 900, gap: 900},
		{name: "gap above the epoch", epoch: 900, gap: 1200},
		{name: "epoch one leaves no usable gap", epoch: 1, gap: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database := rawdb.NewMemoryDatabase()
			config := params.TestnetChainConfig.Clone()
			config.XDPoS = config.XDPoS.Clone()
			config.XDPoS.Epoch = tt.epoch
			config.XDPoS.Gap = tt.gap
			// Keep the switch epoch naming the epoch its block falls on, so the
			// schedule is refused by the gap rule rather than by the pairing rule
			// that is judged before it. An unset epoch is left as written; the
			// engine's own default keeps its pairing.
			if tt.epoch != 0 {
				config.XDPoS.V2.SwitchEpoch = config.XDPoS.V2.SwitchBlock.Uint64() / tt.epoch
			}

			engine, err := New(config, database)
			assert.Nil(t, engine)
			assert.ErrorIs(t, err, params.ErrUnusableGapSchedule)
			assert.Equal(t, tt.epoch, config.XDPoS.Epoch, "rejected config must keep its own epoch")
			if tt.defaultEpoch {
				assert.ErrorIs(t, err, params.ErrUnusableGapScheduleDefaultEpoch)
			} else {
				assert.NotErrorIs(t, err, params.ErrUnusableGapScheduleDefaultEpoch)
			}
		})
	}
}

// TestValidateFakerConfigNamesTheFakerRejection pins the exported helper that lets a
// caller judge a chain config - and name why the faker constructor would refuse it -
// before an engine is built.
func TestValidateFakerConfigNamesTheFakerRejection(t *testing.T) {
	rejected := params.TestnetChainConfig.Clone()
	rejected.XDPoS = rejected.XDPoS.Clone()
	rejected.XDPoS.Gap = 0

	err := ValidateFakerConfig(rejected)
	assert.ErrorIs(t, err, params.ErrUnusableGapSchedule)

	// An unset epoch is judged against the engine default, so a schedule that is
	// usable there still passes.
	usable := params.TestnetChainConfig.Clone()
	usable.XDPoS = usable.XDPoS.Clone()
	usable.XDPoS.Epoch = 0
	assert.NoError(t, ValidateFakerConfig(usable))

	assert.NoError(t, ValidateFakerConfig(nil))

	// A config without an XDPoS section has no engine to build, so the helper has to
	// name that missing section instead of answering "no error" for a config the
	// constructor refuses.
	engineLess := &params.ChainConfig{ChainID: big.NewInt(1), Ethash: &params.EthashConfig{}}
	assert.ErrorIs(t, ValidateFakerConfig(engineLess), params.ErrMissingXDPoSConfig)
}

// TestNewFakerWithErrorKeepsTheConstructionReason pins that a refused config and a
// failed engine build are told apart. Asking ValidateFakerConfig instead cannot
// produce a reason for a build failure at all, and would report a nil judgement next
// to a nil engine.
func TestNewFakerWithErrorKeepsTheConstructionReason(t *testing.T) {
	database := rawdb.NewMemoryDatabase()

	// A refused config: the error is the validation verdict, not a hidden nil.
	rejected := params.TestnetChainConfig.Clone()
	rejected.XDPoS = rejected.XDPoS.Clone()
	rejected.XDPoS.Gap = 0

	engine, err := NewFakerWithError(database, rejected)
	assert.Nil(t, engine)
	assert.ErrorIs(t, err, params.ErrUnusableGapSchedule)

	// A config the faker validation refuses and the engine constructor would too:
	// there is no XDPoS section to build an engine from. Both entry points report the
	// missing section, so the helper can name the reason instead of printing <nil>.
	engineLess := &params.ChainConfig{ChainID: big.NewInt(1), Ethash: &params.EthashConfig{}}
	assert.ErrorIs(t, ValidateFakerConfig(engineLess), params.ErrMissingXDPoSConfig)

	engine, err = NewFakerWithError(database, engineLess)
	assert.Nil(t, engine)
	assert.ErrorIs(t, err, params.ErrMissingXDPoSConfig)
	assert.NotErrorIs(t, err, params.ErrUnusableGapSchedule)
}

// TestConstructorsRefuseAConfigWithoutXDPoSBeforeBuildingV1 pins that a config
// with no XDPoS section never yields an engine whose EngineV1 is nil. Both
// constructors assign EngineV1 from engine_v1.New/NewFaker without checking the
// nil those report for such a config, so the config has to be refused before that
// line is reached: New and the faker path both reject it where the section is
// missing, with params.ErrMissingXDPoSConfig. The faker side is covered in detail by
// TestNewFakerWithErrorKeepsTheConstructionReason.
func TestConstructorsRefuseAConfigWithoutXDPoSBeforeBuildingV1(t *testing.T) {
	database := rawdb.NewMemoryDatabase()
	// The consensus-optional chain id is what keeps CheckConfigForkOrder from
	// demanding an XDPoS section here, so this is the shape that reaches the v2
	// guard with no engine_v1 section to build from.
	engineLess := &params.ChainConfig{
		ChainID: new(big.Int).SetUint64(params.ConsensusOptionalTestChainID),
		Ethash:  &params.EthashConfig{},
	}

	engine, err := New(engineLess, database)
	assert.Nil(t, engine)
	assert.ErrorIs(t, err, params.ErrMissingXDPoSConfig)

	engine, err = NewFakerWithError(database, engineLess)
	assert.Nil(t, engine)
	assert.ErrorIs(t, err, params.ErrMissingXDPoSConfig)
}

// TestNewAcceptsBoundaryGapSchedules pins both inclusive boundaries of the
// schedule New validates, plus the deferred-epoch default that keeps the middle
// of the range usable. The default is resolved onto the config the engine runs
// with, which is why a rejected one must not be rewritten before it is validated
// and why the caller's config keeps the state its source wrote.
func TestNewAcceptsBoundaryGapSchedules(t *testing.T) {
	tests := []struct {
		name      string
		epoch     uint64
		gap       uint64
		wantEpoch uint64
	}{
		{name: "smallest gap", epoch: 900, gap: 1, wantEpoch: 900},
		{name: "largest gap below epoch", epoch: 900, gap: 899, wantEpoch: 900},
		{name: "unset epoch falls back to the default", epoch: 0, gap: 450, wantEpoch: 900},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database := rawdb.NewMemoryDatabase()
			config := params.TestnetChainConfig.Clone()
			config.XDPoS = config.XDPoS.Clone()
			config.XDPoS.Epoch = tt.epoch
			config.XDPoS.Gap = tt.gap

			engine, err := New(config, database)
			assert.NoError(t, err)
			if engine == nil {
				t.Fatal("New refused a schedule the table accepts")
			}
			defer engine.Stop()

			resolved := engine.ChainConfig()
			if resolved == nil || resolved.XDPoS == nil {
				t.Fatal("the engine has to expose the config it resolved")
			}
			assert.Equal(t, tt.wantEpoch, resolved.XDPoS.Epoch)
			assert.Equal(t, tt.epoch, config.XDPoS.Epoch, "the constructor must not write into the caller's config")
		})
	}
}

// TestFakerConstructorResolvesTheDefaultEpoch pins that the faker constructor reaches
// the same verdict as New when a config omits the epoch: the default is resolved onto
// the config the engine runs with, and the caller's object keeps the state its
// source wrote. It used to validate with CheckConfigForkOrder alone and hand the
// config on untouched, which was the only way an engine could be built with
// Epoch == 0 and divide by zero later.
func TestFakerConstructorResolvesTheDefaultEpoch(t *testing.T) {
	config := params.TestnetChainConfig.Clone()
	config.XDPoS = config.XDPoS.Clone()
	config.XDPoS.Epoch = 0
	config.XDPoS.Gap = 450

	engine, err := NewFakerWithError(rawdb.NewMemoryDatabase(), config)
	if err != nil {
		t.Fatalf("the faker constructor rejected a schedule that is usable under the default epoch: %v", err)
	}
	defer engine.Stop()

	resolved := engine.ChainConfig()
	if resolved == nil || resolved.XDPoS == nil {
		t.Fatal("the engine has to expose the config it resolved")
	}
	assert.Equal(t, params.DefaultXDPoSEpoch, resolved.XDPoS.Epoch)
	assert.Equal(t, uint64(0), config.XDPoS.Epoch, "the constructor must not write into the caller's config")
}

// TestFakerConstructorRejectsUnusableGapSchedule is the counterpart: the faker path
// judges the schedule against the epoch it would fill in, so a gap that designates no
// gap block under that default is refused without rewriting the caller's config.
func TestFakerConstructorRejectsUnusableGapSchedule(t *testing.T) {
	tests := []struct {
		name string
		gap  uint64
	}{
		{name: "zero gap", gap: 0},
		{name: "gap equal to the default epoch", gap: params.DefaultXDPoSEpoch},
		{name: "gap above the default epoch", gap: params.DefaultXDPoSEpoch + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := params.TestnetChainConfig.Clone()
			config.XDPoS = config.XDPoS.Clone()
			config.XDPoS.Epoch = 0
			config.XDPoS.Gap = tt.gap

			engine, err := NewFakerWithError(rawdb.NewMemoryDatabase(), config)
			assert.Nil(t, engine)
			assert.ErrorIs(t, err, params.ErrUnusableGapSchedule)
			assert.Equal(t, uint64(0), config.XDPoS.Epoch, "rejected config must keep its own epoch")
		})
	}
}

// TestFakerConstructorFallsBackToACloneOfTheSharedConfig pins that the nil-config fallback
// does not hand out the package-level test config. NewFakerWithError resolves the
// schedule onto the config the engine runs with, and that global is shared with
// every fixture built from it, so resolving into it here would make unrelated tests
// depend on this constructor having run - and would let a caller that never passed a
// config mutate the object they all use.
func TestFakerConstructorFallsBackToACloneOfTheSharedConfig(t *testing.T) {
	engine, err := NewFakerWithError(rawdb.NewMemoryDatabase(), nil)
	assert.NoError(t, err)
	if engine == nil {
		t.Fatal("expected the nil-config fallback to build an engine")
	}
	defer engine.Stop()

	if engine.config == params.TestXDPoSMockChainConfig.XDPoS {
		t.Fatal("the fallback must not expose the shared XDPoS section")
	}
	if engine.config.V2 == params.TestXDPoSMockChainConfig.XDPoS.V2 {
		t.Fatal("the fallback must not share the V2 schedule with the package-level config")
	}
	// No field assertion here: the package-level epoch already is
	// params.DefaultXDPoSEpoch, so comparing it cannot tell a write-back from a
	// no-op. The pointer comparisons above are what pin the "no shared object"
	// contract.
}

func TestCacheNoneTIPSigningTxsSupportsRawReceiptsWithoutTxHash(t *testing.T) {
	database := rawdb.NewMemoryDatabase()
	config := params.TestXDPoSMockChainConfig
	engine, err := New(config, database)
	assert.NoError(t, err)

	signingTx := types.NewTransaction(
		0,
		common.BlockSignersBinary,
		big.NewInt(0),
		200000,
		big.NewInt(0),
		append(common.Hex2Bytes(common.HexSignMethod), make([]byte, 64)...),
	)
	normalTx := types.NewTransaction(
		1,
		common.Address{0x1},
		big.NewInt(0),
		21000,
		big.NewInt(0),
		nil,
	)
	receipts := []*types.Receipt{
		{Status: types.ReceiptStatusSuccessful},
		{Status: types.ReceiptStatusSuccessful},
	}

	cached := engine.CacheNoneTIPSigningTxs(&types.Header{Number: big.NewInt(1)}, []*types.Transaction{signingTx, normalTx}, receipts)

	assert.Len(t, cached, 1)
	assert.Equal(t, signingTx.Hash(), cached[0].Hash())
}

func TestCacheNoneTIPSigningTxsSkipsFailedSigningReceiptByIndex(t *testing.T) {
	database := rawdb.NewMemoryDatabase()
	config := params.TestXDPoSMockChainConfig
	engine, err := New(config, database)
	assert.NoError(t, err)

	signingTx := types.NewTransaction(
		0,
		common.BlockSignersBinary,
		big.NewInt(0),
		200000,
		big.NewInt(0),
		append(common.Hex2Bytes(common.HexSignMethod), make([]byte, 64)...),
	)
	receipts := []*types.Receipt{{Status: types.ReceiptStatusFailed}}

	cached := engine.CacheNoneTIPSigningTxs(&types.Header{Number: big.NewInt(1)}, []*types.Transaction{signingTx}, receipts)

	assert.Empty(t, cached)
}

func TestCacheNoneTIPSigningTxsWithRawReceiptRoundTrip(t *testing.T) {
	database := rawdb.NewMemoryDatabase()
	config := params.TestXDPoSMockChainConfig
	engine, err := New(config, database)
	assert.NoError(t, err)
	blockHash := common.HexToHash("0x1234")
	blockNumber := uint64(1)

	signingTx := types.NewTransaction(
		0,
		common.BlockSignersBinary,
		big.NewInt(0),
		200000,
		big.NewInt(0),
		append(common.Hex2Bytes(common.HexSignMethod), make([]byte, 64)...),
	)
	receipts := []*types.Receipt{{
		Status:            types.ReceiptStatusSuccessful,
		CumulativeGasUsed: 200000,
		TxHash:            signingTx.Hash(),
	}}

	rawdb.WriteReceipts(database, blockHash, blockNumber, receipts)
	rawReceipts := rawdb.ReadRawReceipts(database, blockHash, blockNumber)

	assert.Len(t, rawReceipts, 1)
	assert.Equal(t, common.Hash{}, rawReceipts[0].TxHash)

	cached := engine.CacheNoneTIPSigningTxs(&types.Header{Number: big.NewInt(int64(blockNumber))}, []*types.Transaction{signingTx}, rawReceipts)

	assert.Len(t, cached, 1)
	assert.Equal(t, signingTx.Hash(), cached[0].Hash())
}

// TestChainConfigExposesOnlyWhatTheConstructorsResolved pins the accessor's two
// nil answers. The chain openers guard on it - eth.New and utils.MakeChain keep
// the config they already hold when the engine exposes none - so an engine that
// never went through New or NewFakerWithError has to answer nil rather than a
// half-built config, and a nil engine has to answer nil rather than panic.
func TestChainConfigExposesOnlyWhatTheConstructorsResolved(t *testing.T) {
	// What a constructor resolved is what a built engine exposes, default epoch
	// included.
	engine, err := New(params.TestXDPoSMockChainConfig.Clone(), rawdb.NewMemoryDatabase())
	assert.NoError(t, err)
	assert.NotNil(t, engine.ChainConfig())
	assert.EqualValues(t, params.DefaultXDPoSEpoch, engine.ChainConfig().XDPoS.Epoch)

	// A zero-value engine carries no chain config, so the accessor reports none: the
	// openers rely on that nil to keep the config they resolved themselves.
	assert.Nil(t, (&XDPoS{}).ChainConfig())

	// The nil receiver is the other shape the openers' type assertion can produce.
	var nilEngine *XDPoS
	assert.Nil(t, nilEngine.ChainConfig())
}
