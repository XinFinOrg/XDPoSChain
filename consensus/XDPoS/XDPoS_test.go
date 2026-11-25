package XDPoS

import (
	"errors"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
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

func TestNewAllowsStartupValidatedV2ScheduleGaps(t *testing.T) {
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

// TestNewRejectsInvalidSchedule pins the schedule gate on the constructor: the
// four out-of-bound shapes are refused before an engine is built, via the
// CheckConfigForkOrder call the constructor already made.
func TestNewRejectsInvalidSchedule(t *testing.T) {
	for _, schedule := range []struct {
		name  string
		epoch uint64
		gap   uint64
	}{
		{name: "unset epoch", epoch: 0, gap: 450},
		{name: "zero gap", epoch: 900, gap: 0},
		{name: "gap equal to the epoch", epoch: 900, gap: 900},
		{name: "gap above the epoch", epoch: 900, gap: 1200},
	} {
		t.Run(schedule.name, func(t *testing.T) {
			config := params.TestXDPoSMockChainConfig.Clone()
			config.XDPoS.Epoch = schedule.epoch
			config.XDPoS.Gap = schedule.gap

			engine, err := New(config, rawdb.NewMemoryDatabase())
			if engine != nil {
				t.Fatalf("New() = %v, want no engine", engine)
			}
			if !errors.Is(err, params.ErrInvalidEpochGap) {
				t.Fatalf("New() error = %v, want ErrInvalidEpochGap", err)
			}
		})
	}
}

// TestNewDoesNotRepairUnsetEpoch pins the removal of the Epoch == 0 -> 900
// rewrite: the config is refused instead of being completed in place.
func TestNewDoesNotRepairUnsetEpoch(t *testing.T) {
	config := params.TestXDPoSMockChainConfig.Clone()
	config.XDPoS.Epoch = 0

	engine, err := New(config, rawdb.NewMemoryDatabase())
	if engine != nil || !errors.Is(err, params.ErrInvalidEpochGap) {
		t.Fatalf("New() = (%v, %v), want ErrInvalidEpochGap", engine, err)
	}
	if config.XDPoS.Epoch != 0 {
		t.Fatalf("New() rewrote XDPoS.Epoch to %d", config.XDPoS.Epoch)
	}
}

// TestNewFakerAcceptsUnvalidatedSchedule pins the declared unvalidated path: the
// faker builds an engine for a gap the startup gate would refuse instead of
// returning nil as it did while it validated the schedule.
func TestNewFakerAcceptsUnvalidatedSchedule(t *testing.T) {
	config := params.TestXDPoSMockChainConfig.Clone()
	config.XDPoS.Gap = config.XDPoS.Epoch + 300

	if engine := NewFaker(rawdb.NewMemoryDatabase(), config); engine == nil {
		t.Fatal("NewFaker() = nil for a schedule it does not validate")
	}
}

// TestVerifySealRejectsV2Block pins the v2 guard: a v2 header carries no
// recoverable seal for VerifySeal to check, so the adapter must report that
// instead of accepting whatever the remote-mining SubmitWork path hands it.
func TestVerifySealRejectsV2Block(t *testing.T) {
	engine, err := New(params.TestXDPoSMockChainConfig, rawdb.NewMemoryDatabase())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	// TestXDPoSMockChainConfig switches to v2 after block 900.
	for _, tc := range []struct {
		name   string
		header *types.Header
	}{
		{name: "unsigned", header: &types.Header{Number: big.NewInt(901)}},
		// A submitted header can carry bytes in Validator; every v2 header is
		// refused, not only the ones that happen to be unsigned.
		{name: "with validator bytes", header: &types.Header{Number: big.NewInt(901), Validator: make([]byte, 65)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := engine.VerifySeal(nil, tc.header); err == nil || !errors.Is(err, ErrUnsupportedV2Seal) {
				t.Fatalf("VerifySeal error = %v, want ErrUnsupportedV2Seal", err)
			}
		})
	}
}

// TestVerifySealStillDelegatesV1Headers pins the other side of the guard: a v1
// header still reaches engine_v1 instead of being refused at the adapter. Block
// zero is the one header engine_v1 answers without a chain (utils.ErrUnknownBlock).
func TestVerifySealStillDelegatesV1Headers(t *testing.T) {
	engine, err := New(params.TestXDPoSMockChainConfig, rawdb.NewMemoryDatabase())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = engine.VerifySeal(nil, &types.Header{Number: big.NewInt(0)})
	if err == nil || !errors.Is(err, utils.ErrUnknownBlock) {
		t.Fatalf("VerifySeal(v1 header) error = %v, want utils.ErrUnknownBlock from engine_v1", err)
	}
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
