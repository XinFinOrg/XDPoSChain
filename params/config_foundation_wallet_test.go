package params

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testOldFoundationWallet = common.HexToAddress("0x1111111111111111111111111111111111111111")
	testNewFoundationWallet = common.HexToAddress("0x2222222222222222222222222222222222222222")
)

// foundationRotationConfig returns a mainnet copy that rotates the foundation
// wallet at block forkBlock.
func foundationRotationConfig(forkBlock int64) *ChainConfig {
	cfg := XDCMainnetChainConfig.Clone()
	cfg.TIPFoundationWalletBlock = big.NewInt(forkBlock)
	cfg.XDPoS.NewFoundationWalletAddr = testNewFoundationWallet
	return cfg
}

func TestFoundationWalletAddrAt(t *testing.T) {
	cfg := foundationRotationConfig(900_000)
	old := cfg.XDPoS.FoundationWalletAddr

	assert.Equal(t, old, cfg.FoundationWalletAddrAt(big.NewInt(899_100)))
	assert.Equal(t, old, cfg.FoundationWalletAddrAt(big.NewInt(899_999)))
	assert.Equal(t, testNewFoundationWallet, cfg.FoundationWalletAddrAt(big.NewInt(900_000)))
	assert.Equal(t, testNewFoundationWallet, cfg.FoundationWalletAddrAt(big.NewInt(900_900)))
	assert.Equal(t, old, cfg.FoundationWalletAddrAt(nil))

	assert.False(t, cfg.IsTIPFoundationWallet(big.NewInt(899_999)))
	assert.True(t, cfg.IsTIPFoundationWallet(big.NewInt(900_000)))
	assert.Contains(t, cfg.ActiveForks(big.NewInt(900_000)), "TIPFoundationWallet")
	assert.NotContains(t, cfg.ActiveForks(big.NewInt(899_999)), "TIPFoundationWallet")
}

func TestFoundationWalletAddrAtWithoutFork(t *testing.T) {
	cfg := XDCMainnetChainConfig.Clone()
	cfg.XDPoS.NewFoundationWalletAddr = testNewFoundationWallet // set but never scheduled
	assert.Equal(t, cfg.XDPoS.FoundationWalletAddr, cfg.FoundationWalletAddrAt(big.NewInt(1<<62)))

	var nilCfg *ChainConfig
	assert.Equal(t, common.Address{}, nilCfg.FoundationWalletAddrAt(big.NewInt(1)))
	assert.Equal(t, common.Address{}, (&ChainConfig{}).FoundationWalletAddrAt(big.NewInt(1)))
}

func TestBuiltInNetworksKeepFoundationWallet(t *testing.T) {
	for name, cfg := range map[string]*ChainConfig{
		"mainnet": XDCMainnetChainConfig,
		"testnet": TestnetChainConfig,
		"devnet":  DevnetChainConfig,
	} {
		t.Run(name, func(t *testing.T) {
			assert.Nil(t, cfg.TIPFoundationWalletBlock, "schedule the rotation deliberately, not by default")
			assert.Equal(t, cfg.XDPoS.FoundationWalletAddr, cfg.FoundationWalletAddrAt(big.NewInt(1<<62)))
		})
	}
}

func TestFoundationWalletForkValidation(t *testing.T) {
	require.NoError(t, foundationRotationConfig(200_000_100).CheckConfigForkOrder())

	missing := foundationRotationConfig(200_000_100)
	missing.XDPoS.NewFoundationWalletAddr = common.Address{}
	err := missing.CheckConfigForkOrder()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMissingForkSwitch)
	assert.Contains(t, err.Error(), "XDPoS.NewFoundationWalletAddr")

	same := foundationRotationConfig(200_000_100)
	same.XDPoS.NewFoundationWalletAddr = same.XDPoS.FoundationWalletAddr
	err = same.CheckConfigForkOrder()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "equals XDPoS.FoundationWalletAddr")
}

// TestFoundationWalletForkFollowsProportionalReward keeps the rotation out of
// the linear fork order, so it may activate before a later fork such as
// TIPEpochHalving. When TIPProportionalRewardBlock is set, the rotation must
// follow that block.
func TestFoundationWalletForkFollowsProportionalReward(t *testing.T) {
	cfg := foundationRotationConfig(120_000_000)
	cfg.TIPEpochHalvingBlock = big.NewInt(1_000_000_000)
	require.NoError(t, cfg.CheckConfigForkOrder())

	cfg.TIPProportionalRewardBlock = big.NewInt(120_000_000)
	require.NoError(t, cfg.CheckConfigForkOrder())

	cfg.TIPProportionalRewardBlock = big.NewInt(120_000_001)
	err := cfg.CheckConfigForkOrder()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrWrongForkSwitchOrder)

	ForEachChainConfigForkOrderBlock(cfg, func(name string, _ *big.Int, _ bool) {
		assert.NotEqual(t, "TIPFoundationWalletBlock", name)
	})
}

func TestFoundationWalletForkCompatibility(t *testing.T) {
	stored := XDCMainnetChainConfig.Clone()
	stored.XDPoS.FoundationWalletAddr = testOldFoundationWallet

	// Scheduling the rotation ahead of the head is a plain upgrade.
	scheduled := stored.Clone()
	scheduled.TIPFoundationWalletBlock = big.NewInt(2_000)
	scheduled.XDPoS.NewFoundationWalletAddr = testNewFoundationWallet
	assert.Nil(t, stored.CheckCompatible(scheduled, 1_999))
	// Scheduling it at or below the head rewrites paid rewards.
	err := stored.CheckCompatible(scheduled, 2_000)
	require.NotNil(t, err)
	assert.Equal(t, uint64(1_999), err.RewindTo)

	// Before activation the new address can still be corrected.
	corrected := scheduled.Clone()
	corrected.XDPoS.NewFoundationWalletAddr = common.HexToAddress("0x3333333333333333333333333333333333333333")
	assert.Nil(t, scheduled.CheckCompatible(corrected, 1_999))
	// After activation it cannot.
	err = scheduled.CheckCompatible(corrected, 2_000)
	require.NotNil(t, err)
	assert.Equal(t, "XDPoS.NewFoundationWalletAddr", err.What)
	assert.Equal(t, uint64(1_999), err.RewindTo)

	// Moving an active fork block is rejected too.
	moved := scheduled.Clone()
	moved.TIPFoundationWalletBlock = big.NewInt(2_900)
	assert.Nil(t, scheduled.CheckCompatible(moved, 1_999))
	assert.NotNil(t, scheduled.CheckCompatible(moved, 2_000))

	// The original address stays fixed, with or without the rotation.
	changedOld := scheduled.Clone()
	changedOld.XDPoS.FoundationWalletAddr = testNewFoundationWallet
	assert.NotNil(t, scheduled.CheckCompatible(changedOld, 0))
}

func TestFoundationWalletJSON(t *testing.T) {
	cfg := foundationRotationConfig(200_000_100)
	data, err := json.Marshal(cfg)
	require.NoError(t, err)

	var decoded ChainConfig
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, big.NewInt(200_000_100), decoded.TIPFoundationWalletBlock)
	assert.Equal(t, testNewFoundationWallet, decoded.XDPoS.NewFoundationWalletAddr)
	assert.Equal(t, cfg.XDPoS.FoundationWalletAddr, decoded.XDPoS.FoundationWalletAddr)

	// Configs without the rotation don't gain the keys.
	plain, err := json.Marshal(XDCMainnetChainConfig)
	require.NoError(t, err)
	assert.NotContains(t, string(plain), "tipFoundationWalletBlock")
	assert.NotContains(t, string(plain), "newFoundationWalletAddr")
}

// TestFoundationWalletBackfill covers a node upgrading with a chain config that
// was stored before the rotation existed: both fields come from the built-in
// config, and an explicit stored value wins.
func TestFoundationWalletBackfill(t *testing.T) {
	src := foundationRotationConfig(200_000_100)

	legacy, err := json.Marshal(XDCMainnetChainConfig)
	require.NoError(t, err)
	var stored ChainConfig
	require.NoError(t, json.Unmarshal(legacy, &stored))

	filled := stored.BackfillMissingFieldsFrom(src)
	assert.Equal(t, big.NewInt(200_000_100), filled.TIPFoundationWalletBlock)
	assert.Equal(t, testNewFoundationWallet, filled.XDPoS.NewFoundationWalletAddr)

	explicit := src.Clone()
	explicit.XDPoS.NewFoundationWalletAddr = common.HexToAddress("0x3333333333333333333333333333333333333333")
	data, err := json.Marshal(explicit)
	require.NoError(t, err)
	var storedExplicit ChainConfig
	require.NoError(t, json.Unmarshal(data, &storedExplicit))
	assert.Equal(t, explicit.XDPoS.NewFoundationWalletAddr, storedExplicit.BackfillMissingFieldsFrom(src).XDPoS.NewFoundationWalletAddr)
}
