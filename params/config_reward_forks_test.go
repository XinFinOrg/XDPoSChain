package params

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestChainConfigLegacyTIPFixedRewardKey checks that configs written before
// TIPUpgradeRewardBlock was renamed to TIPFixedRewardBlock still decode to the
// same activation block, and that they are written back under the new key.
func TestChainConfigLegacyTIPFixedRewardKey(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    *big.Int
		wantErr bool
	}{
		{name: "legacy key only", json: `{"chainId":51,"tipUpgradeRewardBlock":83600000}`, want: big.NewInt(83600000)},
		{name: "new key only", json: `{"chainId":51,"tipFixedRewardBlock":83600000}`, want: big.NewInt(83600000)},
		{name: "both keys agree", json: `{"chainId":51,"tipFixedRewardBlock":83600000,"tipUpgradeRewardBlock":83600000}`, want: big.NewInt(83600000)},
		{name: "both keys conflict", json: `{"chainId":51,"tipFixedRewardBlock":83600000,"tipUpgradeRewardBlock":1}`, wantErr: true},
		{name: "legacy key null", json: `{"chainId":51,"tipUpgradeRewardBlock":null}`, want: nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var config ChainConfig
			err := json.Unmarshal([]byte(test.json), &config)
			if test.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.True(t, configNumEqual(test.want, config.TIPFixedRewardBlock), "have %v want %v", config.TIPFixedRewardBlock, test.want)

			out, err := json.Marshal(&config)
			require.NoError(t, err)
			assert.NotContains(t, string(out), legacyTIPFixedRewardJSONKey)
			if test.want != nil {
				assert.Contains(t, string(out), `"tipFixedRewardBlock":83600000`)
			}
		})
	}
}

// TestChainConfigLegacyTIPFixedRewardKeyRoundTrip decodes a full built-in config
// stored under the legacy key, as an older node would have persisted it.
func TestChainConfigLegacyTIPFixedRewardKeyRoundTrip(t *testing.T) {
	data, err := json.Marshal(TestnetChainConfig)
	require.NoError(t, err)
	require.Contains(t, string(data), `"tipFixedRewardBlock"`)
	legacy := strings.Replace(string(data), `"tipFixedRewardBlock"`, `"`+legacyTIPFixedRewardJSONKey+`"`, 1)

	var config ChainConfig
	require.NoError(t, json.Unmarshal([]byte(legacy), &config))
	assert.Zero(t, TestnetChainConfig.TIPFixedRewardBlock.Cmp(config.TIPFixedRewardBlock))
	assert.True(t, TestnetChainConfig.Equal(&config))
}

// TestTIPProportionalRewardForkOrder checks that the proportional reward fork can
// be scheduled without TIPFixedReward, and that it is still ordered after every
// fork that precedes it when both are set.
func TestTIPProportionalRewardForkOrder(t *testing.T) {
	mainnet := XDCMainnetChainConfig.Clone()
	require.Nil(t, mainnet.TIPFixedRewardBlock)
	mainnet.TIPProportionalRewardBlock = big.NewInt(200000000)
	assert.NoError(t, mainnet.CheckConfigForkOrder(), "proportional reward must not require TIPFixedReward")

	testnet := TestnetChainConfig.Clone()
	testnet.TIPProportionalRewardBlock = big.NewInt(90000000)
	assert.NoError(t, testnet.CheckConfigForkOrder())

	testnet.TIPProportionalRewardBlock = new(big.Int).Sub(testnet.TIPFixedRewardBlock, big.NewInt(1))
	err := testnet.CheckConfigForkOrder()
	assert.ErrorIs(t, err, ErrWrongForkSwitchOrder)
}
