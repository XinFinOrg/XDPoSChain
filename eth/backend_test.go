package eth

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/eth/util"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// TestRewardInflation tests reward inflation.
func TestRewardInflation(t *testing.T) {
	for i := 0; i < 100; i++ {
		// the first 2 years
		chainReward := new(big.Int).Mul(new(big.Int).SetUint64(250), new(big.Int).SetUint64(params.Ether))
		chainReward = util.RewardInflation(nil, chainReward, uint64(i), 10)

		// 3rd year, 4th year, 5th year
		halfReward := new(big.Int).Mul(new(big.Int).SetUint64(125), new(big.Int).SetUint64(params.Ether))
		if 20 <= i && i < 50 && chainReward.Cmp(halfReward) != 0 {
			t.Error("Fail tor calculate reward inflation for 2 -> 5 years", "chainReward", chainReward)
		}

		// after 5 years
		quarterReward := new(big.Int).Mul(new(big.Int).SetUint64(62.5*1000), new(big.Int).SetUint64(params.Finney))
		if 50 <= i && chainReward.Cmp(quarterReward) != 0 {
			t.Error("Fail tor calculate reward inflation above 6 years", "chainReward", chainReward)
		}
	}
}

// TestRewardInflationUsesChainConfigTIPNoHalvingMNReward tests reward inflation uses chain config tip no halving mn reward.
func TestRewardInflationUsesChainConfigTIPNoHalvingMNReward(t *testing.T) {
	chainReward := new(big.Int).Mul(new(big.Int).SetUint64(250), new(big.Int).SetUint64(params.Ether))
	config := &params.ChainConfig{TIPNoHalvingMNRewardBlock: big.NewInt(20)}
	reward := util.RewardInflation(testChainReader{cfg: config}, chainReward, 20, 10)
	if reward.Cmp(new(big.Int).Mul(new(big.Int).SetUint64(250), new(big.Int).SetUint64(params.Ether))) != 0 {
		t.Fatalf("unexpected reward with no-halving fork: have %v", reward)
	}
}

type testChainReader struct {
	cfg *params.ChainConfig
}

// Config returns the chain config used by the test chain reader.
func (t testChainReader) Config() *params.ChainConfig { return t.cfg }

// CurrentHeader returns nil because this stub does not track headers.
func (testChainReader) CurrentHeader() *types.Header { return nil }

// GetHeader returns nil because this stub does not serve headers.
func (testChainReader) GetHeader(common.Hash, uint64) *types.Header { return nil }

// GetHeaderByNumber returns nil because this stub does not serve headers.
func (testChainReader) GetHeaderByNumber(uint64) *types.Header { return nil }

// GetHeaderByHash returns nil because this stub does not serve headers.
func (testChainReader) GetHeaderByHash(common.Hash) *types.Header { return nil }

// GetBlock returns nil because this stub does not serve blocks.
func (testChainReader) GetBlock(common.Hash, uint64) *types.Block { return nil }

// TestSetupGenesisBlockResolvesMissingV2ConfigInMemory tests setup genesis block resolves missing v 2 config in memory.
func TestSetupGenesisBlockResolvesMissingV2ConfigInMemory(t *testing.T) {
	db := rawdb.NewMemoryDatabase()

	genesis := core.DefaultTestnetGenesisBlock().MustCommit(db)
	rawCfg, err := rawdb.ReadChainConfigJSON(db, genesis.Hash())
	if err != nil {
		t.Fatalf("failed to read raw chain config: %v", err)
	}
	updatedRawCfg, err := removeXDPoSV2FromRawConfig(rawCfg)
	if err != nil {
		t.Fatalf("failed to remove XDPoS.v2 from raw chain config: %v", err)
	}
	if err := db.Put(testChainConfigKey(genesis.Hash()), updatedRawCfg); err != nil {
		t.Fatalf("failed to write modified raw chain config: %v", err)
	}

	loadedCfg, _, err := core.LoadChainConfig(db, nil)
	if err != nil {
		t.Fatalf("LoadChainConfig failed: %v", err)
	}
	if loadedCfg.XDPoS == nil {
		t.Fatal("expected XDPoS config in loaded chain config")
	}

	persistedBefore, err := rawdb.ReadChainConfig(db, params.TestnetGenesisHash)
	if err != nil {
		t.Fatalf("failed to read persisted chain config: %v", err)
	}
	if persistedBefore == nil || persistedBefore.XDPoS == nil {
		t.Fatalf("expected persisted legacy chain config, have %v", persistedBefore)
	}
	if persistedBefore.XDPoS.V2 != nil {
		t.Fatal("expected persisted legacy chain config to keep nil XDPoS.V2 before setup")
	}

	finalCfg, _, _, err := core.SetupGenesisBlock(db, core.DefaultTestnetGenesisBlock())
	if err != nil {
		t.Fatalf("SetupGenesisBlock failed: %v", err)
	}
	if finalCfg.XDPoS == nil || finalCfg.XDPoS.V2 == nil {
		t.Fatal("expected SetupGenesisBlock to return a config with XDPoS.V2")
	}
	if finalCfg.XDPoS.V2.SwitchBlock.Cmp(params.TestnetChainConfig.XDPoS.V2.SwitchBlock) != 0 {
		t.Fatalf("unexpected switch block after setup: have %v want %v", finalCfg.XDPoS.V2.SwitchBlock, params.TestnetChainConfig.XDPoS.V2.SwitchBlock)
	}

	persistedAfter, err := rawdb.ReadChainConfig(db, params.TestnetGenesisHash)
	if err != nil {
		t.Fatalf("failed to read persisted chain config after setup: %v", err)
	}
	if persistedAfter == nil || persistedAfter.XDPoS == nil {
		t.Fatalf("expected persisted chain config with XDPoS, have %v", persistedAfter)
	}
	if persistedAfter.XDPoS.V2 != nil {
		t.Fatal("expected SetupGenesisBlock to leave persisted legacy V2 config unchanged")
	}
}

// TestLoadChainConfigResolvesMissingV2ConfigInMemory tests load chain config resolves missing v 2 config in memory.
func TestLoadChainConfigResolvesMissingV2ConfigInMemory(t *testing.T) {
	db := rawdb.NewMemoryDatabase()

	genesis := core.DefaultTestnetGenesisBlock().MustCommit(db)
	rawCfg, err := rawdb.ReadChainConfigJSON(db, genesis.Hash())
	if err != nil {
		t.Fatalf("failed to read raw chain config: %v", err)
	}
	updatedRawCfg, err := removeXDPoSV2FromRawConfig(rawCfg)
	if err != nil {
		t.Fatalf("failed to remove XDPoS.v2 from raw chain config: %v", err)
	}
	if err := db.Put(testChainConfigKey(genesis.Hash()), updatedRawCfg); err != nil {
		t.Fatalf("failed to write modified raw chain config: %v", err)
	}

	loadedCfg, loadedHash, err := core.LoadChainConfig(db, nil)
	if err != nil {
		t.Fatalf("LoadChainConfig failed: %v", err)
	}
	if loadedHash != genesis.Hash() {
		t.Fatalf("unexpected genesis hash: have %v want %v", loadedHash, genesis.Hash())
	}
	if loadedCfg == nil || loadedCfg.XDPoS == nil || loadedCfg.XDPoS.V2 == nil {
		t.Fatal("expected LoadChainConfig to return a config with XDPoS.V2")
	}
	if loadedCfg.XDPoS.V2.SwitchBlock.Cmp(params.TestnetChainConfig.XDPoS.V2.SwitchBlock) != 0 {
		t.Fatalf("unexpected switch block after load: have %v want %v", loadedCfg.XDPoS.V2.SwitchBlock, params.TestnetChainConfig.XDPoS.V2.SwitchBlock)
	}

	persistedCfg, err := rawdb.ReadChainConfig(db, genesis.Hash())
	if err != nil {
		t.Fatalf("failed to read persisted chain config after load: %v", err)
	}
	if persistedCfg == nil || persistedCfg.XDPoS == nil {
		t.Fatalf("expected persisted legacy chain config, have %v", persistedCfg)
	}
	if persistedCfg.XDPoS.V2 != nil {
		t.Fatal("expected LoadChainConfig to leave persisted legacy chain config unchanged")
	}
}

// TestSetupGenesisBlockIsIdempotentForTestnet tests setup genesis block is idempotent for testnet.
func TestSetupGenesisBlockIsIdempotentForTestnet(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := core.DefaultTestnetGenesisBlock()

	cfg1, hash1, _, err := core.SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatalf("first SetupGenesisBlock failed: %v", err)
	}
	cfg2, hash2, _, err := core.SetupGenesisBlock(db, genesis)
	if err != nil {
		t.Fatalf("second SetupGenesisBlock failed: %v", err)
	}
	if hash1 != hash2 {
		t.Fatalf("genesis hash changed across SetupGenesisBlock calls: first %v second %v", hash1, hash2)
	}
	if cfg1.XDPoS == nil || cfg2.XDPoS == nil || cfg1.XDPoS.V2 == nil || cfg2.XDPoS.V2 == nil {
		t.Fatal("expected both returned configs to include XDPoS.V2")
	}
	if cfg1.XDPoS.V2.SwitchBlock.Cmp(cfg2.XDPoS.V2.SwitchBlock) != 0 {
		t.Fatalf("switch block changed across SetupGenesisBlock calls: first %v second %v", cfg1.XDPoS.V2.SwitchBlock, cfg2.XDPoS.V2.SwitchBlock)
	}
}

// removeXDPoSV2FromRawConfig removes the v2 section from raw XDPoS config JSON
// for restart-compatibility tests.
func removeXDPoSV2FromRawConfig(raw []byte) ([]byte, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	var xdpos map[string]json.RawMessage
	if err := json.Unmarshal(root["XDPoS"], &xdpos); err != nil {
		return nil, err
	}
	delete(xdpos, "v2")
	updatedXDPoS, err := json.Marshal(xdpos)
	if err != nil {
		return nil, err
	}
	root["XDPoS"] = updatedXDPoS
	return json.Marshal(root)
}

// testChainConfigKey returns the rawdb key used to store a chain-config blob.
func testChainConfigKey(hash common.Hash) []byte {
	return append([]byte("ethereum-config-"), hash.Bytes()...)
}
