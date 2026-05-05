package eth

import (
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/eth/util"
	"github.com/XinFinOrg/XDPoSChain/params"
)

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

func (t testChainReader) Config() *params.ChainConfig { return t.cfg }

func (testChainReader) CurrentHeader() *types.Header { return nil }

func (testChainReader) GetHeader(common.Hash, uint64) *types.Header { return nil }

func (testChainReader) GetHeaderByNumber(uint64) *types.Header { return nil }

func (testChainReader) GetHeaderByHash(common.Hash) *types.Header { return nil }

func (testChainReader) GetBlock(common.Hash, uint64) *types.Block { return nil }

func TestSetupGenesisBlockResolvesMissingV2ConfigInMemory(t *testing.T) {
	db := rawdb.NewMemoryDatabase()

	legacyGenesis := legacyTestnetGenesisWithoutV2()
	legacyGenesis.MustCommit(db)

	loadedCfg, _, err := core.LoadChainConfig(db, core.DefaultTestnetGenesisBlock())
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
	if persistedAfter.XDPoS.V2 == nil {
		t.Fatal("expected SetupGenesisBlock to persist in-memory V2 repair")
	}
}

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

func legacyTestnetGenesisWithoutV2() *core.Genesis {
	legacyGenesis := *core.DefaultTestnetGenesisBlock()
	legacyChainConfig := *params.TestnetChainConfig
	legacyXDPoS := *params.TestnetChainConfig.XDPoS
	legacyXDPoS.V2 = nil
	legacyChainConfig.XDPoS = &legacyXDPoS
	legacyGenesis.Config = &legacyChainConfig
	return &legacyGenesis
}
