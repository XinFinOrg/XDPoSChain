package core

import (
	"bytes"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// These tests pin the upgrade path from v2.7.0 to this version for mainnet and
// for releasenet (the 108-devnet rehearsal chain, which is the built-in devnet
// on this branch). Rerun them whenever a built-in chain config changes.
//
// Fixtures:
//   - v2.7.0_mainnet_chainconfig.json is the chain-config blob a v2.7.0 mainnet
//     node keeps in its database (json.Marshal of params.XDCMainnetChainConfig
//     at tag v2.7.0, rewritten on every start).
//   - xinfin_node_mainnet_genesis.json is mainnet/genesis.json from
//     XinFinOrg/XinFin-Node (bbdfb47), which operators pass to `XDC init`.
//   - v2.7.0_releasenet_chainconfig.json is the blob demo-v2.7.0-releasenet
//     writes when it initialises releasenet_genesis.json. Its hash is not
//     built in on v2.7.0, so later starts keep it unchanged.
//   - releasenet_genesis.json is 108-devnet/kube/files/genesis.json from
//     XinFinOrg/k8-devnet (32ecc8f).
type v270UpgradeNetwork struct {
	name         string
	hash         common.Hash
	builtin      *params.ChainConfig
	genesis      func() *Genesis
	storedConfig string
	genesisFile  string
	forks        map[string]*big.Int // fork schedule v2.7.0 ran with
	upgradeHead  uint64              // head expected when nodes upgrade
	upgradeRound uint64              // new round configs must switch after it
}

var v270UpgradeNetworks = []v270UpgradeNetwork{
	{
		name:         "mainnet",
		hash:         params.MainnetGenesisHash,
		builtin:      params.XDCMainnetChainConfig,
		genesis:      DefaultGenesisBlock,
		storedConfig: "v2.7.0_mainnet_chainconfig.json",
		genesisFile:  "xinfin_node_mainnet_genesis.json",
		// MainnetConstant plus XDCMainnetChainConfig at tag v2.7.0. Petersburg
		// and Istanbul were active from TIPXDCXCancellationFee. Constantinople
		// was nil in v2.7.0 but is inert where Petersburg activates too.
		forks: map[string]*big.Int{
			"HomesteadBlock":              big.NewInt(1),
			"EIP150Block":                 big.NewInt(2),
			"EIP155Block":                 big.NewInt(3),
			"EIP158Block":                 big.NewInt(3),
			"ByzantiumBlock":              big.NewInt(4),
			"ConstantinopleBlock":         big.NewInt(38383838),
			"PetersburgBlock":             big.NewInt(38383838),
			"IstanbulBlock":               big.NewInt(38383838),
			"BerlinBlock":                 big.NewInt(76321000),
			"LondonBlock":                 big.NewInt(76321000),
			"MergeBlock":                  big.NewInt(76321000),
			"ShanghaiBlock":               big.NewInt(76321000),
			"EIP1559Block":                big.NewInt(98800200),
			"CancunBlock":                 big.NewInt(98802000),
			"TIP2019Block":                big.NewInt(1),
			"TIPSigningBlock":             big.NewInt(3000000),
			"TIPRandomizeBlock":           big.NewInt(3464000),
			"TIPIncreaseMasternodesBlock": big.NewInt(5000000),
			"DenylistBlock":               big.NewInt(38383838),
			"TIPNoHalvingMNRewardBlock":   big.NewInt(38383838),
			"TIPXDCXBlock":                big.NewInt(38383838),
			"TIPXDCXLendingBlock":         big.NewInt(38383838),
			"TIPXDCXCancellationFeeBlock": big.NewInt(38383838),
			"TIPTRC21FeeBlock":            big.NewInt(38383838),
			"Gas50xBlock":                 big.NewInt(80370000),
			"TIPXDCXMinerDisableBlock":    big.NewInt(80370000),
			"TIPXDCXReceiverDisableBlock": big.NewInt(80370900),
		},
		// Taken from mainnet on 2026-11-04 (block 109048234, round
		// 28996283); bump to the head expected at release time.
		upgradeHead:  109_000_000,
		upgradeRound: 28_900_000,
	},
	{
		name:         "releasenet",
		hash:         params.DevnetGenesisHash,
		builtin:      params.DevnetChainConfig,
		genesis:      DefaultDevnetGenesisBlock,
		storedConfig: "v2.7.0_releasenet_chainconfig.json",
		genesisFile:  "releasenet_genesis.json",
		// The genesis file's early forks plus DevnetConstant on
		// demo-v2.7.0-releasenet (v2.7.0 with tipTRC21Fee at 0).
		forks: map[string]*big.Int{
			"HomesteadBlock":              big.NewInt(0),
			"EIP150Block":                 big.NewInt(0),
			"EIP155Block":                 big.NewInt(0),
			"EIP158Block":                 big.NewInt(0),
			"ByzantiumBlock":              big.NewInt(0),
			"ConstantinopleBlock":         big.NewInt(0),
			"PetersburgBlock":             big.NewInt(0),
			"IstanbulBlock":               big.NewInt(0),
			"BerlinBlock":                 big.NewInt(0),
			"LondonBlock":                 big.NewInt(0),
			"MergeBlock":                  big.NewInt(0),
			"ShanghaiBlock":               big.NewInt(0),
			"EIP1559Block":                big.NewInt(32400),
			"CancunBlock":                 big.NewInt(43200),
			"TIP2019Block":                big.NewInt(0),
			"TIPSigningBlock":             big.NewInt(0),
			"TIPRandomizeBlock":           big.NewInt(0),
			"TIPIncreaseMasternodesBlock": big.NewInt(0),
			"DenylistBlock":               big.NewInt(0),
			"TIPNoHalvingMNRewardBlock":   big.NewInt(0),
			"TIPXDCXBlock":                big.NewInt(0),
			"TIPXDCXLendingBlock":         big.NewInt(0),
			"TIPXDCXCancellationFeeBlock": big.NewInt(0),
			"TIPTRC21FeeBlock":            big.NewInt(0),
			"Gas50xBlock":                 big.NewInt(21600),
			"TIPXDCXMinerDisableBlock":    big.NewInt(0),
			"TIPXDCXReceiverDisableBlock": big.NewInt(0),
		},
		// Nodes upgrade after Cancun (43200); this is a late point in that
		// window, with rounds ahead of blocks from timeouts.
		upgradeHead:  60_000,
		upgradeRound: 65_000,
	},
}

func readV270Testdata(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("failed to read %s: %v", name, err)
	}
	return raw
}

// newV270DB builds a database the way v2.7.0 leaves it: the genesis, the
// v2.7.0 chain-config blob and a head at headNumber.
func newV270DB(t *testing.T, n v270UpgradeNetwork, headNumber, headRound uint64) (ethdb.Database, []byte) {
	t.Helper()
	db := rawdb.NewMemoryDatabase()
	genesisBlock := n.genesis().MustCommit(db)
	if genesisBlock.Hash() != n.hash {
		t.Fatalf("unexpected genesis hash: %s", genesisBlock.Hash().Hex())
	}
	rawCfg := readV270Testdata(t, n.storedConfig)
	if err := db.Put(testConfigKey(n.hash), rawCfg); err != nil {
		t.Fatalf("failed to write v2.7.0 chain config: %v", err)
	}
	if headNumber == 0 {
		return db, rawCfg
	}
	var extra []byte
	if headNumber > n.builtin.XDPoS.V2.SwitchBlock.Uint64() {
		fields := types.ExtraFields_v2{
			Round: types.Round(headRound),
			QuorumCert: &types.QuorumCert{
				ProposedBlockInfo: &types.BlockInfo{Round: types.Round(headRound - 1), Number: new(big.Int).SetUint64(headNumber - 1)},
			},
		}
		var err error
		if extra, err = fields.EncodeToBytes(); err != nil {
			t.Fatalf("failed to encode v2 extra: %v", err)
		}
	}
	head := &types.Header{
		Number:     new(big.Int).SetUint64(headNumber),
		ParentHash: common.Hash{1},
		Difficulty: big.NewInt(1),
		Extra:      extra,
	}
	rawdb.WriteHeader(db, head)
	rawdb.WriteCanonicalHash(db, head.Hash(), headNumber)
	rawdb.WriteHeadHeaderHash(db, head.Hash())
	rawdb.WriteHeadBlockHash(db, head.Hash())
	return db, rawCfg
}

// TestV270UpgradeStoredConfig tests that a node upgraded from v2.7.0 starts
// with the bundled config, without a compatibility error, and leaves the
// stored v2.7.0 config untouched so it can still roll back.
func TestV270UpgradeStoredConfig(t *testing.T) {
	for _, n := range v270UpgradeNetworks {
		t.Run(n.name, func(t *testing.T) {
			heads := []struct {
				name          string
				number, round uint64
			}{
				{"genesis", 0, 0},
				{"pre-v2", 1, 0},
				{"upgrade-head", n.upgradeHead, n.upgradeRound},
			}
			for _, head := range heads {
				// A nil genesis is a start without --networkid; a built-in
				// network id (--networkid 50 in XinFin-Node) provides the
				// bundled genesis.
				for _, provided := range []bool{false, true} {
					db, rawCfg := newV270DB(t, n, head.number, head.round)
					var genesis *Genesis
					if provided {
						genesis = n.genesis()
					}
					cfg, hash, compatErr, err := SetupGenesisBlock(db, genesis)
					if err != nil {
						t.Fatalf("%s/provided=%v: unexpected error: %v", head.name, provided, err)
					}
					if compatErr != nil {
						t.Fatalf("%s/provided=%v: unexpected compatibility error: %v", head.name, provided, compatErr)
					}
					if hash != n.hash {
						t.Fatalf("%s/provided=%v: unexpected hash: %s", head.name, provided, hash.Hex())
					}
					if !chainConfigSemanticallyEqual(cfg, n.builtin) {
						t.Fatalf("%s/provided=%v: resolved config differs from bundled config", head.name, provided)
					}
					stored, err := db.Get(testConfigKey(n.hash))
					if err != nil {
						t.Fatalf("%s/provided=%v: failed to read stored config: %v", head.name, provided, err)
					}
					if !bytes.Equal(stored, rawCfg) {
						t.Fatalf("%s/provided=%v: stored v2.7.0 config was rewritten:\n%s", head.name, provided, stored)
					}
					marker, err := rawdb.ReadChainConfigOverride(db, n.hash)
					if err != nil || marker {
						t.Fatalf("%s/provided=%v: unexpected override marker: %v err=%v", head.name, provided, marker, err)
					}
				}
			}
		})
	}
}

// TestV270UpgradeFreshInit tests that a fresh node initialised from the
// operators' genesis file resolves to the bundled config and restarts cleanly.
func TestV270UpgradeFreshInit(t *testing.T) {
	for _, n := range v270UpgradeNetworks {
		t.Run(n.name, func(t *testing.T) {
			genesis := new(Genesis)
			if err := json.Unmarshal(readV270Testdata(t, n.genesisFile), genesis); err != nil {
				t.Fatalf("failed to decode genesis: %v", err)
			}
			db := rawdb.NewMemoryDatabase()
			cfg, hash, _, err := SetupGenesisBlock(db, genesis)
			if err != nil {
				t.Fatalf("init failed: %v", err)
			}
			if hash != n.hash {
				t.Fatalf("unexpected hash: %s", hash.Hex())
			}
			if !chainConfigSemanticallyEqual(cfg, n.builtin) {
				t.Fatal("initialised config differs from bundled config")
			}
			for _, provided := range []*Genesis{nil, n.genesis()} {
				cfg, _, compatErr, err := SetupGenesisBlock(db, provided)
				if err != nil || compatErr != nil {
					t.Fatalf("restart (provided=%v) failed: err=%v compat=%v", provided != nil, err, compatErr)
				}
				if !chainConfigSemanticallyEqual(cfg, n.builtin) {
					t.Fatalf("restart (provided=%v): config differs from bundled config", provided != nil)
				}
			}
		})
	}
}

// TestV270UpgradeForkSchedule tests that the bundled config keeps every fork
// v2.7.0 activated at the same block, and schedules any other fork after the
// upgrade head. The startup path backfills forks missing from the stored
// v2.7.0 config, so a fork scheduled at or below the head would not surface
// as a compatibility error; this test is the guard for that.
func TestV270UpgradeForkSchedule(t *testing.T) {
	for _, n := range v270UpgradeNetworks {
		t.Run(n.name, func(t *testing.T) {
			head := new(big.Int).SetUint64(n.upgradeHead)
			params.ForEachChainConfigForkBlock(n.builtin, func(name string, value *big.Int) {
				if want, ok := n.forks[name]; ok {
					if value == nil || value.Cmp(want) != 0 {
						t.Errorf("%s: have %v, want %v (as activated by v2.7.0)", name, value, want)
					}
					return
				}
				if value != nil && value.Cmp(head) <= 0 {
					t.Errorf("%s: scheduled at %v, at or below upgrade head %v that v2.7.0 nodes ran without it", name, value, head)
				}
			})
		})
	}
}

// TestV270UpgradeXDPoSConfig tests that the bundled XDPoS config keeps the
// v2.7.0 settings and V2 round configs, and that any new round config switches
// after the upgrade round.
func TestV270UpgradeXDPoSConfig(t *testing.T) {
	for _, n := range v270UpgradeNetworks {
		t.Run(n.name, func(t *testing.T) {
			old := new(params.ChainConfig)
			if err := json.Unmarshal(readV270Testdata(t, n.storedConfig), old); err != nil {
				t.Fatalf("failed to decode v2.7.0 config: %v", err)
			}
			have, want := n.builtin.XDPoS, old.XDPoS
			if have.Period != want.Period || have.Epoch != want.Epoch || have.Reward != want.Reward ||
				have.RewardCheckpoint != want.RewardCheckpoint || have.Gap != want.Gap ||
				have.FoundationWalletAddr != want.FoundationWalletAddr {
				t.Fatalf("XDPoS settings changed: have %+v, want %+v", have, want)
			}
			if have.V2.SwitchBlock.Cmp(want.V2.SwitchBlock) != 0 {
				t.Fatalf("V2 switch block changed: have %v, want %v", have.V2.SwitchBlock, want.V2.SwitchBlock)
			}
			for round, w := range want.V2.AllConfigs {
				h, ok := have.V2.AllConfigs[round]
				if !ok {
					t.Errorf("round %d: config removed", round)
					continue
				}
				if h.SwitchRound != w.SwitchRound || h.MaxMasternodes != w.MaxMasternodes || h.CertThreshold != w.CertThreshold ||
					h.TimeoutSyncThreshold != w.TimeoutSyncThreshold || h.TimeoutPeriod != w.TimeoutPeriod ||
					h.MinePeriod != w.MinePeriod || h.ExpTimeoutConfig.Base != w.ExpTimeoutConfig.Base ||
					h.ExpTimeoutConfig.MaxExponent != w.ExpTimeoutConfig.MaxExponent {
					t.Errorf("round %d: have %+v, want %+v", round, h, w)
				}
			}
			for round := range have.V2.AllConfigs {
				if _, ok := want.V2.AllConfigs[round]; !ok && round <= n.upgradeRound {
					t.Errorf("round %d: new config switches at or below upgrade round %d", round, n.upgradeRound)
				}
			}
		})
	}
}
