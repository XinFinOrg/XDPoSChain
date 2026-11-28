package core

import (
	"errors"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

func xdpScheduleConfig(epoch, gap uint64) *params.ChainConfig {
	cfg := params.TestXDPoSMockChainConfig.Clone()
	cfg.XDPoS.Epoch, cfg.XDPoS.Gap = epoch, gap
	return cfg
}

func xdpScheduleGenesis(cfg *params.ChainConfig) *Genesis {
	return &Genesis{
		Config:    cfg,
		ExtraData: make([]byte, 32+crypto.SignatureLength),
	}
}

func TestCheckXDPoSSchedule(t *testing.T) {
	for _, test := range []struct {
		name    string
		cfg     *params.ChainConfig
		wantErr bool
		wantMsg string
	}{
		{name: "nil config", cfg: nil},
		{name: "no XDPoS section", cfg: params.AllEthashProtocolChanges},
		{name: "built-in mock schedule", cfg: params.TestXDPoSMockChainConfig},
		{name: "smallest valid schedule", cfg: xdpScheduleConfig(2, 1)},
		{name: "zero epoch", cfg: xdpScheduleConfig(0, 450), wantErr: true},
		{name: "zero epoch and zero gap", cfg: xdpScheduleConfig(0, 0), wantErr: true},
		{
			name:    "zero gap",
			cfg:     xdpScheduleConfig(900, 0),
			wantErr: true,
			wantMsg: "invalid XDPoS schedule: XDPoS.Gap 0 designates no gap block inside XDPoS.Epoch 900 (want 1 <= Gap < Epoch)",
		},
		{name: "gap equal to epoch", cfg: xdpScheduleConfig(900, 900), wantErr: true},
		{name: "gap above epoch", cfg: xdpScheduleConfig(900, 901), wantErr: true},
		{name: "epoch of one", cfg: xdpScheduleConfig(1, 1), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := checkXDPoSSchedule(test.cfg)
			if !test.wantErr {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidEpochGap) {
				t.Fatalf("error = %v, want ErrInvalidEpochGap", err)
			}
			if test.wantMsg != "" && err.Error() != test.wantMsg {
				t.Fatalf("error = %q, want %q", err, test.wantMsg)
			}
		})
	}
}

func TestGenesisCommitRejectsInvalidEpochGap(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	if _, err := xdpScheduleGenesis(xdpScheduleConfig(900, 0)).Commit(db); !errors.Is(err, ErrInvalidEpochGap) {
		t.Fatalf("Commit error = %v, want ErrInvalidEpochGap", err)
	}
	if hash := rawdb.ReadCanonicalHash(db, 0); hash != (common.Hash{}) {
		t.Fatalf("a rejected genesis wrote canonical hash %s", hash)
	}
	if hash := rawdb.ReadHeadBlockHash(db); hash != (common.Hash{}) {
		t.Fatalf("a rejected genesis wrote head block hash %s", hash)
	}
}

func TestSetupGenesisBlockRejectsInvalidEpochGap(t *testing.T) {
	t.Run("empty database", func(t *testing.T) {
		db := rawdb.NewMemoryDatabase()
		if _, _, _, err := SetupGenesisBlock(db, xdpScheduleGenesis(xdpScheduleConfig(900, 0))); !errors.Is(err, ErrInvalidEpochGap) {
			t.Fatalf("error = %v, want ErrInvalidEpochGap", err)
		}
	})
	// A stored config reaches the gate through the resolution path, which runs
	// before XDPoS.New would rewrite a missing epoch to 900.
	t.Run("stored config with a missing epoch", func(t *testing.T) {
		db := rawdb.NewMemoryDatabase()
		block := xdpScheduleGenesis(params.TestXDPoSMockChainConfig.Clone()).MustCommit(db)
		rawdb.WriteChainConfig(db, block.Hash(), xdpScheduleConfig(0, 450))
		if _, _, _, err := SetupGenesisBlock(db, nil); !errors.Is(err, ErrInvalidEpochGap) {
			t.Fatalf("error = %v, want ErrInvalidEpochGap", err)
		}
	})
}

// TestResolveSetupStoredConfigResultRejectsInvalidScheduleBeforeWrite covers the
// stored-config path: the schedule is checked next to CheckConfigForkOrder, so a
// violating config is refused before the reconciliation batch persists it.
func TestResolveSetupStoredConfigResultRejectsInvalidScheduleBeforeWrite(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	storedCfg := params.TestnetChainConfig.Clone()
	newCfg := storedCfg.Clone()
	newCfg.XDPoS.Epoch = 0

	if _, _, err := resolveSetupStoredConfigResult(db, params.TestnetGenesisHash, storedCfg, newCfg, nil, &types.Header{Number: new(big.Int)}, setupStoredOverrideState{trustedOverride: true}); !errors.Is(err, ErrInvalidEpochGap) {
		t.Fatalf("resolveSetupStoredConfigResult error = %v, want ErrInvalidEpochGap", err)
	}
	if _, err := rawdb.ReadChainConfig(db, params.TestnetGenesisHash); !errors.Is(err, rawdb.ErrChainConfigNotFound) {
		t.Fatalf("a rejected config was persisted: %v", err)
	}
}

// TestSetupGenesisRepairsMissingConfigOnlyAfterValidSchedule pins the write order
// of the missing-config repair: an invalid schedule is refused before the config
// reaches the database, so the same database still accepts a corrected genesis
// instead of seeing it as a compatibility drift.
func TestSetupGenesisRepairsMissingConfigOnlyAfterValidSchedule(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	block := xdpScheduleGenesis(params.TestXDPoSMockChainConfig.Clone()).MustCommit(db)
	if err := db.Delete(testConfigKey(block.Hash())); err != nil {
		t.Fatalf("failed to delete stored chain config: %v", err)
	}
	if _, _, _, err := SetupGenesisBlock(db, xdpScheduleGenesis(xdpScheduleConfig(900, 0))); !errors.Is(err, ErrInvalidEpochGap) {
		t.Fatalf("error = %v, want ErrInvalidEpochGap", err)
	}
	if _, err := rawdb.ReadChainConfig(db, block.Hash()); !errors.Is(err, rawdb.ErrChainConfigNotFound) {
		t.Fatalf("a rejected config was persisted: %v", err)
	}
	// The corrected genesis still repairs the missing config in place.
	if _, hash, _, err := SetupGenesisBlock(db, xdpScheduleGenesis(params.TestXDPoSMockChainConfig.Clone())); err != nil {
		t.Fatalf("repair with a valid schedule failed: %v", err)
	} else if hash != block.Hash() {
		t.Fatalf("unexpected repaired genesis hash: have %s want %s", hash.Hex(), block.Hash().Hex())
	}
	storedCfg, err := rawdb.ReadChainConfig(db, block.Hash())
	if err != nil {
		t.Fatalf("expected the repaired config in db: %v", err)
	}
	if storedCfg.XDPoS == nil || storedCfg.XDPoS.Epoch != 900 || storedCfg.XDPoS.Gap != 450 {
		t.Fatalf("repaired config has schedule %v", storedCfg.XDPoS)
	}
}

func TestLoadChainConfigRejectsInvalidEpochGap(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	block := xdpScheduleGenesis(params.TestXDPoSMockChainConfig.Clone()).MustCommit(db)
	rawdb.WriteChainConfig(db, block.Hash(), xdpScheduleConfig(900, 0))

	if _, _, err := LoadChainConfig(db, nil); !errors.Is(err, ErrInvalidEpochGap) {
		t.Fatalf("LoadChainConfig error = %v, want ErrInvalidEpochGap", err)
	}
	if _, _, _, err := LoadChainConfigWithCompat(db, nil); !errors.Is(err, ErrInvalidEpochGap) {
		t.Fatalf("LoadChainConfigWithCompat error = %v, want ErrInvalidEpochGap", err)
	}
}

// TestLoadChainConfigWithCompatClearsCompatErrorOnInvalidSchedule pins the
// single-error contract of the read-only resolver. With a head above genesis, a
// provided config that drifts the schedule out of the bound yields both a
// compatibility rewind and a schedule rejection; only the rejection may reach
// the caller, because the config never reaches the chain.
func TestLoadChainConfigWithCompatClearsCompatErrorOnInvalidSchedule(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesisBlock := xdpScheduleGenesis(xdpScheduleConfig(900, 450)).MustCommit(db)

	// The head makes the resolver compute the drift instead of accepting the
	// provided config at block zero.
	head := types.NewBlockWithHeader(&types.Header{
		Number:     big.NewInt(101),
		ParentHash: genesisBlock.Hash(),
	})
	rawdb.WriteBlock(db, head)
	rawdb.WriteCanonicalHash(db, head.Hash(), head.NumberU64())
	rawdb.WriteHeadHeaderHash(db, head.Hash())
	rawdb.WriteHeadBlockHash(db, head.Hash())
	rawdb.WriteHeadFastBlockHash(db, head.Hash())

	provided := xdpScheduleGenesis(xdpScheduleConfig(900, 0))
	_, _, compatErr, err := LoadChainConfigWithCompat(db, provided)
	if !errors.Is(err, ErrInvalidEpochGap) {
		t.Fatalf("LoadChainConfigWithCompat error = %v, want ErrInvalidEpochGap", err)
	}
	if compatErr != nil {
		t.Fatalf("compatibility error %#v returned alongside a rejected schedule", compatErr)
	}
}

// TestNewBlockChainRejectsInvalidEpochGap covers the public open path end to
// end. The rejection comes from Genesis.commit through SetupGenesisBlock, not
// from newBlockChain's own gate: only a caller-supplied config reaches that one
// (TestNewBlockChainResolvedRejectsInvalidEpochGap).
func TestNewBlockChainRejectsInvalidEpochGap(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	if _, err := NewBlockChain(db, nil, xdpScheduleGenesis(xdpScheduleConfig(900, 0)), ethash.NewFaker(), vm.Config{}); !errors.Is(err, ErrInvalidEpochGap) {
		t.Fatalf("NewBlockChain error = %v, want ErrInvalidEpochGap", err)
	}
}

// TestNewBlockChainResolvedRejectsInvalidEpochGap covers the open that skips
// the resolvers and takes the caller-supplied config directly.
func TestNewBlockChainResolvedRejectsInvalidEpochGap(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	block := xdpScheduleGenesis(params.TestXDPoSMockChainConfig.Clone()).MustCommit(db)
	_, err := NewBlockChainResolved(db, nil, nil, ethash.NewFaker(), vm.Config{}, xdpScheduleConfig(900, 901), block.Hash(), nil, DefaultChainConfigMismatchPolicy)
	if !errors.Is(err, ErrInvalidEpochGap) {
		t.Fatalf("NewBlockChainResolved error = %v, want ErrInvalidEpochGap", err)
	}
}
