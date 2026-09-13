package core

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
)

func TestNormalizeChainConfigMismatchPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input ChainConfigMismatchPolicy
		want  ChainConfigMismatchPolicy
	}{
		{
			name:  "empty defaults to exit",
			input: "",
			want:  DefaultChainConfigMismatchPolicy,
		},
		{
			name:  "non-empty preserved",
			input: MismatchIgnoreMismatch,
			want:  MismatchIgnoreMismatch,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := NormalizeChainConfigMismatchPolicy(tt.input)
			if got != tt.want {
				t.Fatalf("unexpected normalized policy: have %q want %q", got, tt.want)
			}
		})
	}
}

// TestChainConfigAsStoredKeepsAnOmittedEpoch pins the stored form the mismatch
// policies write. A config may omit XDPoS.Epoch - validation deliberately leaves it
// for the resolution - and core/genesis.go stores that state as written, so the
// write back has to persist the same shape instead of the epoch that was filled in
// afterwards. Otherwise the stored config gains a number no file contains, and which
// number it holds depends on which tool wrote it last.
func TestChainConfigAsStoredKeepsAnOmittedEpoch(t *testing.T) {
	t.Parallel()

	// A config whose source omitted the epoch, resolved the way the engine and the
	// resolved blockchain constructors resolve it.
	cfg := params.TestnetChainConfig.Clone()
	cfg.XDPoS = cfg.XDPoS.Clone()
	cfg.XDPoS.Epoch = 0
	resolved, err := cfg.ResolveXDPoSEpoch()
	if err != nil {
		t.Fatalf("failed to resolve an omitted epoch: %v", err)
	}
	if resolved.XDPoS.Epoch != params.DefaultXDPoSEpoch {
		t.Fatalf("resolved epoch: have %d want %d", resolved.XDPoS.Epoch, params.DefaultXDPoSEpoch)
	}
	if cfg.XDPoS.Epoch != 0 {
		t.Fatalf("the resolution must not fill the caller's config in place, have %d", cfg.XDPoS.Epoch)
	}

	stored := chainConfigAsStored(resolved)
	if stored == resolved {
		t.Fatal("an epoch the resolution filled in has to be restored to its written state")
	}
	if stored.XDPoS.Epoch != 0 {
		t.Fatalf("stored epoch: have %d want 0", stored.XDPoS.Epoch)
	}
	if resolved.XDPoS.Epoch != params.DefaultXDPoSEpoch {
		t.Fatalf("the resolved config has to keep the epoch that was filled in, have %d", resolved.XDPoS.Epoch)
	}
	// The persisted form matches what the genesis commit path writes for an omitted
	// epoch: the unset value rather than the filled-in default.
	data, err := json.Marshal(stored)
	if err != nil {
		t.Fatalf("failed to marshal the stored config: %v", err)
	}
	if !strings.Contains(string(data), `"epoch":0`) {
		t.Fatalf("stored config %s does not carry the unset epoch", data)
	}

	// A config that wrote its epoch out is persisted as it is, and so is a config
	// that never went through the resolution: nothing is known to have defaulted it.
	written := &params.ChainConfig{
		ChainID: big.NewInt(5151),
		XDPoS:   &params.XDPoSConfig{Epoch: params.DefaultXDPoSEpoch, Gap: 450},
	}
	if got := chainConfigAsStored(written); got != written {
		t.Fatal("a config that wrote its epoch out has to be persisted as it is")
	}
	if got := chainConfigAsStored(nil); got != nil {
		t.Fatal("a nil config has to stay nil")
	}
	withoutXDPoS := &params.ChainConfig{ChainID: big.NewInt(5151)}
	if got := chainConfigAsStored(withoutXDPoS); got != withoutXDPoS {
		t.Fatal("a config without an XDPoS section has to be persisted as it is")
	}
}

// TestChainConfigAsStoredTreatsARoundTrippedEpochAsWritten pins the limit of the
// judgement EpochFilledByEngine makes, so the boundary is a documented contract
// rather than something callers have to discover. The state it reads is
// process-local: marshalling always writes the epoch out, so a config that goes
// through a database round-trip carries no record of the fill. It answers false and
// is treated as written - the same conservative reading a config that never went
// through the resolution gets - even though the value is the one that was filled in.
//
// The mismatch policies are not affected by that limit, because they are only
// reached when a compatibility error exists and on that path the config comes from
// the genesis the operator supplied or from a bundled network config; the
// neighbouring test covers the shape they actually receive. This test pins the
// boundary so a future change to the stored-only paths cannot quietly invert it.
func TestChainConfigAsStoredTreatsARoundTrippedEpochAsWritten(t *testing.T) {
	t.Parallel()

	// The shape a source that never wrote an epoch produces, resolved the way the
	// engine resolves it.
	cfg := params.TestnetChainConfig.Clone()
	cfg.XDPoS = cfg.XDPoS.Clone()
	cfg.XDPoS.Epoch = 0
	resolved, err := cfg.ResolveXDPoSEpoch()
	if err != nil {
		t.Fatalf("failed to resolve an omitted epoch: %v", err)
	}
	if !resolved.XDPoS.EpochFilledByEngine() {
		t.Fatal("an epoch filled into a config that omitted one has to be recognised")
	}

	// Write it out the way rawdb.WriteChainConfig does and read it back: the
	// marshalled form always spells the epoch out, so the read-back config carries no
	// record of the fill.
	present, err := json.Marshal(resolved.XDPoS)
	if err != nil {
		t.Fatalf("failed to marshal the XDPoS section: %v", err)
	}
	if !strings.Contains(string(present), `"epoch":900`) {
		t.Fatalf("marshalled XDPoS section %s does not spell the epoch out", present)
	}
	var roundTripped params.XDPoSConfig
	if err := json.Unmarshal(present, &roundTripped); err != nil {
		t.Fatalf("failed to unmarshal the stored XDPoS section: %v", err)
	}
	if roundTripped.Epoch == 0 {
		t.Fatal("the round-trip has to keep the stored epoch")
	}
	if roundTripped.EpochFilledByEngine() {
		t.Fatal("a config read back from storage spells its epoch out, so the fill cannot be recognised")
	}

	// The conservative reading follows: nobody is known to have defaulted the value,
	// so the config is persisted as it is.
	roundCfg := &params.ChainConfig{ChainID: big.NewInt(5151), XDPoS: &roundTripped}
	if got := chainConfigAsStored(roundCfg); got != roundCfg {
		t.Fatal("a config read back from storage has to be persisted as it is")
	}

	// The reading has to hold for the narrowest shape as well: a decode into a
	// receiver that still carries the fill record. Reading a config back is what
	// makes it stored, so the record has to be dropped by the decode itself - if it
	// survived, this config would be persisted with an epoch of 0 even though the
	// blob it was read from spells that epoch out.
	reused := *resolved.XDPoS
	if err := json.Unmarshal(present, &reused); err != nil {
		t.Fatalf("failed to unmarshal into a receiver that carries the fill record: %v", err)
	}
	reusedCfg := &params.ChainConfig{ChainID: big.NewInt(5151), XDPoS: &reused}
	if got := chainConfigAsStored(reusedCfg); got != reusedCfg {
		t.Fatal("a config decoded over a filled record has to be persisted as it is")
	}
	if reusedCfg.XDPoS.Epoch != params.DefaultXDPoSEpoch {
		t.Fatalf("the reused receiver has to keep the stored epoch, have %d", reusedCfg.XDPoS.Epoch)
	}
}

func TestParseChainConfigMismatchPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		want      ChainConfigMismatchPolicy
		wantError bool
	}{
		{
			name:  "empty defaults to exit",
			input: "",
			want:  DefaultChainConfigMismatchPolicy,
		},
		{
			name:  "whitespace defaults to exit",
			input: "   \t\n",
			want:  DefaultChainConfigMismatchPolicy,
		},
		{
			name:  "trimmed rewind-and-update",
			input: "  rewind-and-update  ",
			want:  MismatchRewindAndUpdate,
		},
		{
			name:  "exit",
			input: "exit",
			want:  MismatchExit,
		},
		{
			name:  "update-config-only",
			input: "update-config-only",
			want:  MismatchUpdateConfigOnly,
		},
		{
			name:  "ignore-mismatch",
			input: "ignore-mismatch",
			want:  MismatchIgnoreMismatch,
		},
		{
			name:      "invalid value",
			input:     "invalid",
			wantError: true,
		},
		{
			name:      "invalid mixed case",
			input:     "Continue",
			wantError: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseChainConfigMismatchPolicy(tt.input)
			if tt.wantError {
				if err == nil {
					t.Fatalf("expected error for input %q", tt.input)
				}
				if !strings.Contains(err.Error(), "invalid chain config mismatch policy") {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("unexpected parsed policy: have %q want %q", got, tt.want)
			}
		})
	}
}

// newEpochlessXDPoSGenesis builds a custom XDPoS chain whose genesis omits
// XDPoS.Epoch, with a schedule the engine default epoch accepts: the switch block
// sits on that default's boundary and the switch epoch names the epoch it falls on.
func newEpochlessXDPoSGenesis(t *testing.T) *Genesis {
	t.Helper()

	genesis := newCustomXDPoSGenesis(4545, 0)
	genesis.Config = genesis.Config.Clone()
	genesis.Config.XDPoS = genesis.Config.XDPoS.Clone()
	genesis.Config.XDPoS.Epoch = 0
	genesis.Config.XDPoS.Gap = 450
	genesis.Config.XDPoS.V2 = genesis.Config.XDPoS.V2.Clone()
	genesis.Config.XDPoS.V2.SwitchBlock = new(big.Int).SetUint64(params.DefaultXDPoSEpoch)
	genesis.Config.XDPoS.V2.SwitchEpoch = 1
	return genesis
}

// injectSyntheticHead raises the canonical head of db above the genesis block
// without a state transition. The writable setup path only judges compatibility
// when the head is not block zero, so this is what lets the mismatch policies be
// exercised without sealing a chain. The headers are chained from the genesis and
// written for every height, because the chain walks back from its head when it
// closes, and their number stays below the XDPoS v2 switch block so the round
// context is never read from extra data they do not carry.
func injectSyntheticHead(t *testing.T, db ethdb.Database, genesisHash common.Hash, number uint64) {
	t.Helper()

	parent := genesisHash
	for n := uint64(1); n <= number; n++ {
		head := types.NewBlockWithHeader(&types.Header{
			Number:     new(big.Int).SetUint64(n),
			ParentHash: parent,
			Root:       types.EmptyRootHash,
		})
		rawdb.WriteBlock(db, head)
		rawdb.WriteCanonicalHash(db, head.Hash(), n)
		parent = head.Hash()
	}
	rawdb.WriteHeadHeaderHash(db, parent)
	rawdb.WriteHeadBlockHash(db, parent)
	rawdb.WriteHeadFastBlockHash(db, parent)
}

// TestMismatchWritebackKeepsAnOmittedEpochAcrossRounds pins the stored form the
// mismatch policies write on the boot the unit-level judgement cannot see. The
// writeback restores an epoch the resolution filled in, and it recognises that fill
// through the state the resolution records rather than through the source keys, so
// the recognition survives the storage round-trip that writes the omitted epoch out
// as "epoch":0. The test plants the drift twice and checks what the database holds
// after each writeback, which is what shows the second boot still keeps the epoch as
// written instead of persisting the filled-in default the first one supplied.
func TestMismatchWritebackKeepsAnOmittedEpochAcrossRounds(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	genesis := newEpochlessXDPoSGenesis(t)
	block := genesis.MustCommit(db)

	for round := 1; round <= 2; round++ {
		// The drift mirrors a legacy on-disk config: the stored blob claims a fork
		// the genesis does not schedule at that height, so opening the chain needs
		// the mismatch policy to write the resolved config back.
		stored := genesis.Config.Clone()
		stored.TIPTRC21FeeBlock = big.NewInt(100)
		overwriteStoredChainConfig(t, db, block.Hash(), stored)
		injectSyntheticHead(t, db, block.Hash(), 2)

		cfg, ghash, compatErr, err := SetupGenesisBlock(db, genesis)
		if err != nil {
			t.Fatalf("round %d: setup failed: %v", round, err)
		}
		if ghash != block.Hash() {
			t.Fatalf("round %d: unexpected genesis hash: have %s want %s", round, ghash.Hex(), block.Hash().Hex())
		}
		if compatErr == nil {
			t.Fatalf("round %d: the planted drift has to be a compatibility error", round)
		}
		if cfg.XDPoS == nil || cfg.XDPoS.Epoch != 0 {
			t.Fatalf("round %d: resolution has to leave the omitted epoch alone, have %v", round, cfg.XDPoS)
		}

		// The node opens the chain with the config its engine resolved, which is what
		// makes the writeback restore the epoch rather than store it. The engine owns
		// that resolution, so building it must leave the caller's config as written.
		engine, err := XDPoS.NewFakerWithError(db, cfg)
		if err != nil {
			t.Fatalf("round %d: failed to build the engine: %v", round, err)
		}
		resolved := engine.ChainConfig()
		if resolved == nil || resolved.XDPoS == nil || resolved.XDPoS.Epoch != params.DefaultXDPoSEpoch {
			engine.Stop()
			t.Fatalf("round %d: expected the engine to resolve the default epoch, have %v", round, resolved)
		}
		if !resolved.XDPoS.EpochFilledByEngine() {
			engine.Stop()
			t.Fatalf("round %d: the resolved config no longer reports the epoch as filled in", round)
		}
		if cfg.XDPoS.Epoch != 0 {
			engine.Stop()
			t.Fatalf("round %d: building the engine must not write into the caller's config, have %d", round, cfg.XDPoS.Epoch)
		}

		chain, err := NewBlockChainResolved(db, nil, genesis, engine, vm.Config{}, resolved, ghash, compatErr, MismatchUpdateConfigOnly)
		if err != nil {
			engine.Stop()
			t.Fatalf("round %d: failed to open the chain: %v", round, err)
		}
		chain.Stop()
		engine.Stop()

		storedCfg, err := rawdb.ReadChainConfig(db, ghash)
		if err != nil {
			t.Fatalf("round %d: failed to read the stored config: %v", round, err)
		}
		if storedCfg == nil || storedCfg.XDPoS == nil {
			t.Fatalf("round %d: expected a stored XDPoS config, have %v", round, storedCfg)
		}
		if storedCfg.XDPoS.Epoch != 0 {
			t.Fatalf("round %d: the writeback persisted the engine default (%d) instead of the omitted epoch", round, storedCfg.XDPoS.Epoch)
		}
		// The drifted fork has to come back as the genesis schedules it, which is
		// what proves the writeback ran rather than the drift being tolerated.
		if storedCfg.TIPTRC21FeeBlock == nil || storedCfg.TIPTRC21FeeBlock.Cmp(big.NewInt(1)) != 0 {
			t.Fatalf("round %d: the writeback did not replace the drifted fork, have %v", round, storedCfg.TIPTRC21FeeBlock)
		}
		// The persisted form matches what init writes for an omitted epoch, so the
		// genesis the operator holds keeps matching what is judged at the next boot.
		data, err := json.Marshal(storedCfg)
		if err != nil {
			t.Fatalf("round %d: failed to marshal the stored config: %v", round, err)
		}
		if !strings.Contains(string(data), `"epoch":0`) {
			t.Fatalf("round %d: stored config %s does not carry the unset epoch", round, data)
		}
		if genesis.Config.XDPoS.Epoch != 0 {
			t.Fatalf("round %d: opening the chain must not write into the provided genesis, have %d", round, genesis.Config.XDPoS.Epoch)
		}
	}
}
