// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package params

import (
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/stretchr/testify/assert"
)

func TestUpdateV2Config(t *testing.T) {
	TestXDPoSMockChainConfig.XDPoS.V2.BuildConfigIndex()
	c := TestXDPoSMockChainConfig.XDPoS.V2.CurrentConfig
	assert.Equal(t, 0.667, c.CertThreshold)

	TestXDPoSMockChainConfig.XDPoS.V2.UpdateConfig(10)
	c = TestXDPoSMockChainConfig.XDPoS.V2.CurrentConfig
	assert.Equal(t, float64(0.667), c.CertThreshold)

	TestXDPoSMockChainConfig.XDPoS.V2.UpdateConfig(900)
	c = TestXDPoSMockChainConfig.XDPoS.V2.CurrentConfig
	assert.Equal(t, 4, c.TimeoutSyncThreshold)
}

func TestV2Config(t *testing.T) {
	TestXDPoSMockChainConfig.XDPoS.V2.BuildConfigIndex()
	c := TestXDPoSMockChainConfig.XDPoS.V2.Config(1)
	assert.Equal(t, 0.667, c.CertThreshold)

	c = TestXDPoSMockChainConfig.XDPoS.V2.Config(5)
	assert.Equal(t, 0.667, c.CertThreshold)

	c = TestXDPoSMockChainConfig.XDPoS.V2.Config(10)
	assert.Equal(t, 0.667, c.CertThreshold)

	c = TestXDPoSMockChainConfig.XDPoS.V2.Config(11)
	assert.Equal(t, float64(0.667), c.CertThreshold)
}

func TestV2ConfigAccessorsReturnIndependentCopies(t *testing.T) {
	v2 := &V2{
		CurrentConfig: &V2Config{
			SwitchRound: 1,
			json:        jsonFieldPresence{tracked: true, keys: map[string]struct{}{"switchRound": {}}},
			ExpTimeoutConfig: ExpTimeoutConfig{
				Base: 1,
				json: jsonFieldPresence{tracked: true, keys: map[string]struct{}{"base": {}}},
			},
		},
		AllConfigs: map[uint64]*V2Config{
			0: {
				SwitchRound: 0,
				json:        jsonFieldPresence{tracked: true, keys: map[string]struct{}{"switchRound": {}}},
				ExpTimeoutConfig: ExpTimeoutConfig{
					Base: 2,
					json: jsonFieldPresence{tracked: true, keys: map[string]struct{}{"base": {}}},
				},
			},
		},
		configIndex: []uint64{0},
	}

	current := v2.GetCurrentConfig()
	delete(current.json.keys, "switchRound")
	delete(current.ExpTimeoutConfig.json.keys, "base")

	if _, ok := v2.CurrentConfig.json.keys["switchRound"]; !ok {
		t.Fatal("expected GetCurrentConfig to return an independent copy of jsonPresence")
	}
	if _, ok := v2.CurrentConfig.ExpTimeoutConfig.json.keys["base"]; !ok {
		t.Fatal("expected GetCurrentConfig to deep copy ExpTimeoutConfig jsonPresence")
	}

	cfg := v2.Config(0)
	delete(cfg.json.keys, "switchRound")
	delete(cfg.ExpTimeoutConfig.json.keys, "base")

	if _, ok := v2.AllConfigs[0].json.keys["switchRound"]; !ok {
		t.Fatal("expected Config to return an independent copy of jsonPresence")
	}
	if _, ok := v2.AllConfigs[0].ExpTimeoutConfig.json.keys["base"]; !ok {
		t.Fatal("expected Config to deep copy ExpTimeoutConfig jsonPresence")
	}
}

func TestChainConfigEqualConcurrentWithV2Update(t *testing.T) {
	left := TestXDPoSMockChainConfig.Clone()
	right := TestXDPoSMockChainConfig.Clone()
	left.XDPoS.V2.BuildConfigIndex()
	right.XDPoS.V2.BuildConfigIndex()

	rounds := []uint64{0, 10, 900}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 2000; i++ {
			left.XDPoS.V2.UpdateConfig(rounds[i%len(rounds)])
		}
	}()

	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 2000; i++ {
			_ = left.Equal(right)
		}
	}()

	close(start)
	wg.Wait()
}

func TestV2EqualConcurrentWithUpdateConfig(t *testing.T) {
	left := TestXDPoSMockChainConfig.XDPoS.V2.Clone()
	right := TestXDPoSMockChainConfig.XDPoS.V2.Clone()
	left.BuildConfigIndex()
	right.BuildConfigIndex()

	rounds := []uint64{0, 10, 900}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 2000; i++ {
			left.UpdateConfig(rounds[i%len(rounds)])
		}
	}()

	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 2000; i++ {
			_ = V2Equal(left, right)
		}
	}()

	close(start)
	wg.Wait()
}

func TestV2StringConcurrentWithUpdateConfig(t *testing.T) {
	v2 := TestXDPoSMockChainConfig.XDPoS.V2.Clone()
	v2.BuildConfigIndex()

	rounds := []uint64{0, 10, 900}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 2000; i++ {
			v2.UpdateConfig(rounds[i%len(rounds)])
		}
	}()

	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 2000; i++ {
			_ = v2.String()
		}
	}()

	close(start)
	wg.Wait()
}

func TestV2StableLogValueDeterministicAndComplete(t *testing.T) {
	v2 := &V2{
		SwitchEpoch: 63143,
		SwitchBlock: big.NewInt(56828700),
		CurrentConfig: &V2Config{
			MaxMasternodes: 15,
		},
		AllConfigs: map[uint64]*V2Config{
			10: {SwitchRound: 10, MaxMasternodes: 16},
			0:  {SwitchRound: 0, MaxMasternodes: 15},
		},
		configIndex: []uint64{10, 0},
	}

	firstBytes, err := json.Marshal(v2.StableLogValue())
	assert.NoError(t, err)
	secondBytes, err := json.Marshal(v2.StableLogValue())
	assert.NoError(t, err)

	first := string(firstBytes)
	second := string(secondBytes)
	assert.Equal(t, first, second)

	assert.Contains(t, first, `"switchEpoch":63143`)
	assert.Contains(t, first, `"switchBlock":"56828700"`)
	assert.Contains(t, first, `"configIndex":[10,0]`)
	assert.Contains(t, first, `"currentConfig"`)

	idxRound0 := strings.Index(first, `"round":0`)
	idxRound10 := strings.Index(first, `"round":10`)
	if idxRound0 == -1 || idxRound10 == -1 {
		t.Fatalf("expected allConfigs rounds in stable log output, got %q", first)
	}
	if idxRound0 > idxRound10 {
		t.Fatalf("expected allConfigs rounds sorted ascending, got %q", first)
	}
}

func TestBuildConfigIndex(t *testing.T) {
	TestXDPoSMockChainConfig.XDPoS.V2.BuildConfigIndex()
	index := TestXDPoSMockChainConfig.XDPoS.V2.ConfigIndex()
	expected := []uint64{900, 10, 0}
	assert.Equal(t, expected, index)
}

func TestBuildConfigIndexDescendingOrder(t *testing.T) {
	v2 := &V2{
		AllConfigs: map[uint64]*V2Config{
			5:  {SwitchRound: 5},
			2:  {SwitchRound: 2},
			10: {SwitchRound: 10},
			0:  {SwitchRound: 0},
			15: {SwitchRound: 15},
		},
	}
	v2.BuildConfigIndex()
	assert.Equal(t, []uint64{15, 10, 5, 2, 0}, v2.ConfigIndex())
}

func TestV2ConfigIndexReturnsCopy(t *testing.T) {
	v2 := &V2{
		configIndex: []uint64{3, 2, 1},
	}

	index := v2.ConfigIndex()
	index[0] = 99

	assert.Equal(t, []uint64{3, 2, 1}, v2.ConfigIndex())
}

// TestSwitchEpoch pins the invariant the v2 round arithmetic depends on: the
// switch epoch is the epoch number the switch block falls on, i.e.
// SwitchEpoch == SwitchBlock / Epoch. Every built-in network has to satisfy it,
// because isEpochSwitchAtRound derives the epoch number as
// SwitchEpoch + round/Epoch and a drifted pair renumbers every epoch the chain
// reports without failing any other rule.
func TestSwitchEpoch(t *testing.T) {
	config := XDCMainnetChainConfig.XDPoS
	epoch := config.Epoch
	assert.Equal(t, config.V2.SwitchEpoch, config.V2.SwitchBlock.Uint64()/epoch)

	config = TestnetChainConfig.XDPoS
	epoch = config.Epoch
	assert.Equal(t, config.V2.SwitchEpoch, config.V2.SwitchBlock.Uint64()/epoch)

	config = DevnetChainConfig.XDPoS
	epoch = config.Epoch
	assert.Equal(t, config.V2.SwitchEpoch, config.V2.SwitchBlock.Uint64()/epoch)

	config = LocalnetChainConfig.XDPoS
	epoch = config.Epoch
	assert.Equal(t, config.V2.SwitchEpoch, config.V2.SwitchBlock.Uint64()/epoch)

	config = TestXDPoSMockChainConfig.XDPoS
	epoch = config.Epoch
	assert.Equal(t, config.V2.SwitchEpoch, config.V2.SwitchBlock.Uint64()/epoch)
}

func TestXDPoSConfigUnmarshalLegacyFoundationWalletAddr(t *testing.T) {
	const raw = `{"period":2,"epoch":900,"reward":5000,"rewardCheckpoint":900,"gap":450,"foudationWalletAddr":"xdc746249c61f5832c5eed53172776b460491bdcd5c"}`

	var cfg XDPoSConfig
	err := json.Unmarshal([]byte(raw), &cfg)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToAddress("xdc746249c61f5832c5eed53172776b460491bdcd5c"), cfg.FoundationWalletAddr)
}

func TestXDPoSConfigUnmarshalFoundationWalletAddrPrecedence(t *testing.T) {
	const raw = `{"period":2,"epoch":900,"reward":5000,"rewardCheckpoint":900,"gap":450,"foudationWalletAddr":"xdc746249c61f5832c5eed53172776b460491bdcd5c","foundationWalletAddr":"xdc92a289fe95a85c53b8d0d113cbaef0c1ec98ac65"}`

	var cfg XDPoSConfig
	err := json.Unmarshal([]byte(raw), &cfg)
	assert.NoError(t, err)
	assert.Equal(t, common.HexToAddress("xdc92a289fe95a85c53b8d0d113cbaef0c1ec98ac65"), cfg.FoundationWalletAddr)
}

func TestV2UnmarshalSwitchEpochVariants(t *testing.T) {
	jsonLower := `{"switchEpoch": 123, "switchBlock": 456, "config": null, "allConfigs": {}}`
	jsonUpper := `{"SwitchEpoch": 789, "switchBlock": 456, "config": null, "allConfigs": {}}`
	jsonBoth := `{"switchEpoch": 111, "SwitchEpoch": 222, "switchBlock": 456, "config": null, "allConfigs": {}}`

	// 1. Only switchEpoch
	var v2 V2
	assert.NoError(t, json.Unmarshal([]byte(jsonLower), &v2))
	assert.Equal(t, uint64(123), v2.SwitchEpoch)
	assert.Equal(t, big.NewInt(456), v2.SwitchBlock)

	// 2. Only SwitchEpoch
	v2 = V2{}
	assert.NoError(t, json.Unmarshal([]byte(jsonUpper), &v2))
	assert.Equal(t, uint64(789), v2.SwitchEpoch)
	assert.Equal(t, big.NewInt(456), v2.SwitchBlock)

	// 3. Both present: prefer switchEpoch
	v2 = V2{}
	assert.NoError(t, json.Unmarshal([]byte(jsonBoth), &v2))
	assert.Equal(t, uint64(111), v2.SwitchEpoch)
	assert.Equal(t, big.NewInt(456), v2.SwitchBlock)
}

// TestXDPoSConfigGapOffset pins the judgement chain config validation rejects an
// unusable gap schedule with. The offset has to fall strictly inside the epoch:
// Gap == 0 or Gap >= Epoch leaves none there (Gap == Epoch puts it on the
// boundary, which TestGapEqualToEpochMatchesTheEpochSwitchBlock explains), an
// unset Epoch has no offset either, and Epoch == 1 leaves no usable Gap at all.
func TestXDPoSConfigGapOffset(t *testing.T) {
	const (
		epoch = uint64(900)
		gap   = uint64(450)
	)
	tests := []struct {
		name   string
		config *XDPoSConfig
		want   uint64
		wantOK bool
	}{
		{"nil config has no offset", nil, 0, false},
		{"zero epoch has no offset", &XDPoSConfig{Epoch: 0, Gap: gap}, 0, false},
		{"zero epoch and zero gap have no offset", &XDPoSConfig{Epoch: 0, Gap: 0}, 0, false},
		{"epoch one has no offset", &XDPoSConfig{Epoch: 1, Gap: 0}, 0, false},
		{"epoch one and gap one have no offset", &XDPoSConfig{Epoch: 1, Gap: 1}, 0, false},
		{"zero gap has no offset", &XDPoSConfig{Epoch: epoch, Gap: 0}, 0, false},
		{"gap equal to epoch has no offset", &XDPoSConfig{Epoch: epoch, Gap: epoch}, 0, false},
		{"gap above epoch has no offset", &XDPoSConfig{Epoch: epoch, Gap: epoch + 1}, 0, false},
		{"valid schedule is the epoch minus the gap", &XDPoSConfig{Epoch: epoch, Gap: gap}, epoch - gap, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tt.config.GapOffset()
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestSwitchBlockAligned pins the one definition of the v2 alignment rule that
// config validation and the puppeth wizard both judge by. The two >2^64 rows are the
// point: the low 64 bits of a height must not decide the verdict, because
// SwitchBlock.Uint64() folds every bit above 2^64 away and would invert both.
func TestSwitchBlockAligned(t *testing.T) {
	aboveUint64 := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(900))
	// The aligned height just below it: its low 64 bits are 884, so the uint64 form
	// reads it as unaligned while the height itself is a multiple of the epoch.
	alignedAboveUint64 := new(big.Int).Mul(new(big.Int).Div(aboveUint64, big.NewInt(900)), big.NewInt(900))
	tests := []struct {
		name  string
		block *big.Int
		epoch uint64
		want  bool
	}{
		{"nil block names no boundary", nil, 900, false},
		{"negative height names no boundary", big.NewInt(-900), 900, false},
		{"unset epoch names no boundary", big.NewInt(0), 0, false},
		{"zero is a multiple of every epoch", big.NewInt(0), 900, true},
		{"an epoch multiple is aligned", big.NewInt(1800), 900, true},
		{"a non-multiple is not aligned", big.NewInt(901), 900, false},
		{"below one epoch only zero aligns", big.NewInt(900), 1800, false},
		{"above 2^64 whose low bits look aligned is not", aboveUint64, 900, false},
		{"above 2^64 whose low bits look unaligned is", alignedAboveUint64, 900, true},
		{"epoch one aligns every height", big.NewInt(7), 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, SwitchBlockAligned(tt.block, tt.epoch))
		})
	}
}

// TestSwitchEpochFor pins the one definition of the pairing arithmetic: the epoch a
// switch block falls on, and whether XDPoS.V2.SwitchEpoch can name it. The want is
// still returned for a negative block so the validation can name it in the mismatch,
// while fits stays false; a quotient no uint64 can hold is non-nil but never fits.
func TestSwitchEpochFor(t *testing.T) {
	aboveUint64 := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(900))
	tests := []struct {
		name  string
		block *big.Int
		epoch uint64
		want  *big.Int // nil when the pairing names no epoch at all
		fits  bool
	}{
		{"nil block names no epoch", nil, 900, nil, false},
		{"unset epoch names no epoch", big.NewInt(900), 0, nil, false},
		{"a block inside the first epoch is epoch zero", big.NewInt(450), 900, big.NewInt(0), true},
		{"an epoch start is that epoch", big.NewInt(1800), 900, big.NewInt(2), true},
		{"a height above 2^64 divides as a big.Int", aboveUint64, 900, new(big.Int).Div(aboveUint64, big.NewInt(900)), true},
		{"a quotient no uint64 names does not fit", new(big.Int).Lsh(big.NewInt(1), 80), 2, new(big.Int).Lsh(big.NewInt(1), 79), false},
		{"a negative block keeps its sign and does not fit", big.NewInt(-900), 900, big.NewInt(-1), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want, fits := SwitchEpochFor(tt.block, tt.epoch)
			assert.Equal(t, tt.fits, fits)
			if tt.want == nil {
				assert.Nil(t, want)
				return
			}
			if assert.NotNil(t, want) {
				assert.Zero(t, want.Cmp(tt.want))
			}
		})
	}
}

// TestXDPoSConfigIsGapBlock pins the shared gap-trigger predicate that core's
// shouldUpdateM1 and the v2 engine's UpdateMasternodes both route through, so
// "is this height the gap block" has one definition. GapOffset owns the usability
// judgement, so every schedule that designates no gap block answers false, and no
// height divides by an unset epoch.
func TestXDPoSConfigIsGapBlock(t *testing.T) {
	const (
		epoch = uint64(900)
		gap   = uint64(450)
	)
	tests := []struct {
		name   string
		config *XDPoSConfig
		number uint64
		want   bool
	}{
		{"nil config never matches", nil, epoch - gap, false},
		{"unset epoch never matches", &XDPoSConfig{Epoch: 0, Gap: gap}, epoch - gap, false},
		{"zero gap never matches", &XDPoSConfig{Epoch: epoch, Gap: 0}, epoch, false},
		{"gap equal to the epoch never matches a residue", &XDPoSConfig{Epoch: epoch, Gap: epoch}, epoch, false},
		{"gap above the epoch never matches", &XDPoSConfig{Epoch: epoch, Gap: epoch + 1}, epoch, false},
		{"epoch one leaves no gap block", &XDPoSConfig{Epoch: 1, Gap: 1}, 0, false},
		{"the offset inside the first epoch is the gap block", &XDPoSConfig{Epoch: epoch, Gap: gap}, epoch - gap, true},
		{"the next epoch's gap block matches too", &XDPoSConfig{Epoch: epoch, Gap: gap}, 2*epoch - gap, true},
		{"an epoch start is not the gap block", &XDPoSConfig{Epoch: epoch, Gap: gap}, epoch, false},
		{"a height before the offset is not the gap block", &XDPoSConfig{Epoch: epoch, Gap: gap}, epoch - gap - 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.config.IsGapBlock(tt.number))
		})
	}
}

// TestGapEqualToEpochMatchesTheEpochSwitchBlock pins why Gap == Epoch is refused
// instead of being read as "the trigger never fires": the refusal is not a claim
// that no height matches. Epoch-Gap is 0, so the raw trigger matches at every
// epoch boundary, and the v1 checkpoint predicate (n+Gap)%Epoch == 0 matches
// there too - the block that samples the next-epoch candidate set would be the
// block that consumes it. GapOffset still refuses the shape.
//
// This is the arithmetic behind that rationale, written out rather than routed
// through GapOffset, so a future "correction" of the >= in GapOffset cannot be
// justified by the trigger being dead: opening the gate fails here first, next to
// core.TestShouldUpdateM1's "gap equal to epoch never fires" row.
func TestGapEqualToEpochMatchesTheEpochSwitchBlock(t *testing.T) {
	const epoch = uint64(900)
	config := &XDPoSConfig{Epoch: epoch, Gap: epoch}

	offset := config.Epoch - config.Gap
	assert.Equal(t, uint64(0), offset, "gap equal to the epoch has to put the offset on the epoch boundary")

	// Every epoch boundary is a height the raw trigger selects, and the v1
	// checkpoint predicate of the same schedule lands on it as well.
	for _, number := range []uint64{epoch, 2 * epoch, 3 * epoch} {
		assert.True(t, number%config.Epoch == offset, "trigger has to match block %d", number)
		assert.True(t, (number+config.Gap)%config.Epoch == 0, "v1 checkpoint has to match block %d", number)
	}
	// A height that is not an epoch boundary never matches, so the schedule names
	// no gap block strictly inside an epoch either way.
	for _, number := range []uint64{epoch - 1, epoch + 1, 2*epoch - 1} {
		assert.False(t, number%config.Epoch == offset, "trigger must not match block %d", number)
	}

	// Opening the gate (Gap >= Epoch -> Gap > Epoch) fails here and in
	// core.TestShouldUpdateM1.
	got, ok := config.GapOffset()
	assert.False(t, ok)
	assert.Equal(t, uint64(0), got)
}

// TestXDPoSConfigGapBlockNumber pins the height-side counterpart of GapOffset
// that the v2 paths resolve a block number with. It shares GapOffset's judgement,
// so a schedule that designates no gap block yields no height at all instead of a
// division by an unset epoch; an epoch that starts no farther than Gap into the
// chain reads block 0.
func TestXDPoSConfigGapBlockNumber(t *testing.T) {
	const (
		epoch = uint64(900)
		gap   = uint64(450)
	)
	schedule := &XDPoSConfig{Epoch: epoch, Gap: gap}
	tests := []struct {
		name   string
		config *XDPoSConfig
		number uint64
		want   uint64
		wantOK bool
	}{
		{"nil config has no gap block", nil, 1350, 0, false},
		{"unset epoch has no gap block", &XDPoSConfig{Epoch: 0, Gap: gap}, 1350, 0, false},
		{"zero gap has no gap block", &XDPoSConfig{Epoch: epoch, Gap: 0}, 1350, 0, false},
		{"gap equal to epoch has no gap block", &XDPoSConfig{Epoch: epoch, Gap: epoch}, 1350, 0, false},
		{"gap above epoch has no gap block", &XDPoSConfig{Epoch: epoch, Gap: epoch + 1}, 1350, 0, false},
		{"epoch one has no gap block", &XDPoSConfig{Epoch: 1, Gap: 0}, 1, 0, false},
		{"chain start reads block zero", schedule, 0, 0, true},
		{"height below the first gap block reads block zero", schedule, 899, 0, true},
		{"epoch switch block reads its own gap block", schedule, 900, 450, true},
		{"mid epoch reads the gap block of its epoch", schedule, 1350, 450, true},
		{"last height of an epoch reads the same gap block", schedule, 1799, 450, true},
		{"second epoch switch reads its own gap block", schedule, 1800, 1350, true},
		{"third epoch reads its own gap block", schedule, 2700, 2250, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tt.config.GapBlockNumber(tt.number)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestXDPoSConfigIsLendingLiquidationBlock pins the predicate block production and
// block import share: the miner decides with it whether to attach the liquidation
// work at a height, the importer decides with it whether to expect that work, so a
// divergence would leave the two sides with different state roots. It is total like
// the other schedule predicates, so an unset epoch answers false instead of
// dividing by zero.
func TestXDPoSConfigIsLendingLiquidationBlock(t *testing.T) {
	const (
		epoch = uint64(900)
		gap   = uint64(450)
	)
	schedule := &XDPoSConfig{Epoch: epoch, Gap: gap}
	// The height inside an epoch the lending service liquidates at.
	residue := common.LiquidateLendingTradeBlock
	tests := []struct {
		name   string
		config *XDPoSConfig
		number uint64
		want   bool
	}{
		{"nil config never liquidates", nil, residue, false},
		{"unset epoch never liquidates", &XDPoSConfig{Epoch: 0, Gap: gap}, residue, false},
		{"first liquidation height matches", schedule, residue, true},
		{"liquidation height in the next epoch matches", schedule, epoch + residue, true},
		{"epoch switch block does not liquidate", schedule, epoch, false},
		{"gap block does not liquidate", schedule, gap, false},
		{"neighbouring height does not liquidate", schedule, residue + 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.config.IsLendingLiquidationBlock(tt.number))
		})
	}
}

// TestXDPoSConfigIsSameEpoch pins the predicate XDCxlending uses to tell whether a
// contract price was refreshed in the epoch the header belongs to. It is total like
// the other schedule predicates: a missing XDPoS section or an unset epoch answers
// false instead of dividing by zero, which is the state the open-coded divisions it
// replaces would have panicked on.
func TestXDPoSConfigIsSameEpoch(t *testing.T) {
	const (
		epoch = uint64(900)
		gap   = uint64(450)
	)
	schedule := &XDPoSConfig{Epoch: epoch, Gap: gap}
	tests := []struct {
		name   string
		config *XDPoSConfig
		first  uint64
		second uint64
		want   bool
	}{
		{"nil config has no same epoch", nil, 1350, 1351, false},
		{"unset epoch has no same epoch", &XDPoSConfig{Epoch: 0, Gap: gap}, 1350, 1351, false},
		{"identical heights share an epoch", schedule, 0, 0, true},
		{"heights inside one epoch match", schedule, 900, 1799, true},
		{"the epoch switch block starts a new epoch", schedule, 899, 900, false},
		{"heights in different epochs do not match", schedule, 1350, 2250, false},
		{"two epoch starts do not match", schedule, 900, 1800, false},
		{"later heights of the same epoch match", schedule, 2700, 3599, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.config.IsSameEpoch(tt.first, tt.second))
		})
	}
}

// TestGapBlockNumberMatchesOpenCodedSwitchBlockStep pins the equivalence the
// engine_v2 first-epoch special case leans on. That path steps back from the v2
// switch block by Gap instead of asking the height-side definition
// (GapBlockNumber), and the two only agree because the alignment rule puts an
// accepted switch block on its own epoch boundary: stepping back by Gap then lands
// on the same height GapBlockNumber resolves for it.
//
// Pin the equality here rather than inside the engine, so a change to either the
// alignment rule or GapBlockNumber fails a test instead of quietly giving the two
// definitions different answers for the same height - a divergence there would be
// read by block production and by block import as different gap blocks.
func TestGapBlockNumberMatchesOpenCodedSwitchBlockStep(t *testing.T) {
	const epoch = uint64(900)
	tests := []struct {
		name        string
		gap         uint64
		switchBlock uint64
	}{
		{"gap inside the epoch", 450, epoch},
		{"shortest usable gap", 1, epoch},
		{"longest usable gap", epoch - 1, epoch},
		{"longest usable gap, switch block one epoch later", epoch - 1, epoch * 2},
		{"switch block several epochs in", 450, epoch * 3},
		// The only row that reaches the underflow guard: switchBlock is a non-negative
		// multiple of epoch and gap < epoch, so switchBlock == 0 is the one value that
		// satisfies switchBlock <= gap.
		{"switch block at the chain start", 450, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &XDPoSConfig{Epoch: epoch, Gap: tt.gap}
			// The schedule only reaches the engine when it is accepted at all.
			if _, ok := config.GapOffset(); !ok {
				t.Fatalf("the case has to be a usable schedule, have gap %d epoch %d", tt.gap, epoch)
			}
			// The switch block is on an epoch boundary, which is what the alignment rule
			// guarantees and what makes the two definitions agree.
			if tt.switchBlock%epoch != 0 {
				t.Fatalf("the case has to put the switch block on an epoch boundary, have %d", tt.switchBlock)
			}

			// The step engine_v2.initial performs, underflow guard included.
			stepped := uint64(0)
			if tt.switchBlock > tt.gap {
				stepped = tt.switchBlock - tt.gap
			}
			got, ok := config.GapBlockNumber(tt.switchBlock)
			assert.True(t, ok)
			assert.Equal(t, stepped, got)
		})
	}
}

// TestResolveXDPoSEpochFillsAnOmittedEpoch pins the API the XDPoS engine and the
// resolved blockchain constructors share: an unset epoch is judged against
// DefaultXDPoSEpoch and filled into a copy, so the caller's config keeps the state
// its source wrote while the engine runs with an epoch it can divide by.
func TestResolveXDPoSEpochFillsAnOmittedEpoch(t *testing.T) {
	cfg := TestnetChainConfig.Clone()
	cfg.XDPoS = cfg.XDPoS.Clone()
	cfg.XDPoS.Epoch = 0

	resolved, err := cfg.ResolveXDPoSEpoch()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved == cfg {
		t.Fatal("an omitted epoch has to be resolved onto a copy")
	}
	if resolved.XDPoS == cfg.XDPoS {
		t.Fatal("the resolved config must not share the XDPoS section with the receiver")
	}
	if resolved.XDPoS.Epoch != DefaultXDPoSEpoch {
		t.Fatalf("resolved epoch: have %d want %d", resolved.XDPoS.Epoch, DefaultXDPoSEpoch)
	}
	if !resolved.XDPoS.EpochFilledByEngine() {
		t.Fatal("the resolved copy has to record that the epoch was filled in for it")
	}
	if cfg.XDPoS.Epoch != 0 {
		t.Fatalf("resolving must not fill the receiver in place, have %d", cfg.XDPoS.Epoch)
	}
	if cfg.XDPoS.EpochFilledByEngine() {
		t.Fatal("the receiver keeps an omitted epoch, which is not an engine-filled one")
	}
}

// TestResolveXDPoSEpochKeepsAWrittenEpoch pins the zero-allocation branch: a config
// that writes its epoch out is judged and returned as it is.
func TestResolveXDPoSEpochKeepsAWrittenEpoch(t *testing.T) {
	cfg := TestnetChainConfig.Clone()
	cfg.XDPoS = cfg.XDPoS.Clone()

	resolved, err := cfg.ResolveXDPoSEpoch()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved != cfg {
		t.Fatal("a config that writes its epoch out has to be returned as it is")
	}
	if resolved.XDPoS.EpochFilledByEngine() {
		t.Fatal("a written epoch is not an engine-filled one")
	}
}

// TestResolveXDPoSEpochRejectsAnUnusableSchedule pins that the resolution judges the
// schedule it fills the epoch in for, so a caller cannot obtain a config the engine
// would refuse. A refusal leaves the receiver untouched.
func TestResolveXDPoSEpochRejectsAnUnusableSchedule(t *testing.T) {
	cfg := TestnetChainConfig.Clone()
	cfg.XDPoS = cfg.XDPoS.Clone()
	cfg.XDPoS.Epoch = 0
	cfg.XDPoS.Gap = 0

	resolved, err := cfg.ResolveXDPoSEpoch()
	if !errors.Is(err, ErrUnusableGapSchedule) {
		t.Fatalf("unexpected error: have %v want %v", err, ErrUnusableGapSchedule)
	}
	if resolved != nil {
		t.Fatalf("a refused config must not produce a resolved config: %v", resolved)
	}
	if cfg.XDPoS.Epoch != 0 {
		t.Fatalf("a refused config must keep its own epoch, have %d", cfg.XDPoS.Epoch)
	}
}

// TestEpochFilledByEngineFollowsTheExplicitState pins that the judgement reads the
// state the resolution records rather than the source JSON keys: a config that never
// went through the resolution is not engine-filled even when its source omitted the
// epoch key, Clone carries the state, and a JSON round-trip drops it.
func TestEpochFilledByEngineFollowsTheExplicitState(t *testing.T) {
	var written XDPoSConfig
	if err := json.Unmarshal([]byte(`{"period":2,"epoch":900,"gap":450}`), &written); err != nil {
		t.Fatalf("failed to unmarshal the XDPoS section: %v", err)
	}
	if written.EpochFilledByEngine() {
		t.Fatal("a config that never went through the resolution is not engine-filled")
	}

	cfg := TestnetChainConfig.Clone()
	cfg.XDPoS = cfg.XDPoS.Clone()
	cfg.XDPoS.Epoch = 0
	resolved, err := cfg.ResolveXDPoSEpoch()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resolved.XDPoS.Clone().EpochFilledByEngine() {
		t.Fatal("Clone has to carry the engine-filled state")
	}

	data, err := json.Marshal(resolved.XDPoS)
	if err != nil {
		t.Fatalf("failed to marshal the resolved XDPoS section: %v", err)
	}
	var roundTripped XDPoSConfig
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("failed to unmarshal the stored XDPoS section: %v", err)
	}
	if roundTripped.Epoch != DefaultXDPoSEpoch {
		t.Fatalf("the round-trip has to keep the stored epoch, have %d", roundTripped.Epoch)
	}
	if roundTripped.EpochFilledByEngine() {
		t.Fatal("the engine-filled state is process-local and must not survive the round-trip")
	}

	// The reset has to belong to the receiver rather than to the zero value it
	// happens to start as. A caller that decodes over a section which was resolved
	// earlier keeps the record otherwise, which would report an epoch the source
	// wrote out as one the resolution filled in - the state core's chainConfigAsStored
	// restores to 0 when it persists the config.
	reused := *resolved.XDPoS
	if err := json.Unmarshal(data, &reused); err != nil {
		t.Fatalf("failed to unmarshal into a receiver that carries the record: %v", err)
	}
	if reused.Epoch != DefaultXDPoSEpoch {
		t.Fatalf("the reused receiver has to keep the stored epoch, have %d", reused.Epoch)
	}
	if reused.EpochFilledByEngine() {
		t.Fatal("a receiver that carried the record must not report the stored epoch as engine-filled")
	}
}
