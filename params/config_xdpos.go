// Copyright 2016 The go-ethereum Authors
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

// This file owns the XDPoS-side missing-field semantics that backfill relies
// on. UnmarshalJSON records which XDPoS, V2, V2Config, and ExpTimeoutConfig
// keys were present so BackfillMissingFieldsFrom can copy only omitted nested
// fields from a source config into the destination while preserving explicit
// zero and null values; CloneForBackfill is the fallback for programmatic
// configs that need inferred presence before that copy. The legacy
// BackfillCustomMigratedFieldsFrom path reaches into this tree only for the
// historical MaxMasternodesV2 migration and does not hydrate the broader XDPoS
// schedule.

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"strings"
	"sync"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/log"
)

// DefaultXDPoSEpoch is the epoch length the XDPoS engine fills in when a chain
// config leaves XDPoS.Epoch unset. Chain config validation, the genesis load and
// setup paths, and the engine all judge an omitted epoch against this value, so
// the definition is shared instead of owned by the engine.
const DefaultXDPoSEpoch uint64 = 900

// XDPoSConfig is the consensus engine configs for delegated-proof-of-stake based sealing.
type XDPoSConfig struct {
	Period               uint64         `json:"period"`               // Number of seconds between blocks to enforce
	Epoch                uint64         `json:"epoch"`                // Epoch length to reset votes and checkpoint
	Reward               uint64         `json:"reward"`               // Block reward - unit Ether
	RewardCheckpoint     uint64         `json:"rewardCheckpoint"`     // Checkpoint block for calculate rewards.
	Gap                  uint64         `json:"gap"`                  // Gap time preparing for the next epoch
	FoundationWalletAddr common.Address `json:"foundationWalletAddr"` // Foundation Address Wallet
	MaxMasternodesV2     int            `json:"maxMasternodesV2"`     // Last v1 masternodes after TIPIncrease
	SkipV1Validation     bool           //Skip Block Validation for testing purpose, V1 consensus only
	V2                   *V2            `json:"v2"`

	json jsonFieldPresence `json:"-"`

	// epochFilledByEngine records that this config's epoch is the default
	// ChainConfig.ResolveXDPoSEpoch filled in because the source left it unset,
	// rather than a value the source wrote. It is process-local: the marshalled form
	// always writes the epoch out, so the state does not survive a JSON round-trip
	// and a config read back from storage is treated as written. Clone copies it
	// along with the rest of the struct, which pins the one invariant its reader
	// relies on: a config the resolution produced must not be cloned and then have its
	// Epoch rewritten, because core.chainConfigAsStored reads this record to restore
	// the epoch to 0 when it persists the config, so such a rewrite would be stored as
	// an unset epoch instead of the value the caller wrote.
	epochFilledByEngine bool
}

// GapOffset returns the offset of the gap block inside an epoch and whether the
// schedule designates one of its own: Gap has to be a strictly positive offset
// smaller than Epoch, so that Epoch-Gap resolves to a block strictly inside the
// epoch. An unset Epoch never designates one either, because Gap >= Epoch holds
// for every Gap once Epoch is 0, and Epoch == 1 designates none because the
// interval 1 <= Gap < Epoch is empty there.
//
// This is the definition of "does this schedule designate a gap block" shared by
// chain config validation and the v2 gap paths that route through it,
// UpdateMasternodes and the gap snapshot repair. Callers that treat an unset
// Epoch as "wait for the engine default" instead of as invalid have to check
// Epoch themselves, which CheckConfigForkOrder does; GapBlockNumber below
// carries that same check to the paths that resolve a height to the gap block.
//
// The judgement is about the v2 gap trigger n%Epoch == Epoch-Gap. Gap == 0 never
// satisfies it, and Gap > Epoch underflows the subtraction, so CheckConfigForkOrder
// rejects a schedule whose trigger matches no height at all: it can never derive
// the next-epoch masternode set. The v1 snapshot checkpoint predicate
// (n+Gap)%Epoch == 0 does match at Gap == 0, so the rejection is a deliberate
// policy for the v2 schedule every XDPoS chain carries, not a claim that Gap == 0
// never matches anywhere in the engine. Gap == Epoch is refused by the same
// policy, and there the trigger does match: it names the epoch switch block
// itself, so the block that samples the next-epoch candidate set is the block
// that consumes it, and the v1 checkpoint predicate lands on that same height.
// No built-in network uses that schedule.
func (c *XDPoSConfig) GapOffset() (uint64, bool) {
	if c == nil || c.Gap == 0 || c.Gap >= c.Epoch {
		return 0, false
	}
	return c.Epoch - c.Gap, true
}

// SwitchBlockAligned reports whether block is a switch block the v2 alignment rule
// accepts for epoch, i.e. a non-negative multiple of a non-zero epoch. A nil or
// negative block, or an unset epoch, names no boundary and answers false.
//
// This is the single definition of that judgement: CheckSwitchBlockAlignment judges
// a config by it, and the puppeth wizard judges the answer to its switch block
// question by it, so the two cannot drift apart. It runs on the big.Int rather than
// on a uint64 form because block.Uint64() folds every bit above 2^64 away, which
// could make a height that does not fit in a uint64 look aligned to the epoch while
// the height the chain carries is not.
//
// Callers that treat an unset epoch as "wait for the engine default" instead of as
// invalid have to check Epoch themselves, which CheckSwitchBlockAlignment does;
// answering false here is what keeps this predicate total for the others.
func SwitchBlockAligned(block *big.Int, epoch uint64) bool {
	if block == nil || block.Sign() < 0 || epoch == 0 {
		return false
	}
	return new(big.Int).Mod(block, new(big.Int).SetUint64(epoch)).Sign() == 0
}

// SwitchEpochFor returns the epoch number a switch block falls on under epoch, i.e.
// block/epoch, and whether that number fits in a uint64, i.e. whether
// XDPoS.V2.SwitchEpoch can equal it. It is the single definition of the pairing
// rule: CheckV2SwitchEpochAlignment compares a config against the want it returns,
// and the puppeth wizard stores the uint64 form it returns, so the value the wizard
// writes is the value the validation re-derives.
//
// The judgement runs on the big.Int, so want is the epoch the switch block really
// falls on rather than the one its low 64 bits name; a want that no uint64 can hold
// names an epoch SwitchEpoch can never equal, which fits reports as false.
//
// A nil block or an unset epoch names no epoch and returns (nil, false). A negative
// block is still divided - big.Int.Div is Euclidean, so the sign is kept - and
// returns a want that fits reports as false; judging the sign is not this rule's
// job, so checkV2SwitchBlockSign owns it.
func SwitchEpochFor(block *big.Int, epoch uint64) (*big.Int, bool) {
	if block == nil || epoch == 0 {
		return nil, false
	}
	want := new(big.Int).Div(block, new(big.Int).SetUint64(epoch))
	return want, want.IsUint64()
}

// GapBlockNumber returns the gap block that governs the epoch containing
// number, and whether the schedule designates one at all. It resolves number to
// its epoch start and then steps back by Gap.
//
// An epoch that starts no farther than Gap into the chain has no earlier gap
// block, and the answer is then the first block of the chain. That 0 is a fallback
// for the chain start rather than a height the trigger selects: the trigger matches
// number%Epoch == Epoch-Gap, and GapOffset keeps Epoch-Gap inside [1, Epoch-1], so
// a residue of 0 - block 0 included - never matches.
//
// This is the height-side counterpart of GapOffset and the single definition
// behind getSnapshot, verifyQC, sendVote and sendTimeout. Like GapOffset it
// refuses a schedule that designates no gap block, so those callers can report
// an unusable schedule instead of reading a height the schedule never selects or
// dividing by an unset Epoch.
func (c *XDPoSConfig) GapBlockNumber(number uint64) (uint64, bool) {
	if _, ok := c.GapOffset(); !ok {
		return 0, false
	}
	epochStart := number - number%c.Epoch
	if epochStart > c.Gap {
		return epochStart - c.Gap, true
	}
	return 0, true
}

// IsGapBlock reports whether the given canonical block number is the gap block
// the v2 trigger selects, i.e. whether number%Epoch == Epoch-Gap holds for it.
//
// GapOffset owns the judgement of whether the schedule designates a gap block at
// all, so a schedule without one never matches here; that also covers Epoch == 0,
// which would otherwise divide by zero. This is the single definition behind both
// core's shouldUpdateM1 and the v2 engine's UpdateMasternodes: block production
// and block import ask exactly the same question about the same height, and two
// copies of the expression drifting apart would show up as the two sides
// disagreeing about which height carries the next-epoch masternode update.
func (c *XDPoSConfig) IsGapBlock(number uint64) bool {
	offset, ok := c.GapOffset()
	return ok && number%c.Epoch == offset
}

// IsLendingLiquidationBlock reports whether the given canonical block number is
// the height XDCxlending liquidates open trades at, i.e. number%Epoch ==
// common.LiquidateLendingTradeBlock.
//
// Like the other schedule predicates the judgement comes before the division, so
// an unset epoch answers false rather than dividing by zero: the guard that admits
// the callers' branch only skips blocks at or below the epoch, which an unset
// epoch does not cover for a real block.
//
// Block production and block import both ask this question about the same height -
// the miner decides whether to attach the liquidation work, the importer decides
// whether to expect it - so the two sides have to share one definition. A
// divergence would not fail loudly: it would leave the producer and the validator
// with different state roots, which is the same shape as a consensus fault.
func (c *XDPoSConfig) IsLendingLiquidationBlock(number uint64) bool {
	if c == nil || c.Epoch == 0 {
		return false
	}
	return number%c.Epoch == common.LiquidateLendingTradeBlock
}

// IsSameEpoch reports whether the two canonical block heights fall inside the same
// chain epoch, the question XDCxlending asks to tell whether a price a contract
// recorded is still current for the header being processed.
//
// Like the other schedule predicates the judgement comes before the division, so a
// missing XDPoS section or an unset epoch answers false instead of dividing by
// zero. The open-coded divisions this replaces carried no such guard; they were
// safe only because newBlockChain refuses an unset epoch, which a BlockChain built
// inside core can bypass.
func (c *XDPoSConfig) IsSameEpoch(first, second uint64) bool {
	if c == nil || c.Epoch == 0 {
		return false
	}
	return first/c.Epoch == second/c.Epoch
}

// EpochFilledByEngine reports whether this config's epoch is one the resolution
// filled in rather than a value the source wrote. An omitted epoch is a valid state
// - validation deliberately leaves it for the engine - so the struct alone cannot
// tell "the source never wrote an epoch and the default was filled in" from "the
// source wrote this epoch"; the state ChainConfig.ResolveXDPoSEpoch records can.
//
// The judgement reads that state rather than the source JSON keys, so it depends on
// how the config was resolved rather than on which keys the file happened to spell
// out: a config that never went through the resolution answers false whatever its
// source carried, which keeps the conservative reading that a value nobody is known
// to have defaulted is treated as written.
//
// The state is process-local. Marshalling always writes "epoch" out, so a config
// that has been through a database round-trip carries no such record and answers
// false even when the value is the one that was filled in. Such a config is read the
// same way as one that was never resolved - treated as written - which makes this a
// marker for the in-flight config the callers hold rather than a property that
// survives storage.
func (c *XDPoSConfig) EpochFilledByEngine() bool {
	if c == nil || c.Epoch == 0 {
		return false
	}
	return c.epochFilledByEngine
}

// UnmarshalJSON supports both the current and legacy typo-ed JSON key for
// foundation wallet address to keep old on-disk chain configs compatible.
//
// The section is replaced, not merged, so the process-local record
// EpochFilledByEngine reads is cleared the way ChainConfig.UnmarshalJSON clears
// its runtime-only metadata: the marshalled form always spells the epoch out, so
// a value that arrives through JSON was written by the source and must not keep
// being treated as one the resolution filled in for it. Without the reset the
// record would only be dropped when the receiver happens to be a zero value,
// which is a property of the caller rather than of this method.
func (c *XDPoSConfig) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	type xdpJSON struct {
		Period                    uint64         `json:"period"`
		Epoch                     uint64         `json:"epoch"`
		Reward                    uint64         `json:"reward"`
		RewardCheckpoint          uint64         `json:"rewardCheckpoint"`
		Gap                       uint64         `json:"gap"`
		MaxMasternodesV2          int            `json:"maxMasternodesV2"`
		FoundationWalletAddr      common.Address `json:"foundationWalletAddr"`
		LegacyFoudationWalletAddr common.Address `json:"foudationWalletAddr"`
		SkipV1Validation          bool           `json:"SkipV1Validation"`
		V2                        *V2            `json:"v2"`
	}
	var decoded xdpJSON
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	c.Period = decoded.Period
	c.Epoch = decoded.Epoch
	c.Reward = decoded.Reward
	c.RewardCheckpoint = decoded.RewardCheckpoint
	c.Gap = decoded.Gap
	c.MaxMasternodesV2 = decoded.MaxMasternodesV2
	c.FoundationWalletAddr = decoded.FoundationWalletAddr
	if c.FoundationWalletAddr.IsZero() && !decoded.LegacyFoudationWalletAddr.IsZero() {
		c.FoundationWalletAddr = decoded.LegacyFoudationWalletAddr
	}
	c.SkipV1Validation = decoded.SkipV1Validation
	c.V2 = decoded.V2
	// Cleared after the fields are assigned, so a decode that fails before this
	// point leaves the receiver as it was rather than half-replaced.
	c.epochFilledByEngine = false
	c.json.capture(raw)

	return nil
}

// V2 stores the round-indexed XDPoS v2 runtime configs.
//
// BuildConfigIndex is the freeze point for AllConfigs. Callers must finish
// populating AllConfigs before calling BuildConfigIndex and before exposing v2
// for concurrent use. After BuildConfigIndex returns, AllConfigs, its map keys,
// and the pointed *V2Config values are treated as immutable and must not be
// mutated, replaced, added, or deleted.
//
// The lock protects read/write access to CurrentConfig and configIndex, plus
// map traversal of AllConfigs. The only allowed concurrent write after
// BuildConfigIndex is swapping CurrentConfig to point at one of the prebuilt
// immutable entries, and that pointer replacement must hold v2.lock with Lock.
// Read APIs such as Clone, GetCurrentConfig and Config take the read lock and
// return clones so callers cannot mutate shared state. WithReadOnlySnapshot
// must likewise hand out a deep-copy snapshot rather than shared internal
// pointers, maps, or slices.
type V2 struct {
	lock sync.RWMutex // Protects CurrentConfig, configIndex, and AllConfigs traversal

	SwitchEpoch   uint64               `json:"switchEpoch"`
	SwitchBlock   *big.Int             `json:"switchBlock"`
	CurrentConfig *V2Config            `json:"config"`
	AllConfigs    map[uint64]*V2Config `json:"allConfigs"`
	configIndex   []uint64             // list of switch block of configs

	json jsonFieldPresence `json:"-"`
}

type V2Config struct {
	MaxMasternodes       int     `json:"maxMasternodes"`       // v2 max masternodes
	MaxProtectorNodes    int     `json:"maxProtectorNodes"`    // v2 max ProtectorNodes
	MaxObserverNodes     int     `json:"maxObserverNodes"`     // v2 max ObserverNodes
	SwitchRound          uint64  `json:"switchRound"`          // v1 to v2 switch block number
	MinePeriod           int     `json:"minePeriod"`           // Miner mine period to mine a block
	TimeoutSyncThreshold int     `json:"timeoutSyncThreshold"` // send syncInfo after number of timeout
	TimeoutPeriod        int     `json:"timeoutPeriod"`        // Duration in ms
	CertThreshold        float64 `json:"certificateThreshold"` // Necessary number of messages from master nodes to form a certificate

	MasternodeReward float64 `json:"masternodeReward"` // Block reward per master node (core validator) - unit Ether
	ProtectorReward  float64 `json:"protectorReward"`  // Block reward per protector - unit Ether
	ObserverReward   float64 `json:"observerReward"`   // Block reward per observer - unit Ether

	MinimumMinerBlockPerEpoch int `json:"minimumMinerBlockPerEpoch"` // Minimum block per epoch for a miner to not be penalized
	LimitPenaltyEpoch         int `json:"limitPenaltyEpoch"`         // Epochs in a row that a penalty node needs to be penalized
	MinimumSigningTx          int `json:"minimumSigningTx"`          // Signing txs that a node needs to produce to get out of penalty, after `LimitPenaltyEpoch`

	ExpTimeoutConfig ExpTimeoutConfig `json:"expTimeoutConfig"`

	json jsonFieldPresence `json:"-"`
}

type ExpTimeoutConfig struct {
	Base        float64 `json:"base"`        // base in base^exponent
	MaxExponent uint8   `json:"maxExponent"` // max exponent in base^exponent

	json jsonFieldPresence `json:"-"`
}

// UnmarshalJSON captures raw key presence for later v2 backfill decisions.
// It supports both "switchEpoch" and legacy "SwitchEpoch" JSON keys for compatibility.
func (v2 *V2) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	type v2Alias struct {
		SwitchEpoch       uint64               `json:"switchEpoch"`
		LegacySwitchEpoch uint64               `json:"SwitchEpoch"`
		SwitchBlock       *big.Int             `json:"switchBlock"`
		CurrentConfig     *V2Config            `json:"config"`
		AllConfigs        map[uint64]*V2Config `json:"allConfigs"`
		configIndex       []uint64             // not from JSON, but for completeness
	}
	var decoded v2Alias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	// Prefer new key, fallback to legacy if zero
	v2.SwitchEpoch = decoded.SwitchEpoch
	if v2.SwitchEpoch == 0 && decoded.LegacySwitchEpoch != 0 {
		v2.SwitchEpoch = decoded.LegacySwitchEpoch
	}
	v2.SwitchBlock = decoded.SwitchBlock
	v2.CurrentConfig = decoded.CurrentConfig
	v2.AllConfigs = decoded.AllConfigs
	v2.configIndex = decoded.configIndex
	v2.json.capture(raw)
	return nil
}

// UnmarshalJSON captures raw key presence for later v2 config backfill decisions.
func (c *V2Config) UnmarshalJSON(data []byte) error {
	type v2ConfigAlias V2Config
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var decoded v2ConfigAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*c = V2Config(decoded)
	c.json.capture(raw)
	return nil
}

// UnmarshalJSON captures raw key presence for later timeout backfill decisions.
func (c *ExpTimeoutConfig) UnmarshalJSON(data []byte) error {
	type expTimeoutConfigAlias ExpTimeoutConfig
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var decoded expTimeoutConfigAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*c = ExpTimeoutConfig(decoded)
	c.json.capture(raw)
	return nil
}

// Clone returns an independent copy of the v2 config.
func (c *V2Config) Clone() *V2Config {
	if c == nil {
		return nil
	}
	clone := *c
	clone.ExpTimeoutConfig.json = c.ExpTimeoutConfig.json.clone()
	clone.json = c.json.clone()
	return &clone
}

// cloneWithInferredFieldPresence marks only non-zero ExpTimeoutConfig fields as
// explicitly present.
func (c *ExpTimeoutConfig) cloneWithInferredFieldPresence() *ExpTimeoutConfig {
	if c == nil {
		return nil
	}
	clone := *c
	clone.json.startInferredTracking()
	if clone.Base != 0 {
		clone.json.mark("base")
	}
	if clone.MaxExponent != 0 {
		clone.json.mark("maxExponent")
	}
	return &clone
}

// cloneWithInferredFieldPresence marks only non-zero V2Config fields as
// explicitly present so partial programmatic configs can still inherit
// defaults during backfill.
func (c *V2Config) cloneWithInferredFieldPresence() *V2Config {
	if c == nil {
		return nil
	}
	clone := c.Clone()
	clone.json.startInferredTracking()

	intFields := []struct {
		key string
		val int
	}{
		{"maxMasternodes", clone.MaxMasternodes},
		{"maxProtectorNodes", clone.MaxProtectorNodes},
		{"maxObserverNodes", clone.MaxObserverNodes},
		{"minePeriod", clone.MinePeriod},
		{"timeoutSyncThreshold", clone.TimeoutSyncThreshold},
		{"timeoutPeriod", clone.TimeoutPeriod},
		{"minimumMinerBlockPerEpoch", clone.MinimumMinerBlockPerEpoch},
		{"limitPenaltyEpoch", clone.LimitPenaltyEpoch},
		{"minimumSigningTx", clone.MinimumSigningTx},
	}
	for _, field := range intFields {
		if field.val != 0 {
			clone.json.mark(field.key)
		}
	}
	if clone.SwitchRound != 0 {
		clone.json.mark("switchRound")
	}
	floatFields := []struct {
		key string
		val float64
	}{
		{"certificateThreshold", clone.CertThreshold},
		{"masternodeReward", clone.MasternodeReward},
		{"protectorReward", clone.ProtectorReward},
		{"observerReward", clone.ObserverReward},
	}
	for _, field := range floatFields {
		if field.val != 0 {
			clone.json.mark(field.key)
		}
	}
	clone.ExpTimeoutConfig = *clone.ExpTimeoutConfig.cloneWithInferredFieldPresence()
	if len(clone.ExpTimeoutConfig.json.keys) > 0 {
		clone.json.mark("expTimeoutConfig")
	}
	return clone
}

// cloneWithInferredFieldPresence marks only populated V2 fields as explicitly
// present, which keeps absent fields eligible for later default backfill.
func (v2 *V2) cloneWithInferredFieldPresence() *V2 {
	if v2 == nil {
		return nil
	}
	clone := v2.Clone()
	clone.json.startInferredTracking()
	if clone.SwitchEpoch != 0 {
		clone.json.mark("switchEpoch")
	}
	if clone.SwitchBlock != nil {
		clone.json.mark("switchBlock")
	}
	if clone.CurrentConfig != nil {
		clone.json.mark("config")
		clone.CurrentConfig = clone.CurrentConfig.cloneWithInferredFieldPresence()
	}
	if len(clone.AllConfigs) > 0 {
		clone.json.mark("allConfigs")
		for key, cfg := range clone.AllConfigs {
			clone.AllConfigs[key] = cfg.cloneWithInferredFieldPresence()
		}
	}
	return clone
}

// Clone returns a read-locked deep copy of the V2 state.
// It clones the current config, indexed configs and key order so callers can
// safely mutate the returned copy without affecting the shared runtime state.
func (v2 *V2) Clone() *V2 {
	if v2 == nil {
		return nil
	}
	v2.lock.RLock()
	defer v2.lock.RUnlock()

	clone := &V2{
		SwitchEpoch: v2.SwitchEpoch,
		SwitchBlock: common.CloneBigInt(v2.SwitchBlock),
	}
	clone.json = v2.json.clone()
	if v2.CurrentConfig != nil {
		clone.CurrentConfig = v2.CurrentConfig.Clone()
	}
	if v2.AllConfigs != nil {
		clone.AllConfigs = make(map[uint64]*V2Config, len(v2.AllConfigs))
		for key, cfg := range v2.AllConfigs {
			clone.AllConfigs[key] = cfg.Clone()
		}
	}
	if v2.configIndex != nil {
		clone.configIndex = append([]uint64(nil), v2.configIndex...)
	}
	return clone
}

// Clone returns an independent copy of the XDPoS config.
func (c *XDPoSConfig) Clone() *XDPoSConfig {
	if c == nil {
		return nil
	}
	clone := *c
	clone.V2 = c.V2.Clone()
	clone.json = c.json.clone()
	return &clone
}

func XDPoSConfigEqual(a, b *XDPoSConfig) bool {
	if a == nil || b == nil {
		if a != b {
			log.Warn("[XDPoSConfigEqual] One of the configs is nil", "a", a, "b", b)
			return false
		}
		return true
	}
	if a.Period != b.Period {
		log.Warn("[XDPoSConfigEqual] Period mismatch", "a.Period", a.Period, "b.Period", b.Period)
		return false
	}
	if a.Epoch != b.Epoch {
		log.Warn("[XDPoSConfigEqual] Epoch mismatch", "a.Epoch", a.Epoch, "b.Epoch", b.Epoch)
		return false
	}
	if a.Reward != b.Reward {
		log.Warn("[XDPoSConfigEqual] Reward mismatch", "a.Reward", a.Reward, "b.Reward", b.Reward)
		return false
	}
	if a.RewardCheckpoint != b.RewardCheckpoint {
		log.Warn("[XDPoSConfigEqual] RewardCheckpoint mismatch", "a.RewardCheckpoint", a.RewardCheckpoint, "b.RewardCheckpoint", b.RewardCheckpoint)
		return false
	}
	if a.Gap != b.Gap {
		log.Warn("[XDPoSConfigEqual] Gap mismatch", "a.Gap", a.Gap, "b.Gap", b.Gap)
		return false
	}
	if a.FoundationWalletAddr != b.FoundationWalletAddr {
		log.Warn("[XDPoSConfigEqual] FoundationWalletAddr mismatch", "a.FoundationWalletAddr", a.FoundationWalletAddr.Hex(), "b.FoundationWalletAddr", b.FoundationWalletAddr.Hex())
		return false
	}
	if a.MaxMasternodesV2 != b.MaxMasternodesV2 {
		log.Warn("[XDPoSConfigEqual] MaxMasternodesV2 mismatch", "a.MaxMasternodesV2", a.MaxMasternodesV2, "b.MaxMasternodesV2", b.MaxMasternodesV2)
		return false
	}
	if a.SkipV1Validation != b.SkipV1Validation {
		log.Warn("[XDPoSConfigEqual] SkipV1Validation mismatch", "a.SkipV1Validation", a.SkipV1Validation, "b.SkipV1Validation", b.SkipV1Validation)
		return false
	}
	return V2Equal(a.V2, b.V2)
}

func V2Equal(a, b *V2) bool {
	if a == nil || b == nil {
		if a != b {
			log.Warn("[V2Equal] One of the configs is nil", "a", a, "b", b)
			return false
		}
		return true
	}
	left := snapshotV2ReadOnly(a)
	right := snapshotV2ReadOnly(b)
	if left.switchEpoch != right.switchEpoch {
		log.Warn("[V2Equal] SwitchEpoch mismatch", "a.SwitchEpoch", left.switchEpoch, "b.SwitchEpoch", right.switchEpoch)
		return false
	}
	if !configNumEqual(left.switchBlock, right.switchBlock) {
		log.Warn("[V2Equal] SwitchBlock mismatch", "a.SwitchBlock", left.switchBlock, "b.SwitchBlock", right.switchBlock)
		return false
	}
	// Only check configs in both of AllConfigs
	for k1, cfg1 := range left.allConfigs {
		if cfg2, ok := right.allConfigs[k1]; ok {
			if !V2ConfigEqual(cfg1, cfg2) {
				return false
			}
		}
	}
	return true
}

func V2ConfigEqual(a, b *V2Config) bool {
	if a == nil || b == nil {
		if a != b {
			log.Warn("[V2ConfigEqual] One of the configs is nil", "a", a, "b", b)
			return false
		}
		return true
	}
	if a.MaxMasternodes != b.MaxMasternodes {
		log.Warn("[V2ConfigEqual] MaxMasternodes mismatch", "a.MaxMasternodes", a.MaxMasternodes, "b.MaxMasternodes", b.MaxMasternodes)
		return false
	}
	if a.SwitchRound != b.SwitchRound {
		log.Warn("[V2ConfigEqual] SwitchRound mismatch", "a.SwitchRound", a.SwitchRound, "b.SwitchRound", b.SwitchRound)
		return false
	}
	if a.CertThreshold != b.CertThreshold {
		log.Warn("[V2ConfigEqual] CertThreshold mismatch", "a.CertThreshold", a.CertThreshold, "b.CertThreshold", b.CertThreshold)
		return false
	}
	return true
}

func sameV2RuntimeConfig(a, b *V2Config) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.MaxMasternodes == b.MaxMasternodes &&
		a.MaxProtectorNodes == b.MaxProtectorNodes &&
		a.MaxObserverNodes == b.MaxObserverNodes &&
		a.SwitchRound == b.SwitchRound &&
		a.MinePeriod == b.MinePeriod &&
		a.TimeoutSyncThreshold == b.TimeoutSyncThreshold &&
		a.TimeoutPeriod == b.TimeoutPeriod &&
		a.CertThreshold == b.CertThreshold &&
		a.MasternodeReward == b.MasternodeReward &&
		a.ProtectorReward == b.ProtectorReward &&
		a.ObserverReward == b.ObserverReward &&
		a.MinimumMinerBlockPerEpoch == b.MinimumMinerBlockPerEpoch &&
		a.LimitPenaltyEpoch == b.LimitPenaltyEpoch &&
		a.MinimumSigningTx == b.MinimumSigningTx &&
		a.ExpTimeoutConfig.Base == b.ExpTimeoutConfig.Base &&
		a.ExpTimeoutConfig.MaxExponent == b.ExpTimeoutConfig.MaxExponent
}

func (c *XDPoSConfig) String() string {
	if c == nil {
		return "XDPoSConfig: <nil>"
	}

	return fmt.Sprintf("XDPoSConfig{Period: %v, Epoch: %v, Reward: %v, RewardCheckpoint: %v, Gap: %v, MaxMasternodesV2: %v, FoundationWalletAddr: %v, SkipV1Validation: %v, V2: %s}", c.Period, c.Epoch, c.Reward, c.RewardCheckpoint, c.Gap, c.MaxMasternodesV2, c.FoundationWalletAddr.String0x(), c.SkipV1Validation, c.V2.String())
}

// Description returns a human-readable description of XDPoSConfig
// NOTE: don't append "\n" to end
func (c *XDPoSConfig) Description(indent int) string {
	if c == nil {
		return "XDPoS: <nil>"
	}

	banner := "XDPoS\n"
	prefix := strings.Repeat(" ", indent)
	banner += fmt.Sprintf("%s- Period: %v\n", prefix, c.Period)
	banner += fmt.Sprintf("%s- Epoch: %v\n", prefix, c.Epoch)
	banner += fmt.Sprintf("%s- Reward: %v\n", prefix, c.Reward)
	banner += fmt.Sprintf("%s- RewardCheckpoint: %v\n", prefix, c.RewardCheckpoint)
	banner += fmt.Sprintf("%s- Gap: %v\n", prefix, c.Gap)
	banner += fmt.Sprintf("%s- MaxMasternodesV2: %v\n", prefix, c.MaxMasternodesV2)
	banner += fmt.Sprintf("%s- FoundationWalletAddr: %v\n", prefix, c.FoundationWalletAddr.Hex())
	banner += fmt.Sprintf("%s- SkipV1Validation: %v\n", prefix, c.SkipV1Validation)
	banner += fmt.Sprintf("%s- %s", prefix, c.V2.Description(indent+2))
	return banner
}

func (v2 *V2) String() string {
	if v2 == nil {
		return "V2: <nil>"
	}
	snapshot := snapshotV2ReadOnly(v2)
	return fmt.Sprintf("V2{SwitchEpoch: %v, SwitchBlock: %v, %s}", snapshot.switchEpoch, snapshot.switchBlock, snapshot.currentConfig.String())
}

type stableLogConfigEntry struct {
	Round  uint64    `json:"round"`
	Config *V2Config `json:"config"`
}

type stableLogView struct {
	SwitchEpoch   uint64                 `json:"switchEpoch"`
	SwitchBlock   string                 `json:"switchBlock"`
	CurrentConfig *V2Config              `json:"currentConfig"`
	AllConfigs    []stableLogConfigEntry `json:"allConfigs"`
	ConfigIndex   []uint64               `json:"configIndex"`
}

// StableLogValue returns a full, deterministic structured value for startup
// logs. Callers can pass the returned object directly as a field value to
// avoid JSON string escaping in terminal log output.
func (v2 *V2) StableLogValue() stableLogView {
	if v2 == nil {
		return stableLogView{}
	}

	snapshot := snapshotV2ReadOnly(v2)

	keys := slices.Collect(maps.Keys(snapshot.allConfigs))
	slices.Sort(keys)

	allConfigs := make([]stableLogConfigEntry, 0, len(keys))
	for _, round := range keys {
		allConfigs = append(allConfigs, stableLogConfigEntry{
			Round:  round,
			Config: snapshot.allConfigs[round].Clone(),
		})
	}

	var switchBlock string
	if snapshot.switchBlock != nil {
		switchBlock = snapshot.switchBlock.String()
	}

	return stableLogView{
		SwitchEpoch:   snapshot.switchEpoch,
		SwitchBlock:   switchBlock,
		CurrentConfig: snapshot.currentConfig.Clone(),
		AllConfigs:    allConfigs,
		ConfigIndex:   append([]uint64(nil), snapshot.configIndex...),
	}
}

// Description returns a human-readable description of V2
// NOTE: don't append "\n" to end
func (v2 *V2) Description(indent int) string {
	if v2 == nil {
		return "V2: <nil>"
	}
	snapshot := snapshotV2ReadOnly(v2)

	banner := "V2:\n"
	prefix := strings.Repeat(" ", indent)
	banner += fmt.Sprintf("%s- SwitchEpoch: %v\n", prefix, snapshot.switchEpoch)
	banner += fmt.Sprintf("%s- SwitchBlock: %v\n", prefix, snapshot.switchBlock)
	banner += fmt.Sprintf("%s- %s", prefix, snapshot.currentConfig.Description("CurrentConfig", indent+2))
	return banner
}

func (c *V2Config) String() string {
	if c == nil {
		return "V2Config: <nil>"
	}

	return fmt.Sprintf("V2Config{MaxMasternodes: %v, MaxProtectorNodes: %v, MaxObserverNodes: %v, SwitchRound: %v, MinePeriod: %v, TimeoutSyncThreshold: %v, TimeoutPeriod: %v, CertThreshold: %v, MasternodeReward: %v, ProtectorReward: %v, ObserverReward: %v, MinimumMinerBlockPerEpoch: %v, LimitPenaltyEpoch: %v, MinimumSigningTx: %v, %s}", c.MaxMasternodes, c.MaxProtectorNodes, c.MaxObserverNodes, c.SwitchRound, c.MinePeriod, c.TimeoutSyncThreshold, c.TimeoutPeriod, c.CertThreshold, c.MasternodeReward, c.ProtectorReward, c.ObserverReward, c.MinimumMinerBlockPerEpoch, c.LimitPenaltyEpoch, c.MinimumSigningTx, c.ExpTimeoutConfig.String())
}

// Description returns a human-readable description of V2Config
// NOTE: don't append "\n" to end
func (c *V2Config) Description(name string, indent int) string {
	if c == nil {
		return name + ": <nil>"
	}

	banner := name + ":\n"
	prefix := strings.Repeat(" ", indent)
	banner += fmt.Sprintf("%s- MaxMasternodes: %v\n", prefix, c.MaxMasternodes)
	banner += fmt.Sprintf("%s- SwitchRound: %v\n", prefix, c.SwitchRound)
	banner += fmt.Sprintf("%s- MinePeriod: %v\n", prefix, c.MinePeriod)
	banner += fmt.Sprintf("%s- TimeoutSyncThreshold: %v\n", prefix, c.TimeoutSyncThreshold)
	banner += fmt.Sprintf("%s- TimeoutPeriod: %v\n", prefix, c.TimeoutPeriod)
	banner += fmt.Sprintf("%s- CertThreshold: %v\n", prefix, c.CertThreshold)
	banner += fmt.Sprintf("%s- MasternodeReward: %v\n", prefix, c.MasternodeReward)
	banner += fmt.Sprintf("%s- ProtectorReward: %v\n", prefix, c.ProtectorReward)
	banner += fmt.Sprintf("%s- ObserverReward: %v\n", prefix, c.ObserverReward)
	banner += fmt.Sprintf("%s- MinimumMinerBlockPerEpoch: %v\n", prefix, c.MinimumMinerBlockPerEpoch)
	banner += fmt.Sprintf("%s- LimitPenaltyEpoch: %v\n", prefix, c.LimitPenaltyEpoch)
	banner += fmt.Sprintf("%s- MinimumSigningTx: %v\n", prefix, c.MinimumSigningTx)
	banner += fmt.Sprintf("%s- ExpTimeoutBase: %v\n", prefix, c.ExpTimeoutConfig.Base)
	banner += fmt.Sprintf("%s- ExpTimeoutMaxExponent: %v", prefix, c.ExpTimeoutConfig.MaxExponent)
	return banner
}

func (c ExpTimeoutConfig) String() string {
	return fmt.Sprintf("ExpTimeoutConfig{Base: %v, MaxExponent: %v}", c.Base, c.MaxExponent)
}

func (c *XDPoSConfig) BlockConsensusVersion(num *big.Int) string {
	if c.V2 != nil && c.V2.SwitchBlock != nil && num.Cmp(c.V2.SwitchBlock) > 0 {
		return ConsensusEngineVersion2
	}
	return ConsensusEngineVersion1
}

// UpdateConfig repoints CurrentConfig to the indexed config that applies at
// round. It assumes BuildConfigIndex has already been called and that
// AllConfigs entries are immutable once v2 is exposed to concurrent readers.
func (v2 *V2) UpdateConfig(round uint64) {
	v2.lock.Lock()
	defer v2.lock.Unlock()

	var index uint64

	//find the right config
	for i := range v2.configIndex {
		if v2.configIndex[i] <= round {
			index = v2.configIndex[i]
			break
		}
	}
	// update to current config
	log.Info("[updateV2Config] Update config", "index", index, "round", round, "SwitchRound", v2.AllConfigs[index].SwitchRound)
	v2.CurrentConfig = v2.AllConfigs[index]
}

// GetCurrentConfig returns a deep copy of the current config. It assumes v2 is
// not nil and relies on AllConfigs entries remaining immutable after
// BuildConfigIndex, apart from CurrentConfig being repointed under UpdateConfig.
func (v2 *V2) GetCurrentConfig() *V2Config {
	v2.lock.RLock()
	defer v2.lock.RUnlock()

	if v2.CurrentConfig == nil {
		return nil
	}

	// Return a clone so callers cannot mutate shared nested metadata maps.
	return v2.CurrentConfig.Clone()
}

// Config returns a deep copy of the v2 config that applies at the given round.
// It relies on AllConfigs entries being immutable once BuildConfigIndex has
// finished, apart from CurrentConfig being repointed under UpdateConfig.
func (v2 *V2) Config(round uint64) *V2Config {
	v2.lock.RLock()
	defer v2.lock.RUnlock()

	configRound := round
	var index uint64

	//find the right config
	for i := range v2.configIndex {
		if v2.configIndex[i] <= configRound {
			index = v2.configIndex[i]
			break
		}
	}

	// Return a clone so callers cannot mutate shared nested metadata maps.
	return v2.AllConfigs[index].Clone()
}

// BuildConfigIndex snapshots the current AllConfigs keys into descending round
// order for later lookups. Callers are expected to finish populating AllConfigs
// before exposing v2 for concurrent use; after this point, the map entries and
// pointed *V2Config values are treated as immutable.
func (v2 *V2) BuildConfigIndex() {
	v2.lock.Lock()
	defer v2.lock.Unlock()

	list := slices.Collect(maps.Keys(v2.AllConfigs))
	// Make it descending order
	slices.SortFunc(list, func(a, b uint64) int {
		return cmp.Compare(b, a)
	})
	log.Info("[BuildConfigIndex] config list", "list", list)
	v2.configIndex = list
}

// ConfigIndex returns a copy of the cached descending config-index list built
// from AllConfigs.
func (v2 *V2) ConfigIndex() []uint64 {
	v2.lock.RLock()
	defer v2.lock.RUnlock()

	if v2.configIndex == nil {
		return nil
	}
	return append([]uint64(nil), v2.configIndex...)
}

// WithReadOnlySnapshot invokes fn with a detached deep copy of the V2 state.
// The callback receives stable snapshot data for read-only workflows such as
// hashing without exposing shared internal pointers, maps, or slices.
func (v2 *V2) WithReadOnlySnapshot(fn func(switchEpoch uint64, switchBlock *big.Int, currentConfig *V2Config, allConfigs map[uint64]*V2Config, configIndex []uint64)) {
	if v2 == nil {
		fn(0, nil, nil, nil, nil)
		return
	}
	s := v2.Clone()
	fn(s.SwitchEpoch, s.SwitchBlock, s.CurrentConfig, s.AllConfigs, s.configIndex)
}

// WithReadOnlyView invokes fn while holding the read lock and exposes the
// current V2 state without cloning. Callers must treat the provided pointers,
// maps, and slices as ephemeral read-only views and must not retain them.
func (v2 *V2) WithReadOnlyView(fn func(switchEpoch uint64, switchBlock *big.Int, currentConfig *V2Config, allConfigs map[uint64]*V2Config, configIndex []uint64)) {
	if v2 == nil {
		fn(0, nil, nil, nil, nil)
		return
	}
	v2.lock.RLock()
	defer v2.lock.RUnlock()

	fn(v2.SwitchEpoch, v2.SwitchBlock, v2.CurrentConfig, v2.AllConfigs, v2.configIndex)
}

type v2ReadOnlySnapshot struct {
	switchEpoch   uint64
	switchBlock   *big.Int
	currentConfig *V2Config
	allConfigs    map[uint64]*V2Config
	configIndex   []uint64
}

func snapshotV2ReadOnly(v2 *V2) v2ReadOnlySnapshot {
	if v2 == nil {
		return v2ReadOnlySnapshot{}
	}

	var snapshot v2ReadOnlySnapshot
	v2.WithReadOnlySnapshot(func(switchEpoch uint64, switchBlock *big.Int, currentConfig *V2Config, allConfigs map[uint64]*V2Config, configIndex []uint64) {
		snapshot = v2ReadOnlySnapshot{
			switchEpoch:   switchEpoch,
			switchBlock:   switchBlock,
			currentConfig: currentConfig,
			allConfigs:    allConfigs,
			configIndex:   configIndex,
		}
	})
	return snapshot
}
