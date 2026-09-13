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

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/XinFinOrg/XDPoSChain/common"
)

// ChainConfig is the core config which determines the blockchain settings.
//
// ChainConfig is stored in the database on a per block basis. This means
// that any network, identified by its genesis block, can have its own
// set of configuration options.
//
// Clone/Equal selection guide:
//
//  1. Need: deep copy for normal runtime use
//     API: Clone
//     Notes: preserves runtime metadata (json field presence and built-in
//     override markers)
//
//  2. Need: prepare a config for backfill compatibility logic
//     API: CloneForBackfill
//     Notes: keeps tracked JSON presence when captured from JSON; otherwise
//     infers field presence from populated values
//
//  3. Need: serialize a config without runtime-only JSON presence metadata.
//     API: CloneForJSON
//     Notes: clears JSON presence tracking and built-in override markers before
//     marshaling
//
//  4. Need: compare semantic config values (ignore runtime-only metadata)
//     API: Equal
//     Notes: preferred for behavior and compatibility checks.
//
//  5. Need: compare exact JSON output stability
//     API: MarshalJSON
//     Notes: use byte comparison only for persistence and audit serialization
//     checks
type ChainConfig struct {
	ChainID *big.Int `json:"chainId"` // Chain id identifies the current chain and is used for replay protection

	HomesteadBlock *big.Int `json:"homesteadBlock,omitempty"` // Homestead switch block (nil = no fork, 0 = already homestead)

	DAOForkBlock   *big.Int `json:"daoForkBlock,omitempty"`   // TheDAO hard-fork switch block (nil = no fork)
	DAOForkSupport bool     `json:"daoForkSupport,omitempty"` // Whether the nodes supports or opposes the DAO hard-fork

	// EIP150 implements the Gas price changes (https://github.com/ethereum/EIPs/issues/150)
	EIP150Block *big.Int `json:"eip150Block,omitempty"` // EIP150 HF block (nil = no fork)
	EIP155Block *big.Int `json:"eip155Block,omitempty"` // EIP155 HF block
	EIP158Block *big.Int `json:"eip158Block,omitempty"` // EIP158 HF block

	ByzantiumBlock      *big.Int `json:"byzantiumBlock,omitempty"`      // Byzantium switch block (nil = no fork, 0 = already on byzantium)
	ConstantinopleBlock *big.Int `json:"constantinopleBlock,omitempty"` // Constantinople switch block (nil = no fork, 0 = already activated)

	PetersburgBlock *big.Int `json:"petersburgBlock,omitempty"`
	IstanbulBlock   *big.Int `json:"istanbulBlock,omitempty"`
	BerlinBlock     *big.Int `json:"berlinBlock,omitempty"`
	LondonBlock     *big.Int `json:"londonBlock,omitempty"`
	MergeBlock      *big.Int `json:"mergeBlock,omitempty"`
	ShanghaiBlock   *big.Int `json:"shanghaiBlock,omitempty"`
	EIP1559Block    *big.Int `json:"eip1559Block,omitempty"`
	CancunBlock     *big.Int `json:"cancunBlock,omitempty"`
	PragueBlock     *big.Int `json:"pragueBlock,omitempty"`
	OsakaBlock      *big.Int `json:"osakaBlock,omitempty"`

	TIP2019Block                *big.Int `json:"tip2019Block,omitempty"`
	TIPSigningBlock             *big.Int `json:"tipSigningBlock,omitempty"`
	TIPRandomizeBlock           *big.Int `json:"tipRandomizeBlock,omitempty"`
	TIPIncreaseMasternodesBlock *big.Int `json:"tipIncreaseMasternodesBlock,omitempty"`
	DenylistBlock               *big.Int `json:"denylistBlock,omitempty"`
	TIPNoHalvingMNRewardBlock   *big.Int `json:"tipNoHalvingMNRewardBlock,omitempty"`
	TIPXDCXBlock                *big.Int `json:"tipXDCXBlock,omitempty"`
	TIPXDCXLendingBlock         *big.Int `json:"tipXDCXLendingBlock,omitempty"`
	TIPXDCXCancellationFeeBlock *big.Int `json:"tipXDCXCancellationFeeBlock,omitempty"`
	TIPTRC21FeeBlock            *big.Int `json:"tipTRC21FeeBlock,omitempty"`
	Gas50xBlock                 *big.Int `json:"gas50xBlock,omitempty"`
	Gas2500xBlock               *big.Int `json:"gas2500xBlock,omitempty"`
	TIPXDCXMinerDisableBlock    *big.Int `json:"tipXDCXMinerDisableBlock,omitempty"`
	TIPXDCXReceiverDisableBlock *big.Int `json:"tipXDCXReceiverDisableBlock,omitempty"`
	DynamicGasLimitBlock        *big.Int `json:"dynamicGasLimitBlock,omitempty"`
	TIPUpgradeRewardBlock       *big.Int `json:"tipUpgradeRewardBlock,omitempty"`
	TIPUpgradePenaltyBlock      *big.Int `json:"tipUpgradePenaltyBlock,omitempty"`
	TIPEpochHalvingBlock        *big.Int `json:"tipEpochHalvingBlock,omitempty"`

	TRC21IssuerSMC         common.Address `json:"trc21IssuerSMC,omitempty"`
	XDCXListingSMC         common.Address `json:"xdcxListingSMC,omitempty"`
	RelayerRegistrationSMC common.Address `json:"relayerRegistrationSMC,omitempty"`
	LendingRegistrationSMC common.Address `json:"lendingRegistrationSMC,omitempty"`

	// Various consensus engines
	Ethash *EthashConfig `json:"ethash,omitempty"`
	Clique *CliqueConfig `json:"clique,omitempty"`
	XDPoS  *XDPoSConfig  `json:"XDPoS,omitempty"`

	runtime chainConfigRuntimeMetadata `json:"-"`
}

type chainConfigRuntimeMetadata struct {
	customBuiltInGenesisOverride bool
	json                         jsonFieldPresence
}

func (m chainConfigRuntimeMetadata) clone() chainConfigRuntimeMetadata {
	m.json = m.json.clone()
	return m
}

func (m *chainConfigRuntimeMetadata) setBuiltInGenesisOverride(enabled bool) {
	if m != nil {
		m.customBuiltInGenesisOverride = enabled
	}
}

func (m *chainConfigRuntimeMetadata) hasBuiltInGenesisOverride() bool {
	return m != nil && m.customBuiltInGenesisOverride
}

type jsonFieldPresence struct {
	keys     map[string]struct{}
	tracked  bool
	preserve bool
}

func (p jsonFieldPresence) clone() jsonFieldPresence {
	if p.keys == nil {
		return p
	}
	keys := p.keys
	p.keys = make(map[string]struct{}, len(keys))
	for key := range keys {
		p.keys[key] = struct{}{}
	}
	return p
}

func (p *jsonFieldPresence) capture(raw map[string]json.RawMessage) {
	if p == nil {
		return
	}
	p.tracked = true
	p.preserve = true
	p.keys = make(map[string]struct{}, len(raw))
	for key := range raw {
		p.keys[key] = struct{}{}
	}
}

func (p *jsonFieldPresence) startInferredTracking() {
	if p == nil {
		return
	}
	p.tracked = true
	p.preserve = false
	p.keys = make(map[string]struct{})
}

func (p *jsonFieldPresence) clear() {
	if p == nil {
		return
	}
	p.keys = nil
	p.tracked = false
	p.preserve = false
}

func (p *jsonFieldPresence) hasTracking() bool {
	return p != nil && p.tracked
}

func (p *jsonFieldPresence) mark(key string) {
	if p == nil {
		return
	}
	if p.keys == nil {
		p.keys = make(map[string]struct{})
	}
	p.keys[key] = struct{}{}
}

func (p *jsonFieldPresence) isMissing(key string, fallback bool) bool {
	if p == nil || !p.tracked {
		return fallback
	}
	_, ok := p.keys[key]
	return !ok
}

// EthashConfig is the consensus engine configs for proof-of-work based sealing.
type EthashConfig struct{}

// String implements the stringer interface, returning the consensus engine details.
func (c *EthashConfig) String() string {
	return "ethash"
}

// CliqueConfig is the consensus engine configs for proof-of-authority based sealing.
type CliqueConfig struct {
	Period uint64 `json:"period"` // Number of seconds between blocks to enforce
	Epoch  uint64 `json:"epoch"`  // Epoch length to reset votes and checkpoint
}

// String implements the stringer interface, returning the consensus engine details.
func (c *CliqueConfig) String() string {
	return "clique"
}

// UnmarshalJSON captures field presence so strict missing-field backfill can
// distinguish omitted keys from explicit zero-values. Unmarshal replaces the
// entire config, so runtime-only markers such as the built-in genesis override
// annotation are intentionally cleared and must be recomputed by the caller.
func (c *ChainConfig) UnmarshalJSON(data []byte) error {
	type chainConfigAlias ChainConfig
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var decoded chainConfigAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	next := ChainConfig(decoded)
	next.runtime = chainConfigRuntimeMetadata{}
	*c = next
	c.runtime.json.capture(raw)
	return nil
}

// MarshalJSON preserves explicitly provided zero-values so persistence can
// round-trip the difference between omitted keys and deliberate null/false/
// zero-address overrides.
func (c *ChainConfig) MarshalJSON() ([]byte, error) {
	if c == nil {
		return []byte("null"), nil
	}
	type chainConfigAlias ChainConfig
	data, err := json.Marshal(chainConfigAlias(*c))
	if err != nil || !c.runtime.json.tracked || !c.runtime.json.preserve || len(c.runtime.json.keys) == 0 {
		return data, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if raw == nil {
		raw = make(map[string]json.RawMessage)
	}
	fieldValues := make(map[string]any, len(chainConfigTopLevelFields))
	for _, field := range chainConfigTopLevelFields {
		fieldValues[field.jsonKey] = field.marshalValue(c)
	}
	for key := range c.runtime.json.keys {
		if _, ok := raw[key]; ok {
			continue
		}
		value, ok := fieldValues[key]
		if !ok {
			continue
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal chain config field %s: %w", key, err)
		}
		raw[key] = encoded
	}
	return json.Marshal(raw)
}

// Clone supports both the current and legacy typo-ed JSON key for
func (c *ChainConfig) Clone() *ChainConfig {
	if c == nil {
		return nil
	}
	clone := *c
	for _, field := range chainConfigTopLevelFields {
		field.clone(&clone, c)
	}
	clone.runtime = c.runtime.clone()
	return &clone
}

// CloneForBackfill returns a clone whose JSON field presence metadata is ready
// for compatibility backfill. Existing tracked presence is preserved; otherwise
// the clone infers explicit top-level fields from the populated config.
func (c *ChainConfig) CloneForBackfill() *ChainConfig {
	if c == nil {
		return nil
	}
	clone := c.Clone()
	if clone.runtime.json.hasTracking() && clone.runtime.json.preserve {
		return clone
	}
	clone.runtime.json.startInferredTracking()
	for _, field := range chainConfigTopLevelFields {
		if field.shouldInferPresence(clone) {
			clone.runtime.json.mark(field.jsonKey)
		}
	}
	clone.XDPoS = clone.XDPoS.cloneWithInferredFieldPresence()
	return clone
}

// CloneForJSON returns a clone with runtime-only metadata removed so JSON
// marshaling exposes only user-visible configuration fields.
func (c *ChainConfig) CloneForJSON() *ChainConfig {
	clone := c.Clone()
	if clone == nil {
		return nil
	}
	clone.runtime.json.clear()
	clone.runtime.setBuiltInGenesisOverride(false)
	return clone
}

// Equal reports whether two chain configs are semantically equal after
// excluding runtime-only metadata.
func (c *ChainConfig) Equal(other *ChainConfig) bool {
	if c == other {
		return true
	}
	if c == nil || other == nil {
		return c == nil && other == nil
	}
	if !sameChainID(c.ChainID, other.ChainID) || c.DAOForkSupport != other.DAOForkSupport {
		return false
	}
	equal := true
	ForEachChainConfigForkBlockPair(c, other, func(_ string, aValue, bValue *big.Int) {
		if equal && !sameChainID(aValue, bValue) {
			equal = false
		}
	})
	if !equal {
		return false
	}
	ForEachChainConfigXDCSystemContractPair(c, other, func(_ string, aValue, bValue common.Address) {
		if equal && aValue != bValue {
			equal = false
		}
	})
	if !equal {
		return false
	}
	if (c.Ethash == nil) != (other.Ethash == nil) {
		return false
	}
	if !chainConfigSemanticCliqueEqual(c.Clique, other.Clique) {
		return false
	}
	return chainConfigSemanticXDPoSEqual(c.XDPoS, other.XDPoS)
}

func chainConfigSemanticCliqueEqual(a, b *CliqueConfig) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Period == b.Period && a.Epoch == b.Epoch
}

func chainConfigSemanticXDPoSEqual(a, b *XDPoSConfig) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Period == b.Period &&
		a.Epoch == b.Epoch &&
		a.Reward == b.Reward &&
		a.RewardCheckpoint == b.RewardCheckpoint &&
		a.Gap == b.Gap &&
		a.FoundationWalletAddr == b.FoundationWalletAddr &&
		a.MaxMasternodesV2 == b.MaxMasternodesV2 &&
		a.SkipV1Validation == b.SkipV1Validation &&
		chainConfigSemanticV2Equal(a.V2, b.V2)
}

func chainConfigSemanticV2Equal(a, b *V2) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	equal := true
	a.WithReadOnlyView(func(leftSwitchEpoch uint64, leftSwitchBlock *big.Int, leftCurrentConfig *V2Config, leftAllConfigs map[uint64]*V2Config, _ []uint64) {
		if !equal {
			return
		}
		b.WithReadOnlyView(func(rightSwitchEpoch uint64, rightSwitchBlock *big.Int, rightCurrentConfig *V2Config, rightAllConfigs map[uint64]*V2Config, _ []uint64) {
			if leftSwitchEpoch != rightSwitchEpoch || !sameChainID(leftSwitchBlock, rightSwitchBlock) {
				equal = false
				return
			}
			if !sameV2RuntimeConfig(leftCurrentConfig, rightCurrentConfig) {
				equal = false
				return
			}
			if (leftAllConfigs == nil) != (rightAllConfigs == nil) {
				equal = false
				return
			}
			if len(leftAllConfigs) != len(rightAllConfigs) {
				equal = false
				return
			}
			for round, cfg := range leftAllConfigs {
				other, ok := rightAllConfigs[round]
				if !ok || !sameV2RuntimeConfig(cfg, other) {
					equal = false
					return
				}
			}
		})
	})
	return equal
}

// SetBuiltInGenesisOverride marks whether this config is a same-hash custom
// override of a bundled built-in genesis.
func (c *ChainConfig) SetBuiltInGenesisOverride(enabled bool) {
	if c != nil {
		c.runtime.setBuiltInGenesisOverride(enabled)
	}
}

func (c *ChainConfig) hasBuiltInGenesisOverride() bool {
	return c != nil && c.runtime.hasBuiltInGenesisOverride()
}

// isBuiltInTestNetwork reports whether chainID permits reduced startup checks.
func isBuiltInTestNetwork(chainID *big.Int) bool {
	if chainID == nil || !chainID.IsUint64() {
		return false
	}
	switch chainID.Uint64() {
	case ConsensusOptionalTestChainID: // AllEthashProtocolChanges, AllDevChainProtocolChanges, AllCliqueProtocolChanges, TestXDPoSMockChainConfig
		return true
	default:
		return false
	}
}

func sameChainID(a, b *big.Int) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Cmp(b) == 0
}

func isKnownXDCBuiltInChainID(chainID *big.Int) bool {
	if chainID == nil {
		return false
	}
	return sameChainID(chainID, XDCMainnetChainConfig.ChainID) ||
		sameChainID(chainID, TestnetChainConfig.ChainID) ||
		sameChainID(chainID, DevnetChainConfig.ChainID) ||
		sameChainID(chainID, LocalnetChainConfig.ChainID)
}

func shouldWarnOnCustomLocalnetFallback(dest, src *ChainConfig) bool {
	if dest == nil || src == nil || dest.ChainID == nil {
		return false
	}
	if !sameChainID(src.ChainID, LocalnetChainConfig.ChainID) {
		return false
	}
	if isKnownXDCBuiltInChainID(dest.ChainID) || isBuiltInTestNetwork(dest.ChainID) {
		return false
	}
	return true
}

// requiresXDCForkConfig reports whether the config enables any XDC-specific
// fork schedule or system-contract setting that cannot be inferred from plain
// Ethereum defaults.
func (c *ChainConfig) requiresXDCForkConfig() bool {
	if c == nil {
		return false
	}
	for _, field := range chainConfigXDCForkBlockFields {
		if field.get(c) != nil {
			return true
		}
	}
	for _, field := range chainConfigXDCSystemContractFields {
		if !field.get(c).IsZero() {
			return true
		}
	}
	return c.XDPoS != nil
}

// taggedConfigError reports an error a config rule produced, under one or more extra
// sentinels. errors.Is sees every tag as well as the wrapped error, so the sentinel of
// the rule that was broken keeps matching while error formatting can select a more
// specific recovery path. It is what lets the *DefaultEpoch variants say that the epoch
// quoted in the message is the default the validator filled in rather than a value the
// config wrote, and what lets the alignment rejection report its own sentinel next to
// ErrWrongForkSwitchOrder without hiding it. The message stays the wrapped error's, so
// callers and tests that quote the original text are unaffected.
type taggedConfigError struct {
	err  error
	tags []error
}

func (e taggedConfigError) Error() string { return e.err.Error() }

func (e taggedConfigError) Unwrap() []error {
	return append([]error{e.err}, e.tags...)
}

// CheckConfigForkOrderWithEpochDefault validates the config as if an unset
// XDPoS.Epoch carried DefaultXDPoSEpoch, without mutating the receiver.
//
// An unset epoch means "not filled in yet": the effective epoch only exists once
// the XDPoS engine is built, so the gap schedule cannot be judged before that and
// CheckConfigForkOrder skips it. Callers that have to reach the same verdict as
// the engine use this instead. DefaultXDPoSEpoch lives here in params, next to the
// validation it feeds, so the engine, the genesis commit and the stored-config
// load and setup paths judge an omitted epoch against one definition instead of
// each passing its own default in.
//
// Filling the epoch in also subjects the schedule to the rules that skip an unset
// epoch: the XDPoS.V2.SwitchBlock alignment, the XDPoS.V2.SwitchEpoch that has to
// name the epoch that block falls on, and the gap schedule. A config that omits
// the epoch and whose switch block is not a multiple of DefaultXDPoSEpoch is
// refused with ErrWrongForkSwitchOrder, naming a default epoch the config never
// wrote. XDPoS.New already filled the same default before it validated, so this
// moves those refusals earlier rather than introducing them.
//
// Each of the three rejections carries a sentinel of its own -
// ErrSwitchBlockUnalignedToDefaultEpoch, ErrSwitchEpochMismatchAgainstDefaultEpoch
// and ErrUnusableGapScheduleDefaultEpoch - because each quotes DefaultXDPoSEpoch,
// a number the genesis may never have written. Error formatting uses them to say
// where that number came from, and each is reported next to the sentinel of the
// rule it refines so callers that only know the rule keep matching.
//
// The config's own defects are reported before that rejection. An unset epoch
// defers only the rules the effective value governs, so the bare check reports
// exactly the defects the config carries on its own - a missing required field or
// a fork order that does not depend on the epoch - and those must not be masked
// by a rejection quoting a default the genesis never wrote: an operator whose
// config is missing TRC21IssuerSMC has to keep seeing ErrMissingForkSwitch and
// its migration hint, not an alignment message about a 900 that is nowhere in the
// file.
//
// A nil config has no schedule to judge and no rule that could pass, so it is
// reported as the missing XDPoS section rather than dereferenced - the answer
// ResolveXDPoSEpoch gives for the same shape, and the one the XDPoS constructors
// already produce. CheckConfigForkOrder keeps its own precondition instead: it is
// the pre-existing entry point and its callers all hold a config.
func (c *ChainConfig) CheckConfigForkOrderWithEpochDefault() error {
	if c == nil {
		return fmt.Errorf("invalid chain config: %w", ErrMissingXDPoSConfig)
	}
	if c.XDPoS == nil || c.XDPoS.Epoch != 0 {
		return c.CheckConfigForkOrder()
	}
	if err := c.checkNonEpochDependentRules(); err != nil {
		return err
	}
	effective := c.Clone()
	effective.XDPoS.Epoch = DefaultXDPoSEpoch
	err := effective.checkEpochDependentRules()
	if err == nil {
		return nil
	}
	// The bare half returned above, so this error can only come from the three rules
	// the filled-in epoch governs, and each carries a sentinel of its own: tag the
	// rejection with the variant that says it was judged against a number the config
	// never wrote. Any other defect - the sign, which the bare half already reports -
	// is returned untagged rather than dressed up as an artifact of the default epoch.
	switch {
	case errors.Is(err, ErrSwitchEpochMismatch):
		return taggedConfigError{err: err, tags: []error{ErrSwitchEpochMismatchAgainstDefaultEpoch}}
	case errors.Is(err, ErrUnusableGapSchedule):
		return taggedConfigError{err: err, tags: []error{ErrUnusableGapScheduleDefaultEpoch}}
	case errors.Is(err, ErrSwitchBlockUnalignedToEpoch):
		return taggedConfigError{err: err, tags: []error{ErrSwitchBlockUnalignedToDefaultEpoch}}
	default:
		return err
	}
}

// ResolveXDPoSEpoch returns the form of this config the XDPoS engine runs with: a
// copy whose unset XDPoS.Epoch is filled with DefaultXDPoSEpoch once the schedule
// has been judged against that value. The config itself is returned when it writes
// the epoch out already, and a config with no XDPoS section has nothing to resolve,
// so it is judged and returned too. The receiver is never mutated, so a caller that
// has to keep the config its source wrote can hand the result to the engine and to
// the resolved blockchain constructors while keeping the original.
//
// The filled copy records the fill through XDPoSConfig.EpochFilledByEngine, which is
// what lets the mismatch policies persist the state the source wrote instead of a
// number no file contains. That record is process-local and does not survive
// storage, so a config read back from the database answers false and is persisted as
// it is.
//
// A schedule the filled-in epoch cannot make usable is refused here, before any
// engine exists, so a caller cannot obtain a resolved config the engine would
// reject; a refusal leaves the receiver untouched.
func (c *ChainConfig) ResolveXDPoSEpoch() (*ChainConfig, error) {
	if c == nil {
		return nil, fmt.Errorf("invalid chain config: %w", ErrMissingXDPoSConfig)
	}
	if c.XDPoS == nil || c.XDPoS.Epoch != 0 {
		if err := c.CheckConfigForkOrder(); err != nil {
			return nil, err
		}
		return c, nil
	}
	if err := c.CheckConfigForkOrderWithEpochDefault(); err != nil {
		return nil, err
	}
	resolved := c.Clone()
	resolved.XDPoS.Epoch = DefaultXDPoSEpoch
	resolved.XDPoS.epochFilledByEngine = true
	return resolved, nil
}

// CheckSwitchBlockAlignment rejects a switch block that is negative or not a
// multiple of the configured epoch. An unset epoch is skipped: the effective value
// only exists once the engine fills it in, and CheckConfigForkOrderWithEpochDefault
// is where that state is judged.
//
// The sign is judged here as well as in CheckConfigForkOrder because this helper is
// the only judgement engine_v2.New makes on a config it is handed directly: such an
// engine never goes through the full validation, and SwitchBlock.Uint64() folds a
// negative height to its absolute value, so -900 would otherwise look aligned while
// every comparison against the field keeps treating it as a height that can never
// match. CheckConfigForkOrder keeps its own earlier sign judgement so that a
// negative value stays reported as a defect of the config rather than as one the
// filled-in default epoch caused - that placement is what keeps the default-epoch
// tagging honest.
//
// XDPoS.V2 is mandatory for every XDPoS chain and CheckConfigForkOrder already
// refused a nil one by the time it calls this, so the guard here is for a direct
// caller rather than a shape the validation sequence can reach.
//
// The judgement is SwitchBlockAligned, the one definition of the rule, so a caller
// that judges a candidate switch block before it builds a config - the puppeth
// wizard does - reaches the same verdict this check does.
//
// It is exported because the rule is not only a config-validation one: the v2
// engine's first-epoch gap step steps back from the switch block by Gap, and that
// only resolves to GapBlockNumber's answer while the switch block sits on an epoch
// boundary. engine_v2.New judges it on the config it is handed, because a directly
// constructed engine never goes through CheckConfigForkOrder.
//
// The rejection is reported as a taggedConfigError, so errors.Is identifies
// both ErrSwitchBlockUnalignedToEpoch - the rule's own sentinel, which is what
// selects the alignment recovery hint - and ErrWrongForkSwitchOrder, the ordering
// sentinel callers already match. CheckConfigForkOrderWithEpochDefault re-tags that
// error with ErrSwitchBlockUnalignedToDefaultEpoch when the epoch it judged was the
// default it filled in.
func (c *ChainConfig) CheckSwitchBlockAlignment() error {
	if err := c.checkV2SwitchBlockSign(); err != nil {
		return err
	}
	if c.XDPoS == nil || c.XDPoS.V2 == nil || c.XDPoS.V2.SwitchBlock == nil || c.XDPoS.Epoch == 0 {
		return nil
	}
	if !SwitchBlockAligned(c.XDPoS.V2.SwitchBlock, c.XDPoS.Epoch) {
		return taggedConfigError{
			err:  fmt.Errorf("invalid chain config: %w: XDPoS.V2.SwitchBlock %v not aligned to XDPoS.Epoch %d", ErrWrongForkSwitchOrder, c.XDPoS.V2.SwitchBlock, c.XDPoS.Epoch),
			tags: []error{ErrSwitchBlockUnalignedToEpoch},
		}
	}
	return nil
}

// checkV2SwitchBlockSign rejects a negative XDPoS.V2.SwitchBlock. A block height
// has no negative meaning on the chain, and the field's two readers disagree about
// it: SwitchBlock.Uint64() folds -900 to 900, so the value passes the epoch
// alignment rule, while the comparisons against it (XDPoSConfig.BlockConsensusVersion,
// isEpochSwitchAtRound) keep treating it as a height that can never match. Judging
// the sign separately is what keeps the field to a single meaning.
//
// An unset XDPoS section or a missing switch block has nothing to judge, so the
// guard stays total for a direct caller.
func (c *ChainConfig) checkV2SwitchBlockSign() error {
	if c.XDPoS == nil || c.XDPoS.V2 == nil || c.XDPoS.V2.SwitchBlock == nil {
		return nil
	}
	if c.XDPoS.V2.SwitchBlock.Sign() < 0 {
		return fmt.Errorf("invalid chain config: %w: XDPoS.V2.SwitchBlock %v must be non-negative", ErrNegativeSwitchBlock, c.XDPoS.V2.SwitchBlock)
	}
	return nil
}

// CheckV2SwitchEpochAlignment rejects a switch epoch that does not name the epoch
// the switch block falls on, i.e. SwitchEpoch != SwitchBlock / Epoch. The v2 round
// arithmetic derives its epoch number as SwitchEpoch + round/Epoch, so a config
// that keeps the two fields apart renumbers every epoch the engine reports while
// the schedule itself still looks self-consistent. Every built-in network
// satisfies the equality.
//
// It is judged after CheckSwitchBlockAlignment, so an unaligned switch block is
// reported as such instead of as a mismatch against a division it never
// satisfies. The mismatch itself is a defect of the schedule the engine will run
// whether or not the config omitted the epoch: SwitchEpoch is a number the config
// wrote, and the engine fills DefaultXDPoSEpoch in when the file leaves the epoch
// out. The epoch the message divides by may still be a number no file contains,
// which is why CheckConfigForkOrderWithEpochDefault tags this rejection with
// ErrSwitchEpochMismatchAgainstDefaultEpoch when the config omitted the epoch.
//
// An unset epoch is skipped for the same reason CheckSwitchBlockAlignment skips
// it: the effective value only exists once the engine fills it in, and
// CheckConfigForkOrderWithEpochDefault judges that state against
// DefaultXDPoSEpoch.
//
// The want it compares against comes from SwitchEpochFor, the one definition of the
// pairing arithmetic, so a caller that derives a switch epoch before it builds a
// config - the puppeth wizard does - writes the value this check re-derives. The
// derivation runs on the big.Int, so want is the epoch the switch block really falls
// on rather than the one its low 64 bits name. A want that no uint64 can hold names
// an epoch SwitchEpoch can never equal, which is reported as the mismatch it is.
//
// It is exported for the same reason CheckSwitchBlockAlignment is: the rule is not
// only a config-validation one. The v2 round arithmetic reads
// SwitchEpoch + round/Epoch, so a pairing that does not name the epoch its switch
// block falls on renumbers every epoch the engine reports, and engine_v2.New judges
// the rule on the config it is handed because a directly constructed engine never
// goes through CheckConfigForkOrder.
func (c *ChainConfig) CheckV2SwitchEpochAlignment() error {
	if c.XDPoS == nil || c.XDPoS.V2 == nil || c.XDPoS.V2.SwitchBlock == nil || c.XDPoS.Epoch == 0 {
		return nil
	}
	want, fits := SwitchEpochFor(c.XDPoS.V2.SwitchBlock, c.XDPoS.Epoch)
	if fits && c.XDPoS.V2.SwitchEpoch == want.Uint64() {
		return nil
	}
	return fmt.Errorf("invalid chain config: %w: XDPoS.V2.SwitchEpoch %d does not name the epoch XDPoS.V2.SwitchBlock %v falls on (want %s = XDPoS.V2.SwitchBlock / XDPoS.Epoch %d)", ErrSwitchEpochMismatch, c.XDPoS.V2.SwitchEpoch, c.XDPoS.V2.SwitchBlock, want, c.XDPoS.Epoch)
}

// CheckGapSchedule rejects an XDPoS schedule that designates no gap block of its
// own, i.e. one that cannot derive the next-epoch masternode set through the v2
// gap trigger. It is the single definition of that rule: CheckConfigForkOrder
// judges it for the config validation, and the chain open path judges it again on
// the resolved config it is handed, where a caller can still supply a schedule that
// no engine constructor validated.
//
// An unset epoch means "not filled in yet", not "invalid": the effective value only
// exists once the engine fills it in, so the judgement is skipped here and
// CheckConfigForkOrderWithEpochDefault reaches it on the copy that carries
// DefaultXDPoSEpoch. A missing section has no schedule to refuse either, so the
// predicate stays total for a direct caller.
func (c *XDPoSConfig) CheckGapSchedule() error {
	if c == nil || c.Epoch == 0 {
		return nil
	}
	if _, ok := c.GapOffset(); ok {
		return nil
	}
	// The guard above leaves Epoch == 1 as the only value below 2.
	if c.Epoch == 1 {
		return fmt.Errorf("invalid chain config: %w: XDPoS.Epoch %d designates no gap block (want Epoch >= 2 so that 1 <= Gap < Epoch is satisfiable)", ErrUnusableGapSchedule, c.Epoch)
	}
	// Gap == Epoch is the one refused shape whose trigger does match a height:
	// Epoch-Gap is 0, so n%Epoch == 0 selects the epoch switch block itself. Say so
	// instead of folding it into the message the two shapes that match no height at
	// all share - the block that samples the next-epoch candidate set would be the
	// block that consumes it.
	if c.Gap == c.Epoch {
		return fmt.Errorf("invalid chain config: %w: XDPoS.Gap %d designates no gap block of its own inside XDPoS.Epoch %d - it puts the gap trigger on the epoch switch block, which would have to consume the candidate set it samples (want 1 <= Gap < Epoch)", ErrUnusableGapSchedule, c.Gap, c.Epoch)
	}
	return fmt.Errorf("invalid chain config: %w: XDPoS.Gap %d designates no gap block inside XDPoS.Epoch %d (want 1 <= Gap < Epoch)", ErrUnusableGapSchedule, c.Gap, c.Epoch)
}

// CheckConfigForkOrder validates that configured forks, required addresses, and
// XDPoS settings are internally consistent and activate in a supported order.
func (c *ChainConfig) CheckConfigForkOrder() error {
	if err := c.checkNonEpochDependentRules(); err != nil {
		return err
	}
	return c.checkEpochDependentRules()
}

// checkNonEpochDependentRules judges every rule whose verdict does not depend on
// XDPoS.Epoch: the required fields and addresses, the fork order, and every XDPoS.V2
// field the epoch-dependent rules later read. CheckConfigForkOrder runs it before
// its epoch-dependent half, and CheckConfigForkOrderWithEpochDefault runs it alone
// on a config whose epoch is unset, so the defects the config carries on its own are
// reported before any rejection that quotes the default epoch.
func (c *ChainConfig) checkNonEpochDependentRules() error {
	type fork struct {
		name     string
		block    *big.Int
		optional bool
	}
	type requiredAddress struct {
		name  string
		value common.Address
	}
	if c.ChainID == nil {
		return fmt.Errorf("invalid chain config: %w: %s", ErrMissingForkSwitch, "ChainID")
	}
	if c.requiresXDCForkConfig() && c.TIPTRC21FeeBlock == nil {
		return fmt.Errorf("invalid chain config: %w: %s", ErrMissingForkSwitch, "TIPTRC21FeeBlock")
	}
	if c.requiresXDCForkConfig() && c.Gas50xBlock == nil {
		return fmt.Errorf("invalid chain config: %w: %s", ErrMissingForkSwitch, "Gas50xBlock")
	}
	if c.requiresXDCForkConfig() {
		requiredAddresses := make([]requiredAddress, 0, len(chainConfigXDCSystemContractFields))
		for _, field := range chainConfigXDCSystemContractFields {
			requiredAddresses = append(requiredAddresses, requiredAddress{name: field.name, value: field.get(c)})
		}
		for _, addr := range requiredAddresses {
			if addr.value.IsZero() {
				return fmt.Errorf("invalid chain config: %w: %s", ErrMissingForkSwitch, addr.name)
			}
		}
	}
	var lastFork fork
	var forkOrderErr error
	ForEachChainConfigForkOrderBlock(c, func(name string, block *big.Int, optional bool) {
		if forkOrderErr != nil {
			return
		}
		cur := fork{name: name, block: block, optional: optional}
		if lastFork.name != "" && lastFork.block != nil && cur.block != nil && lastFork.block.Cmp(cur.block) > 0 {
			forkOrderErr = fmt.Errorf("invalid chain config: %w: %s %v > %s %v", ErrWrongForkSwitchOrder, lastFork.name, lastFork.block, cur.name, cur.block)
			return
		}
		if !cur.optional || cur.block != nil {
			lastFork = cur
		}
	})
	if forkOrderErr != nil {
		return forkOrderErr
	}
	for _, rule := range chainConfigForkOrderSpecialCaseRules {
		before := rule.before.get(c)
		after := rule.after.get(c)
		if !rule.shouldValidate(before, after) {
			continue
		}
		if before.Cmp(after) > 0 {
			return fmt.Errorf("invalid chain config: %w: %s %v > %s %v", ErrWrongForkSwitchOrder, rule.before.name, before, rule.after.name, after)
		}
	}
	// The BASEFEE opcode is live from London, but XDC only fills the header base
	// fee from EIP-1559 on; in between the opcode falls back to BaseFeeForOpcode,
	// which is pinned to the Gas50x tier price. A tier above Gas50x taking effect
	// inside that window would make the opcode under-report the schedule.
	if c.Gas2500xBlock != nil && c.LondonBlock != nil {
		windowStart := c.LondonBlock
		if c.Gas2500xBlock.Cmp(windowStart) > 0 {
			windowStart = c.Gas2500xBlock
		}
		if c.EIP1559Block == nil || c.EIP1559Block.Cmp(windowStart) > 0 {
			return fmt.Errorf("invalid chain config: %w: Gas2500xBlock %v takes effect before EIP1559Block %v fills the header base fee", ErrWrongForkSwitchOrder, c.Gas2500xBlock, c.EIP1559Block)
		}
	}
	if c.XDPoS == nil && c.Ethash == nil && c.Clique == nil && !isBuiltInTestNetwork(c.ChainID) {
		return fmt.Errorf("invalid chain config: %w: %s", ErrMissingForkSwitch, "XDPoS")
	}
	if c.XDPoS != nil {
		if c.XDPoS.FoundationWalletAddr.IsZero() {
			return fmt.Errorf("invalid chain config: %w: %s", ErrMissingForkSwitch, "XDPoS.FoundationWalletAddr")
		}
		if c.XDPoS.MaxMasternodesV2 == 0 {
			return fmt.Errorf("invalid chain config: %w: %s", ErrMissingForkSwitch, "XDPoS.MaxMasternodesV2")
		}
		// XDPoS.V2 is mandatory, not optional: the v2 engine is the only engine an
		// XDPoS chain opens with, and every rule below reads its fields. The nil
		// branch reports the missing section rather than dereferencing it.
		if c.XDPoS.V2 == nil {
			return fmt.Errorf("invalid chain config: %w: %s", ErrMissingForkSwitch, "XDPoS.V2")
		}
		if c.XDPoS.V2.SwitchBlock == nil {
			return fmt.Errorf("invalid chain config: %w: %s", ErrMissingForkSwitch, "XDPoS.V2.SwitchBlock")
		}
		if c.XDPoS.V2.CurrentConfig == nil {
			return fmt.Errorf("invalid chain config: %w: %s", ErrMissingForkSwitch, "XDPoS.V2.CurrentConfig")
		}
		if len(c.XDPoS.V2.AllConfigs) == 0 {
			return fmt.Errorf("invalid chain config: %w: %s", ErrMissingForkSwitch, "XDPoS.V2.AllConfigs")
		}
		defaultCfg, ok := c.XDPoS.V2.AllConfigs[0]
		if !ok || defaultCfg == nil {
			return fmt.Errorf("invalid chain config: %w: %s", ErrMissingForkSwitch, "XDPoS.V2.AllConfigs[0]")
		}
		for round, cfg := range c.XDPoS.V2.AllConfigs {
			if cfg == nil {
				return fmt.Errorf("invalid chain config: %w: XDPoS.V2.AllConfigs[%d]", ErrMissingForkSwitch, round)
			}
			if cfg.SwitchRound != round {
				return fmt.Errorf("invalid chain config: %w: XDPoS.V2.AllConfigs[%d].SwitchRound %d", ErrWrongForkSwitchOrder, round, cfg.SwitchRound)
			}
		}
		if err := validateV2ExpTimeoutConfig(c.XDPoS.V2.CurrentConfig, "XDPoS.V2.CurrentConfig.ExpTimeoutConfig"); err != nil {
			return fmt.Errorf("invalid chain config: %w: %v", ErrWrongForkSwitchOrder, err)
		}
		for round, cfg := range c.XDPoS.V2.AllConfigs {
			if err := validateV2ExpTimeoutConfig(cfg, fmt.Sprintf("XDPoS.V2.AllConfigs[%d].ExpTimeoutConfig", round)); err != nil {
				return fmt.Errorf("invalid chain config: %w: %v", ErrWrongForkSwitchOrder, err)
			}
		}
		currentCfg, ok := c.XDPoS.V2.AllConfigs[c.XDPoS.V2.CurrentConfig.SwitchRound]
		if !ok || currentCfg == nil {
			return fmt.Errorf("invalid chain config: %w: %s", ErrMissingForkSwitch, "XDPoS.V2.CurrentConfig")
		}
		if !sameV2RuntimeConfig(currentCfg, c.XDPoS.V2.CurrentConfig) {
			return fmt.Errorf("invalid chain config: %w: %s", ErrWrongForkSwitchOrder, "XDPoS.V2.CurrentConfig")
		}
		// The sign is judged before the alignment, and here as well as inside
		// CheckSwitchBlockAlignment: that helper's rejection is what
		// CheckConfigForkOrderWithEpochDefault tags as an unaligned-to-the-default
		// epoch error, and a negative switch block is a defect of the config
		// itself, not an artifact of the default epoch. Judging it in this function
		// keeps it reported as such on every entry point, an unset epoch included,
		// while the helper re-checks it for the callers that never get here.
		if err := c.checkV2SwitchBlockSign(); err != nil {
			return err
		}
	}
	return nil
}

// checkEpochDependentRules judges the rules the effective XDPoS.Epoch governs: the
// switch block the alignment rule measures against the epoch, the switch epoch that
// has to name the epoch that block falls on, and the gap schedule. Each rule keeps
// its own "not filled in yet" skip, so the half is total for an unset epoch;
// CheckConfigForkOrderWithEpochDefault is where that state is judged, on the copy
// that carries DefaultXDPoSEpoch.
func (c *ChainConfig) checkEpochDependentRules() error {
	if c.XDPoS == nil {
		return nil
	}
	// The alignment rule stays first so an unaligned switch block is reported as
	// such instead of as a switch epoch mismatch against a division it never
	// satisfies.
	if err := c.CheckSwitchBlockAlignment(); err != nil {
		return err
	}
	if err := c.CheckV2SwitchEpochAlignment(); err != nil {
		return err
	}
	// A schedule that designates no gap block of its own can never derive the
	// next-epoch masternode set through the v2 gap trigger, so reject it and make
	// geth init fail instead of only failing once a node starts. CheckGapSchedule is
	// where that judgement lives, shared with the chain open path.
	return c.XDPoS.CheckGapSchedule()
}

// String implements the fmt.Stringer interface, returning a string representation
// of ChainConfig.
func (c *ChainConfig) String() string {
	result := fmt.Sprintf("ChainConfig{ChainID: %v", c.ChainID)

	// Add block-based forks
	if c.HomesteadBlock != nil {
		result += fmt.Sprintf(", Homestead: %v", c.HomesteadBlock)
	}
	if c.TIP2019Block != nil {
		result += fmt.Sprintf(", TIP2019: %v", c.TIP2019Block)
	}
	if c.DAOForkBlock != nil {
		result += fmt.Sprintf(", DAOFork: %v", c.DAOForkBlock)
	}
	result += fmt.Sprintf(", DAOForkSupport: %v", c.DAOForkSupport)
	if c.EIP150Block != nil {
		result += fmt.Sprintf(", EIP150: %v", c.EIP150Block)
	}
	if c.EIP155Block != nil {
		result += fmt.Sprintf(", EIP155: %v", c.EIP155Block)
	}
	if c.EIP158Block != nil {
		result += fmt.Sprintf(", EIP158: %v", c.EIP158Block)
	}
	if c.ByzantiumBlock != nil {
		result += fmt.Sprintf(", Byzantium: %v", c.ByzantiumBlock)
	}
	if c.ConstantinopleBlock != nil {
		result += fmt.Sprintf(", Constantinople: %v", c.ConstantinopleBlock)
	}
	if c.PetersburgBlock != nil {
		result += fmt.Sprintf(", Petersburg: %v", c.PetersburgBlock)
	}
	if c.IstanbulBlock != nil {
		result += fmt.Sprintf(", Istanbul: %v", c.IstanbulBlock)
	}
	if c.TIPSigningBlock != nil {
		result += fmt.Sprintf(", TIPSigning: %v", c.TIPSigningBlock)
	}
	if c.TIPRandomizeBlock != nil {
		result += fmt.Sprintf(", TIPRandomize: %v", c.TIPRandomizeBlock)
	}
	if c.TIPIncreaseMasternodesBlock != nil {
		result += fmt.Sprintf(", TIPIncreaseMasternodes: %v", c.TIPIncreaseMasternodesBlock)
	}
	if c.DenylistBlock != nil {
		result += fmt.Sprintf(", Denylist: %v", c.DenylistBlock)
	}
	if c.TIPNoHalvingMNRewardBlock != nil {
		result += fmt.Sprintf(", TIPNoHalvingMNReward: %v", c.TIPNoHalvingMNRewardBlock)
	}
	if c.TIPXDCXBlock != nil {
		result += fmt.Sprintf(", TIPXDCX: %v", c.TIPXDCXBlock)
	}
	if c.TIPXDCXLendingBlock != nil {
		result += fmt.Sprintf(", TIPXDCXLending: %v", c.TIPXDCXLendingBlock)
	}
	if c.TIPXDCXCancellationFeeBlock != nil {
		result += fmt.Sprintf(", TIPXDCXCancellationFee: %v", c.TIPXDCXCancellationFeeBlock)
	}
	if c.TIPTRC21FeeBlock != nil {
		result += fmt.Sprintf(", TIPTRC21Fee: %v", c.TIPTRC21FeeBlock)
	}
	if c.BerlinBlock != nil {
		result += fmt.Sprintf(", Berlin: %v", c.BerlinBlock)
	}
	if c.LondonBlock != nil {
		result += fmt.Sprintf(", London: %v", c.LondonBlock)
	}
	if c.MergeBlock != nil {
		result += fmt.Sprintf(", Merge: %v", c.MergeBlock)
	}
	if c.ShanghaiBlock != nil {
		result += fmt.Sprintf(", Shanghai: %v", c.ShanghaiBlock)
	}
	if c.Gas50xBlock != nil {
		result += fmt.Sprintf(", Gas50x: %v", c.Gas50xBlock)
	}
	if c.Gas2500xBlock != nil {
		result += fmt.Sprintf(", Gas2500x: %v", c.Gas2500xBlock)
	}
	if c.TIPXDCXMinerDisableBlock != nil {
		result += fmt.Sprintf(", TIPXDCXMinerDisable: %v", c.TIPXDCXMinerDisableBlock)
	}
	if c.TIPXDCXReceiverDisableBlock != nil {
		result += fmt.Sprintf(", TIPXDCXReceiverDisable: %v", c.TIPXDCXReceiverDisableBlock)
	}
	if c.EIP1559Block != nil {
		result += fmt.Sprintf(", EIP1559: %v", c.EIP1559Block)
	}
	if c.CancunBlock != nil {
		result += fmt.Sprintf(", Cancun: %v", c.CancunBlock)
	}
	if c.PragueBlock != nil {
		result += fmt.Sprintf(", Prague: %v", c.PragueBlock)
	}
	if c.OsakaBlock != nil {
		result += fmt.Sprintf(", Osaka: %v", c.OsakaBlock)
	}
	if c.DynamicGasLimitBlock != nil {
		result += fmt.Sprintf(", DynamicGasLimit: %v", c.DynamicGasLimitBlock)
	}
	if c.TIPUpgradeRewardBlock != nil {
		result += fmt.Sprintf(", TIPUpgradeReward: %v", c.TIPUpgradeRewardBlock)
	}
	if c.TIPUpgradePenaltyBlock != nil {
		result += fmt.Sprintf(", TIPUpgradePenalty: %v", c.TIPUpgradePenaltyBlock)
	}
	if c.TIPEpochHalvingBlock != nil {
		result += fmt.Sprintf(", TIPEpochHalving: %v", c.TIPEpochHalvingBlock)
	}
	if !c.TRC21IssuerSMC.IsZero() {
		result += fmt.Sprintf(", TRC21IssuerSMC: %s", c.TRC21IssuerSMC.Hex())
	}
	if !c.XDCXListingSMC.IsZero() {
		result += fmt.Sprintf(", XDCXListingSMC: %s", c.XDCXListingSMC.Hex())
	}
	if !c.RelayerRegistrationSMC.IsZero() {
		result += fmt.Sprintf(", RelayerRegistrationSMC: %s", c.RelayerRegistrationSMC.Hex())
	}
	if !c.LendingRegistrationSMC.IsZero() {
		result += fmt.Sprintf(", LendingRegistrationSMC: %s", c.LendingRegistrationSMC.Hex())
	}
	if c.Ethash != nil {
		result += fmt.Sprintf(", Ethash: %s", c.Ethash.String())
	}
	if c.Clique != nil {
		result += fmt.Sprintf(", Clique: %s", c.Clique.String())
	}
	if c.XDPoS != nil {
		result += fmt.Sprintf(", XDPoS: %s", c.XDPoS.String())
	}
	result += "}"
	return result
}

// Description returns a human-readable description of ChainConfig.
// NOTE: don't append "\n" to end
func (c *ChainConfig) Description() string {
	var engine string
	switch {
	case c.Ethash != nil:
		engine = c.Ethash.String()
	case c.XDPoS != nil:
		engine = c.XDPoS.Description(4)
	default:
		engine = "unknown"
	}
	var banner = "Chain configuration"
	if c.hasBuiltInGenesisOverride() {
		banner += " (custom override of built-in genesis)"
	}
	banner += ":\n"
	banner += fmt.Sprintf("  - ChainID:                     %-8v\n", c.ChainID)
	banner += fmt.Sprintf("  - Homestead:                   %-8v\n", c.HomesteadBlock)
	banner += fmt.Sprintf("  - DAO Fork:                    %-8v\n", c.DAOForkBlock)
	banner += fmt.Sprintf("  - DAO Support:                 %-8v\n", c.DAOForkSupport)
	banner += fmt.Sprintf("  - TIP2019:                     %-8v\n", c.TIP2019Block)
	banner += fmt.Sprintf("  - Tangerine Whistle (EIP 150): %-8v\n", c.EIP150Block)
	banner += fmt.Sprintf("  - Spurious Dragon (EIP 155):   %-8v\n", c.EIP155Block)
	banner += fmt.Sprintf("  - Byzantium:                   %-8v\n", c.ByzantiumBlock)
	banner += fmt.Sprintf("  - Constantinople:              %-8v\n", c.ConstantinopleBlock)
	banner += fmt.Sprintf("  - Petersburg:                  %-8v\n", c.PetersburgBlock)
	banner += fmt.Sprintf("  - Istanbul:                    %-8v\n", c.IstanbulBlock)
	banner += fmt.Sprintf("  - TIPSigning:                  %-8v\n", c.TIPSigningBlock)
	banner += fmt.Sprintf("  - TIPRandomize:                %-8v\n", c.TIPRandomizeBlock)
	banner += fmt.Sprintf("  - TIPIncreaseMasternodes:      %-8v\n", c.TIPIncreaseMasternodesBlock)
	banner += fmt.Sprintf("  - Denylist:                    %-8v\n", c.DenylistBlock)
	banner += fmt.Sprintf("  - TIPNoHalvingMNReward:        %-8v\n", c.TIPNoHalvingMNRewardBlock)
	banner += fmt.Sprintf("  - TIPXDCX:                     %-8v\n", c.TIPXDCXBlock)
	banner += fmt.Sprintf("  - TIPXDCXLending:              %-8v\n", c.TIPXDCXLendingBlock)
	banner += fmt.Sprintf("  - TIPXDCXCancellationFee:      %-8v\n", c.TIPXDCXCancellationFeeBlock)
	banner += fmt.Sprintf("  - TIPTRC21Fee:                 %-8v\n", c.TIPTRC21FeeBlock)
	banner += fmt.Sprintf("  - Berlin:                      %-8v\n", c.BerlinBlock)
	banner += fmt.Sprintf("  - London:                      %-8v\n", c.LondonBlock)
	banner += fmt.Sprintf("  - Merge:                       %-8v\n", c.MergeBlock)
	banner += fmt.Sprintf("  - Shanghai:                    %-8v\n", c.ShanghaiBlock)
	banner += fmt.Sprintf("  - Gas50x:                      %-8v\n", c.Gas50xBlock)
	banner += fmt.Sprintf("  - Gas2500x:                    %-8v\n", c.Gas2500xBlock)
	banner += fmt.Sprintf("  - TIPXDCXMinerDisable:         %-8v\n", c.TIPXDCXMinerDisableBlock)
	banner += fmt.Sprintf("  - TIPXDCXReceiverDisable:      %-8v\n", c.TIPXDCXReceiverDisableBlock)
	banner += fmt.Sprintf("  - EIP1559:                     %-8v\n", c.EIP1559Block)
	banner += fmt.Sprintf("  - Cancun:                      %-8v\n", c.CancunBlock)
	banner += fmt.Sprintf("  - Prague:                      %-8v\n", c.PragueBlock)
	banner += fmt.Sprintf("  - Osaka:                       %-8v\n", c.OsakaBlock)
	banner += fmt.Sprintf("  - DynamicGasLimit:             %-8v\n", c.DynamicGasLimitBlock)
	banner += fmt.Sprintf("  - TIPUpgradeReward:            %-8v\n", c.TIPUpgradeRewardBlock)
	banner += fmt.Sprintf("  - TIPUpgradePenalty:           %-8v\n", c.TIPUpgradePenaltyBlock)
	banner += fmt.Sprintf("  - TIPEpochHalving:             %-8v\n", c.TIPEpochHalvingBlock)
	banner += fmt.Sprintf("  - TRC21IssuerSMC:              %-8s\n", c.TRC21IssuerSMC)
	banner += fmt.Sprintf("  - XDCXListingSMC:              %-8s\n", c.XDCXListingSMC)
	banner += fmt.Sprintf("  - RelayerRegistrationSMC:      %-8s\n", c.RelayerRegistrationSMC)
	banner += fmt.Sprintf("  - LendingRegistrationSMC:      %-8s\n", c.LendingRegistrationSMC)
	banner += fmt.Sprintf("  - Engine:                      %v", engine)
	return banner
}

// GatherForks gathers all the known forks and creates a sorted list of
// block number based forks.
func (c *ChainConfig) GatherForks() []uint64 {
	forksByBlock := make([]uint64, 0, len(chainConfigForkBlockFields)+1)
	ForEachChainConfigForkBlock(c, func(_ string, block *big.Int) {
		if block != nil {
			forksByBlock = append(forksByBlock, block.Uint64())
		}
	})
	// Nested fork switches are not discoverable by the reflection pass above and
	// must be appended manually when introduced.
	if c.XDPoS != nil && c.XDPoS.V2 != nil && c.XDPoS.V2.SwitchBlock != nil {
		forksByBlock = append(forksByBlock, c.XDPoS.V2.SwitchBlock.Uint64())
	}
	slices.Sort(forksByBlock)

	// Deduplicate fork identifiers applying multiple forks
	forksByBlock = slices.Compact(forksByBlock)
	// Skip any forks in block 0, that's the genesis ruleset
	if len(forksByBlock) > 0 && forksByBlock[0] == 0 {
		forksByBlock = forksByBlock[1:]
	}
	return forksByBlock
}

// ActiveForks returns the list of active forks at the given block height.
// The returned list is sorted in alphabetical order.
func (c *ChainConfig) ActiveForks(block *big.Int) []string {
	activeForks := make([]string, 0, 37)
	if c.IsBerlin(block) {
		activeForks = append(activeForks, "Berlin")
	}
	if c.IsByzantium(block) {
		activeForks = append(activeForks, "Byzantium")
	}
	if c.IsCancun(block) {
		activeForks = append(activeForks, "Cancun")
	}
	if c.IsConstantinople(block) {
		activeForks = append(activeForks, "Constantinople")
	}
	if c.IsDAOFork(block) {
		activeForks = append(activeForks, "DAO")
	}
	if c.IsDenylist(block) {
		activeForks = append(activeForks, "Denylist")
	}
	if c.IsDynamicGasLimit(block) {
		activeForks = append(activeForks, "DynamicGasLimit")
	}
	if c.IsEIP1559(block) {
		activeForks = append(activeForks, "EIP1559")
	}
	if c.IsEIP158(block) {
		activeForks = append(activeForks, "EIP158")
	}
	if c.IsGas2500x(block) {
		activeForks = append(activeForks, "Gas2500x")
	}
	if c.IsGas50x(block) {
		activeForks = append(activeForks, "Gas50x")
	}
	if c.IsHomestead(block) {
		activeForks = append(activeForks, "Homestead")
	}
	if c.IsIstanbul(block) {
		activeForks = append(activeForks, "Istanbul")
	}
	if c.IsLondon(block) {
		activeForks = append(activeForks, "London")
	}
	if c.IsMerge(block) {
		activeForks = append(activeForks, "Merge")
	}
	if c.IsOsaka(block) {
		activeForks = append(activeForks, "Osaka")
	}
	if c.IsPetersburg(block) {
		activeForks = append(activeForks, "Petersburg")
	}
	if c.IsPrague(block) {
		activeForks = append(activeForks, "Prague")
	}
	if c.IsShanghai(block) {
		activeForks = append(activeForks, "Shanghai")
	}
	if c.IsEIP155(block) {
		activeForks = append(activeForks, "SpuriousDragon")
	}
	if c.IsTIP2019(block) {
		activeForks = append(activeForks, "TIP2019")
	}
	if c.IsTIPIncreaseMasternodes(block) {
		activeForks = append(activeForks, "TIPIncreaseMasternodes")
	}
	if c.IsTIPNoHalvingMNReward(block) {
		activeForks = append(activeForks, "TIPNoHalvingMNReward")
	}
	if c.IsTIPRandomize(block) {
		activeForks = append(activeForks, "TIPRandomize")
	}
	if c.IsTIPSigning(block) {
		activeForks = append(activeForks, "TIPSigning")
	}
	if c.IsTIPTRC21Fee(block) {
		activeForks = append(activeForks, "TIPTRC21Fee")
	}
	if c.IsTIPUpgradePenalty(block) {
		activeForks = append(activeForks, "TIPUpgradePenalty")
	}
	if c.IsTIPUpgradeReward(block) {
		activeForks = append(activeForks, "TIPUpgradeReward")
	}
	if c.IsTIPXDCX(block) {
		activeForks = append(activeForks, "TIPXDCX")
	}
	if c.IsTIPXDCXCancellationFee(block) {
		activeForks = append(activeForks, "TIPXDCXCancellationFee")
	}
	if c.IsTIPXDCXLending(block) {
		activeForks = append(activeForks, "TIPXDCXLending")
	}
	if c.IsTIPXDCXMiner(block) {
		activeForks = append(activeForks, "TIPXDCXMiner")
	}
	if c.IsTIPXDCXReceiver(block) {
		activeForks = append(activeForks, "TIPXDCXReceiver")
	}
	if c.IsEIP150(block) {
		activeForks = append(activeForks, "TangerineWhistle")
	}
	if c.IsTIPEpochHalving(block) {
		activeForks = append(activeForks, "TIPEpochHalving")
	}
	if c.IsXDCxDisable(block) {
		activeForks = append(activeForks, "XDCxDisable")
	}
	if c.IsXDPoSV2(block) {
		activeForks = append(activeForks, "XDPoSV2")
	}
	return activeForks
}

// ActiveSystemContracts returns the currently active system contracts at the
// given block height.
func (c *ChainConfig) ActiveSystemContracts(block uint64) map[string]common.Address {
	active := make(map[string]common.Address)
	blockNum := new(big.Int).SetUint64(block)
	add := func(name string, addr common.Address) {
		if !addr.IsZero() {
			active[name] = addr
		}
	}
	// MASTERNODE_VOTING_SMC and BLOCK_SIGNERS are XDPoS-specific and have no
	// dedicated config address fields. The XDPoS config is the local signal
	// that this chain actually deploys them, whereas the other entries below
	// are already gated by their own fork helpers or configured addresses.
	if c.XDPoS != nil {
		add("MASTERNODE_VOTING_SMC", common.MasternodeVotingSMCBinary)
	}
	if c.XDPoS != nil && !c.IsTIPSigning(blockNum) {
		add("BLOCK_SIGNERS", common.BlockSignersBinary)
	}
	if c.IsTIPRandomize(blockNum) {
		add("RANDOMIZE_SMC", common.RandomizeSMCBinary)
	}
	if c.IsTIPXDCX(blockNum) {
		add("XDCX_LISTING_SMC", c.XDCXListingSMC)
		add("RELAYER_REGISTRATION_SMC", c.RelayerRegistrationSMC)
	}
	if c.IsTIPXDCXLending(blockNum) {
		add("LENDING_REGISTRATION_SMC", c.LendingRegistrationSMC)
	}
	if c.IsTIPXDCXReceiver(blockNum) {
		add("XDCX_ADDRESS", common.XDCXAddrBinary)
		add("TRADING_STATE_ADDRESS", common.TradingStateAddrBinary)
		add("XDCX_LENDING_ADDRESS", common.XDCXLendingAddressBinary)
		add("XDCX_LENDING_FINALIZED_TRADE_ADDRESS", common.XDCXLendingFinalizedTradeAddressBinary)
	}
	if c.IsTIPTRC21Fee(blockNum) {
		add("TRC21_ISSUER_SMC", c.TRC21IssuerSMC)
	}
	if c.IsPrague(blockNum) {
		active["HISTORY_STORAGE_ADDRESS"] = HistoryStorageAddress
	}
	return active
}
