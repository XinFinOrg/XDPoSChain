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
	"fmt"
	"math/big"

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
	left := snapshotV2ReadOnly(a)
	right := snapshotV2ReadOnly(b)
	if left.switchEpoch != right.switchEpoch || !sameChainID(left.switchBlock, right.switchBlock) {
		return false
	}
	if !sameV2RuntimeConfig(left.currentConfig, right.currentConfig) {
		return false
	}
	if (left.allConfigs == nil) != (right.allConfigs == nil) {
		return false
	}
	if len(left.allConfigs) != len(right.allConfigs) {
		return false
	}
	for round, cfg := range left.allConfigs {
		other, ok := right.allConfigs[round]
		if !ok || !sameV2RuntimeConfig(cfg, other) {
			return false
		}
	}
	return true
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

// CheckConfigForkOrder validates that configured forks, required addresses, and
// XDPoS settings are internally consistent and activate in a supported order.
func (c *ChainConfig) CheckConfigForkOrder() error {
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
		if c.XDPoS.Epoch != 0 && c.XDPoS.V2.SwitchBlock.Uint64()%c.XDPoS.Epoch != 0 {
			return fmt.Errorf("invalid chain config: %w: XDPoS.V2.SwitchBlock %v not aligned to XDPoS.Epoch %d", ErrWrongForkSwitchOrder, c.XDPoS.V2.SwitchBlock, c.XDPoS.Epoch)
		}
	}
	return nil
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
