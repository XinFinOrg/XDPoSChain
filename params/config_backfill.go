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

// Backfill in this file is the hydration step that runs after decoding or
// cloning a ChainConfig and before compatibility checks compare effective
// values. CloneForBackfill prepares destination-side field-presence metadata so
// BackfillMissingFieldsFrom can copy only omitted fields from a canonical
// source config into the destination: generic fork blocks, system-contract
// addresses, consensus-engine selectors, and nested XDPoS/V2 fields. The
// narrower BackfillCustomMigratedFieldsFrom path is reserved for legacy custom
// network migrations and copies only the historical XDC-specific whitelist.

import (
	"fmt"
	"math"
	"math/big"
	"slices"
	"strings"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/log"
)

type chainConfigBigIntField struct {
	name           string
	jsonKey        string
	customMigrated bool
	xdcSpecific    bool
	get            func(*ChainConfig) *big.Int
	bind           func(*ChainConfig) **big.Int
}

type chainConfigAddressField struct {
	name    string
	jsonKey string
	get     func(*ChainConfig) common.Address
	bind    func(*ChainConfig) *common.Address
	compat  func(*ChainConfig) *big.Int
}

type chainConfigTopLevelField struct {
	jsonKey             string
	clone               func(dst, src *ChainConfig)
	marshalValue        func(*ChainConfig) any
	shouldInferPresence func(*ChainConfig) bool
}

type chainConfigBigIntBackfillField struct {
	key string
	dst **big.Int
	src *big.Int
}

type chainConfigForkOrderField struct {
	field    chainConfigBigIntField
	optional func(*ChainConfig) bool
}

type chainConfigForkOrderSpecialCaseRule struct {
	before         chainConfigBigIntField
	after          chainConfigBigIntField
	shouldValidate func(before, after *big.Int) bool
}

type chainConfigAddressBackfillField struct {
	key string
	dst *common.Address
	src common.Address
}

func (field chainConfigBigIntField) set(cfg *ChainConfig, value *big.Int) {
	*field.bind(cfg) = value
}

func (field chainConfigAddressField) set(cfg *ChainConfig, value common.Address) {
	*field.bind(cfg) = value
}

// chainConfigCommonBackfillBigIntFields is generated from config_backfill_fields.json.
var chainConfigCommonBackfillBigIntFields = generatedChainConfigCommonBackfillBigIntFields

// chainConfigBuiltInBackfillForkBlockFields is generated from config_backfill_fields.json.
var chainConfigBuiltInBackfillForkBlockFields = generatedChainConfigBuiltInBackfillForkBlockFields

// chainConfigXDCSystemContractFields is generated from config_backfill_fields.json.
var chainConfigXDCSystemContractFields = generatedChainConfigXDCSystemContractFields

// chainConfigXDCForkBlockFields is the authoritative list of top-level XDC-specific
// ChainConfig fork fields. When adding a new XDC field, add it here first so
// requiresXDCForkConfig, Clone, CloneWithInferredFieldPresence, MarshalJSON,
// backfill, semantic equality, and digesting stay in sync.
var chainConfigXDCForkBlockFields = filterChainConfigBigIntFields(chainConfigBuiltInBackfillForkBlockFields, func(field chainConfigBigIntField) bool {
	return field.xdcSpecific
})

// chainConfigForkBlockFields is the authoritative list of all top-level
// ChainConfig fork block fields. Add new standard or XDC fork blocks here via
// the source field lists so semantic equality, digesting, and fork iteration
// stay synchronized.
var chainConfigForkBlockFields = func() []chainConfigBigIntField {
	fields := filterChainConfigBigIntFields(chainConfigCommonBackfillBigIntFields, func(field chainConfigBigIntField) bool {
		return field.name != "ChainID"
	})
	fields = append(fields, chainConfigBuiltInBackfillForkBlockFields...)
	return fields
}()

func chainConfigForkBlockFieldByName(name string) (chainConfigBigIntField, bool) {
	for _, field := range chainConfigForkBlockFields {
		if field.name == name {
			return field, true
		}
	}
	return chainConfigBigIntField{}, false
}

// chainConfigForkOrderFields is the authoritative fork activation order used
// by CheckConfigForkOrder. It reuses the unified fork field descriptors and
// fails fast if any known fork field is missing from this order or the
// explicitly handled special-case rules below.
var chainConfigForkOrderSpecialCaseRules = func() []chainConfigForkOrderSpecialCaseRule {
	ruleDefs := []struct {
		before         string
		after          string
		shouldValidate func(before, after *big.Int) bool
	}{
		{
			before:         "TIPTRC21FeeBlock",
			after:          "Gas50xBlock",
			shouldValidate: func(before, after *big.Int) bool { return before != nil && after != nil },
		},
		{
			before: "Gas50xBlock",
			after:  "TIPXDCXMinerDisableBlock",
			shouldValidate: func(before, after *big.Int) bool {
				return before != nil && after != nil && after.Sign() > 0
			},
		},
	}
	rules := make([]chainConfigForkOrderSpecialCaseRule, 0, len(ruleDefs))
	for _, ruleDef := range ruleDefs {
		before, ok := chainConfigForkBlockFieldByName(ruleDef.before)
		if !ok {
			panic("chain config fork order special case references unknown before field: " + ruleDef.before)
		}
		after, ok := chainConfigForkBlockFieldByName(ruleDef.after)
		if !ok {
			panic("chain config fork order special case references unknown after field: " + ruleDef.after)
		}
		rules = append(rules, chainConfigForkOrderSpecialCaseRule{
			before:         before,
			after:          after,
			shouldValidate: ruleDef.shouldValidate,
		})
	}
	return rules
}()

var chainConfigForkOrderFieldDefs = generatedChainConfigForkOrderFieldDefs

var chainConfigForkOrderFieldNames = func() map[string]struct{} {
	fieldNames := make(map[string]struct{}, len(chainConfigForkOrderFieldDefs))
	for _, field := range chainConfigForkOrderFieldDefs {
		fieldNames[field.name] = struct{}{}
	}
	return fieldNames
}()

var chainConfigForkOrderSpecialCaseFieldNames = func() map[string]struct{} {
	fieldNames := make(map[string]struct{}, len(chainConfigForkOrderSpecialCaseRules))
	for _, rule := range chainConfigForkOrderSpecialCaseRules {
		if _, ordered := chainConfigForkOrderFieldNames[rule.before.name]; !ordered {
			fieldNames[rule.before.name] = struct{}{}
		}
		if _, ordered := chainConfigForkOrderFieldNames[rule.after.name]; !ordered {
			fieldNames[rule.after.name] = struct{}{}
		}
	}
	return fieldNames
}()

var chainConfigForkOrderFields = func() []chainConfigForkOrderField {
	fieldByName := make(map[string]chainConfigBigIntField, len(chainConfigForkBlockFields))
	for _, field := range chainConfigForkBlockFields {
		fieldByName[field.name] = field
	}
	resolved := make([]chainConfigForkOrderField, 0, len(chainConfigForkOrderFieldDefs))
	seen := make(map[string]struct{}, len(chainConfigForkOrderFieldDefs))
	for _, entry := range chainConfigForkOrderFieldDefs {
		field, ok := fieldByName[entry.name]
		if !ok {
			panic("chain config fork order references unknown field: " + entry.name)
		}
		if _, exists := seen[entry.name]; exists {
			panic("duplicate chain config fork order field: " + entry.name)
		}
		seen[entry.name] = struct{}{}
		resolved = append(resolved, chainConfigForkOrderField{field: field, optional: entry.optional})
	}
	if len(seen)+len(chainConfigForkOrderSpecialCaseFieldNames) != len(chainConfigForkBlockFields) {
		for _, field := range chainConfigForkBlockFields {
			if _, ok := seen[field.name]; ok {
				continue
			}
			if _, ok := chainConfigForkOrderSpecialCaseFieldNames[field.name]; ok {
				continue
			}
			panic("chain config fork order missing field: " + field.name)
		}
	}
	for fieldName := range chainConfigForkOrderSpecialCaseFieldNames {
		if _, ok := fieldByName[fieldName]; !ok {
			panic("chain config fork order special case references unknown field: " + fieldName)
		}
	}
	return resolved
}()

var chainConfigCompatibilitySpecialCaseFieldNames = func() map[string]struct{} {
	fieldNames := map[string]struct{}{
		"PetersburgBlock": {},
	}
	for fieldName := range fieldNames {
		if _, ok := chainConfigForkBlockFieldByName(fieldName); !ok {
			panic("chain config compatibility special case references unknown field: " + fieldName)
		}
	}
	return fieldNames
}()

var chainConfigCompatibilityInsertionDefs = []struct {
	after string
	name  string
}{
	{after: "ShanghaiBlock", name: "Gas50xBlock"},
}

var chainConfigCompatibilityFields = func() []chainConfigBigIntField {
	fieldByName := make(map[string]chainConfigBigIntField, len(chainConfigForkBlockFields))
	for _, field := range chainConfigForkBlockFields {
		fieldByName[field.name] = field
	}
	insertAfter := make(map[string][]chainConfigBigIntField, len(chainConfigCompatibilityInsertionDefs))
	for _, entry := range chainConfigCompatibilityInsertionDefs {
		if _, ok := fieldByName[entry.after]; !ok {
			panic("chain config compatibility insertion references unknown after field: " + entry.after)
		}
		field, ok := fieldByName[entry.name]
		if !ok {
			panic("chain config compatibility insertion references unknown field: " + entry.name)
		}
		insertAfter[entry.after] = append(insertAfter[entry.after], field)
	}
	resolved := make([]chainConfigBigIntField, 0, len(chainConfigForkBlockFields))
	seen := make(map[string]struct{}, len(chainConfigForkBlockFields))
	appendField := func(field chainConfigBigIntField) {
		if _, exists := seen[field.name]; exists {
			panic("duplicate chain config compatibility field: " + field.name)
		}
		seen[field.name] = struct{}{}
		resolved = append(resolved, field)
	}
	for _, field := range chainConfigForkOrderFields {
		appendField(field.field)
		for _, inserted := range insertAfter[field.field.name] {
			appendField(inserted)
		}
	}
	if len(seen) != len(chainConfigForkBlockFields) {
		for _, field := range chainConfigForkBlockFields {
			if _, ok := seen[field.name]; ok {
				continue
			}
			panic("chain config compatibility missing field: " + field.name)
		}
	}
	return resolved
}()

func alwaysOptionalChainConfigForkOrderField(*ChainConfig) bool {
	return true
}

func chainConfigBigIntFieldJSONKeys(fields []chainConfigBigIntField) []string {
	keys := make([]string, 0, len(fields))
	for _, field := range fields {
		keys = append(keys, field.jsonKey)
	}
	return keys
}

// BuiltInBackfillForkFieldJSONKeys returns a copy of the authoritative top-level
// fork JSON keys that built-in config backfill may hydrate.
func BuiltInBackfillForkFieldJSONKeys() []string {
	return append([]string(nil), chainConfigBigIntFieldJSONKeys(chainConfigBuiltInBackfillForkBlockFields)...)
}

func filterChainConfigBigIntFields(fields []chainConfigBigIntField, keep func(chainConfigBigIntField) bool) []chainConfigBigIntField {
	filtered := make([]chainConfigBigIntField, 0, len(fields))
	for _, field := range fields {
		if keep(field) {
			filtered = append(filtered, field)
		}
	}
	return filtered
}

func chainConfigBigIntBackfillFields(dest, src *ChainConfig, fields []chainConfigBigIntField) []chainConfigBigIntBackfillField {
	backfillFields := make([]chainConfigBigIntBackfillField, 0, len(fields))
	for _, field := range fields {
		backfillFields = append(backfillFields, chainConfigBigIntBackfillField{
			key: field.jsonKey,
			dst: field.bind(dest),
			src: field.get(src),
		})
	}
	return backfillFields
}

func chainConfigAddressBackfillFields(dest, src *ChainConfig, fields []chainConfigAddressField) []chainConfigAddressBackfillField {
	backfillFields := make([]chainConfigAddressBackfillField, 0, len(fields))
	for _, field := range fields {
		backfillFields = append(backfillFields, chainConfigAddressBackfillField{
			key: field.jsonKey,
			dst: field.bind(dest),
			src: field.get(src),
		})
	}
	return backfillFields
}

func chainConfigBigIntFieldValue(cfg *ChainConfig, field chainConfigBigIntField) *big.Int {
	if cfg == nil {
		return nil
	}
	return field.get(cfg)
}

func chainConfigAddressFieldValue(cfg *ChainConfig, field chainConfigAddressField) common.Address {
	if cfg == nil {
		return common.Address{}
	}
	return field.get(cfg)
}

func chainConfigTopLevelBigIntFields(fields []chainConfigBigIntField) []chainConfigTopLevelField {
	topLevelFields := make([]chainConfigTopLevelField, 0, len(fields))
	for _, field := range fields {
		field := field
		topLevelFields = append(topLevelFields, chainConfigTopLevelField{
			jsonKey: field.jsonKey,
			clone: func(dst, src *ChainConfig) {
				field.set(dst, common.CloneBigInt(field.get(src)))
			},
			marshalValue: func(cfg *ChainConfig) any {
				return field.get(cfg)
			},
			shouldInferPresence: func(cfg *ChainConfig) bool {
				return field.get(cfg) != nil
			},
		})
	}
	return topLevelFields
}

func chainConfigTopLevelAddressFields(fields []chainConfigAddressField) []chainConfigTopLevelField {
	topLevelFields := make([]chainConfigTopLevelField, 0, len(fields))
	for _, field := range fields {
		field := field
		topLevelFields = append(topLevelFields, chainConfigTopLevelField{
			jsonKey: field.jsonKey,
			clone: func(dst, src *ChainConfig) {
				field.set(dst, field.get(src))
			},
			marshalValue: func(cfg *ChainConfig) any {
				return field.get(cfg)
			},
			shouldInferPresence: func(cfg *ChainConfig) bool {
				return !field.get(cfg).IsZero()
			},
		})
	}
	return topLevelFields
}

var chainConfigTopLevelFields = func() []chainConfigTopLevelField {
	fields := make([]chainConfigTopLevelField, 0, len(chainConfigCommonBackfillBigIntFields)+len(chainConfigBuiltInBackfillForkBlockFields)+len(chainConfigXDCSystemContractFields)+4)
	fields = append(fields, chainConfigTopLevelBigIntFields(chainConfigCommonBackfillBigIntFields)...)
	fields = append(fields, chainConfigTopLevelField{
		jsonKey: "daoForkSupport",
		clone: func(dst, src *ChainConfig) {
			dst.DAOForkSupport = src.DAOForkSupport
		},
		marshalValue: func(cfg *ChainConfig) any {
			return cfg.DAOForkSupport
		},
		shouldInferPresence: func(cfg *ChainConfig) bool {
			return cfg.DAOForkBlock != nil || cfg.DAOForkSupport
		},
	})
	fields = append(fields, chainConfigTopLevelBigIntFields(chainConfigBuiltInBackfillForkBlockFields)...)
	fields = append(fields, chainConfigTopLevelField{
		jsonKey: "denylistActivations",
		clone: func(dst, src *ChainConfig) {
			dst.DenylistActivations = cloneDenylistActivations(src.DenylistActivations)
		},
		marshalValue: func(cfg *ChainConfig) any {
			return cfg.DenylistActivations
		},
		shouldInferPresence: func(cfg *ChainConfig) bool {
			return cfg.DenylistActivations != nil
		},
	})
	fields = append(fields, chainConfigTopLevelAddressFields(chainConfigXDCSystemContractFields)...)
	fields = append(fields,
		chainConfigTopLevelField{
			jsonKey: "ethash",
			clone: func(dst, src *ChainConfig) {
				if src.Ethash != nil {
					dst.Ethash = new(EthashConfig)
				} else {
					dst.Ethash = nil
				}
			},
			marshalValue: func(cfg *ChainConfig) any {
				return cfg.Ethash
			},
			shouldInferPresence: func(cfg *ChainConfig) bool {
				return cfg.Ethash != nil
			},
		},
		chainConfigTopLevelField{
			jsonKey: "clique",
			clone: func(dst, src *ChainConfig) {
				if src.Clique != nil {
					clique := *src.Clique
					dst.Clique = &clique
				} else {
					dst.Clique = nil
				}
			},
			marshalValue: func(cfg *ChainConfig) any {
				return cfg.Clique
			},
			shouldInferPresence: func(cfg *ChainConfig) bool {
				return cfg.Clique != nil
			},
		},
		chainConfigTopLevelField{
			jsonKey: "XDPoS",
			clone: func(dst, src *ChainConfig) {
				dst.XDPoS = src.XDPoS.Clone()
			},
			marshalValue: func(cfg *ChainConfig) any {
				return cfg.XDPoS
			},
			shouldInferPresence: func(cfg *ChainConfig) bool {
				return cfg.XDPoS != nil
			},
		},
	)
	return fields
}()

// cloneDenylistActivations deep-copies a denylist activation schedule so a clone
// never aliases the source config's heights.
func cloneDenylistActivations(src map[uint8]*big.Int) map[uint8]*big.Int {
	if src == nil {
		return nil
	}
	dst := make(map[uint8]*big.Int, len(src))
	for version, block := range src {
		dst[version] = common.CloneBigInt(block)
	}
	return dst
}

// DenylistActivationVersions returns the versions scheduled by cfg in
// ascending order, giving callers a deterministic iteration order over a map.
func DenylistActivationVersions(cfg *ChainConfig) []uint8 {
	if cfg == nil || len(cfg.DenylistActivations) == 0 {
		return nil
	}
	versions := make([]uint8, 0, len(cfg.DenylistActivations))
	for version := range cfg.DenylistActivations {
		versions = append(versions, version)
	}
	slices.Sort(versions)
	return versions
}

func chainConfigTopLevelFieldJSONKeys() []string {
	keys := make([]string, 0, len(chainConfigTopLevelFields))
	for _, field := range chainConfigTopLevelFields {
		keys = append(keys, field.jsonKey)
	}
	return keys
}

// ForEachChainConfigXDCForkBlock visits XDC-specific top-level fork blocks in authoritative order.
func ForEachChainConfigXDCForkBlock(cfg *ChainConfig, visit func(name string, value *big.Int)) {
	for _, field := range chainConfigXDCForkBlockFields {
		visit(field.name, chainConfigBigIntFieldValue(cfg, field))
	}
}

// ForEachChainConfigForkBlock visits all top-level fork blocks in authoritative order.
func ForEachChainConfigForkBlock(cfg *ChainConfig, visit func(name string, value *big.Int)) {
	for _, field := range chainConfigForkBlockFields {
		visit(field.name, chainConfigBigIntFieldValue(cfg, field))
	}
}

// ForEachChainConfigXDCForkBlockPair visits XDC-specific top-level fork block pairs in authoritative order.
func ForEachChainConfigXDCForkBlockPair(a, b *ChainConfig, visit func(name string, aValue, bValue *big.Int)) {
	for _, field := range chainConfigXDCForkBlockFields {
		visit(field.name, chainConfigBigIntFieldValue(a, field), chainConfigBigIntFieldValue(b, field))
	}
}

// ForEachChainConfigForkBlockPair visits all top-level fork block pairs in authoritative order.
func ForEachChainConfigForkBlockPair(a, b *ChainConfig, visit func(name string, aValue, bValue *big.Int)) {
	for _, field := range chainConfigForkBlockFields {
		visit(field.name, chainConfigBigIntFieldValue(a, field), chainConfigBigIntFieldValue(b, field))
	}
}

// ForEachChainConfigForkOrderBlock visits fork blocks in validation order.
func ForEachChainConfigForkOrderBlock(cfg *ChainConfig, visit func(name string, value *big.Int, optional bool)) {
	for _, field := range chainConfigForkOrderFields {
		visit(field.field.name, chainConfigBigIntFieldValue(cfg, field.field), field.optional(cfg))
	}
}

// ForEachChainConfigForkOrderBlockPair visits fork block pairs in validation order.
func ForEachChainConfigForkOrderBlockPair(a, b *ChainConfig, visit func(name string, aValue, bValue *big.Int)) {
	for _, field := range chainConfigForkOrderFields {
		visit(field.field.name, chainConfigBigIntFieldValue(a, field.field), chainConfigBigIntFieldValue(b, field.field))
	}
}

// ForEachChainConfigCompatibleForkBlockPair visits the simple block-based
// compatibility checks derived from the shared fork validation order.
func ForEachChainConfigCompatibleForkBlockPair(a, b *ChainConfig, visit func(name string, aValue, bValue *big.Int)) {
	for _, field := range chainConfigCompatibilityFields {
		name := field.name
		if _, specialCase := chainConfigCompatibilitySpecialCaseFieldNames[name]; specialCase {
			continue
		}
		visit(name, chainConfigBigIntFieldValue(a, field), chainConfigBigIntFieldValue(b, field))
	}
}

// ForEachChainConfigForkOrderSpecialCaseRule visits fork-order relationships that
// are validated outside the main linear order.
func ForEachChainConfigForkOrderSpecialCaseRule(visit func(before, after string)) {
	for _, rule := range chainConfigForkOrderSpecialCaseRules {
		visit(rule.before.name, rule.after.name)
	}
}

// ForEachChainConfigXDCSystemContract visits XDC-specific top-level system-contract addresses in authoritative order.
func ForEachChainConfigXDCSystemContract(cfg *ChainConfig, visit func(name string, value common.Address)) {
	for _, field := range chainConfigXDCSystemContractFields {
		visit(field.name, chainConfigAddressFieldValue(cfg, field))
	}
}

// ForEachChainConfigXDCSystemContractPair visits XDC-specific top-level system-contract address pairs in authoritative order.
func ForEachChainConfigXDCSystemContractPair(a, b *ChainConfig, visit func(name string, aValue, bValue common.Address)) {
	for _, field := range chainConfigXDCSystemContractFields {
		visit(field.name, chainConfigAddressFieldValue(a, field), chainConfigAddressFieldValue(b, field))
	}
}

var customBackfillForkFieldJSONKeys = func() []string {
	keys := make([]string, 0, len(chainConfigXDCForkBlockFields))
	for _, field := range chainConfigXDCForkBlockFields {
		if !field.customMigrated {
			continue
		}
		keys = append(keys, field.jsonKey)
	}
	return keys
}()

func (c *XDPoSConfig) cloneWithInferredFieldPresence() *XDPoSConfig {
	if c == nil {
		return nil
	}
	clone := c.Clone()
	clone.json.startInferredTracking()

	if clone.Period != 0 {
		clone.json.mark("period")
	}
	if clone.Epoch != 0 {
		clone.json.mark("epoch")
	}
	if clone.Reward != 0 {
		clone.json.mark("reward")
	}
	if clone.RewardCheckpoint != 0 {
		clone.json.mark("rewardCheckpoint")
	}
	if clone.Gap != 0 {
		clone.json.mark("gap")
	}
	if !clone.FoundationWalletAddr.IsZero() {
		clone.json.mark("foundationWalletAddr")
	}
	if clone.MaxMasternodesV2 != 0 {
		clone.json.mark("maxMasternodesV2")
	}
	if clone.SkipV1Validation || len(clone.json.keys) > 0 || clone.V2 != nil {
		clone.json.mark("SkipV1Validation")
	}
	if clone.V2 != nil {
		clone.json.mark("v2")
		clone.V2 = clone.V2.cloneWithInferredFieldPresence()
	}
	return clone
}

// HasJSONFieldPresence reports whether this config tracks which JSON fields
// isJSONFieldMissing reports whether key was omitted from the source JSON.
func (c *ChainConfig) isJSONFieldMissing(key string, fallback bool) bool {
	if c == nil {
		return false
	}
	return c.runtime.json.isMissing(key, fallback)
}

func validateV2ExpTimeoutConfig(cfg *V2Config, fieldPath string) error {
	if cfg == nil {
		return nil
	}
	if cfg.ExpTimeoutConfig.MaxExponent >= 32 {
		return fmt.Errorf("%s: max_exponent (%d)= >= max_exponent_upperbound (%d)", fieldPath, cfg.ExpTimeoutConfig.MaxExponent, 32)
	}
	if math.Pow(cfg.ExpTimeoutConfig.Base, float64(cfg.ExpTimeoutConfig.MaxExponent)) >= float64(math.MaxUint32) {
		return fmt.Errorf("%s: base^max_exponent (%f^%d) should be less than 2^32", fieldPath, cfg.ExpTimeoutConfig.Base, cfg.ExpTimeoutConfig.MaxExponent)
	}
	return nil
}

// isJSONFieldMissing reports whether key was omitted from the XDPoS JSON.
func (c *XDPoSConfig) isJSONFieldMissing(key string, fallback bool) bool {
	if c == nil {
		return false
	}
	if !c.json.tracked {
		return fallback
	}
	if key == "foundationWalletAddr" {
		if _, ok := c.json.keys["foudationWalletAddr"]; ok {
			return false
		}
	}
	_, ok := c.json.keys[key]
	return !ok
}

// isJSONFieldMissing reports whether key was omitted from the V2 JSON.
func (v2 *V2) isJSONFieldMissing(key string, fallback bool) bool {
	if v2 == nil {
		return false
	}
	if !v2.json.tracked {
		return fallback
	}
	if key == "switchEpoch" {
		if _, ok := v2.json.keys["SwitchEpoch"]; ok {
			return false
		}
	}
	_, ok := v2.json.keys[key]
	return !ok
}

// isJSONFieldMissing reports whether key was omitted from the V2Config JSON.
func (c *V2Config) isJSONFieldMissing(key string, fallback bool) bool {
	if c == nil {
		return false
	}
	if !c.json.tracked {
		return fallback
	}
	_, ok := c.json.keys[key]
	return !ok
}

// isJSONFieldMissing reports whether key was omitted from the timeout JSON.
func (c *ExpTimeoutConfig) isJSONFieldMissing(key string, fallback bool) bool {
	if c == nil {
		return false
	}
	if !c.json.tracked {
		return fallback
	}
	_, ok := c.json.keys[key]
	return !ok
}

// cloneV2ConfigMap deep-copies a V2 config map.
func cloneV2ConfigMap(configs map[uint64]*V2Config) map[uint64]*V2Config {
	if configs == nil {
		return nil
	}
	clone := make(map[uint64]*V2Config, len(configs))
	for key, cfg := range configs {
		clone[key] = cfg.Clone()
	}
	return clone
}

// isZeroExpTimeoutConfig reports whether cfg only contains zero values.
func isZeroExpTimeoutConfig(cfg ExpTimeoutConfig) bool {
	return cfg.Base == 0 && cfg.MaxExponent == 0
}

// backfillMissingFieldsFrom copies omitted timeout fields from src into c.
func (c *ExpTimeoutConfig) backfillMissingFieldsFrom(src *ExpTimeoutConfig) *ExpTimeoutConfig {
	if c == nil {
		return nil
	}
	dest := *c
	dest.json = c.json.clone()
	if src == nil {
		return &dest
	}
	dest.backfillMissingScalarFieldsFrom(src)
	return &dest
}

func (c *ExpTimeoutConfig) backfillMissingScalarFieldsFrom(src *ExpTimeoutConfig) {
	if c == nil || src == nil {
		return
	}
	if c.isJSONFieldMissing("base", c.Base == 0) {
		log.Info("Backfilled missing field", "field", "XDPoS.v2.expTimeoutConfig.base", "old", c.Base, "new", src.Base)
		c.Base = src.Base
	}
	if c.isJSONFieldMissing("maxExponent", c.MaxExponent == 0) {
		log.Info("Backfilled missing field", "field", "XDPoS.v2.expTimeoutConfig.maxExponent", "old", c.MaxExponent, "new", src.MaxExponent)
		c.MaxExponent = src.MaxExponent
	}
}

// backfillMissingFieldsFrom copies omitted V2 config fields from src into c.
func (c *V2Config) backfillMissingFieldsFrom(src *V2Config) *V2Config {
	if c == nil {
		return nil
	}
	dest := c.Clone()
	if src == nil {
		return dest
	}
	dest.backfillMissingScalarFieldsFrom(src)
	if dest.isJSONFieldMissing("expTimeoutConfig", isZeroExpTimeoutConfig(dest.ExpTimeoutConfig)) {
		log.Info("Backfilled missing field", "field", "XDPoS.v2.config.expTimeoutConfig", "old", dest.ExpTimeoutConfig, "new", src.ExpTimeoutConfig)
		dest.ExpTimeoutConfig = src.ExpTimeoutConfig
		dest.ExpTimeoutConfig.json = src.ExpTimeoutConfig.json.clone()
	} else {
		dest.ExpTimeoutConfig = *(&dest.ExpTimeoutConfig).backfillMissingFieldsFrom(&src.ExpTimeoutConfig)
	}
	return dest
}

func (c *V2Config) backfillMissingScalarFieldsFrom(src *V2Config) {
	if c == nil || src == nil {
		return
	}
	intFields := []struct {
		key string
		dst *int
		src int
	}{
		{"maxMasternodes", &c.MaxMasternodes, src.MaxMasternodes},
		{"maxProtectorNodes", &c.MaxProtectorNodes, src.MaxProtectorNodes},
		{"maxObserverNodes", &c.MaxObserverNodes, src.MaxObserverNodes},
		{"minePeriod", &c.MinePeriod, src.MinePeriod},
		{"timeoutSyncThreshold", &c.TimeoutSyncThreshold, src.TimeoutSyncThreshold},
		{"timeoutPeriod", &c.TimeoutPeriod, src.TimeoutPeriod},
		{"minimumMinerBlockPerEpoch", &c.MinimumMinerBlockPerEpoch, src.MinimumMinerBlockPerEpoch},
		{"limitPenaltyEpoch", &c.LimitPenaltyEpoch, src.LimitPenaltyEpoch},
		{"minimumSigningTx", &c.MinimumSigningTx, src.MinimumSigningTx},
	}
	uintFields := []struct {
		key string
		dst *uint64
		src uint64
	}{
		{"switchRound", &c.SwitchRound, src.SwitchRound},
	}
	floatFields := []struct {
		key string
		dst *float64
		src float64
	}{
		{"certificateThreshold", &c.CertThreshold, src.CertThreshold},
		{"masternodeReward", &c.MasternodeReward, src.MasternodeReward},
		{"protectorReward", &c.ProtectorReward, src.ProtectorReward},
		{"observerReward", &c.ObserverReward, src.ObserverReward},
	}
	for _, field := range intFields {
		if c.isJSONFieldMissing(field.key, *field.dst == 0) {
			log.Info("Backfilled missing field", "field", "XDPoS.v2.config."+field.key, "old", *field.dst, "new", field.src)
			*field.dst = field.src
		}
	}
	for _, field := range uintFields {
		if c.isJSONFieldMissing(field.key, *field.dst == 0) {
			log.Info("Backfilled missing field", "field", "XDPoS.v2.config."+field.key, "old", *field.dst, "new", field.src)
			*field.dst = field.src
		}
	}
	for _, field := range floatFields {
		if c.isJSONFieldMissing(field.key, *field.dst == 0) {
			log.Info("Backfilled missing field", "field", "XDPoS.v2.config."+field.key, "old", *field.dst, "new", field.src)
			*field.dst = field.src
		}
	}
}

// backfillMissingFieldsFrom copies omitted V2 scheduling fields from src.
func (v2 *V2) backfillMissingFieldsFrom(src *V2) *V2 {
	if v2 == nil {
		return nil
	}
	dest := v2.Clone()
	if src == nil {
		return dest
	}
	if dest.isJSONFieldMissing("switchEpoch", dest.SwitchEpoch == 0) {
		log.Info("Backfilled missing field", "field", "XDPoS.v2.switchEpoch", "old", dest.SwitchEpoch, "new", src.SwitchEpoch)
		dest.SwitchEpoch = src.SwitchEpoch
	}
	if dest.isJSONFieldMissing("switchBlock", dest.SwitchBlock == nil) {
		log.Info("Backfilled missing field", "field", "XDPoS.v2.switchBlock", "old", dest.SwitchBlock, "new", src.SwitchBlock)
		dest.SwitchBlock = common.CloneBigInt(src.SwitchBlock)
	}
	if dest.isJSONFieldMissing("config", dest.CurrentConfig == nil) {
		log.Info("Backfilled missing field", "field", "XDPoS.v2.config", "old", dest.CurrentConfig, "new", src.CurrentConfig)
		dest.CurrentConfig = src.CurrentConfig.Clone()
	} else if dest.CurrentConfig != nil && src.CurrentConfig != nil {
		dest.CurrentConfig = dest.CurrentConfig.backfillMissingFieldsFrom(src.CurrentConfig)
	}
	if dest.isJSONFieldMissing("allConfigs", dest.AllConfigs == nil) {
		log.Info("Backfilled missing field", "field", "XDPoS.v2.allConfigs", "old", dest.AllConfigs, "new", src.AllConfigs)
		dest.AllConfigs = cloneV2ConfigMap(src.AllConfigs)
	} else if src.AllConfigs != nil {
		if dest.AllConfigs == nil {
			dest.AllConfigs = make(map[uint64]*V2Config, len(src.AllConfigs))
		}
		for key, srcCfg := range src.AllConfigs {
			if destCfg, ok := dest.AllConfigs[key]; ok {
				if destCfg != nil && srcCfg != nil {
					dest.AllConfigs[key] = destCfg.backfillMissingFieldsFrom(srcCfg)
				}
				continue
			}
			if _, ok := dest.AllConfigs[key]; !ok {
				log.Info("Backfilled missing field", "field", fmt.Sprintf("XDPoS.v2.allConfigs[%d]", key), "old", nil, "new", srcCfg)
			}
			dest.AllConfigs[key] = srcCfg.Clone()
		}
	}
	if len(dest.configIndex) == 0 && len(src.configIndex) > 0 {
		dest.configIndex = append([]uint64(nil), src.configIndex...)
	}
	return dest
}

// BackfillMissingFieldsFrom copies missing fields from source into c.
//
// When c was populated through UnmarshalJSON, missingness is determined by the
// original JSON keys: explicit values such as berlinBlock: 0 or pragueBlock:
// null remain authoritative and are not overwritten. When JSON presence
// metadata is unavailable, the compatibility fallback degrades to treating nil
// pointers and zero values as missing. This preserves legacy callers that build
// ChainConfig values directly in code, but a custom network that backfills from
// LocalnetChainConfig should declare every fork explicitly if it needs to avoid
// inheriting Localnet defaults.
func (c *ChainConfig) BackfillMissingFieldsFrom(src *ChainConfig) *ChainConfig {
	if c == nil {
		return c
	}
	dest := c.Clone()
	if src == nil {
		return dest
	}

	bigIntFields := chainConfigBigIntBackfillFields(dest, src, chainConfigCommonBackfillBigIntFields)
	bigIntFields = append(bigIntFields, chainConfigBigIntBackfillFields(dest, src, chainConfigBuiltInBackfillForkBlockFields)...)

	addressFields := chainConfigAddressBackfillFields(dest, src, chainConfigXDCSystemContractFields)
	customLocalnetFallbackFields := make([]string, 0, len(bigIntFields)+len(addressFields)+1)
	trackCustomLocalnetFallback := shouldWarnOnCustomLocalnetFallback(dest, src)

	for _, field := range bigIntFields {
		if dest.isJSONFieldMissing(field.key, *field.dst == nil) {
			log.Info("Backfilled missing field", "field", field.key, "old", *field.dst, "new", field.src)
			*field.dst = common.CloneBigInt(field.src)
			if trackCustomLocalnetFallback {
				customLocalnetFallbackFields = append(customLocalnetFallbackFields, field.key)
			}
		}
	}

	for _, field := range addressFields {
		if dest.isJSONFieldMissing(field.key, field.dst.IsZero()) {
			log.Info("Backfilled missing field", "field", field.key, "old", field.dst, "new", field.src)
			*field.dst = field.src
			if trackCustomLocalnetFallback {
				customLocalnetFallbackFields = append(customLocalnetFallbackFields, field.key)
			}
		}
	}

	// denylist activation schedule
	if dest.isJSONFieldMissing("denylistActivations", dest.DenylistActivations == nil) {
		log.Info("Backfilled missing field", "field", "denylistActivations", "old", dest.DenylistActivations, "new", src.DenylistActivations)
		dest.DenylistActivations = cloneDenylistActivations(src.DenylistActivations)
		if trackCustomLocalnetFallback {
			customLocalnetFallbackFields = append(customLocalnetFallbackFields, "denylistActivations")
		}
	}

	// bool fields
	if dest.isJSONFieldMissing("daoForkSupport", !dest.DAOForkSupport) {
		log.Info("Backfilled missing field", "field", "daoForkSupport", "old", dest.DAOForkSupport, "new", src.DAOForkSupport)
		dest.DAOForkSupport = src.DAOForkSupport
		if trackCustomLocalnetFallback {
			customLocalnetFallbackFields = append(customLocalnetFallbackFields, "daoForkSupport")
		}
	}
	if dest.runtime.json.tracked && !dest.runtime.json.preserve {
		dest = dest.CloneForBackfill()
	}

	dest.backfillMissingConsensusConfigsFrom(src)

	if dest.XDPoS == nil {
		log.Warn("XDPoS in destination chain config is nil", "chainId", dest.ChainID)
	} else if src.XDPoS == nil {
		log.Warn("XDPoS in source chain config is nil", "chainId", src.ChainID)
		return dest
	} else {
		dest.XDPoS.backfillMissingScalarFieldsFrom(src.XDPoS)
		if dest.XDPoS.isJSONFieldMissing("v2", dest.XDPoS.V2 == nil) {
			log.Info("Backfilled missing field", "field", "XDPoS.v2", "old", dest.XDPoS.V2, "new", src.XDPoS.V2)
			dest.XDPoS.V2 = src.XDPoS.V2.Clone()
		} else if dest.XDPoS.V2 != nil && src.XDPoS.V2 != nil {
			dest.XDPoS.V2 = dest.XDPoS.V2.backfillMissingFieldsFrom(src.XDPoS.V2)
		}
	}
	if trackCustomLocalnetFallback && len(customLocalnetFallbackFields) > 0 {
		log.Warn("Custom chain config used Localnet fallback defaults", "chainId", dest.ChainID, "jsonPresenceTracked", dest.runtime.json.tracked, "fields", strings.Join(customLocalnetFallbackFields, ","))
	}

	return dest
}

// BackfillCustomMigratedFieldsFrom copies only the historical custom-network
// compatibility fields from src into c when those fields were omitted.
func (c *ChainConfig) BackfillCustomMigratedFieldsFrom(src *ChainConfig) *ChainConfig {
	if c == nil {
		return c
	}
	dest := c.Clone()
	if src == nil {
		return dest
	}

	bigIntFields := customMigratedBackfillBigIntFields(dest, src)
	addressFields := chainConfigAddressBackfillFields(dest, src, chainConfigXDCSystemContractFields)

	for _, field := range bigIntFields {
		if dest.isJSONFieldMissing(field.key, *field.dst == nil) {
			log.Info("Backfilled missing field", "field", field.key, "old", *field.dst, "new", field.src)
			*field.dst = common.CloneBigInt(field.src)
		}
	}
	for _, field := range addressFields {
		if dest.isJSONFieldMissing(field.key, field.dst.IsZero()) {
			log.Info("Backfilled missing field", "field", field.key, "old", field.dst, "new", field.src)
			*field.dst = field.src
		}
	}
	if dest.XDPoS != nil && src.XDPoS != nil && dest.XDPoS.isJSONFieldMissing("maxMasternodesV2", dest.XDPoS.MaxMasternodesV2 == 0) {
		log.Info("Backfilled missing field", "field", "XDPoS.maxMasternodesV2", "old", dest.XDPoS.MaxMasternodesV2, "new", src.XDPoS.MaxMasternodesV2)
		dest.XDPoS.MaxMasternodesV2 = src.XDPoS.MaxMasternodesV2
	}
	return dest
}

func (c *ChainConfig) backfillMissingConsensusConfigsFrom(src *ChainConfig) {
	if c == nil || src == nil {
		return
	}
	if c.Clique == nil && c.XDPoS == nil && c.isJSONFieldMissing("ethash", c.Ethash == nil) {
		log.Info("Backfilled missing field", "field", "ethash", "old", c.Ethash, "new", src.Ethash)
		if src.Ethash != nil {
			c.Ethash = new(EthashConfig)
		}
	}
	if c.Ethash == nil && c.XDPoS == nil && c.isJSONFieldMissing("clique", c.Clique == nil) {
		log.Info("Backfilled missing field", "field", "clique", "old", c.Clique, "new", src.Clique)
		if src.Clique != nil {
			clique := *src.Clique
			c.Clique = &clique
		}
	}
	if c.Ethash == nil && c.Clique == nil && c.isJSONFieldMissing("XDPoS", c.XDPoS == nil) {
		log.Info("Backfilled missing field", "field", "XDPoS", "old", c.XDPoS, "new", src.XDPoS)
		c.XDPoS = src.XDPoS.Clone()
	}
}

func (c *XDPoSConfig) backfillMissingScalarFieldsFrom(src *XDPoSConfig) {
	if c == nil || src == nil {
		return
	}
	uintFields := []struct {
		key string
		dst *uint64
		src uint64
	}{
		{"period", &c.Period, src.Period},
		{"epoch", &c.Epoch, src.Epoch},
		{"reward", &c.Reward, src.Reward},
		{"rewardCheckpoint", &c.RewardCheckpoint, src.RewardCheckpoint},
		{"gap", &c.Gap, src.Gap},
	}
	addressFields := []struct {
		key string
		dst *common.Address
		src common.Address
	}{
		{"foundationWalletAddr", &c.FoundationWalletAddr, src.FoundationWalletAddr},
	}
	intFields := []struct {
		key string
		dst *int
		src int
	}{
		{"maxMasternodesV2", &c.MaxMasternodesV2, src.MaxMasternodesV2},
	}
	boolFields := []struct {
		key string
		dst *bool
		src bool
	}{
		{"SkipV1Validation", &c.SkipV1Validation, src.SkipV1Validation},
	}

	for _, field := range uintFields {
		if c.isJSONFieldMissing(field.key, *field.dst == 0) {
			log.Info("Backfilled missing field", "field", "XDPoS."+field.key, "old", *field.dst, "new", field.src)
			*field.dst = field.src
		}
	}
	for _, field := range addressFields {
		if c.isJSONFieldMissing(field.key, field.dst.IsZero()) {
			log.Info("Backfilled missing field", "field", "XDPoS."+field.key, "old", field.dst.Hex(), "new", field.src.Hex())
			*field.dst = field.src
		}
	}
	for _, field := range intFields {
		if c.isJSONFieldMissing(field.key, *field.dst == 0) {
			log.Info("Backfilled missing field", "field", "XDPoS."+field.key, "old", *field.dst, "new", field.src)
			*field.dst = field.src
		}
	}
	for _, field := range boolFields {
		if c.isJSONFieldMissing(field.key, !*field.dst) {
			log.Info("Backfilled missing field", "field", "XDPoS."+field.key, "old", *field.dst, "new", field.src)
			*field.dst = field.src
		}
	}
}

// customMigratedBackfillBigIntFields returns the migrated big-int fork fields used for legacy custom-chain backfill.
func customMigratedBackfillBigIntFields(dest, src *ChainConfig) []struct {
	key string
	dst **big.Int
	src *big.Int
} {
	fields := make([]struct {
		key string
		dst **big.Int
		src *big.Int
	}, 0, len(customBackfillForkFieldJSONKeys))
	for _, field := range chainConfigXDCForkBlockFields {
		if !field.customMigrated {
			continue
		}
		fields = append(fields, struct {
			key string
			dst **big.Int
			src *big.Int
		}{field.jsonKey, field.bind(dest), field.get(src)})
	}
	return fields
}
