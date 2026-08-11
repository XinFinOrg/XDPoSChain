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

// Compatibility checks in this file consume already-hydrated configs; they do
// not decide missingness or copy defaults themselves. Callers that loaded a
// partial config should first use CloneForBackfill plus BackfillMissingFieldsFrom
// to copy omitted generic and XDPoS fields from the appropriate built-in source,
// or BackfillCustomMigratedFieldsFrom when only the historical custom-migration
// whitelist is allowed. The comparison logic here then evaluates the effective
// post-backfill values and reports rewinds only for real historical mismatches.

import (
	"fmt"
	"maps"
	"math/big"
	"slices"
	"strings"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/log"
)

// CheckCompatible checks whether scheduled fork transitions have been imported
// with a mismatching chain configuration.
func (c *ChainConfig) CheckCompatible(newcfg *ChainConfig, height uint64) *ConfigCompatError {
	return c.CheckCompatibleWithXDPoSRound(newcfg, height, nil)
}

// CheckCompatibleWithXDPoSRound checks whether scheduled fork transitions have
// been imported with a mismatching chain configuration. If xdposRound is set,
// it is used as the authoritative XDPoS V2 round for schedule compatibility.
func (c *ChainConfig) CheckCompatibleWithXDPoSRound(newcfg *ChainConfig, height uint64, xdposRound *uint64) *ConfigCompatError {
	bhead := new(big.Int).SetUint64(height)

	// Iterate checkCompatible to find the lowest conflict.
	var lasterr *ConfigCompatError
	for {
		err := c.checkCompatible(newcfg, bhead, xdposRound)
		if err == nil || (lasterr != nil && err.RewindTo == lasterr.RewindTo) {
			break
		}
		lasterr = err
		bhead.SetUint64(err.RewindTo)
	}
	return lasterr
}

func (c *ChainConfig) checkCompatible(newcfg *ChainConfig, head *big.Int, xdposRound *uint64) *ConfigCompatError {
	var compatErr *ConfigCompatError
compatLoop:
	for _, field := range chainConfigCompatibilityFields {
		name := field.name
		storedBlock := chainConfigBigIntFieldValue(c, field)
		newBlock := chainConfigBigIntFieldValue(newcfg, field)
		if compatErr != nil {
			break
		}
		switch name {
		case "PetersburgBlock":
			// The only allowed historical Petersburg rewrite is aliasing it to Constantinople.
			if isForkIncompatible(storedBlock, newBlock, head) && isForkIncompatible(c.ConstantinopleBlock, newcfg.PetersburgBlock, head) {
				compatErr = newCompatError("Petersburg fork block", storedBlock, newBlock)
			}
		default:
			if isForkIncompatible(storedBlock, newBlock, head) {
				compatErr = newCompatError(chainConfigForkCompatErrorLabel(name), storedBlock, newBlock)
				break compatLoop
			}
		}
		if compatErr != nil {
			break compatLoop
		}
		switch name {
		case "DAOForkBlock":
			if c.IsDAOFork(head) && c.DAOForkSupport != newcfg.DAOForkSupport {
				compatErr = newCompatError("DAO fork support flag", c.DAOForkBlock, newcfg.DAOForkBlock)
			}
		case "EIP158Block":
			if c.IsEIP158(head) && !configNumEqual(c.ChainID, newcfg.ChainID) {
				compatErr = newCompatError("EIP158 chain ID", c.EIP158Block, newcfg.EIP158Block)
			}
		}
	}
	if compatErr != nil {
		return compatErr
	}
	if err := checkXDCSystemContractCompatible(c, newcfg, head); err != nil {
		return err
	}
	if err := checkXDPoSCompatible(c.XDPoS, newcfg.XDPoS, head, xdposRound); err != nil {
		return err
	}
	return nil
}

func chainConfigForkCompatErrorLabel(name string) string {
	switch name {
	case "DAOForkBlock":
		return "DAO fork block"
	default:
		return strings.TrimSuffix(name, "Block") + " fork block"
	}
}

// checkXDPoSCompatible compares stored and new XDPoS config for historical
// incompatibilities that require a rewind.
func checkXDPoSCompatible(stored, newcfg *XDPoSConfig, head *big.Int, xdposRound *uint64) *ConfigCompatError {
	if stored == nil || newcfg == nil {
		if stored == newcfg {
			return nil
		}
		return newCompatError("XDPoS not equal", xdposCompatBlock(stored), xdposCompatBlock(newcfg))
	}
	if stored.Period != newcfg.Period {
		return newCompatError("XDPoS.Period", xdposCompatBlock(stored), xdposCompatBlock(newcfg))
	}
	if stored.Epoch != newcfg.Epoch {
		return newCompatError("XDPoS.Epoch", xdposCompatBlock(stored), xdposCompatBlock(newcfg))
	}
	if stored.Reward != newcfg.Reward {
		return newCompatError("XDPoS.Reward", xdposCompatBlock(stored), xdposCompatBlock(newcfg))
	}
	if stored.RewardCheckpoint != newcfg.RewardCheckpoint {
		return newCompatError("XDPoS.RewardCheckpoint", xdposCompatBlock(stored), xdposCompatBlock(newcfg))
	}
	if stored.Gap != newcfg.Gap {
		return newCompatError("XDPoS.Gap", xdposCompatBlock(stored), xdposCompatBlock(newcfg))
	}
	if stored.FoundationWalletAddr != newcfg.FoundationWalletAddr {
		return newCompatError("XDPoS.FoundationWalletAddr", xdposCompatBlock(stored), xdposCompatBlock(newcfg))
	}
	if stored.MaxMasternodesV2 != newcfg.MaxMasternodesV2 {
		return newCompatError("XDPoS.MaxMasternodesV2", xdposCompatBlock(stored), xdposCompatBlock(newcfg))
	}
	if stored.SkipV1Validation != newcfg.SkipV1Validation {
		return newCompatError("XDPoS.SkipV1Validation", xdposCompatBlock(stored), xdposCompatBlock(newcfg))
	}
	if stored.V2 == nil || newcfg.V2 == nil {
		if stored.V2 == newcfg.V2 {
			return nil
		}
		return newCompatError("XDPoS.V2", xdposCompatBlock(stored), xdposCompatBlock(newcfg))
	}
	if isForkIncompatible(stored.V2.SwitchBlock, newcfg.V2.SwitchBlock, head) {
		return newCompatError("XDPoS.V2.SwitchBlock", stored.V2.SwitchBlock, newcfg.V2.SwitchBlock)
	}
	if stored.V2.SwitchEpoch != newcfg.V2.SwitchEpoch && (isForked(stored.V2.SwitchBlock, head) || isForked(newcfg.V2.SwitchBlock, head)) {
		return newCompatError("XDPoS.V2.SwitchEpoch", stored.V2.SwitchBlock, newcfg.V2.SwitchBlock)
	}
	if !isForked(stored.V2.SwitchBlock, head) && !isForked(newcfg.V2.SwitchBlock, head) {
		return nil
	}
	return checkV2ScheduleCompatible(stored.V2, newcfg.V2, xdposRound)
}

// checkAddressCompatible reports a compatibility error when a system-contract
// address changes after its activation point.
func checkAddressCompatible(name string, stored, new common.Address, activation, head *big.Int) *ConfigCompatError {
	if stored == new || !isForked(activation, head) {
		return nil
	}
	return newAddressCompatError(name, stored, new, activation)
}

func checkXDCSystemContractCompatible(stored, newcfg *ChainConfig, head *big.Int) *ConfigCompatError {
	for _, field := range chainConfigXDCSystemContractFields {
		if field.compat == nil {
			continue
		}
		if err := checkAddressCompatible(field.name, field.get(stored), field.get(newcfg), field.compat(stored), head); err != nil {
			return err
		}
	}
	return nil
}

// checkV2ScheduleCompatible compares the historically active V2 round configs
// between stored and new chain config.
func checkV2ScheduleCompatible(stored, candidate *V2, xdposRound *uint64) *ConfigCompatError {
	activeRound := v2ActiveCompatRound(stored, candidate, xdposRound)
	for _, round := range v2HistoricalRounds(stored, candidate, activeRound) {
		storedCfg, storedOK := stored.AllConfigs[round]
		candidateCfg, newOK := candidate.AllConfigs[round]
		if !storedOK || !newOK || !v2ConsensusConfigEqual(storedCfg, candidateCfg) {
			log.Warn(strings.Repeat("-", 153))
			log.Warn("V2 config mismatch", "stored", stored.StableLogValue())
			log.Warn(strings.Repeat("-", 153))
			log.Warn("V2 config mismatch", "candidate", candidate.StableLogValue())
			log.Warn(strings.Repeat("-", 153))
			log.Warn("V2 config mismatch",
				"round", round,
				"activeRound", activeRound,
				"storedOK", storedOK,
				"newOK", newOK,
				"storedCfg", v2ConsensusConfigSnapshot(storedCfg),
				"candidateCfg", v2ConsensusConfigSnapshot(candidateCfg),
			)
			log.Warn(strings.Repeat("-", 153))
			return newCompatError(fmt.Sprintf("XDPoS.V2 config at round %d", round), xdposV2CompatBlock(stored), xdposV2CompatBlock(candidate))
		}
	}
	return nil
}

func v2ConsensusConfigSnapshot(cfg *V2Config) map[string]any {
	if cfg == nil {
		return nil
	}
	return map[string]any{
		"maxMasternodes":            cfg.MaxMasternodes,
		"maxProtectorNodes":         cfg.MaxProtectorNodes,
		"maxObserverNodes":          cfg.MaxObserverNodes,
		"switchRound":               cfg.SwitchRound,
		"minePeriod":                cfg.MinePeriod,
		"certThreshold":             cfg.CertThreshold,
		"masternodeReward":          cfg.MasternodeReward,
		"protectorReward":           cfg.ProtectorReward,
		"observerReward":            cfg.ObserverReward,
		"minimumMinerBlockPerEpoch": cfg.MinimumMinerBlockPerEpoch,
		"limitPenaltyEpoch":         cfg.LimitPenaltyEpoch,
		"minimumSigningTx":          cfg.MinimumSigningTx,
	}
}

// v2ActiveCompatRound returns the latest round whose config must remain stable
// across restarts.
func v2ActiveCompatRound(stored, newcfg *V2, xdposRound *uint64) uint64 {
	if xdposRound != nil {
		return *xdposRound
	}
	var activeRound uint64
	if stored != nil && stored.CurrentConfig != nil && stored.CurrentConfig.SwitchRound > activeRound {
		activeRound = stored.CurrentConfig.SwitchRound
	}
	if newcfg != nil && newcfg.CurrentConfig != nil && newcfg.CurrentConfig.SwitchRound > activeRound {
		activeRound = newcfg.CurrentConfig.SwitchRound
	}
	return activeRound
}

// v2HistoricalRounds returns the set of historical V2 rounds that must be
// compared for compatibility.
func v2HistoricalRounds(stored, newcfg *V2, activeRound uint64) []uint64 {
	roundSet := make(map[uint64]struct{})
	if stored != nil {
		for round := range stored.AllConfigs {
			if round <= activeRound {
				roundSet[round] = struct{}{}
			}
		}
	}
	if newcfg != nil {
		for round := range newcfg.AllConfigs {
			if round <= activeRound {
				roundSet[round] = struct{}{}
			}
		}
	}
	rounds := slices.Collect(maps.Keys(roundSet))
	slices.Sort(rounds)
	return rounds
}

// v2ConsensusConfigEqual compares only the consensus-relevant V2 parameters.
func v2ConsensusConfigEqual(a, b *V2Config) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.MaxMasternodes != b.MaxMasternodes {
		return false
	}
	if a.MaxProtectorNodes != b.MaxProtectorNodes {
		return false
	}
	if a.MaxObserverNodes != b.MaxObserverNodes {
		return false
	}
	if a.SwitchRound != b.SwitchRound {
		return false
	}
	if a.MinePeriod != b.MinePeriod {
		return false
	}
	if a.CertThreshold != b.CertThreshold {
		return false
	}
	if a.MasternodeReward != b.MasternodeReward {
		return false
	}
	if a.ProtectorReward != b.ProtectorReward {
		return false
	}
	if a.ObserverReward != b.ObserverReward {
		return false
	}
	if a.MinimumMinerBlockPerEpoch != b.MinimumMinerBlockPerEpoch {
		return false
	}
	if a.LimitPenaltyEpoch != b.LimitPenaltyEpoch {
		return false
	}
	if a.MinimumSigningTx != b.MinimumSigningTx {
		return false
	}
	return true
}

// xdposCompatBlock returns the earliest block used to report XDPoS
// compatibility mismatches.
func xdposCompatBlock(cfg *XDPoSConfig) *big.Int {
	if cfg != nil && cfg.V2 != nil && cfg.V2.SwitchBlock != nil {
		return cfg.V2.SwitchBlock
	}
	return big.NewInt(1)
}

// xdposV2CompatBlock returns the earliest block used to report V2 schedule
// compatibility mismatches.
func xdposV2CompatBlock(v2 *V2) *big.Int {
	if v2 != nil && v2.SwitchBlock != nil {
		return v2.SwitchBlock
	}
	return big.NewInt(1)
}

// isForkIncompatible returns true if a fork scheduled at s1 cannot be rescheduled to
// block s2 because head is already past the fork.
func isForkIncompatible(s1, s2, head *big.Int) bool {
	return (isForked(s1, head) || isForked(s2, head)) && !configNumEqual(s1, s2)
}

func configNumEqual(x, y *big.Int) bool {
	if x == nil || y == nil {
		return x == y
	}
	return x.Cmp(y) == 0
}

// ConfigCompatError is raised if the locally-stored blockchain is initialised with a
// ChainConfig that would alter the past.
type ConfigCompatError struct {
	What string
	// block numbers of the stored and new configurations
	StoredConfig, NewConfig *big.Int
	// optional stored and new values for non-block compatibility mismatches
	StoredValue, NewValue string
	// the block number to which the local chain must be rewound to correct the error
	RewindTo uint64
}

func newCompatError(what string, storedblock, newblock *big.Int) *ConfigCompatError {
	var rew *big.Int
	switch {
	case storedblock == nil:
		rew = newblock
	case newblock == nil || storedblock.Cmp(newblock) < 0:
		rew = storedblock
	default:
		rew = newblock
	}
	err := &ConfigCompatError{What: what, StoredConfig: storedblock, NewConfig: newblock}
	if rew != nil && rew.Sign() > 0 {
		err.RewindTo = rew.Uint64() - 1
	}
	return err
}

func newAddressCompatError(what string, stored, new common.Address, activation *big.Int) *ConfigCompatError {
	err := newCompatError(what, activation, activation)
	err.StoredValue = stored.Hex()
	err.NewValue = new.Hex()
	return err
}

func (err *ConfigCompatError) Error() string {
	if err.StoredValue != "" || err.NewValue != "" {
		return fmt.Sprintf("mismatching %s in database (have %s, want %s, activated at %d, rewindto %d)", err.What, err.StoredValue, err.NewValue, err.StoredConfig, err.RewindTo)
	}
	return fmt.Sprintf("mismatching %s in database (have %d, want %d, rewindto %d)", err.What, err.StoredConfig, err.NewConfig, err.RewindTo)
}

// Rules wraps ChainConfig and is merely syntatic sugar or can be used for functions
// that do not have or require information about the block.
//
// Rules is a one time interface meaning that it shouldn't be used in between transition
