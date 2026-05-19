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
	"fmt"
	"maps"
	"math/big"
	"slices"

	"github.com/XinFinOrg/XDPoSChain/common"
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
	if isForkIncompatible(c.HomesteadBlock, newcfg.HomesteadBlock, head) {
		return newCompatError("Homestead fork block", c.HomesteadBlock, newcfg.HomesteadBlock)
	}
	if isForkIncompatible(c.TIP2019Block, newcfg.TIP2019Block, head) {
		return newCompatError("TIP2019 fork block", c.TIP2019Block, newcfg.TIP2019Block)
	}
	if isForkIncompatible(c.DAOForkBlock, newcfg.DAOForkBlock, head) {
		return newCompatError("DAO fork block", c.DAOForkBlock, newcfg.DAOForkBlock)
	}
	if c.IsDAOFork(head) && c.DAOForkSupport != newcfg.DAOForkSupport {
		return newCompatError("DAO fork support flag", c.DAOForkBlock, newcfg.DAOForkBlock)
	}
	if isForkIncompatible(c.EIP150Block, newcfg.EIP150Block, head) {
		return newCompatError("EIP150 fork block", c.EIP150Block, newcfg.EIP150Block)
	}
	if isForkIncompatible(c.EIP155Block, newcfg.EIP155Block, head) {
		return newCompatError("EIP155 fork block", c.EIP155Block, newcfg.EIP155Block)
	}
	if isForkIncompatible(c.EIP158Block, newcfg.EIP158Block, head) {
		return newCompatError("EIP158 fork block", c.EIP158Block, newcfg.EIP158Block)
	}
	if c.IsEIP158(head) && !configNumEqual(c.ChainID, newcfg.ChainID) {
		return newCompatError("EIP158 chain ID", c.EIP158Block, newcfg.EIP158Block)
	}
	if isForkIncompatible(c.ByzantiumBlock, newcfg.ByzantiumBlock, head) {
		return newCompatError("Byzantium fork block", c.ByzantiumBlock, newcfg.ByzantiumBlock)
	}
	if isForkIncompatible(c.ConstantinopleBlock, newcfg.ConstantinopleBlock, head) {
		return newCompatError("Constantinople fork block", c.ConstantinopleBlock, newcfg.ConstantinopleBlock)
	}
	if isForkIncompatible(c.PetersburgBlock, newcfg.PetersburgBlock, head) {
		// the only case where we allow Petersburg to be set in the past is if it is equal to Constantinople
		// mainly to satisfy fork ordering requirements which state that Petersburg fork be set if Constantinople fork is set
		if isForkIncompatible(c.ConstantinopleBlock, newcfg.PetersburgBlock, head) {
			return newCompatError("Petersburg fork block", c.PetersburgBlock, newcfg.PetersburgBlock)
		}
	}
	if isForkIncompatible(c.IstanbulBlock, newcfg.IstanbulBlock, head) {
		return newCompatError("Istanbul fork block", c.IstanbulBlock, newcfg.IstanbulBlock)
	}
	if isForkIncompatible(c.TIPSigningBlock, newcfg.TIPSigningBlock, head) {
		return newCompatError("TIPSigning fork block", c.TIPSigningBlock, newcfg.TIPSigningBlock)
	}
	if isForkIncompatible(c.TIPRandomizeBlock, newcfg.TIPRandomizeBlock, head) {
		return newCompatError("TIPRandomize fork block", c.TIPRandomizeBlock, newcfg.TIPRandomizeBlock)
	}
	if isForkIncompatible(c.TIPIncreaseMasternodesBlock, newcfg.TIPIncreaseMasternodesBlock, head) {
		return newCompatError("TIPIncreaseMasternodes fork block", c.TIPIncreaseMasternodesBlock, newcfg.TIPIncreaseMasternodesBlock)
	}
	if isForkIncompatible(c.DenylistBlock, newcfg.DenylistBlock, head) {
		return newCompatError("Denylist fork block", c.DenylistBlock, newcfg.DenylistBlock)
	}
	if isForkIncompatible(c.TIPNoHalvingMNRewardBlock, newcfg.TIPNoHalvingMNRewardBlock, head) {
		return newCompatError("TIPNoHalvingMNReward fork block", c.TIPNoHalvingMNRewardBlock, newcfg.TIPNoHalvingMNRewardBlock)
	}
	if isForkIncompatible(c.TIPXDCXBlock, newcfg.TIPXDCXBlock, head) {
		return newCompatError("TIPXDCX fork block", c.TIPXDCXBlock, newcfg.TIPXDCXBlock)
	}
	if isForkIncompatible(c.TIPXDCXLendingBlock, newcfg.TIPXDCXLendingBlock, head) {
		return newCompatError("TIPXDCXLending fork block", c.TIPXDCXLendingBlock, newcfg.TIPXDCXLendingBlock)
	}
	if isForkIncompatible(c.TIPXDCXCancellationFeeBlock, newcfg.TIPXDCXCancellationFeeBlock, head) {
		return newCompatError("TIPXDCXCancellationFee fork block", c.TIPXDCXCancellationFeeBlock, newcfg.TIPXDCXCancellationFeeBlock)
	}
	if isForkIncompatible(c.TIPTRC21FeeBlock, newcfg.TIPTRC21FeeBlock, head) {
		return newCompatError("TIPTRC21Fee fork block", c.TIPTRC21FeeBlock, newcfg.TIPTRC21FeeBlock)
	}
	if err := checkXDCSystemContractCompatible(c, newcfg, head); err != nil {
		return err
	}
	if isForkIncompatible(c.BerlinBlock, newcfg.BerlinBlock, head) {
		return newCompatError("Berlin fork block", c.BerlinBlock, newcfg.BerlinBlock)
	}
	if isForkIncompatible(c.LondonBlock, newcfg.LondonBlock, head) {
		return newCompatError("London fork block", c.LondonBlock, newcfg.LondonBlock)
	}
	if isForkIncompatible(c.MergeBlock, newcfg.MergeBlock, head) {
		return newCompatError("Merge fork block", c.MergeBlock, newcfg.MergeBlock)
	}
	if isForkIncompatible(c.ShanghaiBlock, newcfg.ShanghaiBlock, head) {
		return newCompatError("Shanghai fork block", c.ShanghaiBlock, newcfg.ShanghaiBlock)
	}
	if isForkIncompatible(c.Gas50xBlock, newcfg.Gas50xBlock, head) {
		return newCompatError("Gas50x fork block", c.Gas50xBlock, newcfg.Gas50xBlock)
	}
	if isForkIncompatible(c.TIPXDCXMinerDisableBlock, newcfg.TIPXDCXMinerDisableBlock, head) {
		return newCompatError("TIPXDCXMinerDisable fork block", c.TIPXDCXMinerDisableBlock, newcfg.TIPXDCXMinerDisableBlock)
	}
	if isForkIncompatible(c.TIPXDCXReceiverDisableBlock, newcfg.TIPXDCXReceiverDisableBlock, head) {
		return newCompatError("TIPXDCXReceiverDisable fork block", c.TIPXDCXReceiverDisableBlock, newcfg.TIPXDCXReceiverDisableBlock)
	}
	if isForkIncompatible(c.EIP1559Block, newcfg.EIP1559Block, head) {
		return newCompatError("EIP1559 fork block", c.EIP1559Block, newcfg.EIP1559Block)
	}
	if isForkIncompatible(c.CancunBlock, newcfg.CancunBlock, head) {
		return newCompatError("Cancun fork block", c.CancunBlock, newcfg.CancunBlock)
	}
	if isForkIncompatible(c.PragueBlock, newcfg.PragueBlock, head) {
		return newCompatError("Prague fork block", c.PragueBlock, newcfg.PragueBlock)
	}
	if isForkIncompatible(c.OsakaBlock, newcfg.OsakaBlock, head) {
		return newCompatError("Osaka fork block", c.OsakaBlock, newcfg.OsakaBlock)
	}
	if isForkIncompatible(c.DynamicGasLimitBlock, newcfg.DynamicGasLimitBlock, head) {
		return newCompatError("DynamicGasLimit fork block", c.DynamicGasLimitBlock, newcfg.DynamicGasLimitBlock)
	}
	if isForkIncompatible(c.TIPUpgradeRewardBlock, newcfg.TIPUpgradeRewardBlock, head) {
		return newCompatError("TIPUpgradeReward fork block", c.TIPUpgradeRewardBlock, newcfg.TIPUpgradeRewardBlock)
	}
	if isForkIncompatible(c.TIPUpgradePenaltyBlock, newcfg.TIPUpgradePenaltyBlock, head) {
		return newCompatError("TIPUpgradePenalty fork block", c.TIPUpgradePenaltyBlock, newcfg.TIPUpgradePenaltyBlock)
	}
	if isForkIncompatible(c.TIPEpochHalvingBlock, newcfg.TIPEpochHalvingBlock, head) {
		return newCompatError("TIPEpochHalving fork block", c.TIPEpochHalvingBlock, newcfg.TIPEpochHalvingBlock)
	}
	if err := checkXDPoSCompatible(c.XDPoS, newcfg.XDPoS, head, xdposRound); err != nil {
		return err
	}
	return nil
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
func checkV2ScheduleCompatible(stored, newcfg *V2, xdposRound *uint64) *ConfigCompatError {
	activeRound := v2ActiveCompatRound(stored, newcfg, xdposRound)
	for _, round := range v2HistoricalRounds(stored, newcfg, activeRound) {
		storedCfg, storedOK := stored.AllConfigs[round]
		newCfg, newOK := newcfg.AllConfigs[round]
		if !storedOK || !newOK || !v2ConsensusConfigEqual(storedCfg, newCfg) {
			return newCompatError(fmt.Sprintf("XDPoS.V2 config at round %d", round), xdposV2CompatBlock(stored), xdposV2CompatBlock(newcfg))
		}
	}
	return nil
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
	if a.MaxObverserNodes != b.MaxObverserNodes {
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
