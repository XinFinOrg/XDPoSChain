// Copyright 2017 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/params"
	"gopkg.in/yaml.v3"

	"context"
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/accounts/abi/bind"
	"github.com/XinFinOrg/XDPoSChain/accounts/abi/bind/backends"
	blockSignerContract "github.com/XinFinOrg/XDPoSChain/contracts/blocksigner"
	multiSignWalletContract "github.com/XinFinOrg/XDPoSChain/contracts/multisigwallet"
	randomizeContract "github.com/XinFinOrg/XDPoSChain/contracts/randomize"
	validatorContract "github.com/XinFinOrg/XDPoSChain/contracts/validator"
	"github.com/XinFinOrg/XDPoSChain/crypto"
)

// deployChainV2SwitchBlock is the block at which the throwaway chain used to
// deploy the genesis contracts would switch to the XDPoS v2 engine. Deploying
// takes a handful of blocks, so the switch is never reached and the chain stays
// on v1 throughout. It must be a whole number of epochs and must not be 0.
const deployChainV2SwitchBlock = 900

// GenesisInput is what the non-interactive input file carries. Epoch is the only
// schedule field it can express; checkGenesisInputScheduleKeys refuses the rest.
type GenesisInput struct {
	Name                    string   // informational network name
	ChainId                 uint64   // network id
	Epoch                   uint64   // epoch length; applied to the template, baked into BlockSigner
	MasternodesOwner        string   // owner registered for the initial masternodes
	Masternodes             []string // initial masternode (validator) set
	StakingThreshold        uint64   // per-masternode deposit in whole coins; sizes validator caps
	RewardYield             uint64   // masternode reward yield in APY%
	FoundationWalletAddress string   // foundation wallet address to collect 10% of all rewards
}

func NewGenesisInput() *GenesisInput {
	return &GenesisInput{
		Name:                    "xdc-custom-network",
		ChainId:                 params.LocalnetChainConfig.ChainID.Uint64(),
		Epoch:                   params.LocalnetChainConfig.XDPoS.Epoch,
		StakingThreshold:        10_000_000, // 10M
		RewardYield:             10,         // 10% APY
		FoundationWalletAddress: common.FoundationAddrBinary.Hex(),
	}
}

// canonicalInputKey folds the spelling differences the schedule guard tolerates,
// so Epoch and epoch reach the same field.
func canonicalInputKey(key string) string {
	return strings.ToLower(strings.ReplaceAll(key, "_", ""))
}

// yamlInputKey is the spelling yaml matches a field by: its yaml tag, or the
// lowercased Go field name when there is no tag. A "-" tag makes yaml ignore the
// field, so it accepts no key at all.
func yamlInputKey(field reflect.StructField) string {
	tag, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
	switch tag {
	case "-":
		return ""
	case "":
		return strings.ToLower(field.Name)
	}
	return tag
}

// inputKeys maps every canonical spelling accepted for a struct onto the
// spelling yaml matches, so a field with a tag or an underscore still receives
// its value. The keys are derived from the fields, so a new field needs no
// second list to keep in step.
func inputKeys(t reflect.Type) map[string]string {
	keys := make(map[string]string)
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		// yaml skips an unexported field unless it is anonymous, where the field
		// name is the type name; the table has to leave out the same fields.
		if field.PkgPath != "" && !field.Anonymous {
			continue
		}
		if name := yamlInputKey(field); name != "" {
			keys[canonicalInputKey(name)] = name
		}
	}
	return keys
}

// genesisInputKeys maps the spellings accepted for GenesisInput onto the keys
// yaml actually matches.
var genesisInputKeys = inputKeys(reflect.TypeOf(GenesisInput{}))

// inputDocument re-keys the fields yaml would recognise onto its spelling and
// reports two spellings of one field as a conflict.
func inputDocument(raw map[string]yaml.Node) (*yaml.Node, error) {
	return foldInputKeys(raw, genesisInputKeys)
}

// foldInputKeys rewrites the recognised keys and leaves the rest out, since yaml
// would drop them anyway; they are warned about instead of disappearing without
// a word.
func foldInputKeys(raw map[string]yaml.Node, keys map[string]string) (*yaml.Node, error) {
	// Sorted so the same file is refused with the same message every run.
	sorted := make([]string, 0, len(raw))
	for key := range raw {
		sorted = append(sorted, key)
	}
	sort.Strings(sorted)

	doc := &yaml.Node{Kind: yaml.MappingNode}
	seen := make(map[string]string, len(raw))
	for _, key := range sorted {
		value := raw[key]
		canonical := canonicalInputKey(key)
		name, ok := keys[canonical]
		if !ok {
			log.Warn("Ignoring genesis input key with no GenesisInput field", "key", key)
			continue
		}
		if other, ok := seen[canonical]; ok {
			return nil, fmt.Errorf("keys %q and %q both set %s", other, key, canonical)
		}
		seen[canonical] = key
		doc.Content = append(doc.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: name}, &value)
	}
	return doc, nil
}

// checkGenesisInputScheduleKeys refuses gap, switchBlock and switchEpoch, which have no
// GenesisInput field and would be dropped by yaml. Every other key without a field warns
// instead, for example period, reward, rewardCheckpoint, foundationWalletAddr,
// maxMasternodesV2, skipV1Validation and v2.
func checkGenesisInputScheduleKeys(raw map[string]yaml.Node) error {
	return checkScheduleKeys(raw, genesisInputKeys)
}

// checkScheduleKeys refuses the schedule keys the field table has no field for. A key with
// a field is applied by inputDocument, so it must not be refused here: the two lists are
// read from the same table instead of drifting apart.
func checkScheduleKeys(raw map[string]yaml.Node, keys map[string]string) error {
	var gap, switchBlock, switchEpoch bool
	for key := range raw {
		canonical := canonicalInputKey(key)
		if _, hasField := keys[canonical]; hasField {
			continue
		}
		switch canonical {
		case "gap":
			gap = true
		case "switchblock":
			switchBlock = true
		case "switchepoch":
			switchEpoch = true
		}
	}
	var present []string
	if gap {
		present = append(present, "gap")
	}
	if switchBlock {
		present = append(present, "switchBlock")
	}
	if switchEpoch {
		present = append(present, "switchEpoch")
	}
	if len(present) == 0 {
		return nil
	}
	return fmt.Errorf("input file carries %s, but only epoch can be applied; remove them or use the interactive path",
		strings.Join(present, ", "))
}

func (w *wizard) loadGenesisInput() *GenesisInput {
	// No input file means interactive mode: return nil so makeGenesis prompts.
	if w.conf.inpath == "" {
		return nil
	}
	log.Info("Decoding genesis input file", "path", w.conf.inpath)

	data, err := os.ReadFile(w.conf.inpath)
	if err != nil {
		log.Warn("Failed to open genesis input file", "err", err)
		os.Exit(1)
		return nil
	}
	// Decoded twice: once for its keys, once for the fields, re-keyed onto the
	// spelling yaml matches.
	var raw map[string]yaml.Node
	if err := yaml.Unmarshal(data, &raw); err != nil {
		log.Warn("Failed to decode genesis input file (expect yaml format)", "err", err)
		os.Exit(1)
		return nil
	}
	// A file with no fields at all - empty, only comments, or an explicitly empty
	// mapping like {} - would otherwise decode to nothing and silently produce the
	// template's defaults; yaml decodes the mapping to a non-nil empty map, so the
	// length has to be judged alongside the nil.
	if raw == nil || len(raw) == 0 {
		log.Warn("Refusing the genesis input file (no fields in it)", "path", w.conf.inpath)
		os.Exit(1)
		return nil
	}
	if err := checkGenesisInputScheduleKeys(raw); err != nil {
		log.Warn("Refusing the genesis input file", "err", err)
		os.Exit(1)
		return nil
	}
	doc, err := inputDocument(raw)
	if err != nil {
		log.Warn("Refusing the genesis input file", "err", err)
		os.Exit(1)
		return nil
	}
	input := NewGenesisInput()
	if err := doc.Decode(input); err != nil {
		log.Warn("Failed to decode genesis input file (expect yaml format)", "err", err)
		os.Exit(1)
		return nil
	}
	fmt.Println("Generating genesis file with the below input")
	fmt.Printf("%+v\n", input)

	return input
}

// makeGenesis creates a new genesis struct based on some user input.
// masternodeRewards are the per-epoch reward figures derived from the staking
// threshold and the target yield, in whole coins.
type masternodeRewards struct {
	TotalPerEpoch    uint64  // rewards paid out to the whole masternode set each epoch
	MasternodeReward float64 // reward of a single masternode (core validator)
	ProtectorReward  float64 // reward of a single protector, 80% of a masternode
	ObserverReward   float64 // reward of a single observer, 40% of a masternode
}

// calcMasternodeRewards derives the per-epoch rewards from the block period,
// the epoch length, the per-masternode staking threshold and the target reward
// yield in APY%. The per-node rewards are grossed up by the foundation cut, so
// that a masternode still earns the requested yield after the foundation has
// taken its percentage. It reports false when the period and epoch length do
// not add up to at least one epoch per year, in which case there is nothing to
// pay out and the caller should leave the reward config untouched.
func calcMasternodeRewards(period, epoch, threshold, yield uint64, masternodes int) (masternodeRewards, bool) {
	if period == 0 || epoch == 0 {
		return masternodeRewards{}, false
	}
	blocksPerYear := 31536000 / period
	epochsPerYear := blocksPerYear / epoch
	if epochsPerYear == 0 {
		return masternodeRewards{}, false
	}
	rewardsPerYear := float64(threshold) * (float64(yield) / 100)
	rewardPerEpochPerMNWithoutFoundation := rewardsPerYear / float64(epochsPerYear)
	rewardPerEpochPerMN := rewardPerEpochPerMNWithoutFoundation * 100 / float64(100-common.RewardFoundationPercent)
	totalRewardPerEpoch := rewardPerEpochPerMN * float64(masternodes)

	return masternodeRewards{
		TotalPerEpoch:    uint64(math.Round(totalRewardPerEpoch)),
		MasternodeReward: math.Round(rewardPerEpochPerMN*10000) / 10000,
		ProtectorReward:  math.Round(rewardPerEpochPerMN*0.8*10000) / 10000,
		ObserverReward:   math.Round(rewardPerEpochPerMN*0.4*10000) / 10000,
	}, true
}

// interactiveGapDefault is half the epoch, which is inside 0 < gap < epoch for every
// epoch the prompt accepts: 1 at epoch 2, 50 at epoch 100, 450 at epoch 900.
func interactiveGapDefault(epoch uint64) uint64 {
	return epoch / 2
}

// checkXDPoSSchedule rejects a schedule the params bound refuses. The judgement
// and its wording belong to params.XDPoSConfig.CheckSchedule and are returned as
// is, so the wizard and a node starting on the generated genesis report one
// contract.
func checkXDPoSSchedule(cfg *params.XDPoSConfig) error {
	if cfg == nil {
		return errors.New("missing XDPoS config")
	}
	return cfg.CheckSchedule()
}

// checkNegativeSwitchBlock refuses a switch block below zero where it can be
// named. CheckSwitchBlockAlignment takes the remainder on the big.Int, so its
// verdict is the same for a block and its absolute value: a negative multiple of
// the epoch passes alignment and would only surface later as an XDPoS.V2.SwitchEpoch
// that does not fit.
func checkNegativeSwitchBlock(cfg *params.ChainConfig) error {
	xdpos := cfg.XDPoS
	if xdpos == nil || xdpos.V2 == nil || xdpos.V2.SwitchBlock == nil || xdpos.V2.SwitchBlock.Sign() >= 0 {
		return nil
	}
	return fmt.Errorf("the v2 switch block must not be negative: XDPoS.V2.SwitchEpoch is a uint64, so a negative block cannot be represented (switchBlock %v, epoch %d)", xdpos.V2.SwitchBlock, xdpos.Epoch)
}

// finalizeGenesisConfig refuses a genesis the init path would refuse, then keeps
// XDPoS.V2.SwitchEpoch consistent with the switch block that was finally asked
// for. Both run on the object about to be written: the prompt checks judge each
// answer where it is given, and this is the one place that sees the complete
// config. The pairing needs this because no validator compares SwitchEpoch with
// the switch block - CheckConfigForkOrder aligns the switch block with the epoch
// and compares no switch epoch - and the template supplies a SwitchEpoch of its
// own, which a switch block typed at the prompt would otherwise leave describing
// a different schedule. The gate just above already refuses every shape the
// derivation can fail on - an unset switch block as a missing field, an unset
// epoch through the schedule gate, and a quotient that fits no uint64 through
// CheckSwitchBlockAlignment - so the refusal below cannot fire behind it. It
// stays as the local guarantee that SwitchEpoch is assigned a quotient and never
// a truncation of one, should that gate stop judging the quotient.
func finalizeGenesisConfig(cfg *params.ChainConfig) error {
	if err := checkNegativeSwitchBlock(cfg); err != nil {
		return err
	}
	xdpos := cfg.XDPoS
	if xdpos != nil {
		if err := cfg.CheckConfigForkOrder(); err != nil {
			return err
		}
		want, ok := params.SwitchEpochFor(xdpos.V2.SwitchBlock, xdpos.Epoch)
		if !ok {
			return fmt.Errorf("the v2 switch block names an epoch no uint64 can hold (switchBlock %v, epoch %d)", xdpos.V2.SwitchBlock, xdpos.Epoch)
		}
		xdpos.V2.SwitchEpoch = want.Uint64()
	}
	return nil
}

func (w *wizard) makeGenesis() {
	genesis := &core.Genesis{
		Timestamp:  uint64(time.Now().Unix()),
		GasLimit:   50_000_000,
		Difficulty: big.NewInt(1),
		Alloc:      make(types.GenesisAlloc),
		Config:     params.LocalnetChainConfig.Clone(),
	}
	if xdpos := genesis.Config.XDPoS; xdpos != nil && xdpos.V2 != nil {
		if cfg, ok := xdpos.V2.AllConfigs[0]; ok {
			xdpos.V2.CurrentConfig = cfg
		}
	}

	// Figure out which consensus engine to choose
	fmt.Println()
	fmt.Println("Which consensus engine to use? (default = XDPoS)")
	fmt.Println(" 1. Ethash - proof-of-work")
	fmt.Println(" 2. Clique - proof-of-authority")
	fmt.Println(" 3. XDPoS - delegated-proof-of-stake")

	input := w.loadGenesisInput()
	var choice string
	if input != nil {
		choice = "3"
	} else {
		choice = w.read()
	}
	switch {
	case choice == "1":
		// In case of ethash, we're pretty much done
		genesis.Config.XDPoS = nil
		genesis.Config.Ethash = new(params.EthashConfig)
		genesis.ExtraData = make([]byte, 32)

	case choice == "2":
		// In the case of clique, configure the consensus parameters
		genesis.Config.XDPoS = nil
		genesis.Config.Clique = &params.CliqueConfig{
			Period: 15,
			Epoch:  900,
		}
		fmt.Println()
		fmt.Println("How many seconds should blocks take? (default = 15)")
		genesis.Config.Clique.Period = uint64(w.readDefaultInt(15))

		// We also need the initial list of signers
		fmt.Println()
		fmt.Println("Which accounts are allowed to seal? (mandatory at least one)")

		var signers []common.Address
		for {
			if address := w.readAddress(); address != nil {
				signers = append(signers, *address)
				continue
			}
			if len(signers) > 0 {
				break
			}
		}
		// Sort the signers and embed into the extra-data section
		for i := 0; i < len(signers); i++ {
			for j := i + 1; j < len(signers); j++ {
				if bytes.Compare(signers[i][:], signers[j][:]) > 0 {
					signers[i], signers[j] = signers[j], signers[i]
				}
			}
		}
		genesis.ExtraData = make([]byte, 32+len(signers)*common.AddressLength+crypto.SignatureLength)
		for i, signer := range signers {
			copy(genesis.ExtraData[32+i*common.AddressLength:], signer[:])
		}

	case choice == "" || choice == "3":
		fmt.Println()
		fmt.Println("How many seconds should blocks take? (default = 2)")
		if input == nil {
			genesis.Config.XDPoS.Period = uint64(w.readDefaultInt(2))
			genesis.Config.XDPoS.V2.CurrentConfig.MinePeriod = int(genesis.Config.XDPoS.Period)
		}

		fmt.Println()
		fmt.Println("How long is the v2 timeout period? (default = 10)")
		if input == nil {
			genesis.Config.XDPoS.V2.CurrentConfig.TimeoutPeriod = w.readDefaultInt(10)
		}

		fmt.Println()
		fmt.Println("How many v2 timeout reach to send Synchronize message? (default = 3)")
		if input == nil {
			genesis.Config.XDPoS.V2.CurrentConfig.TimeoutSyncThreshold = w.readDefaultInt(3)
		}

		fmt.Println()
		fmt.Printf("Proportion of total masternodes v2 vote collection to generate a QC (float value), should be two thirds of masternodes? (default = %f)\n", 0.667)
		if input == nil {
			genesis.Config.XDPoS.V2.CurrentConfig.CertThreshold = w.readDefaultFloat(0.667)
		}

		fmt.Println()
		fmt.Println("Who own the first masternodes? (mandatory)")
		var owner common.Address
		if input != nil {
			owner = common.HexToAddress(input.MasternodesOwner)
		} else {
			owner = *w.readAddress()
		}

		// We also need the initial list of signers
		fmt.Println()
		fmt.Println("Which accounts are Masternodes? (mandatory at least one)")

		var signers []common.Address
		if input != nil {
			for _, m := range input.Masternodes {
				signers = append(signers, common.HexToAddress(m))
			}
		} else {
			for {
				if address := w.readAddress(); address != nil {
					signers = append(signers, *address)
					continue
				}
				if len(signers) > 0 {
					break
				}
			}
		}
		// Sort the signers and embed into the extra-data section
		for i := 0; i < len(signers); i++ {
			for j := i + 1; j < len(signers); j++ {
				if bytes.Compare(signers[i][:], signers[j][:]) > 0 {
					signers[i], signers[j] = signers[j], signers[i]
				}
			}
		}

		// Ask these only inline: the file overwrites the epoch and never reads the gap.
		// The gap bound is judged here through checkXDPoSSchedule once the pair is final,
		// and again below on the complete config, which also sees an input file's epoch.
		if input == nil {
			fmt.Println()
			fmt.Println("How many blocks per epoch? (default = 900, must be at least 2)")
			epoch := w.readDefaultInt(900)
			// The epoch floor is its own: the gap answer is still pending, so the pair
			// cannot be judged yet - the template's gap would be the one on trial.
			if epoch < 2 {
				log.Crit("Epoch must be at least 2 so that a gap block exists inside it", "epoch", epoch)
			}
			genesis.Config.XDPoS.Epoch = uint64(epoch)

			defaultGap := interactiveGapDefault(genesis.Config.XDPoS.Epoch)
			fmt.Println()
			fmt.Printf("How many blocks before the end of the epoch should the gap block fall? "+
				"(1 <= Gap < %d, default = %d)\n", genesis.Config.XDPoS.Epoch, defaultGap)
			// Zero means unspecified; the sign is judged before the uint64 conversion,
			// because a negative answer has no spelling params could see.
			gap := w.readDefaultInt(int(defaultGap))
			if gap < 0 {
				log.Crit("Gap must not be negative", "gap", gap)
			}
			if gap == 0 {
				gap = int(defaultGap)
			}
			genesis.Config.XDPoS.Gap = uint64(gap)
			// The pair is final now, so the bound is judged by the rule the node runs at
			// startup and reports the same message, whatever shape was answered.
			if err := checkXDPoSSchedule(genesis.Config.XDPoS); err != nil {
				log.Crit("Unusable XDPoS schedule", "err", err)
			}

			// The switch block is asked here, once, after the epoch is final: the
			// answer is judged against the epoch it has to divide, so the schedule
			// the operator sees is the schedule that gets stored. Asking it next to
			// the v2 runtime questions meant a later epoch answer invalidated it.
			fmt.Println()
			fmt.Printf("Which block number start v2 consensus? (default = %v)\n", genesis.Config.XDPoS.V2.SwitchBlock)
			genesis.Config.XDPoS.V2.SwitchBlock = w.readDefaultBigInt(genesis.Config.XDPoS.V2.SwitchBlock)
			// The sign is refused first: the alignment check below is blind to it, so a
			// negative multiple of the epoch would pass the modulo.
			if err := checkNegativeSwitchBlock(genesis.Config); err != nil {
				log.Crit("Unusable XDPoS v2 switch block", "err", err)
			}
			// Judge the answer here as well as in CheckConfigForkOrder below, which is
			// only reached after every genesis contract has been deployed.
			if err := params.CheckSwitchBlockAlignment(genesis.Config.XDPoS.V2.SwitchBlock, genesis.Config.XDPoS.Epoch); err != nil {
				log.Crit("Unusable XDPoS v2 switch block", "err", err)
			}
		}

		fmt.Println()
		fmt.Println("What is minimum staking threshold to become a Validator? (default = 10M)")
		var threshold uint64
		if input != nil {
			threshold = input.StakingThreshold
		} else {
			threshold = uint64(w.readDefaultInt(10000000))
		}

		fmt.Println()
		// fmt.Println("How many Ethers should be rewarded to masternode each Epoch? (default = 10)")
		fmt.Println("What should be the reward yield of Masternodes in APY% (default = 10)")
		var yield uint64
		if input != nil {
			yield = input.RewardYield
		} else {
			yield = uint64(w.readDefaultInt(10))
		}
		// The file can only set the epoch; the gap keeps the template value.
		if input != nil {
			genesis.Config.XDPoS.Epoch = input.Epoch
		}
		// Judge the pair before anything is derived from it: the epoch is baked
		// into BlockSigner, the gap is not.
		if err := checkXDPoSSchedule(genesis.Config.XDPoS); err != nil {
			// Name the template value and the ways out once for every tier: the file
			// sets the epoch and the template supplies the gap, so each refusal above
			// is answered by an epoch the template's gap fits in.
			if input != nil && errors.Is(err, params.ErrInvalidEpochGap) {
				err = fmt.Errorf("%w; the input file sets the epoch and the template supplies Gap %d: set an epoch above that, or use the interactive path", err, params.LocalnetChainConfig.XDPoS.Gap)
			}
			log.Crit("Unusable XDPoS schedule", "err", err)
		}
		if rewards, ok := calcMasternodeRewards(genesis.Config.XDPoS.Period, genesis.Config.XDPoS.Epoch, threshold, yield, len(signers)); ok {
			fmt.Println()
			fmt.Println("Calculated Total Masternode rewards per epoch based on yield: ", rewards.TotalPerEpoch)
			genesis.Config.XDPoS.Reward = rewards.TotalPerEpoch
			genesis.Config.XDPoS.V2.CurrentConfig.MasternodeReward = rewards.MasternodeReward
			genesis.Config.XDPoS.V2.CurrentConfig.ProtectorReward = rewards.ProtectorReward
			genesis.Config.XDPoS.V2.CurrentConfig.ObserverReward = rewards.ObserverReward
		}

		fmt.Println()
		fmt.Println("What is foundation wallet address (collect 10% of all rewards)? (default = xdc0000000000000000000000000000000000000068)")
		if input == nil {
			genesis.Config.XDPoS.FoundationWalletAddr = w.readDefaultAddress(common.FoundationAddrBinary)
		} else {
			if !common.IsHexAddress(input.FoundationWalletAddress) {
				log.Crit("Invalid foundation wallet address", "address", input.FoundationWalletAddress)
			}
			genesis.Config.XDPoS.FoundationWalletAddr = common.HexToAddress(input.FoundationWalletAddress)
		}

		// Validator Smart Contract Code
		pKey, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr := crypto.PubkeyToAddress(pKey.PublicKey)
		deployerFunds := new(big.Int).Mul(big.NewInt(1_000_000), big.NewInt(1e18)) // 1,000,000 ETH
		deployConfig := params.LocalnetChainConfig.Clone()
		deployConfig.XDPoS.V2.SwitchBlock = new(big.Int).SetUint64(deployChainV2SwitchBlock)
		deployConfig.XDPoS.V2.SwitchEpoch = deployChainV2SwitchBlock / deployConfig.XDPoS.Epoch
		// Gas limit increased to 10,000,000,000 to support validator contract deployment with large masternode counts (>38).
		contractBackend := backends.NewXDCSimulatedBackend(types.GenesisAlloc{addr: {Balance: deployerFunds}}, 10_000_000_000, deployConfig)
		transactOpts, err := bind.NewKeyedTransactorWithChainID(pKey, deployConfig.ChainID)
		if err != nil {
			log.Crit("Failed to create genesis contract deployer", "err", err)
		}

		minDeposit := new(big.Int).SetUint64(threshold)
		minDeposit.Mul(minDeposit, big.NewInt(1e18)) //convert to wei
		validatorCap := new(big.Int).Set(minDeposit)
		var validatorCaps []*big.Int
		genesis.ExtraData = make([]byte, 32+len(signers)*common.AddressLength+crypto.SignatureLength)
		for i, signer := range signers {
			validatorCaps = append(validatorCaps, validatorCap)
			copy(genesis.ExtraData[32+i*common.AddressLength:], signer[:])
		}
		validatorAddress, _, err := validatorContract.DeployValidator(transactOpts, contractBackend, signers, validatorCaps, owner, minDeposit, nil)
		if err != nil {
			log.Crit("Failed to deploy validator (MasternodeVotingSMC) contract", "err", err)
		}
		contractBackend.Commit()

		d := time.Now().Add(1000 * time.Millisecond)
		ctx, cancel := context.WithDeadline(context.Background(), d)
		defer cancel()
		code, _ := contractBackend.CodeAt(ctx, validatorAddress, nil)
		storage := make(map[common.Hash]common.Hash)
		f := func(key, val common.Hash) bool {
			storage[key] = common.BytesToHash(val.Bytes())
			log.Info("DecodeBytes", "value", val, "decode", storage[key])
			return true
		}
		contractBackend.ForEachStorageAt(ctx, validatorAddress, nil, f)
		genesis.Alloc[common.MasternodeVotingSMCBinary] = types.Account{
			Balance: validatorCap.Mul(validatorCap, big.NewInt(int64(len(validatorCaps)))),
			Code:    code,
			Storage: storage,
		}

		fmt.Println()
		fmt.Println("Which accounts are allowed to confirm in Foundation MultiSignWallet?")
		var owners []common.Address
		if input != nil {
			owners = append(owners, owner)
		} else {
			for {
				if address := w.readAddress(); address != nil {
					owners = append(owners, *address)
					continue
				}
				if len(owners) > 0 {
					break
				}
			}
		}

		fmt.Println()
		fmt.Println("How many require for confirm tx in Foundation MultiSignWallet? (default = 1)")
		var required uint64
		if input != nil {
			required = 1
		} else {
			required = uint64(w.readDefaultInt(1))
		}

		// MultiSigWallet.
		multiSignWalletAddr, _, err := multiSignWalletContract.DeployMultiSigWallet(transactOpts, contractBackend, owners, big.NewInt(int64(required)))
		if err != nil {
			log.Crit("Failed to deploy Foundation MultiSigWallet contract", "err", err)
		}
		contractBackend.Commit()
		code, _ = contractBackend.CodeAt(ctx, multiSignWalletAddr, nil)
		storage = make(map[common.Hash]common.Hash)
		contractBackend.ForEachStorageAt(ctx, multiSignWalletAddr, nil, f)
		fBalance := big.NewInt(0) // 16m
		fBalance.Add(fBalance, big.NewInt(16*1000*1000))
		fBalance.Mul(fBalance, big.NewInt(1000000000000000000))
		genesis.Alloc[common.FoundationAddrBinary] = types.Account{
			Balance: fBalance,
			Code:    code,
			Storage: storage,
		}

		// Block Signers Smart Contract
		blockSignerAddress, _, err := blockSignerContract.DeployBlockSigner(transactOpts, contractBackend, new(big.Int).SetUint64(genesis.Config.XDPoS.Epoch))
		if err != nil {
			log.Crit("Failed to deploy BlockSigners contract", "err", err)
		}
		contractBackend.Commit()

		code, _ = contractBackend.CodeAt(ctx, blockSignerAddress, nil)
		storage = make(map[common.Hash]common.Hash)
		contractBackend.ForEachStorageAt(ctx, blockSignerAddress, nil, f)
		genesis.Alloc[common.BlockSignersBinary] = types.Account{
			Balance: big.NewInt(0),
			Code:    code,
			Storage: storage,
		}

		// Randomize Smart Contract Code
		randomizeAddress, _, err := randomizeContract.DeployRandomize(transactOpts, contractBackend)
		if err != nil {
			log.Crit("Failed to deploy Randomize contract", "err", err)
		}
		contractBackend.Commit()

		code, _ = contractBackend.CodeAt(ctx, randomizeAddress, nil)
		storage = make(map[common.Hash]common.Hash)
		contractBackend.ForEachStorageAt(ctx, randomizeAddress, nil, f)
		genesis.Alloc[common.RandomizeSMCBinary] = types.Account{
			Balance: big.NewInt(0),
			Code:    code,
			Storage: storage,
		}

		fmt.Println()
		fmt.Println("Which accounts are allowed to confirm in Team MultiSignWallet?")
		var teams []common.Address
		if input != nil {
			teams = append(teams, owner)
		} else {
			for {
				if address := w.readAddress(); address != nil {
					teams = append(teams, *address)
					continue
				}
				if len(teams) > 0 {
					break
				}
			}
		}

		fmt.Println()
		fmt.Println("How many require for confirm tx in Team MultiSignWallet? (default = 2)")
		var requiredTeam int64
		if input != nil {
			requiredTeam = 1
		} else {
			requiredTeam = int64(w.readDefaultInt(1))
		}

		// MultiSigWallet.
		multiSignWalletTeamAddr, _, err := multiSignWalletContract.DeployMultiSigWallet(transactOpts, contractBackend, teams, big.NewInt(requiredTeam))
		if err != nil {
			log.Crit("Failed to deploy Team MultiSigWallet contract", "err", err)
		}
		contractBackend.Commit()
		code, _ = contractBackend.CodeAt(ctx, multiSignWalletTeamAddr, nil)
		storage = make(map[common.Hash]common.Hash)
		contractBackend.ForEachStorageAt(ctx, multiSignWalletTeamAddr, nil, f)
		// Team balance.
		balance := big.NewInt(0) // 12m
		balance.Add(balance, big.NewInt(12*1000*1000))
		balance.Mul(balance, big.NewInt(1000000000000000000))
		subBalance := big.NewInt(0) // i * 50k
		subBalance.Add(subBalance, big.NewInt(int64(len(signers))*50*1000))
		subBalance.Mul(subBalance, big.NewInt(1000000000000000000))
		balance.Sub(balance, subBalance) // 12m - i * 50k
		genesis.Alloc[common.TeamAddrBinary] = types.Account{
			Balance: balance,
			Code:    code,
			Storage: storage,
		}

	default:
		log.Crit("Invalid consensus engine choice", "choice", choice)
	}
	// Consensus all set, just ask for initial funds and go
	fmt.Println()
	fmt.Println("Which accounts should be pre-funded? (advisable at least one)")
	var addresses []common.Address
	if input != nil {
		addresses = append(addresses, common.HexToAddress(input.MasternodesOwner))
	} else {
		for {
			if address := w.readAddress(); address != nil {
				addresses = append(addresses, *address)
				continue
			}
			break
		}
	}
	for _, address := range addresses {
		baseBalance := big.NewInt(0) // 21m
		baseBalance.Add(baseBalance, big.NewInt(21_000_000))
		baseBalance.Mul(baseBalance, big.NewInt(1e18))
		genesis.Alloc[address] = types.Account{
			Balance: baseBalance,
		}
	}

	// Add a batch of precompile balances to avoid them getting deleted
	for i := int64(0); i < 2; i++ {
		genesis.Alloc[common.BigToAddress(big.NewInt(i))] = types.Account{Balance: big.NewInt(0)}
	}
	// Query the user for some custom extras
	fmt.Println()
	fmt.Println("Specify your chain/network ID if you want an explicit one (default = random)")
	if input != nil {
		genesis.Config.ChainID = new(big.Int).SetUint64(input.ChainId)
	} else {
		genesis.Config.ChainID = new(big.Int).SetUint64(uint64(w.readDefaultInt(rand.Intn(65536))))
	}

	// Refuse to store a genesis the init path would refuse. The prompt checks
	// judge each answer where it is given; this is the one place that sees the
	// complete config, so it re-derives the paired switch epoch from the switch
	// block and the epoch that are final by now, then runs the same gate. Both
	// paths run it: an input file carries the template pair, so the derivation
	// is a no-op there, and a template or input file carrying a negative switch
	// block is refused here because CheckSwitchBlockAlignment cannot see the
	// sign.
	if err := finalizeGenesisConfig(genesis.Config); err != nil {
		log.Crit("Refusing to generate an invalid genesis", "err", err)
	}
	// All done, store the genesis and flush to disk
	log.Info("Configured new genesis block")

	w.conf.Genesis = genesis
	w.conf.flush()
}

// manageGenesis permits the modification of chain configuration parameters in
// a genesis config and the export of the entire genesis spec.
func (w *wizard) manageGenesis() {
	// Figure out whether to modify or export the genesis
	fmt.Println()
	fmt.Println(" 1. Modify existing fork rules")
	fmt.Println(" 2. Export genesis configuration")
	fmt.Println(" 3. Remove genesis configuration")

	choice := w.read()
	switch {
	case choice == "1":
		// Fork rule updating requested, iterate over each fork
		fmt.Println()
		fmt.Printf("Which block should Homestead come into effect? (default = %v)\n", w.conf.Genesis.Config.HomesteadBlock)
		w.conf.Genesis.Config.HomesteadBlock = w.readDefaultBigInt(w.conf.Genesis.Config.HomesteadBlock)

		fmt.Println()
		fmt.Printf("Which block should EIP150 come into effect? (default = %v)\n", w.conf.Genesis.Config.EIP150Block)
		w.conf.Genesis.Config.EIP150Block = w.readDefaultBigInt(w.conf.Genesis.Config.EIP150Block)

		fmt.Println()
		fmt.Printf("Which block should EIP155 come into effect? (default = %v)\n", w.conf.Genesis.Config.EIP155Block)
		w.conf.Genesis.Config.EIP155Block = w.readDefaultBigInt(w.conf.Genesis.Config.EIP155Block)

		fmt.Println()
		fmt.Printf("Which block should EIP158 come into effect? (default = %v)\n", w.conf.Genesis.Config.EIP158Block)
		w.conf.Genesis.Config.EIP158Block = w.readDefaultBigInt(w.conf.Genesis.Config.EIP158Block)

		fmt.Println()
		fmt.Printf("Which block should Byzantium come into effect? (default = %v)\n", w.conf.Genesis.Config.ByzantiumBlock)
		w.conf.Genesis.Config.ByzantiumBlock = w.readDefaultBigInt(w.conf.Genesis.Config.ByzantiumBlock)

		out, _ := json.MarshalIndent(w.conf.Genesis.Config, "", "  ")
		fmt.Printf("Chain configuration updated:\n\n%s\n", out)

	case choice == "2":
		// Save whatever genesis configuration we currently have
		fmt.Println()
		fmt.Printf("Which file to save the genesis into? (default = %s.json)\n", w.network)
		out, _ := json.MarshalIndent(w.conf.Genesis, "", "  ")
		if err := os.WriteFile(w.readDefaultString(fmt.Sprintf("%s.json", w.network)), out, 0644); err != nil {
			log.Error("Failed to save genesis file", "err", err)
		}
		log.Info("Exported existing genesis block")

	case choice == "3":
		// Make sure we don't have any services running
		if len(w.conf.servers()) > 0 {
			log.Error("Genesis reset requires all services and servers torn down")
			return
		}
		log.Info("Genesis block destroyed")

		w.conf.Genesis = nil
		w.conf.flush()

	default:
		log.Error("That's not something I can do")
	}
}
