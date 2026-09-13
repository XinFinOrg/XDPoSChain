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
	"fmt"
	"math"
	"math/rand"
	"os"
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

// GenesisInput is what the non-interactive input file carries. It deliberately has
// no schedule fields: makeGenesis stores the cloned Localnet template schedule, so a
// schedule the file asked for could not be applied, and
// checkGenesisInputScheduleKeys refuses such a file before it gets here.
type GenesisInput struct {
	Name                    string   // informational network name
	ChainId                 uint64   // network id
	MasternodesOwner        string   // owner registered for the initial masternodes
	Masternodes             []string // initial masternode (validator) set
	StakingThreshold        uint64   // per-masternode deposit in whole coins; sizes validator caps
	RewardYield             uint64   // masternode reward yield in APY%
	FoundationWalletAddress string   // foundation wallet address to collect 10% of all rewards
}

// defaultXDPoSGap is the gap the interactive wizard offers. It is half the engine
// default epoch, which keeps 1 <= Gap < Epoch satisfiable whenever the epoch
// question accepts its default.
const defaultXDPoSGap = params.DefaultXDPoSEpoch / 2

// xdposGapDefault returns the gap the wizard offers for epoch: the shared
// default, or the largest gap that epoch can hold when the default does not fit.
// An epoch below 2 has no gap at all; the shared default is returned for it so a
// caller that only prints the offer never underflows, and the interactive path
// refuses such an epoch before it reaches the gap question.
func xdposGapDefault(epoch uint64) uint64 {
	if epoch >= 2 && defaultXDPoSGap >= epoch {
		return epoch - 1
	}
	return defaultXDPoSGap
}

// readXDPoSEpoch reads the epoch and re-asks until it can hold a gap block.
// readDefaultInt accepts 0 and 1, and 1 <= gap < epoch has no solution for
// either, so the gap question used to loop forever - offering a default it could
// never accept - with Ctrl-C as the only way out.
func (w *wizard) readXDPoSEpoch() uint64 {
	for {
		epoch := w.readDefaultInt(int(params.DefaultXDPoSEpoch))
		if epoch >= 2 {
			return uint64(epoch)
		}
		fmt.Printf("The epoch has to be at least 2 so that a gap block (1 <= gap < epoch) exists\n")
	}
}

// readXDPoSGap reads the gap and re-asks until it designates a block inside
// epoch. The offered default always fits, so an epoch only just above the
// minimum still has a one-keystroke answer. readDefaultInt parses a signed
// integer, so the value is judged before the conversion to uint64: converting -1
// first would turn it into a huge gap that loops again.
//
// An epoch below 2 cannot hold a gap at all, so no answer would end the loop
// below. makeGenesis never asks it that way because readXDPoSEpoch refuses the
// epoch first; returning 0 keeps a direct caller from spinning, and the
// validation makeGenesis runs before it stores the config refuses that value.
func (w *wizard) readXDPoSGap(epoch uint64) uint64 {
	if epoch < 2 {
		return 0
	}
	for {
		gap := w.readDefaultInt(int(xdposGapDefault(epoch)))
		if gap > 0 && uint64(gap) < epoch {
			return uint64(gap)
		}
		fmt.Printf("The gap has to designate a block inside the epoch (1 <= gap < %d)\n", epoch)
	}
}

// xdposSwitchBlockAligned reports whether the height already satisfies the rule the
// config validation applies, i.e. whether it is a non-negative multiple of the epoch.
// The judgement is params.SwitchBlockAligned, the one definition of the rule, so the
// answer this question accepts is the answer the config validation re-derives: the
// wizard does not keep a second copy of the rule that could drift from it.
func xdposSwitchBlockAligned(block *big.Int, epoch uint64) bool {
	return params.SwitchBlockAligned(block, epoch)
}

// xdposAlignedSwitchBlock returns a switch block the alignment rule accepts, so the
// question it defaults can always be ended with a bare enter. A block that already
// satisfies the rule is returned as given; otherwise the nearest boundary below it
// is used, and 0 stands in for a missing or negative height because every epoch
// divides it - 0 is also the value the wizard templates carry.
//
// An epoch of zero names no boundary at all, so the answer is 0 rather than a
// division by it. The interactive path refuses such an epoch before it reaches any
// question, so this only keeps a direct caller total.
func xdposAlignedSwitchBlock(block *big.Int, epoch uint64) *big.Int {
	if epoch == 0 {
		// An epoch of zero names no boundary this question could accept, and the
		// caller refuses such an epoch before asking. Kept total so the modulo and
		// the division below cannot divide by zero.
		return new(big.Int)
	}
	if xdposSwitchBlockAligned(block, epoch) {
		return block
	}
	if block != nil && block.Sign() > 0 {
		epochBig := new(big.Int).SetUint64(epoch)
		return new(big.Int).Mul(new(big.Int).Div(block, epochBig), epochBig)
	}
	return new(big.Int)
}

// readXDPoSSwitchBlock reads the v2 switch block and re-asks until it lands on an
// epoch boundary. makeGenesis collects the switch block before the epoch, so
// shrinking the epoch afterwards can leave the two inconsistent, and the genesis
// commit refuses that shape (the v2 switch block has to be a multiple of the
// epoch). Re-asking here is where an interactive operator can still fix it.
//
// Only the alignment is settled here. The paired XDPoS.V2.SwitchEpoch is derived by
// the caller once the epoch is final (xdposSwitchEpoch), because the two fields
// describe one schedule and the config validation refuses an epoch that does not
// name the epoch its block falls on.
//
// A refusal keeps a default instead of dropping it: the rejected height is never
// offered again - readDefaultBigInt returns the default, not the answer that was
// just refused - while the question still has an answer a bare enter can take, so
// the loop cannot spin on an operator who keeps pressing enter. That is the same
// contract readXDPoSEpoch and readXDPoSGap keep. The default is normalized first,
// because it has to satisfy the rule above to end the loop: a missing, negative or
// unaligned height names no boundary this question could accept. epoch is the value
// readXDPoSEpoch returned and is at least 2 in the only path that asks this
// question; an epoch of zero is answered from the normalized default instead of
// being divided by, so a direct caller can neither spin nor panic.
func (w *wizard) readXDPoSSwitchBlock(epoch uint64, def *big.Int) *big.Int {
	if epoch == 0 {
		// An epoch of zero names no boundary this question could accept, so there is
		// nothing to announce and nothing to re-ask: the caller refuses such an epoch
		// before it gets here.
		return xdposAlignedSwitchBlock(def, epoch)
	}
	aligned := xdposAlignedSwitchBlock(def, epoch)
	// A height the rule cannot accept is replaced by the nearest boundary below it,
	// because the offered default is what a bare enter takes and it has to be an
	// answer the rule accepts. Say so instead of letting 950 become 900, or 5 become 0,
	// while the operator still believes the value they wrote is on offer.
	if def != nil && aligned.Cmp(def) != 0 {
		fmt.Printf("The switch block %v is not a non-negative multiple of the epoch (%d); offering the nearest boundary below, %v, instead\n", def, epoch, aligned)
	}
	def = aligned
	for {
		block := w.readDefaultBigInt(def)
		if xdposSwitchBlockAligned(block, epoch) {
			return block
		}
		fmt.Printf("The v2 switch block has to be a non-negative multiple of the epoch (%d); press enter for %s\n", epoch, def)
	}
}

// xdposSwitchEpoch derives the v2 switch epoch that pairs with a switch block.
// SwitchEpoch is the epoch number the block falls on, and the v2 round arithmetic
// reads it as SwitchEpoch + round/Epoch, so a genesis that lets the two fields
// drift renumbers every epoch the chain reports. The wizard collects the switch
// block before the epoch and starts from the template's SwitchEpoch, so the pairing
// has to be re-derived once both answers are final - which is also what the config
// validation now requires, so deriving it is what keeps an interactive run able to
// store what it collected.
//
// A nil block, a negative height or an unset epoch names no epoch; every one of
// those shapes is refused by the validation makeGenesis runs before it stores the
// genesis, and 0 keeps this helper total for a direct caller.
func xdposSwitchEpoch(switchBlock *big.Int, epoch uint64) uint64 {
	// Derived by params.SwitchEpochFor, the same definition the validation derives
	// its want with, so the value stored here is the value
	// CheckV2SwitchEpochAlignment re-derives - the wizard does not keep a second
	// copy of the pairing arithmetic that could drift from it. The derivation runs
	// on the big.Int, so the epoch named is the one the block really falls on
	// rather than the one a truncated height would. A quotient no uint64 can hold
	// names an epoch SwitchEpoch can never equal, which is the mismatch the
	// validation reports; 0 keeps this helper total for a direct caller.
	want, ok := params.SwitchEpochFor(switchBlock, epoch)
	if !ok {
		return 0
	}
	return want.Uint64()
}

func NewGenesisInput() *GenesisInput {
	return &GenesisInput{
		Name:                    "xdc-custom-network",
		ChainId:                 5151,
		StakingThreshold:        10_000_000, // 10M
		RewardYield:             10,         // 10% APY
		FoundationWalletAddress: common.FoundationAddrBinary.Hex(),
	}
}

// checkGenesisInputScheduleKeys refuses an input file that requests a schedule.
// The input-file path stores the cloned Localnet template schedule, so a schedule in
// the file cannot be applied - GenesisInput has no schedule field makeGenesis would
// read - and it would be dropped silently, leaving the operator with a genesis that
// describes a schedule the file does not. Refusing the file says so instead.
//
// The keys are judged on the decoded document rather than on GenesisInput, because
// yaml matches a key against the lowercased field name exactly: a file that spells
// switchBlock, switchblock or switch_block would land on no field at all, and the
// values are ignored either way - what matters is that the file asked, since the
// generated genesis keeps the template schedule. switchEpoch belongs to the same
// schedule: makeGenesis re-derives it from the switch block and the epoch, so a value
// the file writes for it cannot take effect either.
//
// The refusal reports the canonical key names in a fixed order, whatever spelling the
// file used: the case and the underscores are folded away to recognise the key, and
// the message is built from the canonical names instead.
func checkGenesisInputScheduleKeys(doc *yaml.Node) error {
	root := doc
	if root != nil && root.Kind == yaml.DocumentNode {
		if len(root.Content) == 0 {
			return nil
		}
		root = root.Content[0]
	}
	if root == nil || root.Kind != yaml.MappingNode {
		return nil
	}
	var epoch, gap, switchBlock, switchEpoch bool
	for i := 0; i+1 < len(root.Content); i += 2 {
		switch strings.ToLower(strings.ReplaceAll(root.Content[i].Value, "_", "")) {
		case "epoch":
			epoch = true
		case "gap":
			gap = true
		case "switchblock":
			switchBlock = true
		case "switchepoch":
			switchEpoch = true
		}
	}
	// Reported in a fixed order, so a refusal names the keys the same way whatever
	// order the file lists them in.
	var present []string
	if epoch {
		present = append(present, "epoch")
	}
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
	return fmt.Errorf("input file carries %s, but the input-file path stores the cloned Localnet template schedule (epoch %d, gap %d) instead of applying a schedule of its own; remove the schedule keys, or use the interactive path to choose a schedule",
		strings.Join(present, ", "), params.LocalnetChainConfig.XDPoS.Epoch, params.LocalnetChainConfig.XDPoS.Gap)
}

func (w *wizard) loadGenesisInput() *GenesisInput {
	// No input file means interactive mode: return nil so makeGenesis prompts.
	if w.conf.inpath == "" {
		return nil
	}
	input := NewGenesisInput()
	file, err := os.Open(w.conf.inpath)
	if err != nil {
		log.Warn("Failed to open genesis input file", "err", err)
		os.Exit(1)
		return nil
	}
	defer file.Close()

	log.Info("Decoding genesis input file", "path", w.conf.inpath)
	decoder := yaml.NewDecoder(file)
	// The document is decoded once as a node so its keys can be judged before the
	// fields are: yaml matches a key against the lowercased field name exactly, so an
	// epoch or switchBlock the file carries would otherwise be dropped without a
	// trace, and the genesis below would silently describe the template's schedule.
	var doc yaml.Node
	if err := decoder.Decode(&doc); err != nil {
		log.Warn("Failed to decode genesis input file (expect yaml format)", "err", err)
		os.Exit(1)
		return nil
	}
	if err := checkGenesisInputScheduleKeys(&doc); err != nil {
		log.Error("Refusing the genesis input file", "err", err)
		os.Exit(1)
		return nil
	}
	if err := doc.Decode(&input); err != nil {
		log.Warn("Failed to decode genesis input file into the wizard fields", "err", err)
		os.Exit(1)
		return nil
	}
	fmt.Println("Generating genesis file with the below input")
	fmt.Printf("%+v\n", input)

	return input
}

// makeGenesis creates a new genesis struct based on some user input.
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

		fmt.Println()
		fmt.Printf("How many blocks per epoch? (default = %d)\n", params.DefaultXDPoSEpoch)
		if input == nil {
			genesis.Config.XDPoS.Epoch = w.readXDPoSEpoch()
		}

		fmt.Println()
		fmt.Printf("How many blocks before checkpoint need to prepare new set of masternodes? (default = %d)\n", xdposGapDefault(genesis.Config.XDPoS.Epoch))
		if input == nil {
			genesis.Config.XDPoS.Gap = w.readXDPoSGap(genesis.Config.XDPoS.Epoch)
		}

		// The switch block is asked here, once, after the epoch is final: the question
		// is then judged against the epoch the block has to divide, so the schedule the
		// operator sees is the schedule that gets stored. Asking it earlier - next to the
		// V2 runtime questions, before the epoch is known - meant the answer had to be
		// re-asked once the epoch arrived, or silently overridden. The input-file path
		// carries the Localnet template's aligned pair, so it never asks.
		fmt.Println()
		fmt.Printf("Which block number start v2 consesus? (default = %v)\n", xdposAlignedSwitchBlock(genesis.Config.XDPoS.V2.SwitchBlock, genesis.Config.XDPoS.Epoch))
		if input == nil {
			genesis.Config.XDPoS.V2.SwitchBlock = w.readXDPoSSwitchBlock(genesis.Config.XDPoS.Epoch, genesis.Config.XDPoS.V2.SwitchBlock)
		}
		// Both answers are final now, so the paired switch epoch is re-derived: the
		// template supplies a SwitchEpoch of its own, and a switch block the operator
		// typed would otherwise leave the two describing different schedules, which
		// the validation below refuses. Re-deriving the template's pair on the
		// input-file path is a no-op, so this runs for both paths rather than only
		// where the question was asked.
		genesis.Config.XDPoS.V2.SwitchEpoch = xdposSwitchEpoch(genesis.Config.XDPoS.V2.SwitchBlock, genesis.Config.XDPoS.Epoch)

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
		if genesis.Config.XDPoS.Period > 0 && genesis.Config.XDPoS.Epoch > 0 {
			blocksPerYear := 31536000 / genesis.Config.XDPoS.Period
			epochsPerYear := blocksPerYear / genesis.Config.XDPoS.Epoch
			if epochsPerYear > 0 {
				rewardsPerYear := float64(threshold) * (float64(yield) / float64(100))
				rewardPerEpochPerMN := uint64(rewardsPerYear / float64(epochsPerYear))
				totalRewardPerEpoch := rewardPerEpochPerMN * uint64(len(signers))
				fmt.Println()
				fmt.Println("Calculated Total Masternode rewards per epoch based on yield: ", totalRewardPerEpoch)
				genesis.Config.XDPoS.Reward = totalRewardPerEpoch
				genesis.Config.XDPoS.V2.CurrentConfig.MasternodeReward = math.Round(float64(rewardPerEpochPerMN)*1000) / 1000
				genesis.Config.XDPoS.V2.CurrentConfig.ProtectorReward = math.Round(float64(rewardPerEpochPerMN)*0.8*1000) / 1000
				genesis.Config.XDPoS.V2.CurrentConfig.ObserverReward = math.Round(float64(rewardPerEpochPerMN)*0.6*1000) / 1000

			}
		}

		fmt.Println()
		fmt.Println("What is foundation wallet address (collect 10% of all rewards)? (default = xdc0000000000000000000000000000000000000068)")
		if input == nil {
			genesis.Config.XDPoS.FoundationWalletAddr = w.readDefaultAddress(common.FoundationAddrBinary)
		}

		// Validator Smart Contract Code
		pKey, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr := crypto.PubkeyToAddress(pKey.PublicKey)
		deployerFunds := new(big.Int).Mul(big.NewInt(1_000_000), big.NewInt(1e18)) // 1,000,000 ETH
		// Gas limit increased to 10,000,000,000 to support validator contract deployment with large masternode counts (>38).
		contractBackend := backends.NewXDCSimulatedBackend(types.GenesisAlloc{addr: {Balance: deployerFunds}}, 10_000_000_000, params.TestXDPoSMockChainConfig)
		transactOpts, err := bind.NewKeyedTransactorWithChainID(pKey, new(big.Int).SetUint64(params.ConsensusOptionalTestChainID))
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
		blockSignerAddress, _, err := blockSignerContract.DeployBlockSigner(transactOpts, contractBackend, big.NewInt(int64(genesis.Config.XDPoS.Epoch)))
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

	// Refuse to store a genesis the init path would refuse. The interactive path
	// collects the epoch and the gap separately, so the schedule can come out
	// unusable; the input-file path carries no schedule of its own - GenesisInput
	// only probes the schedule keys so a file that asks for one is refused - and
	// stores the cloned Localnet template as written. The
	// same judgement the genesis commit applies is what tells the two apart. The
	// alignment question above already covers the schedule the operator just
	// answered; this one also covers the remaining required fields and the fork
	// order, and reports on stdout as well, because an interactive run otherwise
	// just ends without storing anything.
	if genesis.Config.XDPoS != nil {
		if err := genesis.Config.CheckConfigForkOrderWithEpochDefault(); err != nil {
			fmt.Println("Refusing to generate an invalid genesis:", err)
			log.Error("Refusing to generate an invalid genesis", "err", err)
			return
		}
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
