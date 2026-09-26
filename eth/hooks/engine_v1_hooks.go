package hooks

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/contracts"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/eth/util"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/params"
)

func AttachConsensusV1Hooks(adaptor *XDPoS.XDPoS, bc *core.BlockChain, chainConfig *params.ChainConfig) {
	// Hook scans for bad masternodes and decide to penalty them
	adaptor.EngineV1.HookPenalty = func(chain consensus.ChainReader, blockNumberEpoc uint64) ([]common.Address, error) {
		canonicalState, err := bc.State()
		if canonicalState == nil || err != nil {
			log.Crit("Can't get state at head of canonical chain", "head number", bc.CurrentHeader().Number.Uint64(), "err", err)
		}
		prevEpoc := blockNumberEpoc - chain.Config().XDPoS.Epoch

		start := time.Now()
		prevHeader := chain.GetHeaderByNumber(prevEpoc)
		penSigners := adaptor.GetMasternodes(chain, prevHeader)
		if len(penSigners) > 0 {
			// Loop for each block to check missing sign.
			for i := prevEpoc; i < blockNumberEpoc; i++ {
				if i%common.MergeSignRange == 0 || !chainConfig.IsTIP2019(big.NewInt(int64(i))) {
					bheader := chain.GetHeaderByNumber(i)
					bhash := bheader.Hash()
					block := chain.GetBlock(bhash, i)
					if len(penSigners) > 0 {
						signedMasternodes, err := contracts.GetSignersFromContract(canonicalState, block)
						if err != nil {
							return nil, err
						}
						if len(signedMasternodes) > 0 {
							// Check signer signed?
							for _, signed := range signedMasternodes {
								for j, addr := range penSigners {
									if signed == addr {
										// Remove it from dupSigners.
										penSigners = append(penSigners[:j], penSigners[j+1:]...)
									}
								}
							}
						}
					} else {
						break
					}
				}
			}
		}
		log.Debug("Time Calculated HookPenalty ", "block", blockNumberEpoc, "time", common.PrettyDuration(time.Since(start)))
		return penSigners, nil
	}

	// Hook scans for bad masternodes and decide to penalty them
	adaptor.EngineV1.HookPenaltyTIPSigning = func(chain consensus.ChainReader, header *types.Header, candidates []common.Address) ([]common.Address, error) {
		prevEpoc := header.Number.Uint64() - chain.Config().XDPoS.Epoch
		combackEpoch := uint64(0)
		comebackLength := (common.LimitPenaltyEpoch + 1) * chain.Config().XDPoS.Epoch
		if header.Number.Uint64() > comebackLength {
			combackEpoch = header.Number.Uint64() - comebackLength
		}

		start := time.Now()

		listBlockHash := make([]common.Hash, chain.Config().XDPoS.Epoch)

		// get list block hash & stats total created block
		statMiners := make(map[common.Address]int)
		listBlockHash[0] = header.ParentHash
		parentnumber := header.Number.Uint64() - 1
		parentHash := header.ParentHash
		for i := uint64(1); i < chain.Config().XDPoS.Epoch; i++ {
			parentHeader := chain.GetHeader(parentHash, parentnumber)
			miner, _ := adaptor.RecoverSigner(parentHeader)
			value, exist := statMiners[miner]
			if exist {
				value = value + 1
			} else {
				value = 1
			}
			statMiners[miner] = value
			parentHash = parentHeader.ParentHash
			parentnumber--
			listBlockHash[i] = parentHash
		}

		// add list not miner to penalties
		prevHeader := chain.GetHeaderByNumber(prevEpoc)
		preMasternodes := adaptor.GetMasternodes(chain, prevHeader)
		penalties := []common.Address{}
		for miner, total := range statMiners {
			if total < common.MinimunMinerBlockPerEpoch {
				log.Debug("Find a node not enough requirement create block", "addr", miner.Hex(), "total", total)
				penalties = append(penalties, miner)
			}
		}
		for _, addr := range preMasternodes {
			if _, exist := statMiners[addr]; !exist {
				log.Debug("Find a node don't create block", "addr", addr.Hex())
				penalties = append(penalties, addr)
			}
		}

		// get list check penalties signing block & list master nodes wil comeback
		penComebacks := []common.Address{}
		if combackEpoch > 0 {
			combackHeader := chain.GetHeaderByNumber(combackEpoch)
			penalties := common.ExtractAddressFromBytes(combackHeader.Penalties)
			for _, penaltie := range penalties {
				for _, addr := range candidates {
					if penaltie == addr {
						penComebacks = append(penComebacks, penaltie)
					}
				}
			}
		}

		// Loop for each block to check missing sign. with comeback nodes
		mapBlockHash := map[common.Hash]bool{}
		for i := common.RangeReturnSigner - 1; i >= 0; i-- {
			if len(penComebacks) > 0 {
				blockNumber := header.Number.Uint64() - uint64(i) - 1
				bhash := listBlockHash[i]
				if blockNumber%common.MergeSignRange == 0 {
					mapBlockHash[bhash] = true
				}
				signingTxs, ok := adaptor.GetCachedSigningTxs(bhash)
				if !ok {
					block := chain.GetBlock(bhash, blockNumber)
					txs := block.Transactions()
					signingTxs = adaptor.CacheSigningTxs(bhash, txs)
				}
				// Check signer signed?
				for _, tx := range signingTxs {
					blkHash := common.BytesToHash(tx.Data()[len(tx.Data())-32:])
					from := *tx.From()
					if mapBlockHash[blkHash] {
						for j, addr := range penComebacks {
							if from == addr {
								// Remove it from dupSigners.
								penComebacks = append(penComebacks[:j], penComebacks[j+1:]...)
								break
							}
						}
					}
				}
			} else {
				break
			}
		}

		log.Debug("Time Calculated HookPenaltyTIPSigning ", "block", header.Number, "hash", header.Hash().Hex(), "pen comeback nodes", len(penComebacks), "not enough miner", len(penalties), "time", common.PrettyDuration(time.Since(start)))
		penalties = append(penalties, penComebacks...)
		if chain.Config().IsTIPRandomize(header.Number) {
			return penalties, nil
		}

		return penComebacks, nil
	}

	// Hook prepares validators M2 for the current epoch at checkpoint block
	adaptor.EngineV1.HookValidator = func(parent, header *types.Header, signers []common.Address) ([]byte, error) {
		start := time.Now()
		validators, err := getValidatorsAtNumber(bc, signers, parent)
		if err != nil {
			return []byte{}, err
		}
		header.Validators = validators
		log.Debug("Time Calculated HookValidator ", "block", header.Number.Uint64(), "time", common.PrettyDuration(time.Since(start)))
		return validators, nil
	}

	// Hook verifies masternodes set
	adaptor.EngineV1.HookVerifyMNs = func(parent, header *types.Header, signers []common.Address) error {
		number := header.Number.Int64()
		if number > 0 && number%common.EpocBlockRandomize == 0 {
			start := time.Now()
			validators, err := getValidatorsAtNumber(bc, signers, parent)
			log.Debug("Time Calculated HookVerifyMNs ", "block", header.Number.Uint64(), "time", common.PrettyDuration(time.Since(start)))
			if err != nil {
				return err
			}
			if !bytes.Equal(header.Validators, validators) {
				return utils.ErrInvalidCheckpointValidators
			}
		}
		return nil
	}

	/*
	   HookGetSignersFromContract return list masternode for current state (block)
	   This is a solution for work around issue return wrong list signers from snapshot
	*/
	adaptor.EngineV1.HookGetSignersFromContract = func(gapHeader *types.Header) ([]common.Address, error) {
		var (
			candidateAddresses []common.Address
			candidates         []utils.Masternode
		)
		if gapHeader == nil {
			return nil, errors.New("nil gap block header in HookGetSignersFromContract")
		}

		// The gap block header comes from the caller, which resolves it from the
		// local chain or from the batch it is verifying. Looking it up here by
		// hash would find nothing for the gap block of a fork, and the chain
		// state is what the candidates are read from.
		stateDB, err := bc.StateAt(gapHeader.Root)
		if err != nil {
			return nil, err
		}

		// Read the candidates and their stakes off the same state. The stakes
		// used to come back from the voting contract over this node's own IPC
		// endpoint: that made the hook depend on an IPC endpoint at all, so a
		// node without one could not fall back to the signers from the contract.
		//
		// That call carried no block number, so it answered from "latest": each
		// verifying node judged the checkpoint against its own head at the moment
		// of the call, and the same node could judge the same checkpoint
		// differently later. The gap block is the block to settle on, because it
		// is the state UpdateM1At reads for the next epoch's set.
		//
		// No fork block gates that settlement. Replaying the v1 era can therefore
		// classify a checkpoint differently than the latest-block reading did.
		candidateAddresses = stateDB.GetCandidates()
		for _, address := range candidateAddresses {
			candidates = append(candidates, utils.Masternode{Address: address, Stake: stateDB.GetCandidateCap(address)})
		}
		// GetCandidates and GetCandidateCap return zero values when the voting
		// contract storage cannot be read, memoizing the failure in
		// StateDB.Error(); surface it instead of returning a partial list.
		if err := stateDB.Error(); err != nil {
			return nil, fmt.Errorf("reading the signers of %s from state: %w", gapHeader.Hash().Hex(), err)
		}
		// sort candidates by stake descending
		utils.SortMasternodesByStakeDesc(candidates)
		if len(candidates) > 150 {
			candidates = candidates[:150]
		}
		result := []common.Address{}
		for _, candidate := range candidates {
			result = append(result, candidate.Address)
		}
		return result, nil
	}

	// Hook calculates reward for masternodes
	adaptor.EngineV1.HookReward = func(chain consensus.ChainReader, stateBlock vm.StateDB, parentState *state.StateDB, header *types.Header) (map[string]interface{}, error) {
		number := header.Number.Uint64()
		rCheckpoint := chain.Config().XDPoS.RewardCheckpoint
		foundationWalletAddr := chain.Config().XDPoS.FoundationWalletAddr
		if foundationWalletAddr == (common.Address{}) {
			log.Error("Foundation Wallet Address is empty", "error", foundationWalletAddr)
			return nil, errors.New("foundation Wallet Address is empty")
		}
		rewards := make(map[string]interface{})
		if number > 0 && number-rCheckpoint > 0 && foundationWalletAddr != (common.Address{}) {
			start := time.Now()
			// Get signers in blockSigner smartcontract.
			// Get reward inflation.
			chainReward := new(big.Int).Mul(new(big.Int).SetUint64(chain.Config().XDPoS.Reward), new(big.Int).SetUint64(params.Ether))
			chainReward = util.RewardInflation(chain, chainReward, number, common.BlocksPerYear)

			totalSigner := new(uint64)
			signers, err := contracts.GetRewardForCheckpoint(adaptor, chain, header, rCheckpoint, totalSigner)

			log.Debug("Time Get Signers", "block", header.Number.Uint64(), "time", common.PrettyDuration(time.Since(start)))
			if err != nil {
				log.Crit("Fail to get signers for reward checkpoint", "error", err)
			}
			rewards["signers"] = signers
			rewardSigners, err := contracts.CalculateRewardForSigner(chainReward, signers, *totalSigner)
			if err != nil {
				log.Crit("Fail to calculate reward for signers", "error", err)
			}
			// Add reward for coin holders.
			voterResults := make(map[common.Address]interface{})
			if len(signers) > 0 {
				for signer, calcReward := range rewardSigners {
					rewards, err := contracts.CalculateRewardForHolders(chain.Config(), foundationWalletAddr, parentState, signer, calcReward, header.Number)
					if err != nil {
						log.Crit("Fail to calculate reward for holders.", "error", err)
					}
					if len(rewards) > 0 {
						for holder, reward := range rewards {
							stateBlock.AddBalance(holder, reward, tracing.BalanceIncreaseRewardMineBlock)
						}
					}
					voterResults[signer] = rewards
				}
			}
			rewards["rewards"] = voterResults
			log.Debug("Time Calculated HookReward ", "block", header.Number.Uint64(), "time", common.PrettyDuration(time.Since(start)))
		}
		return rewards, nil
	}
}

// getValidatorsAtNumber derives the next epoch's validators from the randomize
// values committed at the parent of the checkpoint being checked.
//
// The parent is resolved by the caller and handed in, rather than looked up by
// height here. A checkpoint on a fork has a parent that may only exist in the
// verifier's batch, while the canonical block of the same height belongs to the
// competing branch, so deriving validators from that one would validate the
// wrong chain. Both in-tree callers resolve the parent before they get here and
// refuse to continue without it, so a nil one is reported rather than answered
// from the head, which is a block the caller did not ask about.
func getValidatorsAtNumber(bc *core.BlockChain, masternodes []common.Address, parent *types.Header) ([]byte, error) {
	if bc.Config().XDPoS == nil {
		return nil, core.ErrNotXDPoS
	}
	lenSigners := int64(len(masternodes))
	if lenSigners == 0 {
		return nil, core.ErrNotFoundM1
	}
	if parent == nil {
		return nil, errors.New("nil parent block to derive the validators from")
	}
	// Get secrets and opening at epoc block checkpoint.
	//
	// Both are read off the parent's state. The randomize contract used to
	// answer for them over this node's own IPC endpoint, which made the hook
	// depend on an IPC endpoint at all.
	stateDB, err := bc.StateAt(parent.Root)
	if err != nil {
		return nil, err
	}

	var candidates []int64
	for _, addr := range masternodes {
		random, err := contracts.DecryptRandomizeFromSecretsAndOpening(stateDB.GetSecret(addr), stateDB.GetOpening(addr))
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, random)
	}
	// GetSecret and GetOpening return zero values when the randomize contract
	// storage cannot be read, memoizing the failure in StateDB.Error(); surface
	// it instead of deriving validators from them.
	if err := stateDB.Error(); err != nil {
		return nil, fmt.Errorf("reading the randomize values from state: %w", err)
	}
	// Get randomize m2 list.
	m2, err := contracts.GenM2FromRandomize(candidates, lenSigners)
	if err != nil {
		return nil, err
	}
	return contracts.BuildValidatorFromM2(m2), nil
}
