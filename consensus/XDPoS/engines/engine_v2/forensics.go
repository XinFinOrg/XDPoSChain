package engine_v2

import (
	"errors"

	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/event"
	"github.com/XinFinOrg/XDPoSChain/log"
)

const (
	NUM_OF_FORENSICS_QC = 3
)

// Forensics instance. Placeholder for future properties to be added
type Forensics struct {
	HighestCommittedQCs []types.QuorumCert
	forensicsFeed       event.Feed
	scope               event.SubscriptionScope
}

// Initiate a forensics process
func NewForensics() *Forensics {
	return &Forensics{}
}

// SubscribeForensicsEvent registers a subscription of ForensicsEvent and
// starts sending event to the given channel.
func (f *Forensics) SubscribeForensicsEvent(ch chan<- types.ForensicsEvent) event.Subscription {
	return f.scope.Track(f.forensicsFeed.Subscribe(ch))
}

func (f *Forensics) ForensicsMonitoring(chain consensus.ChainReader, engine *XDPoS_v2, headerQcToBeCommitted []types.Header, incomingQC types.QuorumCert) error {
	f.ProcessForensics(chain, engine, incomingQC)
	return f.SetCommittedQCs(headerQcToBeCommitted, incomingQC)
}

// Set the forensics committed QCs list. The order is from grandparent to current header. i.e it shall follow the QC in its header as follow [hcqc1, hcqc2, hcqc3]
func (f *Forensics) SetCommittedQCs(headers []types.Header, incomingQC types.QuorumCert) error {
	// highestCommitQCs is an array, assign the parentBlockQc and its child as well as its grandchild QC into this array for forensics purposes.
	if len(headers) != NUM_OF_FORENSICS_QC-1 {
		log.Error("[SetCommittedQcs] Received input length not equal to 2", len(headers))
		return errors.New("received headers length not equal to 2 ")
	}

	var committedQCs []types.QuorumCert
	for i, h := range headers {
		var decodedExtraField types.ExtraFields_v2
		// Decode the qc1 and qc2
		err := utils.DecodeBytesExtraFields(h.Extra, &decodedExtraField)
		if err != nil {
			log.Error("[SetCommittedQCs] Fail to decode extra when committing QC to forensics", "err", err, "index", i)
			return err
		}
		if i != 0 {
			if decodedExtraField.QuorumCert.ProposedBlockInfo.Hash != headers[i-1].Hash() {
				log.Error("[SetCommittedQCs] Headers shall be on the same chain and in the right order", "parentHash", h.ParentHash.Hex(), "headers[i-1].Hash()", headers[i-1].Hash().Hex())
				return errors.New("headers shall be on the same chain and in the right order")
			} else if i == len(headers)-1 { // The last header shall be pointed by the incoming QC
				if incomingQC.ProposedBlockInfo.Hash != h.Hash() {
					log.Error("[SetCommittedQCs] incomingQc is not pointing at the last header received", "hash", h.Hash().Hex(), "incomingQC.ProposedBlockInfo.Hash", incomingQC.ProposedBlockInfo.Hash.Hex())
					return errors.New("incomingQc is not pointing at the last header received")
				}
			}
		}

		committedQCs = append(committedQCs, *decodedExtraField.QuorumCert)
	}
	f.HighestCommittedQCs = append(committedQCs, incomingQC)
	return nil
}

func (f *Forensics) ProcessForensics(chain consensus.ChainReader, engine *XDPoS_v2, incomingQC types.QuorumCert) error {
	return nil
}

/*
Entry point for processing forensics.
Triggered once processQC is successfully.
Forensics runs in a separate go routine as its no system critical
Link to the flow diagram: https://hashlabs.atlassian.net/wiki/spaces/HASHLABS/pages/97878029/Forensics+Diagram+flow
func (f *Forensics) ProcessForensics(chain consensus.ChainReader, engine *XDPoS_v2, incomingQC types.QuorumCert) error {
	log.Debug("Received a QC in forensics", "QC", incomingQC)
	// Clone the values to a temporary variable
	highestCommittedQCs := f.HighestCommittedQCs
	if len(highestCommittedQCs) != NUM_OF_FORENSICS_QC {
		log.Error("[ProcessForensics] HighestCommittedQCs value not set", "incomingQcProposedBlockHash", incomingQC.ProposedBlockInfo.Hash, "incomingQcProposedBlockNumber", incomingQC.ProposedBlockInfo.Number.Uint64(), "incomingQcProposedBlockRound", incomingQC.ProposedBlockInfo.Round)
		return errors.New("HighestCommittedQCs value not set")
	}
	// Find the QC1 and QC2. We only care 2 parents in front of the incomingQC. The returned value contains QC1, QC2 and QC3(the incomingQC)
	incomingQuorunCerts, err := f.findAncestorQCs(chain, incomingQC, 2)
	if err != nil {
		return err
	}
	isOnTheChain, err := f.checkQCsOnTheSameChain(chain, highestCommittedQCs, incomingQuorunCerts)
	if err != nil {
		return err
	}
	if isOnTheChain {
		// Passed the checking, nothing suspicious.
		log.Debug("[ProcessForensics] Passed forensics checking, nothing suspicious need to be reported", "incomingQcProposedBlockHash", incomingQC.ProposedBlockInfo.Hash, "incomingQcProposedBlockNumber", incomingQC.ProposedBlockInfo.Number.Uint64(), "incomingQcProposedBlockRound", incomingQC.ProposedBlockInfo.Round)
		return nil
	}
	// Trigger the safety Alarm if failed
	// First, find the QC in the two sets that have the same round
	foundSameRoundQC, sameRoundHCQC, sameRoundQC := f.findQCsInSameRound(highestCommittedQCs, incomingQuorunCerts)

	if foundSameRoundQC {
		f.SendForensicProof(chain, engine, sameRoundHCQC, sameRoundQC)
	} else {
		// Not found, need a more complex approach to find the two QC
		ancestorQC, lowerRoundQCs, _, err := f.findAncestorQcThroughRound(chain, highestCommittedQCs, incomingQuorunCerts)
		if err != nil {
			log.Error("[ProcessForensics] Error while trying to find ancestor QC through round number", "err", err)
		}
		f.SendForensicProof(chain, engine, ancestorQC, lowerRoundQCs[NUM_OF_FORENSICS_QC-1])
	}

	return nil
}
*/

func (f *Forensics) ProcessVoteEquivocation(chain consensus.ChainReader, engine *XDPoS_v2, incomingVote *types.Vote) error {
	return nil
}

/*
Entry point for processing vote equivocation.
Triggered once handle vote is successfully.
Forensics runs in a separate go routine as its no system critical
Link to the flow diagram: https://hashlabs.atlassian.net/wiki/spaces/HASHLABS/pages/99516417/Vote+Equivocation+detection+specification
func (f *Forensics) ProcessVoteEquivocation(chain consensus.ChainReader, engine *XDPoS_v2, incomingVote *types.Vote) error {
	log.Debug("Received a vote in forensics", "vote", incomingVote)
	// Clone the values to a temporary variable
	highestCommittedQCs := f.HighestCommittedQCs
	if len(highestCommittedQCs) != NUM_OF_FORENSICS_QC {
		log.Error("[ProcessVoteEquivocation] HighestCommittedQCs value not set", "incomingVoteProposedBlockHash", incomingVote.ProposedBlockInfo.Hash, "incomingVoteProposedBlockNumber", incomingVote.ProposedBlockInfo.Number.Uint64(), "incomingVoteProposedBlockRound", incomingVote.ProposedBlockInfo.Round)
		return errors.New("HighestCommittedQCs value not set")
	}
	if incomingVote.ProposedBlockInfo.Round < highestCommittedQCs[NUM_OF_FORENSICS_QC-1].ProposedBlockInfo.Round {
		log.Debug("Received a too old vote in forensics", "vote", incomingVote)
		return nil
	}
	// is vote extending committed block
	isOnTheChain, err := f.isExtendingFromAncestor(chain, incomingVote.ProposedBlockInfo, highestCommittedQCs[0].ProposedBlockInfo)
	if err != nil {
		return err
	}
	if isOnTheChain {
		// Passed the checking, nothing suspicious.
		log.Debug("[ProcessVoteEquivocation] Passed forensics checking, nothing suspicious need to be reported", "incomingVoteProposedBlockHash", incomingVote.ProposedBlockInfo.Hash, "incomingVoteProposedBlockNumber", incomingVote.ProposedBlockInfo.Number.Uint64(), "incomingVoteProposedBlockRound", incomingVote.ProposedBlockInfo.Round)
		return nil
	}
	// Trigger the safety Alarm if failed
	isVoteBlamed, parentQC, err := f.isVoteBlamed(chain, highestCommittedQCs, incomingVote)
	if err != nil {
		log.Error("[ProcessVoteEquivocation] Error while trying to call isVoteBlamed", "error", err)
		return err
	}
	if isVoteBlamed {
		signer, err := GetVoteSignerAddresses(incomingVote)
		if err != nil {
			log.Error("[ProcessVoteEquivocation] GetVoteSignerAddresses", "error", err)
		}
		qc := highestCommittedQCs[NUM_OF_FORENSICS_QC-1]
		for _, signature := range qc.Signatures {
			voteFromQC := &types.Vote{ProposedBlockInfo: qc.ProposedBlockInfo, Signature: signature, GapNumber: qc.GapNumber}
			signerFromQC, err := GetVoteSignerAddresses(voteFromQC)
			if err != nil {
				log.Error("[ProcessVoteEquivocation] GetVoteSignerAddresses", "error", err)
				return err
			}
			if signerFromQC == signer {
				f.SendVoteEquivocationProof(incomingVote, voteFromQC, signer)
				break
			}
		}
		// if no same-signer vote, nothing to report
	} else {
		// use the parent QC to do forensics
		f.ProcessForensics(chain, engine, *parentQC)
	}

	return nil
}
*/

func (f *Forensics) DetectEquivocationInVotePool(vote *types.Vote, votePool *utils.Pool) {
	return
}

/*
func (f *Forensics) DetectEquivocationInVotePool(vote *types.Vote, votePool *utils.Pool) {
	poolKey := vote.PoolKey()
	votePoolKeys := votePool.PoolObjKeysList()
	signer, err := GetVoteSignerAddresses(vote)
	if err != nil {
		log.Error("[detectEquivocationInVotePool]", "err", err)
	}

	for _, k := range votePoolKeys {
		if k == poolKey {
			continue
		}
		keyedRound, err := strconv.ParseInt(strings.Split(k, ":")[0], 10, 64)
		if err != nil {
			log.Error("[detectEquivocationInVotePool] Error while trying to get keyedRound inside pool", "Error", err)
			continue
		}
		if types.Round(keyedRound) == vote.ProposedBlockInfo.Round {
			votes := votePool.GetObjsByKey(k)
			for _, v := range votes {
				voteTransfered, ok := v.(*types.Vote)
				if !ok {
					log.Warn("[detectEquivocationInVotePool] obj type is not vote, potential a bug in votePool")
					continue
				}
				signer2, err := GetVoteSignerAddresses(voteTransfered)
				if err != nil {
					log.Warn("[detectEquivocationInVotePool]", "err", err)
					continue
				}
				if signer == signer2 {
					f.SendVoteEquivocationProof(vote, voteTransfered, signer)
				}
			}
		}
	}
}
*/
