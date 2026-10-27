package engine_v2

import (
	"errors"

	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/log"
)

const (
	NUM_OF_FORENSICS_QC = 3
)

// Forensics instance. Placeholder for future properties to be added
type Forensics struct {
	HighestCommittedQCs []types.QuorumCert
}

// Initiate a forensics process
func NewForensics() *Forensics {
	return &Forensics{}
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

// ProcessForensics is the entry point for processing forensics, triggered
// once processQC succeeds; it runs in a separate goroutine as it is not
// system critical. The real implementation was commented out in #1517
// (1a2c8ee180) and is preserved in git history (flow diagram:
// https://hashlabs.atlassian.net/wiki/spaces/HASHLABS/pages/97878029/Forensics+Diagram+flow).
// Restoring it needs findAncestorQCs, checkQCsOnTheSameChain,
// findAncestorQcThroughRound and isVoteBlamed (gone with #1517) plus
// findQCsInSameRound and SendForensicProof back first.
func (f *Forensics) ProcessForensics(chain consensus.ChainReader, engine *XDPoS_v2, incomingQC types.QuorumCert) error {
	return nil
}

// ProcessVoteEquivocation is the entry point for processing vote
// equivocation, triggered once a vote is handled. The real implementation
// was commented out in #1517 (1a2c8ee180) and is preserved in git history
// (specification:
// https://hashlabs.atlassian.net/wiki/spaces/HASHLABS/pages/99516417/Vote+Equivocation+detection+specification).
// Restoring it needs GetVoteSignerAddresses, SendVoteEquivocationProof and
// isVoteBlamed back, and the isExtendingFromAncestor call must go through
// the engine argument, since it is a method of XDPoS_v2 (vote.go), not of
// Forensics.
func (f *Forensics) ProcessVoteEquivocation(chain consensus.ChainReader, engine *XDPoS_v2, incomingVote *types.Vote) error {
	return nil
}

// DetectEquivocationInVotePool reports two votes in the vote pool on the
// same round signed by the same signer. The real implementation was
// commented out in #1517 (1a2c8ee180) and is preserved in git history;
// restoring it needs GetVoteSignerAddresses and SendVoteEquivocationProof
// back, and the strconv/strings imports with them.
func (f *Forensics) DetectEquivocationInVotePool(vote *types.Vote, votePool *utils.Pool) {
	return
}
