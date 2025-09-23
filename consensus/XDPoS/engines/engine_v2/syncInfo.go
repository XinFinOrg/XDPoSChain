package engine_v2

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/log"
)

// Verify syncInfo and trigger process QC or TC if successful
func (x *XDPoS_v2) VerifySyncInfoMessage(chain consensus.ChainReader, syncInfo *types.SyncInfo) (bool, error) {
	qc := syncInfo.HighestQuorumCert
	tc := syncInfo.HighestTimeoutCert

	if qc == nil {
		log.Warn("[VerifySyncInfoMessage] SyncInfo message is missing QC", "highestQC", qc)
		return false, nil
	}

	if x.highestQuorumCert.ProposedBlockInfo.Round >= qc.ProposedBlockInfo.Round && (tc == nil || x.highestTimeoutCert.Round >= tc.Round) {
		log.Debug("[VerifySyncInfoMessage] Local Round is larger or equal than syncinfo round", "highestQCRound", x.highestQuorumCert.ProposedBlockInfo.Round, "highestTCRound", x.highestTimeoutCert.Round, "incomingSyncInfoQCRound", qc.ProposedBlockInfo.Round, "incomingSyncInfoTCRound", tc.Round)
		return false, nil
	}

	snapshot, err := x.getSnapshot(chain, qc.GapNumber, true)
	if err != nil {
		log.Error("[VerifySyncInfoMessage] fail to get snapshot for a syncInfo message", "blockNum", qc.ProposedBlockInfo.Number, "blockHash", qc.ProposedBlockInfo.Hash, "error", err)
		return false, err
	}

	voteSigHash := types.VoteSigHash(&types.VoteForSign{
		ProposedBlockInfo: qc.ProposedBlockInfo,
		GapNumber:         qc.GapNumber,
	})

	if err := x.verifySignatures(voteSigHash, qc.Signatures, snapshot.NextEpochCandidates); err != nil {
		log.Warn("[VerifySyncInfoMessage] SyncInfo message verification failed due to QC", "blockNum", qc.ProposedBlockInfo.Number, "gapNum", qc.GapNumber, "round", qc.ProposedBlockInfo.Round, "error", err)
		return false, err
	}

	if tc != nil { // tc is optional, when the node is starting up there is no TC at the memory
		snapshot, err = x.getSnapshot(chain, tc.GapNumber, true)
		if err != nil {
			log.Error("[VerifySyncInfoMessage] Fail to get snapshot when verifying TC!", "tcGapNumber", tc.GapNumber)
			return false, fmt.Errorf("[VerifySyncInfoMessage] Unable to get snapshot, %s", err)
		}

		signedTimeoutObj := types.TimeoutSigHash(&types.TimeoutForSign{
			Round:     tc.Round,
			GapNumber: tc.GapNumber,
		})

		if err := x.verifySignatures(signedTimeoutObj, tc.Signatures, snapshot.NextEpochCandidates); err != nil {
			log.Warn("[VerifySyncInfoMessage] SyncInfo message verification failed due to TC", "gapNum", tc.GapNumber, "round", tc.Round, "error", err)
			return false, err
		}
	}

	return true, nil
}

func (x *XDPoS_v2) SyncInfoHandler(chain consensus.ChainReader, syncInfo *types.SyncInfo) error {
	x.lock.Lock()
	defer x.lock.Unlock()
	x.syncInfoPool.Add(syncInfo) // Add syncInfo to the pool, in case this is valid syncInfo but chain is not sync to latest height
	return x.syncInfoHandler(chain, syncInfo)
}

func (x *XDPoS_v2) syncInfoHandler(chain consensus.ChainReader, syncInfo *types.SyncInfo) error {
	qc := syncInfo.HighestQuorumCert
	tc := syncInfo.HighestTimeoutCert

	if x.highestQuorumCert.ProposedBlockInfo.Round >= qc.ProposedBlockInfo.Round && (tc == nil || x.highestTimeoutCert.Round >= tc.Round) {
		log.Debug("[syncInfoHandler] Local Round is larger or equal than syncinfo round, skip process message", "highestQCRound", x.highestQuorumCert.ProposedBlockInfo.Round, "highestTCRound", x.highestTimeoutCert.Round, "incomingSyncInfoQCRound", qc.ProposedBlockInfo.Round, "incomingSyncInfoTCRound", tc.Round)
		return nil
	}

	if err := x.verifyQC(chain, qc, nil); err != nil {
		return fmt.Errorf("[syncInfoHandler] Failed to verify QC, err %s", err)
	}
	if err := x.processQC(chain, qc); err != nil {
		return fmt.Errorf("[syncInfoHandler] Failed to process QC, err %s", err)
	}

	if tc != nil {
		if x.highestTimeoutCert.Round >= tc.Round {
			log.Debug("[syncInfoHandler] Round from incoming syncInfo message is equal or smaller then local TC round, skip process message", "highestTCRound", x.highestTimeoutCert.Round, "incomingSyncInfoTCRound", tc.Round)
			return nil
		}
		if err := x.verifyTC(chain, tc); err != nil {
			return fmt.Errorf("[syncInfoHandler] Failed to verify TC, err %s", err)
		}

		if err := x.processTC(chain, tc); err != nil {
			return fmt.Errorf("[syncInfoHandler] Failed to process TC, err %s", err)
		}
	}

	return nil
}

func (x *XDPoS_v2) processSyncInfoPool(chain consensus.ChainReader) {
	syncInfo := x.syncInfoPool.PoolObjKeysList()
	for _, key := range syncInfo {
		log.Debug("[processSyncInfoPool] Processing syncInfo message from pool", "key", key)
		for _, obj := range x.syncInfoPool.Get()[key] {
			if syncInfoObj, ok := obj.(*types.SyncInfo); ok {
				if err := x.syncInfoHandler(chain, syncInfoObj); err != nil {
					log.Error("[processSyncInfoPool] Failed to handle sync info", "error", err, "currenBlock", chain.CurrentHeader().Number.Uint64(), "x.currentRound", x.currentRound, "key", key)
					// must be something wrong with this message, so continue process next object in the pool for same round
					continue
				}
			} else {
				log.Error("[processSyncInfoPool] Object in sync info pool is not of type SyncInfo", "objectType", fmt.Sprintf("%T", obj), "key", key)
				continue
			}
			break // We only need to process the first object in the pool ideally
		}
	}
}

func (x *XDPoS_v2) verifySignatures(messageHash common.Hash, signatures []types.Signature, candidates []common.Address) error {
	var wg sync.WaitGroup
	wg.Add(len(signatures))
	var haveError error

	for _, signature := range signatures {
		go func(sig types.Signature) {
			defer wg.Done()
			verified, _, err := x.verifyMsgSignature(messageHash, sig, candidates)
			if err != nil {
				log.Error("[verifySignatures] Error while verfying QC message signatures", "error", err)
				haveError = errors.New("error while verfying QC message signatures")
				return
			}
			if !verified {
				log.Error("[verifySignatures] Signature not verified doing signature verification")
				haveError = errors.New("fail to verify QC due to signature mismatch")
				return
			}
		}(signature)
	}
	wg.Wait()
	if haveError != nil {
		return haveError
	}
	return nil
}

func (x *XDPoS_v2) hygieneSyncInfoPool() {
	x.lock.RLock()
	round := x.currentRound
	x.lock.RUnlock()
	syncInfoPoolKeys := x.syncInfoPool.PoolObjKeysList()

	// Extract round number
	for _, k := range syncInfoPoolKeys {
		// Key format: qcRound:qcGapNum:qcBlockNum:timeoutRound:timeoutGapNum:qcBlockHash
		qcRound, qcErr := strconv.ParseInt(strings.Split(k, ":")[0], 10, 64)
		tcRound, tcErr := strconv.ParseInt(strings.Split(k, ":")[3], 10, 64)
		if qcErr != nil || tcErr != nil {
			log.Error("[hygieneSyncInfoPool] Error while trying to get keyedRound inside pool", "Error", qcErr, "tcError", tcErr, "Key", k)
			continue
		}
		lowerBoundRound := int64(round) - utils.PoolHygieneRound
		// Clean up any sync info round that is 10 rounds older
		if qcRound < lowerBoundRound && (tcRound == 0 || tcRound < lowerBoundRound) {
			log.Debug("[hygieneSyncInfoPool] Cleaned sync info pool at round", "Round", qcRound, "currentRound", round, "Key", k)
			x.syncInfoPool.ClearByPoolKey(k)
		}
	}
}

func (x *XDPoS_v2) ReceivedSyncInfo() map[string]map[common.Hash]utils.PoolObj {
	return x.syncInfoPool.Get()
}
