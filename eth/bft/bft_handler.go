package bft

import (
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/log"
)

const maxBlockDist = 7 // Maximum allowed backward distance from the chain head, 7 is just a magic number indicate very close block

// Define Broadcast Group functions
type broadcastVoteFn func(*types.Vote)
type broadcastTimeoutFn func(*types.Timeout)
type broadcastSyncInfoFn func(*types.SyncInfo)

// chainHeightFn is a callback type to retrieve the current chain height.
type chainHeightFn func() uint64

type Bfter struct {
	epoch uint64

	blockChainReader consensus.ChainReader
	broadcastCh      chan interface{}
	quit             chan struct{}
	consensus        ConsensusFns
	broadcast        BroadcastFns
	chainHeight      chainHeightFn // Retrieves the current chain's height
}

type ConsensusFns struct {
	verifyVote  func(consensus.ChainReader, *types.Vote) (bool, error)
	voteHandler func(consensus.ChainReader, *types.Vote) error

	verifyTimeout  func(consensus.ChainReader, *types.Timeout) (bool, error)
	timeoutHandler func(consensus.ChainReader, *types.Timeout) error

	verifySyncInfo  func(consensus.ChainReader, *types.SyncInfo) (bool, error)
	syncInfoHandler func(consensus.ChainReader, *types.SyncInfo) error
}

type BroadcastFns struct {
	Vote     broadcastVoteFn
	Timeout  broadcastTimeoutFn
	SyncInfo broadcastSyncInfoFn
}

func New(broadcasts BroadcastFns, blockChainReader *core.BlockChain, chainHeight chainHeightFn) *Bfter {
	return &Bfter{
		broadcast:        broadcasts,
		blockChainReader: blockChainReader,
		chainHeight:      chainHeight,

		quit:        make(chan struct{}),
		broadcastCh: make(chan interface{}),
	}
}

// Create this function to avoid massive test change
func (b *Bfter) InitEpochNumber() {
	b.epoch = b.blockChainReader.Config().XDPoS.Epoch
}

func (b *Bfter) SetConsensusFuns(engine consensus.Engine) {
	e := engine.(*XDPoS.XDPoS)
	b.broadcastCh = e.EngineV2.BroadcastCh
	b.consensus = ConsensusFns{
		verifySyncInfo: e.EngineV2.VerifySyncInfoMessage,
		verifyVote:     e.EngineV2.VerifyVoteMessage,
		verifyTimeout:  e.EngineV2.VerifyTimeoutMessage,

		voteHandler:     e.EngineV2.VoteHandler,
		timeoutHandler:  e.EngineV2.TimeoutHandler,
		syncInfoHandler: e.EngineV2.SyncInfoHandler,
	}
}

// isNearBlockNumber compares number against head without going through
// big.Int.Int64, which truncates values above 2^63 and let 2^64+head pass as a
// block next to the head.
func isNearBlockNumber(number *big.Int, head, dist uint64) bool {
	if !number.IsUint64() {
		return false
	}
	n := number.Uint64()
	if n >= head {
		return n-head <= dist
	}
	return head-n <= dist
}

// isNearGapNumber bounds gap to the heights that can back a vote for a block
// within maxBlockDist of head: a switch sits at most an epoch below the voted
// block and its gap at most Gap+epoch below the switch, so an honest gap is at
// most 2*Epoch+Gap+maxBlockDist-2 below the head. The epoch*3 window covers it
// for Gap <= Epoch-5 (every built-in network is 900/450); a larger Gap only
// drops votes the round check already discards.
func (b *Bfter) isNearGapNumber(gap, head uint64) bool {
	// Faker chains skip CheckSchedule and can reach here with Epoch 0, so leave
	// the window open
	if b.epoch == 0 {
		return true
	}
	window := b.epoch * 3
	if gap >= head {
		return gap-head <= window
	}
	return head-gap <= window
}

func (b *Bfter) Vote(peer string, vote *types.Vote) error {
	if vote == nil || vote.ProposedBlockInfo == nil || vote.ProposedBlockInfo.Number == nil {
		return nil
	}
	log.Trace("[Vote] Received Vote", "hash", vote.Hash().Hex(), "voted block hash", vote.ProposedBlockInfo.Hash.Hex(), "number", vote.ProposedBlockInfo.Number, "round", vote.ProposedBlockInfo.Round)

	head := b.chainHeight()
	if !isNearBlockNumber(vote.ProposedBlockInfo.Number, head, maxBlockDist) {
		log.Debug("[Vote] Discarded propagated vote, too far away", "peer", peer, "number", vote.ProposedBlockInfo.Number, "hash", vote.ProposedBlockInfo.Hash)
		return nil
	}
	if !b.isNearGapNumber(vote.GapNumber, head) {
		log.Debug("[Vote] Discarded propagated vote, gap number out of range", "peer", peer, "gapNumber", vote.GapNumber, "head", head)
		return nil
	}

	verified, err := b.consensus.verifyVote(b.blockChainReader, vote)

	if err != nil {
		log.Error("[Vote] Verify BFT Vote", "error", err)
		return err
	}

	if verified {
		if !b.enqueueForBroadcast(vote) {
			return nil
		}
		err = b.consensus.voteHandler(b.blockChainReader, vote)
		if err != nil {
			if _, ok := err.(*utils.ErrIncomingMessageRoundTooFarFromCurrentRound); ok {
				log.Debug("[Vote] Vote round not equal", "error", err, "vote", vote.Hash())
				return err
			}
			if _, ok := err.(*utils.ErrIncomingMessageBlockNotFound); ok {
				log.Debug("[Vote] Vote proposed block not found", "error", err, "vote", vote.Hash())
				return err
			}
			log.Error("[Vote] Handle BFT Vote", "error", err)
			return err
		}
	}

	return nil
}
func (b *Bfter) Timeout(peer string, timeout *types.Timeout) error {
	gapNum := timeout.GapNumber

	// dist times 3, ex: timeout message's gap number is based on block and find out it's epoch switch number, then mod 900 then minus 450
	if dist := int64(gapNum) - int64(b.chainHeight()); dist < -int64(b.epoch)*3 || dist > int64(b.epoch)*3 {
		log.Debug("[Timeout] Discarded propagated timeout, too far away", "peer", peer, "gapNumber", gapNum, "hash", timeout.Hash, "distance", dist)
		return nil
	}

	verified, err := b.consensus.verifyTimeout(b.blockChainReader, timeout)
	if err != nil {
		log.Error("[Timeout] Verify BFT Timeout", "timeoutRound", timeout.Round, "timeoutGapNum", gapNum, "error", err)
		return err
	}
	log.Debug("[Timeout] Received Timeout", "gap", gapNum, "hash", timeout.Hash().Hex(), "round", timeout.Round, "signer", timeout.GetSigner().Hex()) //get signer after verifyTimeout

	if verified {
		if !b.enqueueForBroadcast(timeout) {
			return nil
		}
		err = b.consensus.timeoutHandler(b.blockChainReader, timeout)
		if err != nil {
			if _, ok := err.(*utils.ErrIncomingMessageRoundNotEqualCurrentRound); ok {
				log.Debug("[Timeout] Timeout round not equal", "error", err)
				return err
			}
			log.Error("[Timeout] Handle BFT Timeout", "error", err)
			return err
		}
	}

	return nil
}
func (b *Bfter) SyncInfo(peer string, syncInfo *types.SyncInfo) error {
	// The wire decoder rejects a QC without block info, so this only catches an
	// internally built one; the log line below would dereference it.
	if syncInfo == nil || syncInfo.HighestQuorumCert == nil || syncInfo.HighestQuorumCert.ProposedBlockInfo == nil {
		log.Warn("[SyncInfo] Received nil SyncInfo or a QC without block info", "syncInfo", syncInfo)
		return nil
	}
	log.Debug("[SyncInfo] Received SyncInfo", "syncInfo", syncInfo, "syncInfoHash", syncInfo.Hash().Hex())
	log.Debug("[SyncInfo] Received SyncInfo", "qcRound", syncInfo.HighestQuorumCert.ProposedBlockInfo.Round, "qcBlocknum", syncInfo.HighestQuorumCert.ProposedBlockInfo.Number, "qcBlockhash", syncInfo.HighestQuorumCert.ProposedBlockInfo.Hash.Hex())
	if syncInfo.HighestTimeoutCert != nil {
		log.Debug("[SyncInfo] Received SyncInfo", "tcRound", syncInfo.HighestTimeoutCert.Round)
	}

	qcBlockNum := syncInfo.HighestQuorumCert.ProposedBlockInfo.Number
	if qcBlockNum == nil || !isNearBlockNumber(qcBlockNum, b.chainHeight(), maxBlockDist) {
		log.Debug("[SyncInfo] Discarded propagated syncInfo, too far away", "peer", peer, "blockNum", qcBlockNum, "hash", syncInfo.Hash().Hex())
		return nil
	}

	verified, err := b.consensus.verifySyncInfo(b.blockChainReader, syncInfo)
	if err != nil {
		log.Error("[SyncInfo] Verify BFT SyncInfo", "error", err)
		return err
	}

	// Process only if verified and qualified
	if verified {
		if !b.enqueueForBroadcast(syncInfo) {
			return nil
		}
		err = b.consensus.syncInfoHandler(b.blockChainReader, syncInfo)
		if err != nil {
			log.Error("[SyncInfo] Handle BFT SyncInfo", "error", err)
			return err
		}
	}
	return nil
}

func (b *Bfter) enqueueForBroadcast(msg interface{}) bool {
	select {
	case <-b.quit:
		return false
	case b.broadcastCh <- msg:
		return true
	}
}

// Start Bft receiver
func (b *Bfter) Start() {
	go b.loop()
}
func (b *Bfter) Stop() {
	close(b.quit)
}
func (b *Bfter) loop() {
	log.Info("BFT Loop Start")
	for {
		select {
		case <-b.quit:
			log.Warn("BFT Loop Close")
			return
		case obj := <-b.broadcastCh:
			switch v := obj.(type) {
			case *types.Vote:
				go b.broadcast.Vote(v)
			case *types.Timeout:
				go b.broadcast.Timeout(v)
			case *types.SyncInfo:
				go b.broadcast.SyncInfo(v)
			default:
				log.Error("Unknown message type received", "value", v)
			}
		}
	}
}
