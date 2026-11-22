package bft

import (
	"errors"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/engines/engine_v2"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

const peerID = "abc"

// make different votes based on Signatures
func makeVotes(n int) []types.Vote {
	var votes []types.Vote
	for i := 0; i < n; i++ {
		votes = append(votes, types.Vote{
			ProposedBlockInfo: &types.BlockInfo{Number: big.NewInt(1350)},
			Signature:         []byte{byte(i)},
			GapNumber:         450,
		})
	}
	return votes
}

// bfterTester is a test simulator for mocking out bfter worker.
type bfterTester struct {
	bfter *Bfter
}

// newTester creates a new bft fetcher test mocker.
func newTester() *bfterTester {
	testConsensus := &XDPoS.XDPoS{EngineV2: &engine_v2.XDPoS_v2{}}
	broadcasts := BroadcastFns{}
	blockChain := &core.BlockChain{}
	blockChain.SetChainConfig(params.TestXDPoSMockChainConfig)
	chainHeight := func() uint64 {
		return 1351
	}

	tester := &bfterTester{}
	tester.bfter = New(broadcasts, blockChain, chainHeight)
	tester.bfter.InitEpochNumber()
	tester.bfter.SetConsensusFuns(testConsensus)
	tester.bfter.broadcastCh = make(chan interface{})
	tester.bfter.Start()

	return tester
}

// Tests that a bfter accepts vote and process verfiy and broadcast
func TestSequentialVotes(t *testing.T) {
	tester := newTester()
	verifyCounter := uint32(0)
	handlerCounter := uint32(0)
	broadcastCounter := uint32(0)
	targetVotes := 10

	tester.bfter.consensus.verifyVote = func(chain consensus.ChainReader, vote *types.Vote) (bool, error) {
		atomic.AddUint32(&verifyCounter, 1)
		return true, nil
	}

	tester.bfter.consensus.voteHandler = func(chain consensus.ChainReader, vote *types.Vote) error {
		atomic.AddUint32(&handlerCounter, 1)
		return nil
	}

	tester.bfter.broadcast.Vote = func(*types.Vote) {
		atomic.AddUint32(&broadcastCounter, 1)
	}

	votes := makeVotes(targetVotes)
	for _, vote := range votes {
		err := tester.bfter.Vote(peerID, &vote)
		if err != nil {
			t.Fatal(err)
		}
	}

	time.Sleep(100 * time.Millisecond)

	if int(atomic.LoadUint32(&verifyCounter)) != targetVotes || int(atomic.LoadUint32(&handlerCounter)) != targetVotes || int(atomic.LoadUint32(&broadcastCounter)) != targetVotes {
		t.Fatalf("count mismatch: have %v on verify, %v on handler, %v on broadcast, want %v", atomic.LoadUint32(&verifyCounter), atomic.LoadUint32(&handlerCounter), atomic.LoadUint32(&broadcastCounter), targetVotes)
	}
}

// Test that avoid broadcast if there is bad vote
func TestNotBoardcastInvalidVote(t *testing.T) {
	tester := newTester()
	handlerCounter := uint32(0)
	broadcastCounter := uint32(0)
	targetVotes := 0

	tester.bfter.consensus.verifyVote = func(chain consensus.ChainReader, vote *types.Vote) (bool, error) {
		return false, errors.New("This is invalid vote")
	}

	tester.bfter.consensus.voteHandler = func(chain consensus.ChainReader, vote *types.Vote) error {
		atomic.AddUint32(&handlerCounter, 1)
		return nil
	}
	tester.bfter.broadcast.Vote = func(*types.Vote) {
		atomic.AddUint32(&broadcastCounter, 1)
	}

	vote := types.Vote{ProposedBlockInfo: &types.BlockInfo{Number: big.NewInt(1)}}
	tester.bfter.Vote(peerID, &vote)

	time.Sleep(50 * time.Millisecond)
	if int(atomic.LoadUint32(&handlerCounter)) != targetVotes || int(atomic.LoadUint32(&broadcastCounter)) != targetVotes {
		t.Fatalf("count mismatch: have %v on handler, %v on broadcast, want %v", atomic.LoadUint32(&handlerCounter), atomic.LoadUint32(&broadcastCounter), targetVotes)
	}
}

func TestBoardcastButNotProcessDisqualifiedVotes(t *testing.T) {
	tester := newTester()
	handlerCounter := uint32(0)
	broadcastCounter := uint32(0)
	targetVotes := 0

	tester.bfter.consensus.verifyVote = func(chain consensus.ChainReader, vote *types.Vote) (bool, error) {
		return false, nil // return false but with nil in error means the message is valid but disqualified
	}

	tester.bfter.consensus.voteHandler = func(chain consensus.ChainReader, vote *types.Vote) error {
		atomic.AddUint32(&handlerCounter, 1)
		return nil
	}
	tester.bfter.broadcast.Vote = func(*types.Vote) {
		atomic.AddUint32(&broadcastCounter, 1)
	}

	vote := types.Vote{ProposedBlockInfo: &types.BlockInfo{Number: big.NewInt(1350)}}
	tester.bfter.Vote(peerID, &vote)

	time.Sleep(50 * time.Millisecond)
	if int(atomic.LoadUint32(&handlerCounter)) != targetVotes || int(atomic.LoadUint32(&broadcastCounter)) != 0 {
		t.Fatalf("count mismatch: have %v on handler, %v on broadcast, want %v", atomic.LoadUint32(&handlerCounter), atomic.LoadUint32(&broadcastCounter), targetVotes)
	}
}

func TestBoardcastButNotProcessDisqualifiedTimeout(t *testing.T) {
	tester := newTester()
	handlerCounter := uint32(0)
	broadcastCounter := uint32(0)
	targetTimeout := 0

	tester.bfter.consensus.verifyTimeout = func(chain consensus.ChainReader, timeout *types.Timeout) (bool, error) {
		return false, nil // return false but with nil in error means the message is valid but disqualified
	}

	tester.bfter.consensus.timeoutHandler = func(chain consensus.ChainReader, timeout *types.Timeout) error {
		atomic.AddUint32(&handlerCounter, 1)
		return nil
	}
	tester.bfter.broadcast.Timeout = func(*types.Timeout) {
		atomic.AddUint32(&broadcastCounter, 1)
	}

	timeout := types.Timeout{GapNumber: 450}
	tester.bfter.Timeout(peerID, &timeout)

	time.Sleep(50 * time.Millisecond)
	if int(atomic.LoadUint32(&handlerCounter)) != targetTimeout || int(atomic.LoadUint32(&broadcastCounter)) != 0 {
		t.Fatalf("count mismatch: have %v on handler, %v on broadcast, want %v", atomic.LoadUint32(&handlerCounter), atomic.LoadUint32(&broadcastCounter), targetTimeout)
	}
}

func TestBoardcastButNotProcessDisqualifiedSyncInfo(t *testing.T) {
	tester := newTester()
	handlerCounter := uint32(0)
	broadcastCounter := uint32(0)
	targetSyncInfo := 0

	tester.bfter.consensus.verifySyncInfo = func(chain consensus.ChainReader, syncInfo *types.SyncInfo) (bool, error) {
		return false, nil // return false but with nil in error means the message is valid but disqualified
	}

	tester.bfter.consensus.syncInfoHandler = func(chain consensus.ChainReader, syncInfo *types.SyncInfo) error {
		atomic.AddUint32(&handlerCounter, 1)
		return nil
	}
	tester.bfter.broadcast.SyncInfo = func(*types.SyncInfo) {
		atomic.AddUint32(&broadcastCounter, 1)
	}

	syncInfo := types.SyncInfo{HighestQuorumCert: &types.QuorumCert{ProposedBlockInfo: &types.BlockInfo{Number: big.NewInt(1350)}}}
	tester.bfter.SyncInfo(peerID, &syncInfo)

	time.Sleep(50 * time.Millisecond)
	if int(atomic.LoadUint32(&handlerCounter)) != targetSyncInfo || int(atomic.LoadUint32(&broadcastCounter)) != 0 {
		t.Fatalf("count mismatch: have %v on handler, %v on broadcast, want %v", atomic.LoadUint32(&handlerCounter), atomic.LoadUint32(&broadcastCounter), targetSyncInfo)
	}
}

func TestTimeoutHandler(t *testing.T) {
	tester := newTester()
	verifyCounter := uint32(0)
	handlerCounter := uint32(0)
	broadcastCounter := uint32(0)
	targetVotes := 1

	tester.bfter.consensus.verifyTimeout = func(consensus.ChainReader, *types.Timeout) (bool, error) {
		atomic.AddUint32(&verifyCounter, 1)
		return true, nil
	}

	tester.bfter.consensus.timeoutHandler = func(chain consensus.ChainReader, timeout *types.Timeout) error {
		atomic.AddUint32(&handlerCounter, 1)
		return nil
	}

	tester.bfter.broadcast.Timeout = func(*types.Timeout) {
		atomic.AddUint32(&broadcastCounter, 1)
	}

	timeoutMsg := &types.Timeout{GapNumber: 450}

	err := tester.bfter.Timeout(peerID, timeoutMsg)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(100 * time.Millisecond)

	if int(atomic.LoadUint32(&verifyCounter)) != targetVotes || int(atomic.LoadUint32(&handlerCounter)) != targetVotes || int(atomic.LoadUint32(&broadcastCounter)) != targetVotes {
		t.Fatalf("count mismatch: have %v on verify, %v on handler, %v on broadcast, want %v", atomic.LoadUint32(&verifyCounter), atomic.LoadUint32(&handlerCounter), atomic.LoadUint32(&broadcastCounter), targetVotes)
	}
}

func TestTimeoutHandlerRoundNotEqual(t *testing.T) {
	tester := newTester()

	tester.bfter.consensus.verifyTimeout = func(consensus.ChainReader, *types.Timeout) (bool, error) {
		return true, nil
	}

	tester.bfter.consensus.timeoutHandler = func(chain consensus.ChainReader, timeout *types.Timeout) error {
		return &utils.ErrIncomingMessageRoundNotEqualCurrentRound{
			Type:          "timeout",
			IncomingRound: types.Round(1),
			CurrentRound:  types.Round(2),
		}
	}

	tester.bfter.broadcast.Timeout = func(*types.Timeout) {}

	timeoutMsg := &types.Timeout{}

	err := tester.bfter.Timeout(peerID, timeoutMsg)
	assert.Equal(t, "timeout message round number: 1 does not match currentRound: 2", err.Error())
}

func TestSyncInfoHandler(t *testing.T) {
	tester := newTester()
	verifyCounter := uint32(0)
	handlerCounter := uint32(0)
	broadcastCounter := uint32(0)
	targetSyncInfo := 1

	tester.bfter.consensus.verifySyncInfo = func(chain consensus.ChainReader, syncInfo *types.SyncInfo) (bool, error) {
		atomic.AddUint32(&verifyCounter, 1)
		return true, nil // return false but with nil in error means the message is valid but disqualified
	}

	tester.bfter.consensus.syncInfoHandler = func(chain consensus.ChainReader, syncInfo *types.SyncInfo) error {
		atomic.AddUint32(&handlerCounter, 1)
		return nil
	}
	tester.bfter.broadcast.SyncInfo = func(*types.SyncInfo) {
		atomic.AddUint32(&broadcastCounter, 1)
	}

	syncInfo := types.SyncInfo{HighestQuorumCert: &types.QuorumCert{ProposedBlockInfo: &types.BlockInfo{Number: big.NewInt(1350)}}}
	tester.bfter.SyncInfo(peerID, &syncInfo)

	time.Sleep(50 * time.Millisecond)
	if int(atomic.LoadUint32(&verifyCounter)) != targetSyncInfo || int(atomic.LoadUint32(&handlerCounter)) != targetSyncInfo || int(atomic.LoadUint32(&broadcastCounter)) != 1 {
		t.Fatalf("count mismatch: have %v on verify, have %v on handler, %v on broadcast, want %v", atomic.LoadUint32(&verifyCounter), atomic.LoadUint32(&handlerCounter), atomic.LoadUint32(&broadcastCounter), targetSyncInfo)
	}
}

func TestTooFarVotes(t *testing.T) {
	tester := newTester()
	verifyCounter := uint32(0)
	handlerCounter := uint32(0)
	broadcastCounter := uint32(0)
	numberVotes := 10
	targetVotes := 0

	tester.bfter.consensus.verifyVote = func(chain consensus.ChainReader, vote *types.Vote) (bool, error) {
		atomic.AddUint32(&verifyCounter, 1)
		return true, nil
	}

	tester.bfter.consensus.voteHandler = func(chain consensus.ChainReader, vote *types.Vote) error {
		atomic.AddUint32(&handlerCounter, 1)
		return nil
	}

	tester.bfter.broadcast.Vote = func(*types.Vote) {
		atomic.AddUint32(&broadcastCounter, 1)
	}

	tester.bfter.chainHeight = func() uint64 { return 10000 }

	votes := makeVotes(numberVotes)
	for _, vote := range votes {
		err := tester.bfter.Vote(peerID, &vote)
		if err != nil {
			t.Fatal(err)
		}
	}

	time.Sleep(100 * time.Millisecond)
	if int(atomic.LoadUint32(&verifyCounter)) != targetVotes || int(atomic.LoadUint32(&handlerCounter)) != targetVotes || int(atomic.LoadUint32(&broadcastCounter)) != targetVotes {
		t.Fatalf("count mismatch: have %v on verify, %v on handler, %v on broadcast, want %v", atomic.LoadUint32(&verifyCounter), atomic.LoadUint32(&handlerCounter), atomic.LoadUint32(&broadcastCounter), targetVotes)
	}
}

func TestTooFarTimeout(t *testing.T) {
	tester := newTester()
	verifyCounter := uint32(0)
	handlerCounter := uint32(0)
	broadcastCounter := uint32(0)
	targetTimeout := 1

	tester.bfter.consensus.verifyTimeout = func(consensus.ChainReader, *types.Timeout) (bool, error) {
		atomic.AddUint32(&verifyCounter, 1)
		return true, nil
	}

	tester.bfter.consensus.timeoutHandler = func(chain consensus.ChainReader, timeout *types.Timeout) error {
		atomic.AddUint32(&handlerCounter, 1)
		return nil
	}

	tester.bfter.broadcast.Timeout = func(*types.Timeout) {
		atomic.AddUint32(&broadcastCounter, 1)
	}

	tester.bfter.chainHeight = func() uint64 { return 7175258 }

	timeoutMsg := &types.Timeout{GapNumber: 7173450}

	err := tester.bfter.Timeout(peerID, timeoutMsg)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(100 * time.Millisecond)

	if int(atomic.LoadUint32(&verifyCounter)) != targetTimeout || int(atomic.LoadUint32(&handlerCounter)) != targetTimeout || int(atomic.LoadUint32(&broadcastCounter)) != targetTimeout {
		t.Fatalf("count mismatch: have %v on verify, %v on handler, %v on broadcast, want %v", atomic.LoadUint32(&verifyCounter), atomic.LoadUint32(&handlerCounter), atomic.LoadUint32(&broadcastCounter), targetTimeout)
	}
}

func TestTooFarSyncInfo(t *testing.T) {
	tester := newTester()
	verifyCounter := uint32(0)
	handlerCounter := uint32(0)
	broadcastCounter := uint32(0)
	targetSyncInfo := 0

	tester.bfter.consensus.verifySyncInfo = func(chain consensus.ChainReader, syncInfo *types.SyncInfo) (bool, error) {
		atomic.AddUint32(&verifyCounter, 1)
		return true, nil // return false but with nil in error means the message is valid but disqualified
	}

	tester.bfter.consensus.syncInfoHandler = func(chain consensus.ChainReader, syncInfo *types.SyncInfo) error {
		atomic.AddUint32(&handlerCounter, 1)
		return nil
	}
	tester.bfter.broadcast.SyncInfo = func(*types.SyncInfo) {
		atomic.AddUint32(&broadcastCounter, 1)
	}

	syncInfo := types.SyncInfo{HighestQuorumCert: &types.QuorumCert{ProposedBlockInfo: &types.BlockInfo{Number: big.NewInt(100)}}}
	tester.bfter.SyncInfo(peerID, &syncInfo)

	time.Sleep(50 * time.Millisecond)
	if int(atomic.LoadUint32(&verifyCounter)) != targetSyncInfo || int(atomic.LoadUint32(&handlerCounter)) != targetSyncInfo || int(atomic.LoadUint32(&broadcastCounter)) != targetSyncInfo {
		t.Fatalf("count mismatch: have %v on verify, have %v on handler, %v on broadcast, want %v", atomic.LoadUint32(&verifyCounter), atomic.LoadUint32(&handlerCounter), atomic.LoadUint32(&broadcastCounter), targetSyncInfo)
	}
}

func TestVoteReturnsAfterBftStop(t *testing.T) {
	tester := newTester()
	tester.bfter.consensus.verifyVote = func(chain consensus.ChainReader, vote *types.Vote) (bool, error) {
		return true, nil
	}
	tester.bfter.consensus.voteHandler = func(chain consensus.ChainReader, vote *types.Vote) error {
		return nil
	}

	tester.bfter.Stop()

	vote := types.Vote{ProposedBlockInfo: &types.BlockInfo{Number: big.NewInt(1350)}}
	done := make(chan struct{})
	go func() {
		_ = tester.bfter.Vote(peerID, &vote)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("Vote blocks after bft loop is stopped")
	}
}

// TestVoteRejectsGapNumberOutsideWindow pins the DB-free gap gate: a vote whose
// GapNumber is far from the head must not reach verification, which would read
// a canonical header for that height.
func TestVoteRejectsGapNumberOutsideWindow(t *testing.T) {
	tester := newTester()
	verifyCounter := uint32(0)
	tester.bfter.consensus.verifyVote = func(chain consensus.ChainReader, vote *types.Vote) (bool, error) {
		atomic.AddUint32(&verifyCounter, 1)
		return true, nil
	}
	tester.bfter.consensus.voteHandler = func(chain consensus.ChainReader, vote *types.Vote) error {
		return nil
	}
	tester.bfter.broadcast.Vote = func(*types.Vote) {}

	vote := types.Vote{
		ProposedBlockInfo: &types.BlockInfo{Number: big.NewInt(1350)},
		Signature:         []byte{1},
		// newTester reports head 1351 and the configured epoch is 900, so this
		// is 1 past the epoch*3 window.
		GapNumber: 1351 + 2700 + 1,
	}
	if err := tester.bfter.Vote(peerID, &vote); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadUint32(&verifyCounter); n != 0 {
		t.Fatalf("verifyVote called %d times for an out-of-window gap number, want 0", n)
	}
}

// TestVoteRejectsOversizedBlockNumber covers the Int64 truncation: 2^64+1350
// used to compare as 1350 and pass the head±7 gate.
func TestVoteRejectsOversizedBlockNumber(t *testing.T) {
	tester := newTester()
	verifyCounter := uint32(0)
	tester.bfter.consensus.verifyVote = func(chain consensus.ChainReader, vote *types.Vote) (bool, error) {
		atomic.AddUint32(&verifyCounter, 1)
		return true, nil
	}
	tester.bfter.consensus.voteHandler = func(chain consensus.ChainReader, vote *types.Vote) error {
		return nil
	}
	tester.bfter.broadcast.Vote = func(*types.Vote) {}

	number := new(big.Int).Lsh(big.NewInt(1), 64)
	number.Add(number, big.NewInt(1350))
	vote := types.Vote{
		ProposedBlockInfo: &types.BlockInfo{Number: number},
		Signature:         []byte{1},
		GapNumber:         450,
	}
	if err := tester.bfter.Vote(peerID, &vote); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadUint32(&verifyCounter); n != 0 {
		t.Fatalf("verifyVote called %d times for a 2^64+1350 block number, want 0", n)
	}
}

// TestVoteGapNumberWindowLowerBound covers the lower half of the window: a gap
// number far below the head. newTester reports head 1351, which is inside the
// 2700 window, so the head has to be raised to reach the bound. Without this
// half, a peer could drive getSnapshot for gap blocks of long finished epochs
// and evict the live snapshot from the 128-entry LRU.
func TestVoteGapNumberWindowLowerBound(t *testing.T) {
	tester := newTester()
	tester.bfter.chainHeight = func() uint64 { return 100000 }

	for _, tc := range []struct {
		name string
		gap  uint64
		want uint32
	}{
		{"boundary inside", 100000 - 2700, 1},
		{"one past the boundary", 100000 - 2700 - 1, 0},
		{"gap block of a finished epoch", 450, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verifyCounter := uint32(0)
			tester.bfter.consensus.verifyVote = func(chain consensus.ChainReader, vote *types.Vote) (bool, error) {
				atomic.AddUint32(&verifyCounter, 1)
				return false, nil
			}

			vote := types.Vote{
				ProposedBlockInfo: &types.BlockInfo{Number: big.NewInt(100000)},
				Signature:         []byte{1},
				GapNumber:         tc.gap,
			}
			if err := tester.bfter.Vote(peerID, &vote); err != nil {
				t.Fatal(err)
			}
			if n := atomic.LoadUint32(&verifyCounter); n != tc.want {
				t.Fatalf("verifyVote called %d times, want %d", n, tc.want)
			}
		})
	}
}

// TestSyncInfoRejectsOversizedBlockNumber covers the same Int64 truncation on
// the QC block number: 2^64+1350 used to compare as 1350 and pass the head±7 gate.
func TestSyncInfoRejectsOversizedBlockNumber(t *testing.T) {
	tester := newTester()
	verifyCounter := uint32(0)
	tester.bfter.consensus.verifySyncInfo = func(chain consensus.ChainReader, syncInfo *types.SyncInfo) (bool, error) {
		atomic.AddUint32(&verifyCounter, 1)
		return false, nil
	}

	number := new(big.Int).Lsh(big.NewInt(1), 64)
	number.Add(number, big.NewInt(1350))
	syncInfo := types.SyncInfo{
		HighestQuorumCert: &types.QuorumCert{
			ProposedBlockInfo: &types.BlockInfo{Number: number},
		},
	}
	if err := tester.bfter.SyncInfo(peerID, &syncInfo); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadUint32(&verifyCounter); n != 0 {
		t.Fatalf("verifySyncInfo called %d times for a 2^64+1350 QC block number, want 0", n)
	}
}
