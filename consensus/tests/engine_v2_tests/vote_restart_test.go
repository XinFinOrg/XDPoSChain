package engine_v2_tests

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/accounts"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVotedRoundSurvivesRestart checks that the highest round a node voted in
// is kept across a restart: an engine rebuilt on the same database must not
// vote again in that round, and must still vote in later rounds.
func TestVotedRoundSurvivesRestart(t *testing.T) {
	t.Parallel()
	config := params.TestXDPoSMockChainConfig
	blockchain, _, currentBlock, signer, signFn, _ := PrepareXDCTestBlockChainForV2Engine(t, 906, config, nil)
	engineV2 := blockchain.Engine().(*XDPoS.XDPoS).EngineV2

	// Vote for block 906 in round 6.
	engineV2.SetNewRoundFaker(blockchain, types.Round(5), false)
	require.NoError(t, engineV2.ProposedBlockHandler(blockchain, currentBlock.Header()))
	vote := expectVote(t, engineV2.BroadcastCh, 5*time.Second)
	require.Equal(t, types.Round(6), vote.ProposedBlockInfo.Round)

	// Restart: a fresh engine on the same database, same signer.
	restarted := XDPoS.NewFaker(blockchain.ChainDb(), config)
	restarted.Authorize(signer, signFn)
	restartedV2 := restarted.EngineV2
	_, _, _, _, highestVotedRound, _ := restartedV2.GetPropertiesFaker()
	assert.Equal(t, types.Round(6), highestVotedRound, "restarted engine must load the voted round")

	// The same proposal in the same round must not get a second vote.
	restartedV2.SetNewRoundFaker(blockchain, types.Round(5), false)
	require.NoError(t, restartedV2.ProposedBlockHandler(blockchain, currentBlock.Header()))
	expectNoVote(t, restartedV2.BroadcastCh, time.Second)

	// A proposal in the next round is voted for as usual.
	blockNum := 907
	block907 := CreateBlock(blockchain, config, currentBlock, blockNum, 7, fmt.Sprintf("0x111000000000000000000000000000000%03d", blockNum), signer, signFn, nil, nil, "")
	require.NoError(t, blockchain.InsertBlock(block907))
	require.NoError(t, restartedV2.ProposedBlockHandler(blockchain, block907.Header()))
	vote = expectVote(t, restartedV2.BroadcastCh, 5*time.Second)
	require.Equal(t, types.Round(7), vote.ProposedBlockInfo.Round)
	require.Equal(t, block907.Hash(), vote.ProposedBlockInfo.Hash)
}

// keyRecorder captures the key of a single write.
type keyRecorder struct{ key []byte }

func (r *keyRecorder) Put(key []byte, value []byte) error {
	r.key = common.CopyBytes(key)
	return nil
}

func (r *keyRecorder) Delete(key []byte) error { return nil }

// votedRoundDB fails every write of the voted round with putErr, if set.
type votedRoundDB struct {
	ethdb.Database
	key    []byte
	putErr error
}

func (db *votedRoundDB) Put(key []byte, value []byte) error {
	if db.putErr != nil && bytes.Equal(key, db.key) {
		return db.putErr
	}
	return db.Database.Put(key, value)
}

// TestVotedRoundWrittenBeforeVote checks that sendVote stores the voted round
// before it signs the vote, and that a node whose write fails neither signs,
// keeps nor broadcasts a vote. The failing case runs first, while the shared
// chain database holds no voted round.
func TestVotedRoundWrittenBeforeVote(t *testing.T) {
	t.Parallel()
	config := params.TestXDPoSMockChainConfig
	blockchain, _, currentBlock, signer, signFn, _ := PrepareXDCTestBlockChainForV2Engine(t, 906, config, nil)

	rec := &keyRecorder{}
	require.NoError(t, rawdb.WriteXdposV2HighestVotedRound(rec, 0))
	require.NotEmpty(t, rec.key)

	// newEngine builds an engine on db whose signer records, per signed hash,
	// the voted round stored in db at the time of signing.
	newEngine := func(db *votedRoundDB) (*XDPoS.XDPoS, map[common.Hash]uint64, *sync.Mutex) {
		var mu sync.Mutex
		storedAtSign := map[common.Hash]uint64{}
		engine := XDPoS.NewFaker(db, config)
		engine.Authorize(signer, func(account accounts.Account, hash []byte) ([]byte, error) {
			mu.Lock()
			storedAtSign[common.BytesToHash(hash)] = rawdb.ReadXdposV2HighestVotedRound(db)
			mu.Unlock()
			return signFn(account, hash)
		})
		return engine, storedAtSign, &mu
	}

	t.Run("write fails", func(t *testing.T) {
		db := &votedRoundDB{Database: blockchain.ChainDb(), key: rec.key, putErr: errors.New("disk full")}
		engine, storedAtSign, mu := newEngine(db)
		engineV2 := engine.EngineV2
		engineV2.SetNewRoundFaker(blockchain, types.Round(5), false)
		require.Error(t, engineV2.ProposedBlockHandler(blockchain, currentBlock.Header()), "a vote whose round cannot be stored must fail")
		expectNoVote(t, engineV2.BroadcastCh, time.Second)
		_, _, _, _, highestVotedRound, _ := engineV2.GetPropertiesFaker()
		assert.Equal(t, types.Round(0), highestVotedRound, "a failed vote must not advance the voted round")
		mu.Lock()
		signed := len(storedAtSign)
		mu.Unlock()
		assert.Zero(t, signed, "a vote whose round cannot be stored must not be signed")
	})

	t.Run("write succeeds", func(t *testing.T) {
		db := &votedRoundDB{Database: blockchain.ChainDb(), key: rec.key}
		engine, storedAtSign, mu := newEngine(db)
		engineV2 := engine.EngineV2
		engineV2.SetNewRoundFaker(blockchain, types.Round(5), false)
		require.NoError(t, engineV2.ProposedBlockHandler(blockchain, currentBlock.Header()))
		vote := expectVote(t, engineV2.BroadcastCh, 5*time.Second)
		require.Equal(t, types.Round(6), vote.ProposedBlockInfo.Round)
		voteHash := types.VoteSigHash(&types.VoteForSign{ProposedBlockInfo: vote.ProposedBlockInfo, GapNumber: vote.GapNumber})
		mu.Lock()
		stored, signed := storedAtSign[voteHash]
		mu.Unlock()
		require.True(t, signed, "the vote must be signed by the engine's signer")
		assert.Equal(t, uint64(6), stored, "the voted round must be stored before the vote is signed")
	})
}
