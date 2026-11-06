package eth

import (
	"context"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/tests/xdpos_test_utils"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	internalethapi "github.com/XinFinOrg/XDPoSChain/internal/ethapi"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rpc"
	"github.com/stretchr/testify/require"
)

// The candidate RPCs used to read the voting contract through the node's own IPC endpoint:
// eth_getCandidates and eth_getCandidateStatus fetched the candidate list and every candidate cap
// with an eth_call to themselves, so on a node started with --ipcdisable both RPCs failed outright
// instead of returning the data the state already holds.
//
// The chain below has no IPC endpoint at all, and the candidate list it must serve is laid out in
// the genesis state of the voting contract. The genesis also names the first candidate as a
// masternode, so the response has to return it under a different status than the other one: a
// candidate list read from the wrong state, or built without caps, cannot produce both.
type candidatesFixture struct {
	chain      *core.BlockChain
	db         ethdb.Database
	api        *internalethapi.BlockChainAPI
	candidates []common.Address
	caps       []*big.Int
}

func newCandidatesFixture(t *testing.T) *candidatesFixture {
	t.Helper()
	return newCandidatesFixtureWith(t,
		[]common.Address{{0x11}, {0x22}},
		[]*big.Int{big.NewInt(30), big.NewInt(10)},
	)
}

func newCandidatesFixtureWith(t *testing.T, candidates []common.Address, caps []*big.Int) *candidatesFixture {
	t.Helper()

	// An XDPoS checkpoint header carries its signers as vanity, the addresses, then the seal.
	extraData := make([]byte, 32)
	extraData = append(extraData, candidates[0].Bytes()...)
	extraData = append(extraData, make([]byte, crypto.SignatureLength)...)

	db := rawdb.NewMemoryDatabase()
	engine := XDPoS.NewFaker(db, params.TestXDPoSMockChainConfig)
	require.NotNil(t, engine)
	genesis := &core.Genesis{
		Config: params.TestXDPoSMockChainConfig,
		Alloc: types.GenesisAlloc{
			common.MasternodeVotingSMCBinary: {Storage: candidateStorage(candidates, caps)},
		},
		BaseFee:   big.NewInt(params.InitialBaseFee),
		ExtraData: extraData,
	}
	chain, err := core.NewBlockChain(db, nil, genesis, engine, vm.Config{})
	require.NoError(t, err)
	t.Cleanup(chain.Stop)

	backend := &EthAPIBackend{eth: &Ethereum{blockchain: chain, engine: engine}}
	// What the RPCs used to depend on, and what a node started with --ipcdisable cannot offer.
	_, err = backend.GetIPCClient()
	require.Error(t, err, "the fixture must model a node without an IPC endpoint")

	return &candidatesFixture{
		chain:      chain,
		db:         db,
		api:        internalethapi.NewBlockChainAPI(backend, chain),
		candidates: candidates,
		caps:       caps,
	}
}

func TestGetCandidatesDoesNotNeedAnIPCEndpoint(t *testing.T) {
	fixture := newCandidatesFixture(t)

	result, err := fixture.api.GetCandidates(context.Background(), rpc.LatestEpochNumber)
	require.NoError(t, err)
	require.Equal(t, true, result["success"])

	statuses, ok := result["candidates"].(map[string]map[string]interface{})
	require.True(t, ok, "the response must carry the candidate map, have %v", result)
	require.Len(t, statuses, len(fixture.candidates))
	require.Equal(t, "MASTERNODE", statuses[fixture.candidates[0].Hex()]["status"])
	require.Equal(t, fixture.caps[0], statuses[fixture.candidates[0].Hex()]["capacity"])
	require.Equal(t, "PROPOSED", statuses[fixture.candidates[1].Hex()]["status"])
	require.Equal(t, fixture.caps[1], statuses[fixture.candidates[1].Hex()]["capacity"])

	// eth_getCandidateStatus answers for one candidate off the same list.
	status, err := fixture.api.GetCandidateStatus(context.Background(), fixture.candidates[0], rpc.LatestEpochNumber)
	require.NoError(t, err)
	require.Equal(t, "MASTERNODE", status["status"])
	require.Equal(t, fixture.caps[0], status["capacity"])

	status, err = fixture.api.GetCandidateStatus(context.Background(), fixture.candidates[1], rpc.LatestEpochNumber)
	require.NoError(t, err)
	require.Equal(t, "PROPOSED", status["status"])
	require.Equal(t, fixture.caps[1], status["capacity"])
}

// Both RPCs pick the candidate list by epoch: the latest epoch reads the head state, an explicit
// epoch reads its checkpoint block. The chain here is one block past genesis, with the first
// candidate's cap changed in that block, so a response built from the wrong block returns 30 where
// 70 is expected, or the other way round.
func TestCandidateEpochsReadTheirOwnState(t *testing.T) {
	fixture := newCandidatesFixture(t)

	head := fixture.chain.CurrentBlock()
	headState, err := fixture.chain.StateAt(head.Root)
	require.NoError(t, err)
	xdpos_test_utils.SetCandidateCap(headState, fixture.candidates[0], big.NewInt(70))
	header := &types.Header{
		ParentHash: head.Hash(),
		Number:     big.NewInt(1),
		Root:       headState.IntermediateRoot(false),
		Time:       head.Time + 1,
		BaseFee:    big.NewInt(params.InitialBaseFee),
		Extra:      append(make([]byte, 32), make([]byte, crypto.SignatureLength)...),
	}
	_, err = fixture.chain.WriteBlockWithState(types.NewBlockWithHeader(header), nil, headState, nil, nil)
	require.NoError(t, err)
	require.Equal(t, uint64(1), fixture.chain.CurrentBlock().Number.Uint64())

	latest, err := fixture.api.GetCandidates(context.Background(), rpc.LatestEpochNumber)
	require.NoError(t, err)
	latestCandidates, ok := latest["candidates"].(map[string]map[string]interface{})
	require.True(t, ok, "the response must carry the candidate map, have %v", latest)
	require.Equal(t, big.NewInt(70), latestCandidates[fixture.candidates[0].Hex()]["capacity"])
	require.Equal(t, fixture.caps[1], latestCandidates[fixture.candidates[1].Hex()]["capacity"])

	checkpoint, err := fixture.api.GetCandidates(context.Background(), rpc.EpochNumber(1))
	require.NoError(t, err)
	checkpointCandidates, ok := checkpoint["candidates"].(map[string]map[string]interface{})
	require.True(t, ok, "the response must carry the candidate map, have %v", checkpoint)
	require.Equal(t, fixture.caps[0], checkpointCandidates[fixture.candidates[0].Hex()]["capacity"])
	require.Equal(t, fixture.caps[1], checkpointCandidates[fixture.candidates[1].Hex()]["capacity"])

	status, err := fixture.api.GetCandidateStatus(context.Background(), fixture.candidates[0], rpc.LatestEpochNumber)
	require.NoError(t, err)
	require.Equal(t, "MASTERNODE", status["status"])
	require.Equal(t, big.NewInt(70), status["capacity"])

	status, err = fixture.api.GetCandidateStatus(context.Background(), fixture.candidates[0], rpc.EpochNumber(1))
	require.NoError(t, err)
	require.Equal(t, "MASTERNODE", status["status"])
	require.Equal(t, fixture.caps[0], status["capacity"])
}

// A state that cannot serve the voting contract's storage must surface as an error: the state
// readers return zero values and memoize the failure in StateDB.Error(), so a list built from them
// would otherwise be reported as the chain's (empty or partial) candidate set.
func TestGetCandidatesSurfacesStateReadError(t *testing.T) {
	fixture := newCandidatesFixture(t)

	statedb, err := fixture.chain.StateAt(fixture.chain.CurrentBlock().Root)
	require.NoError(t, err)
	storageRoot := statedb.GetStorageRoot(common.MasternodeVotingSMCBinary)
	require.NotEqual(t, types.EmptyRootHash, storageRoot)
	require.NoError(t, fixture.db.Delete(storageRoot.Bytes()))

	result, err := fixture.api.GetCandidates(context.Background(), rpc.LatestEpochNumber)
	require.Error(t, err)
	require.Contains(t, err.Error(), "reading the candidates")
	require.Equal(t, false, result["success"])
}

// resign and invalidateMasternode delete a candidate from the contract's array without shrinking
// it, so the array keeps a zero entry where the candidate was. The state reader has to skip those
// entries the way the contract caller did: a list that kept them would report the zero address as
// a candidate with a zero cap.
func TestGetCandidatesSkipsZeroEntries(t *testing.T) {
	candidates := []common.Address{{0x11}, {}, {0x22}}
	caps := []*big.Int{big.NewInt(30), big.NewInt(0), big.NewInt(10)}
	fixture := newCandidatesFixtureWith(t, candidates, caps)

	result, err := fixture.api.GetCandidates(context.Background(), rpc.LatestEpochNumber)
	require.NoError(t, err)
	statuses, ok := result["candidates"].(map[string]map[string]interface{})
	require.True(t, ok, "the response must carry the candidate map, have %v", result)
	require.Len(t, statuses, 2)
	require.NotContains(t, statuses, common.Address{}.Hex())
	require.Equal(t, fixture.caps[0], statuses[fixture.candidates[0].Hex()]["capacity"])
	require.Equal(t, fixture.caps[2], statuses[fixture.candidates[2].Hex()]["capacity"])
}

// candidateStorage lays out the voting contract storage the candidate RPCs read: the candidates
// array (slot 8, its length in the slot itself and its elements after it) and the cap in
// ValidatorState of each candidate (validatorsState is slot 1, cap follows the address at offset
// 1, see CandidateCapSlot).
func candidateStorage(candidates []common.Address, caps []*big.Int) map[common.Hash]common.Hash {
	// core/state keeps the slot number in its private slotValidatorMapping (statedb_utils.go).
	candidatesSlot := common.BigToHash(big.NewInt(8))
	storage := map[common.Hash]common.Hash{
		candidatesSlot: common.BigToHash(new(big.Int).SetUint64(uint64(len(candidates)))),
	}
	for i, candidate := range candidates {
		storage[state.GetLocDynamicArrAtElement(candidatesSlot, uint64(i), 1)] = candidate.Hash()
		storage[xdpos_test_utils.CandidateCapSlot(candidate)] = common.BigToHash(caps[i])
	}
	return storage
}
