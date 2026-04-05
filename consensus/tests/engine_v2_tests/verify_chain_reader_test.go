package engine_v2_tests

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/stretchr/testify/assert"
)

func TestVerifyEpochSwitchHeadersWithBatchReader(t *testing.T) {
	b, err := json.Marshal(params.TestXDPoSMockChainConfig)
	assert.Nil(t, err)
	configString := string(b)

	var config params.ChainConfig
	err = json.Unmarshal([]byte(configString), &config)
	assert.Nil(t, err)

	epochSwitchNumber := int(config.XDPoS.Epoch) * 2
	blockchain, _, currentBlock, signer, signFn, _ := PrepareXDCTestBlockChainForV2Engine(t, epochSwitchNumber-2, &config, nil)
	adaptor := blockchain.Engine().(*XDPoS.XDPoS)

	parentBlockNumber := epochSwitchNumber - 1
	parentRound := int64(parentBlockNumber) - config.XDPoS.V2.SwitchBlock.Int64()
	parentBlock := CreateBlock(blockchain, &config, currentBlock, parentBlockNumber, parentRound, signer.Hex(), signer, signFn, nil, nil, "")

	candidates, err := adaptor.EngineV2.GetSignersFromSnapshot(blockchain, &types.Header{Number: big.NewInt(int64(epochSwitchNumber))})
	assert.Nil(t, err)
	epochSwitchRound := int64(config.XDPoS.Epoch)
	maxMasternodes := config.XDPoS.V2.Config(uint64(epochSwitchRound)).MaxMasternodes
	if len(candidates) > maxMasternodes {
		candidates = candidates[:maxMasternodes]
	}
	validators := make([]byte, 0, len(candidates)*common.AddressLength)
	for _, candidate := range candidates {
		validators = append(validators, candidate[:]...)
	}
	leaderIndex := -1
	leader := common.Address{}
	leaderSignFn := signFn
	for i, candidate := range candidates {
		switch candidate {
		case acc1Addr:
			leaderIndex = i
			leader = candidate
			_, leaderSignFn, err = getSignerAndSignFn(acc1Key)
		case acc2Addr:
			leaderIndex = i
			leader = candidate
			_, leaderSignFn, err = getSignerAndSignFn(acc2Key)
		case acc3Addr:
			leaderIndex = i
			leader = candidate
			_, leaderSignFn, err = getSignerAndSignFn(acc3Key)
		case voterAddr:
			leaderIndex = i
			leader = candidate
			_, leaderSignFn, err = getSignerAndSignFn(voterKey)
		case signer:
			leaderIndex = i
			leader = candidate
			leaderSignFn = signFn
		}
		if leaderIndex >= 0 {
			epochSwitchRound += int64(i)
			break
		}
	}
	if leaderIndex < 0 {
		t.Fatal("snapshot candidates do not include a signer with a known test key")
	}
	assert.Nil(t, err)
	epochSwitchHeader := &types.Header{
		ParentHash:  parentBlock.Hash(),
		UncleHash:   types.EmptyUncleHash,
		TxHash:      types.EmptyRootHash,
		ReceiptHash: types.EmptyRootHash,
		Root:        common.HexToHash("35999dded35e8db12de7e6c1471eb9670c162eec616ecebbaf4fddd4676fb930"),
		Coinbase:    leader,
		Difficulty:  big.NewInt(1),
		Number:      big.NewInt(int64(epochSwitchNumber)),
		GasLimit:    1200000000,
		Time:        big.NewInt(time.Now().Unix() - 1000000 + int64(epochSwitchNumber*10)),
		Extra:       generateV2Extra(epochSwitchRound, parentBlock, leader, leaderSignFn, nil),
		Validators:  validators,
	}
	sealHeader(blockchain, epochSwitchHeader, leader, leaderSignFn)
	epochSwitchBlock := types.NewBlockWithHeader(epochSwitchHeader)

	adaptor.EngineV2.HookPenalty = func(chain consensus.ChainReader, number *big.Int, parentHash common.Hash, candidates []common.Address) ([]common.Address, error) {
		parentNumber := number.Uint64() - 1
		byHashAndNumber := chain.GetHeader(parentHash, parentNumber)
		if byHashAndNumber == nil {
			return nil, fmt.Errorf("missing parent header by hash and number: %d", parentNumber)
		}
		byHash := chain.GetHeaderByHash(parentHash)
		if byHash == nil {
			return nil, fmt.Errorf("missing parent header by hash: %d", parentNumber)
		}
		byNumber := chain.GetHeaderByNumber(parentNumber)
		if byNumber == nil {
			return nil, fmt.Errorf("missing parent header by number: %d", parentNumber)
		}
		if byHash.Hash() != parentHash || byNumber.Hash() != parentHash || byHashAndNumber.Hash() != parentHash {
			return nil, fmt.Errorf("batch parent header lookup returned unexpected header: got %s %s %s want %s", byHashAndNumber.Hash(), byHash.Hash(), byNumber.Hash(), parentHash)
		}
		return nil, nil
	}

	headersToVerify := []*types.Header{parentBlock.Header(), epochSwitchBlock.Header()}
	fullVerifies := []bool{true, true}
	_, results := adaptor.VerifyHeaders(blockchain, headersToVerify, fullVerifies)

	for _, header := range headersToVerify {
		select {
		case result := <-results:
			assert.Nil(t, result, "header %d should verify with batch-visible parent lookup", header.Number.Uint64())
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out while verifying header %d", header.Number.Uint64())
		}
	}
}

func TestInsertHeaderChainWithBatchReader(t *testing.T) {
	b, err := json.Marshal(params.TestXDPoSMockChainConfig)
	assert.Nil(t, err)
	configString := string(b)

	var config params.ChainConfig
	err = json.Unmarshal([]byte(configString), &config)
	assert.Nil(t, err)

	epochSwitchNumber := int(config.XDPoS.Epoch) * 2
	blockchain, _, currentBlock, signer, signFn, _ := PrepareXDCTestBlockChainForV2Engine(t, epochSwitchNumber-2, &config, nil)
	adaptor := blockchain.Engine().(*XDPoS.XDPoS)

	parentBlockNumber := epochSwitchNumber - 1
	parentRound := int64(parentBlockNumber) - config.XDPoS.V2.SwitchBlock.Int64()
	parentBlock := CreateBlock(blockchain, &config, currentBlock, parentBlockNumber, parentRound, signer.Hex(), signer, signFn, nil, nil, "")

	candidates, err := adaptor.EngineV2.GetSignersFromSnapshot(blockchain, &types.Header{Number: big.NewInt(int64(epochSwitchNumber))})
	assert.Nil(t, err)
	epochSwitchRound := int64(config.XDPoS.Epoch)
	maxMasternodes := config.XDPoS.V2.Config(uint64(epochSwitchRound)).MaxMasternodes
	if len(candidates) > maxMasternodes {
		candidates = candidates[:maxMasternodes]
	}
	validators := make([]byte, 0, len(candidates)*common.AddressLength)
	for _, candidate := range candidates {
		validators = append(validators, candidate[:]...)
	}
	leaderIndex := -1
	leader := common.Address{}
	leaderSignFn := signFn
	for i, candidate := range candidates {
		switch candidate {
		case acc1Addr:
			leaderIndex = i
			leader = candidate
			_, leaderSignFn, err = getSignerAndSignFn(acc1Key)
		case acc2Addr:
			leaderIndex = i
			leader = candidate
			_, leaderSignFn, err = getSignerAndSignFn(acc2Key)
		case acc3Addr:
			leaderIndex = i
			leader = candidate
			_, leaderSignFn, err = getSignerAndSignFn(acc3Key)
		case voterAddr:
			leaderIndex = i
			leader = candidate
			_, leaderSignFn, err = getSignerAndSignFn(voterKey)
		case signer:
			leaderIndex = i
			leader = candidate
			leaderSignFn = signFn
		}
		if leaderIndex >= 0 {
			epochSwitchRound += int64(i)
			break
		}
	}
	if leaderIndex < 0 {
		t.Fatal("snapshot candidates do not include a signer with a known test key")
	}
	assert.Nil(t, err)
	epochSwitchHeader := &types.Header{
		ParentHash:  parentBlock.Hash(),
		UncleHash:   types.EmptyUncleHash,
		TxHash:      types.EmptyRootHash,
		ReceiptHash: types.EmptyRootHash,
		Root:        common.HexToHash("35999dded35e8db12de7e6c1471eb9670c162eec616ecebbaf4fddd4676fb930"),
		Coinbase:    leader,
		Difficulty:  big.NewInt(1),
		Number:      big.NewInt(int64(epochSwitchNumber)),
		GasLimit:    1200000000,
		Time:        big.NewInt(time.Now().Unix() - 1000000 + int64(epochSwitchNumber*10)),
		Extra:       generateV2Extra(epochSwitchRound, parentBlock, leader, leaderSignFn, nil),
		Validators:  validators,
	}
	sealHeader(blockchain, epochSwitchHeader, leader, leaderSignFn)

	adaptor.EngineV2.HookPenalty = func(chain consensus.ChainReader, number *big.Int, parentHash common.Hash, candidates []common.Address) ([]common.Address, error) {
		parentNumber := number.Uint64() - 1
		if chain.GetHeader(parentHash, parentNumber) == nil {
			return nil, fmt.Errorf("missing parent header by hash and number: %d", parentNumber)
		}
		if chain.GetHeaderByHash(parentHash) == nil {
			return nil, fmt.Errorf("missing parent header by hash: %d", parentNumber)
		}
		if chain.GetHeaderByNumber(parentNumber) == nil {
			return nil, fmt.Errorf("missing parent header by number: %d", parentNumber)
		}
		return nil, nil
	}

	headersToInsert := []*types.Header{parentBlock.Header(), epochSwitchHeader}
	_, err = blockchain.InsertHeaderChain(headersToInsert, 1)
	assert.Nil(t, err, "header-only import should see in-batch parent headers")
}
