// Copyright 2023 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package ethapi

import (
	"context"
	"encoding/json"
	"errors"
	"hash"
	"math/big"
	"strings"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/XDCx"
	"github.com/XinFinOrg/XDPoSChain/XDCx/tradingstate"
	"github.com/XinFinOrg/XDPoSChain/accounts"
	"github.com/XinFinOrg/XDPoSChain/accounts/keystore"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/hexutil"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/crypto/keccak"
	"github.com/XinFinOrg/XDPoSChain/eth/downloader"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/internal/ethapi/override"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rpc"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

// testHasher is the helper tool for transaction/receipt list hashing.
// The original hasher is trie, in order to get rid of import cycle,
// use the testing hasher instead.
type testHasher struct {
	hasher hash.Hash
}

func newHasher() *testHasher {
	return &testHasher{hasher: keccak.NewLegacyKeccak256()}
}

func (h *testHasher) Reset() {
	h.hasher.Reset()
}

func (h *testHasher) Update(key, val []byte) error {
	h.hasher.Write(key)
	h.hasher.Write(val)
	return nil
}

func (h *testHasher) Hash() common.Hash {
	return common.BytesToHash(h.hasher.Sum(nil))
}

func TestRPCMarshalBlock(t *testing.T) {
	var (
		txs []*types.Transaction
		to  = common.BytesToAddress([]byte{0x11})
	)
	for i := uint64(1); i <= 4; i++ {
		var tx *types.Transaction
		if i%2 == 0 {
			tx = types.NewTx(&types.LegacyTx{
				Nonce:    i,
				GasPrice: big.NewInt(11111),
				Gas:      1111,
				To:       &to,
				Value:    big.NewInt(111),
				Data:     []byte{0x11, 0x11, 0x11},
			})
		} else {
			tx = types.NewTx(&types.AccessListTx{
				ChainID:  big.NewInt(1337),
				Nonce:    i,
				GasPrice: big.NewInt(11111),
				Gas:      1111,
				To:       &to,
				Value:    big.NewInt(111),
				Data:     []byte{0x11, 0x11, 0x11},
			})
		}
		txs = append(txs, tx)
	}
	block := types.NewBlock(&types.Header{Number: big.NewInt(100)}, &types.Body{Transactions: txs}, nil, newHasher())

	var testSuite = []struct {
		inclTx bool
		fullTx bool
		want   string
	}{
		// without txs
		{
			inclTx: false,
			fullTx: false,
			want: `{
				"difficulty":"0x0",
				"extraData":"0x",
				"gasLimit":"0x0",
				"gasUsed":"0x0",
				"hash":"0x2cb4e4b5b5be5a2520377e87e8d7d2cf83fc0783fa6518d67b9606d3c5317b50",
				"logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				"miner":"0x0000000000000000000000000000000000000000",
				"mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
				"nonce":"0x0000000000000000",
				"number":"0x64",
				"parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
				"penalties":"0x",
				"receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
				"sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
				"size":"0x299",
				"stateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000",
				"timestamp":"0x0",
				"transactionsRoot":"0x661a9febcfa8f1890af549b874faf9fa274aede26ef489d9db0b25daa569450e",
				"uncles":[],
				"validator":"0x",
				"validators":"0x"
			}`,
		},
		// only tx hashes
		{
			inclTx: true,
			fullTx: false,
			want: `{
				"difficulty":"0x0",
				"extraData":"0x",
				"gasLimit":"0x0",
				"gasUsed":"0x0",
				"hash":"0x2cb4e4b5b5be5a2520377e87e8d7d2cf83fc0783fa6518d67b9606d3c5317b50",
				"logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				"miner":"0x0000000000000000000000000000000000000000",
				"mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
				"nonce":"0x0000000000000000",
				"number":"0x64",
				"parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
				"penalties":"0x",
				"receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
				"sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
				"size":"0x299",
				"stateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000",
				"timestamp":"0x0",
				"transactions": [
					"0x7d39df979e34172322c64983a9ad48302c2b889e55bda35324afecf043a77605",
					"0x9bba4c34e57c875ff57ac8d172805a26ae912006985395dc1bdf8f44140a7bf4",
					"0x98909ea1ff040da6be56bc4231d484de1414b3c1dac372d69293a4beb9032cb5",
					"0x12e1f81207b40c3bdcc13c0ee18f5f86af6d31754d57a0ea1b0d4cfef21abef1"
				],
				"transactionsRoot":"0x661a9febcfa8f1890af549b874faf9fa274aede26ef489d9db0b25daa569450e",
				"uncles":[],
				"validator":"0x",
				"validators":"0x"
			}`,
		},

		// full tx details
		{
			inclTx: true,
			fullTx: true,
			want: `{
				"difficulty":"0x0",
				"extraData":"0x",
				"gasLimit":"0x0",
				"gasUsed":"0x0",
				"hash":"0x2cb4e4b5b5be5a2520377e87e8d7d2cf83fc0783fa6518d67b9606d3c5317b50",
				"logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				"miner":"0x0000000000000000000000000000000000000000",
				"mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
				"nonce":"0x0000000000000000",
				"number":"0x64",
				"parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
				"penalties":"0x",
				"receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
				"sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
				"size":"0x299",
				"stateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000",
				"timestamp":"0x0",
				"transactions": [
					{
						"blockHash":"0x2cb4e4b5b5be5a2520377e87e8d7d2cf83fc0783fa6518d67b9606d3c5317b50",
						"blockNumber":"0x64",
						"from":"0x0000000000000000000000000000000000000000",
						"gas":"0x457",
						"gasPrice":"0x2b67",
						"hash":"0x7d39df979e34172322c64983a9ad48302c2b889e55bda35324afecf043a77605",
						"input":"0x111111",
						"nonce":"0x1",
						"to":"0x0000000000000000000000000000000000000011",
						"transactionIndex":"0x0",
						"value":"0x6f",
						"type":"0x1",
						"accessList":[],
						"chainId":"0x539",
						"v":"0x0",
						"r":"0x0",
						"s":"0x0",
						"yParity":"0x0"
					},
					{
						"blockHash":"0x2cb4e4b5b5be5a2520377e87e8d7d2cf83fc0783fa6518d67b9606d3c5317b50",
						"blockNumber":"0x64",
						"from":"0x0000000000000000000000000000000000000000",
						"gas":"0x457",
						"gasPrice":"0x2b67",
						"hash":"0x9bba4c34e57c875ff57ac8d172805a26ae912006985395dc1bdf8f44140a7bf4",
						"input":"0x111111",
						"nonce":"0x2",
						"to":"0x0000000000000000000000000000000000000011",
						"transactionIndex":"0x1",
						"value":"0x6f",
						"type":"0x0",
						"chainId":"0x7fffffffffffffee",
						"v":"0x0",
						"r":"0x0",
						"s":"0x0"
					},
					{
						"blockHash":"0x2cb4e4b5b5be5a2520377e87e8d7d2cf83fc0783fa6518d67b9606d3c5317b50",
						"blockNumber":"0x64",
						"from":"0x0000000000000000000000000000000000000000",
						"gas":"0x457",
						"gasPrice":"0x2b67",
						"hash":"0x98909ea1ff040da6be56bc4231d484de1414b3c1dac372d69293a4beb9032cb5",
						"input":"0x111111",
						"nonce":"0x3",
						"to":"0x0000000000000000000000000000000000000011",
						"transactionIndex":"0x2",
						"value":"0x6f",
						"type":"0x1",
						"accessList":[],
						"chainId":"0x539",
						"v":"0x0",
						"r":"0x0",
						"s":"0x0",
						"yParity":"0x0"
					},
					{
						"blockHash":"0x2cb4e4b5b5be5a2520377e87e8d7d2cf83fc0783fa6518d67b9606d3c5317b50",
						"blockNumber":"0x64",
						"from":"0x0000000000000000000000000000000000000000",
						"gas":"0x457",
						"gasPrice":"0x2b67",
						"hash":"0x12e1f81207b40c3bdcc13c0ee18f5f86af6d31754d57a0ea1b0d4cfef21abef1",
						"input":"0x111111",
						"nonce":"0x4",
						"to":"0x0000000000000000000000000000000000000011",
						"transactionIndex":"0x3",
						"value":"0x6f",
						"type":"0x0",
						"chainId":"0x7fffffffffffffee",
						"v":"0x0",
						"r":"0x0",
						"s":"0x0"
					}
				],
				"transactionsRoot":"0x661a9febcfa8f1890af549b874faf9fa274aede26ef489d9db0b25daa569450e",
				"uncles":[],
				"validator":"0x",
				"validators":"0x"
			}`,
		},
	}

	for i, tc := range testSuite {
		resp := RPCMarshalBlock(block, tc.inclTx, tc.fullTx, params.MainnetChainConfig)
		out, err := json.Marshal(resp)
		if err != nil {
			t.Errorf("test %d: json marshal error: %v", i, err)
			continue
		}
		require.JSONEqf(t, tc.want, string(out), "test %d", i)
	}
}

type testEngine struct{}

func (testEngine) Author(header *types.Header) (common.Address, error) { return header.Coinbase, nil }

func (testEngine) VerifyHeader(consensus.ChainReader, *types.Header, bool) error { return nil }

func (testEngine) VerifyHeaders(consensus.ChainReader, []*types.Header, []bool) (chan<- struct{}, <-chan error) {
	quit := make(chan struct{})
	results := make(chan error)
	close(results)
	return quit, results
}

func (testEngine) VerifyUncles(consensus.ChainReader, *types.Block) error { return nil }

func (testEngine) VerifySeal(consensus.ChainReader, *types.Header) error { return nil }

func (testEngine) Prepare(consensus.ChainReader, *types.Header) error { return nil }

func (testEngine) Finalize(consensus.ChainReader, *types.Header, vm.StateDB, *state.StateDB, []*types.Transaction, []*types.Header, []*types.Receipt) (*types.Block, error) {
	return nil, nil
}

func (testEngine) Seal(consensus.ChainReader, *types.Block, <-chan struct{}) (*types.Block, error) {
	return nil, nil
}

func (testEngine) CalcDifficulty(consensus.ChainReader, uint64, *types.Header) *big.Int {
	return big.NewInt(0)
}

func (testEngine) APIs(consensus.ChainReader) []rpc.API { return nil }

type storageBackendMock struct {
	*backendMock
	stateDB *state.StateDB
	header  *types.Header
	err     error
	reward  map[string]map[string]map[string]*big.Int
}

func (b *storageBackendMock) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	if b.err != nil {
		return nil, nil, b.err
	}
	return b.stateDB, b.header, nil
}

func (b *storageBackendMock) Engine() consensus.Engine { return testEngine{} }

func (b *storageBackendMock) HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error) {
	if b.header == nil {
		return nil, b.err
	}
	return b.header, nil
}

func (b *storageBackendMock) GetRewardByHash(hash common.Hash) map[string]map[string]map[string]*big.Int {
	return b.reward
}

func TestGetStorageValues(t *testing.T) {
	t.Parallel()

	var (
		addr1 = common.HexToAddress("0x1111")
		addr2 = common.HexToAddress("0x2222")
		slot0 = common.Hash{}
		slot1 = common.BigToHash(big.NewInt(1))
		slot2 = common.BigToHash(big.NewInt(2))
		val0  = common.BigToHash(big.NewInt(42))
		val1  = common.BigToHash(big.NewInt(100))
		val2  = common.BigToHash(big.NewInt(200))

		genesis = &core.Genesis{
			Config: params.MergedTestChainConfig,
			Alloc: types.GenesisAlloc{
				addr1: {
					Balance: big.NewInt(params.Ether),
					Storage: map[common.Hash]common.Hash{
						slot0: val0,
						slot1: val1,
					},
				},
				addr2: {
					Balance: big.NewInt(params.Ether),
					Storage: map[common.Hash]common.Hash{
						slot2: val2,
					},
				},
			},
		}
	)
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	backend := &storageBackendMock{
		backendMock: newBackendMock(),
		stateDB:     stateDB,
		header:      block.Header(),
	}
	api := NewBlockChainAPI(backend, nil)
	latest := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)

	// Happy path: multiple addresses, multiple slots.
	result, err := api.GetStorageValues(context.Background(), map[common.Address][]common.Hash{
		addr1: {slot0, slot1},
		addr2: {slot2},
	}, latest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 addresses in result, got %d", len(result))
	}
	if got := common.BytesToHash(result[addr1][0]); got != val0 {
		t.Errorf("addr1 slot0: want %x, got %x", val0, got)
	}
	if got := common.BytesToHash(result[addr1][1]); got != val1 {
		t.Errorf("addr1 slot1: want %x, got %x", val1, got)
	}
	if got := common.BytesToHash(result[addr2][0]); got != val2 {
		t.Errorf("addr2 slot2: want %x, got %x", val2, got)
	}

	// Missing slot returns zero.
	result, err = api.GetStorageValues(context.Background(), map[common.Address][]common.Hash{
		addr1: {common.HexToHash("0xff")},
	}, latest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := common.BytesToHash(result[addr1][0]); got != (common.Hash{}) {
		t.Errorf("missing slot: want zero, got %x", got)
	}

	// Empty slot list for an address is treated as an empty request.
	_, err = api.GetStorageValues(context.Background(), map[common.Address][]common.Hash{
		addr1: {},
	}, latest)
	if err == nil {
		t.Fatal("expected error for empty slot list request")
	}
	var invalidReqErr *invalidParamsError
	if !errors.As(err, &invalidReqErr) {
		t.Fatalf("expected invalidParamsError for empty slot list request, got %T (%v)", err, err)
	}
	if invalidReqErr.message != "empty request" {
		t.Fatalf("unexpected invalid request message: %q", invalidReqErr.message)
	}

	// Empty request returns error.
	_, err = api.GetStorageValues(context.Background(), map[common.Address][]common.Hash{}, latest)
	if err == nil {
		t.Fatal("expected error for empty request")
	}
	invalidReqErr = nil
	if !errors.As(err, &invalidReqErr) {
		t.Fatalf("expected invalidParamsError for empty request, got %T (%v)", err, err)
	}
	if invalidReqErr.message != "empty request" {
		t.Fatalf("unexpected invalid request message: %q", invalidReqErr.message)
	}

	// Exceeding slot limit returns error.
	tooMany := make([]common.Hash, maxGetStorageSlots+1)
	for i := range tooMany {
		tooMany[i] = common.BigToHash(big.NewInt(int64(i)))
	}
	_, err = api.GetStorageValues(context.Background(), map[common.Address][]common.Hash{
		addr1: tooMany,
	}, latest)
	if err == nil {
		t.Fatal("expected error for exceeding slot limit")
	}
	var limitErr *clientLimitExceededError
	if !errors.As(err, &limitErr) {
		t.Fatalf("expected clientLimitExceededError for too many slots, got %T (%v)", err, err)
	}
	if limitErr.message == "" {
		t.Fatal("expected non-empty limit exceeded message")
	}
	if !strings.Contains(limitErr.message, "too many slots") {
		t.Fatalf("unexpected limit exceeded message: %q", limitErr.message)
	}

	// Backend/state lookup failure should be propagated.
	backend.err = errors.New("state unavailable")
	_, err = api.GetStorageValues(context.Background(), map[common.Address][]common.Hash{
		addr1: {slot0},
	}, latest)
	if err == nil || err.Error() != "state unavailable" {
		t.Fatalf("expected state unavailable error, got %v", err)
	}

	// Nil state with nil error follows current API behavior and returns nil, nil.
	backend.err = nil
	backend.stateDB = nil
	result, err = api.GetStorageValues(context.Background(), map[common.Address][]common.Hash{
		addr1: {slot0},
	}, latest)
	if err != nil {
		t.Fatalf("unexpected error for nil state behavior: %v", err)
	}
	if result != nil {
		t.Fatalf("expected nil result for nil state behavior, got %v", result)
	}
}

func TestDoEstimateGasRespectsBlockOverrideGasLimit(t *testing.T) {
	t.Parallel()

	var (
		from    = common.HexToAddress("0x1001")
		to      = common.HexToAddress("0x1002")
		cap     = hexutil.Uint64(20000)
		genesis = &core.Genesis{
			Config: params.MergedTestChainConfig,
			Alloc: types.GenesisAlloc{
				from: {Balance: big.NewInt(params.Ether)},
			},
		}
	)
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}
	header := types.CopyHeader(block.Header())
	header.GasLimit = 30000

	backend := &storageBackendMock{
		backendMock: newBackendMock(),
		stateDB:     stateDB,
		header:      header,
	}
	args := TransactionArgs{From: &from, To: &to}
	_, err = DoEstimateGas(
		context.Background(),
		backend,
		args,
		rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber),
		nil,
		&override.BlockOverrides{GasLimit: &cap},
		0,
	)
	if err == nil {
		t.Fatal("expected gas estimation to fail when block override gas limit is below intrinsic gas")
	}
	require.ErrorContains(t, err, "gas required exceeds allowance (20000)")
}

func TestTransaction_RoundTripRpcJSON(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	require.NoError(t, err)

	config := params.TestChainConfig
	signer := types.LatestSigner(config)
	to := common.Address{0xde, 0xad}

	testCases := []types.TxData{
		&types.LegacyTx{
			Nonce:    5,
			GasPrice: big.NewInt(6),
			Gas:      21000,
			To:       &to,
			Value:    big.NewInt(8),
			Data:     []byte{0, 1, 2, 3, 4},
		},
		&types.AccessListTx{
			ChainID:  config.ChainID,
			Nonce:    6,
			GasPrice: big.NewInt(7),
			Gas:      30000,
			To:       &to,
			Value:    big.NewInt(9),
			Data:     []byte{5, 6, 7},
			AccessList: types.AccessList{
				{Address: common.Address{0x2}, StorageKeys: []common.Hash{types.EmptyRootHash}},
			},
		},
		&types.DynamicFeeTx{
			ChainID:    config.ChainID,
			Nonce:      7,
			GasTipCap:  big.NewInt(2),
			GasFeeCap:  big.NewInt(20),
			Gas:        32000,
			To:         nil,
			Value:      big.NewInt(10),
			Data:       []byte{8, 9, 10},
			AccessList: types.AccessList{},
		},
	}

	for i, txdata := range testCases {
		tx, err := types.SignNewTx(key, signer, txdata)
		require.NoErrorf(t, err, "test %d: signing failed", i)

		rpcTx := newRPCTransaction(tx, common.Hash{}, 0, 0, nil, config)
		data, err := json.Marshal(rpcTx)
		require.NoErrorf(t, err, "test %d: rpc marshal failed", i)

		var tx2 types.Transaction
		err = tx2.UnmarshalJSON(data)
		require.NoErrorf(t, err, "test %d: rpc unmarshal failed", i)
		require.Equalf(t, tx.Hash(), tx2.Hash(), "test %d: tx hash mismatch after round-trip", i)
	}
}

func TestEstimateGas(t *testing.T) {
	t.Parallel()

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	poor := common.HexToAddress("0x3333333333333333333333333333333333333333")

	genesis := &core.Genesis{
		Config: params.MergedTestChainConfig,
		Alloc: types.GenesisAlloc{
			from: {Balance: big.NewInt(params.Ether)},
			to:   {Balance: big.NewInt(params.Ether)},
		},
	}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	backend := &estimateBackendMock{
		backendMock: newBackendMock(),
		stateDB:     stateDB,
		header:      block.Header(),
		engine:      ethash.NewFaker(),
	}
	api := NewBlockChainAPI(backend, nil)
	blockRef := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	var overrides override.StateOverride

	got, err := api.EstimateGas(context.Background(), TransactionArgs{
		From:  &from,
		To:    &to,
		Value: (*hexutil.Big)(big.NewInt(1000)),
	}, nil, nil, nil)
	require.NoError(t, err)
	require.EqualValues(t, 21000, got)

	_, err = api.EstimateGas(context.Background(), TransactionArgs{
		From:  &poor,
		To:    &to,
		Value: (*hexutil.Big)(big.NewInt(1000)),
	}, nil, nil, nil)
	require.ErrorIs(t, err, core.ErrInsufficientFunds)

	got, err = api.EstimateGas(context.Background(), TransactionArgs{
		From:     &from,
		To:       &to,
		Value:    (*hexutil.Big)(big.NewInt(1000)),
		GasPrice: (*hexutil.Big)(big.NewInt(1_000_000_000)),
	}, &blockRef, nil, nil)
	require.NoError(t, err)
	require.EqualValues(t, 21000, got)

	got, err = api.EstimateGas(context.Background(), TransactionArgs{
		From:         &from,
		To:           &to,
		Value:        (*hexutil.Big)(big.NewInt(1000)),
		MaxFeePerGas: (*hexutil.Big)(big.NewInt(1_000_000_000)),
	}, &blockRef, nil, nil)
	require.NoError(t, err)
	require.EqualValues(t, 21000, got)

	_, err = api.EstimateGas(context.Background(), TransactionArgs{
		From:                 &from,
		To:                   &to,
		Value:                (*hexutil.Big)(big.NewInt(1000)),
		GasPrice:             (*hexutil.Big)(big.NewInt(1_000_000_000)),
		MaxFeePerGas:         (*hexutil.Big)(big.NewInt(1_000_000_000)),
		MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(1)),
	}, &blockRef, nil, nil)
	require.ErrorContains(t, err, "both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified")

	_, err = api.EstimateGas(context.Background(), TransactionArgs{
		From:    &from,
		To:      &to,
		Value:   (*hexutil.Big)(big.NewInt(1000)),
		ChainID: (*hexutil.Big)(big.NewInt(1)),
	}, &blockRef, nil, nil)
	require.ErrorContains(t, err, "chainId does not match node's")

	overrides = override.StateOverride{
		poor: override.OverrideAccount{Balance: (*hexutil.Big)(big.NewInt(params.Ether))},
	}
	got, err = api.EstimateGas(context.Background(), TransactionArgs{
		From:  &poor,
		To:    &to,
		Value: (*hexutil.Big)(big.NewInt(1000)),
	}, &blockRef, &overrides, nil)
	require.NoError(t, err)
	require.EqualValues(t, 21000, got)

	overrides = override.StateOverride{
		poor: override.OverrideAccount{Balance: (*hexutil.Big)(big.NewInt(0))},
	}
	_, err = api.EstimateGas(context.Background(), TransactionArgs{
		From:  &poor,
		To:    &to,
		Value: (*hexutil.Big)(big.NewInt(1000)),
	}, &blockRef, &overrides, nil)
	require.ErrorIs(t, err, core.ErrInsufficientFunds)

	refArgs := TransactionArgs{To: &to}
	backendDefault := &estimateRefBackendMock{backendMock: newBackendMock(), stateErr: errors.New("state failed")}
	apiDefault := NewBlockChainAPI(backendDefault, nil)
	_, err = apiDefault.EstimateGas(context.Background(), refArgs, nil, nil, nil)
	require.ErrorContains(t, err, "state failed")
	require.NotNil(t, backendDefault.seenRef)
	require.NotNil(t, backendDefault.seenRef.BlockNumber)
	require.Equal(t, rpc.LatestBlockNumber, *backendDefault.seenRef.BlockNumber)

	pending := rpc.BlockNumberOrHashWithNumber(rpc.PendingBlockNumber)
	backendPending := &estimateRefBackendMock{backendMock: newBackendMock(), stateErr: errors.New("state failed")}
	apiPending := NewBlockChainAPI(backendPending, nil)
	_, err = apiPending.EstimateGas(context.Background(), refArgs, &pending, nil, nil)
	require.ErrorContains(t, err, "state failed")
	require.NotNil(t, backendPending.seenRef)
	require.NotNil(t, backendPending.seenRef.BlockNumber)
	require.Equal(t, rpc.PendingBlockNumber, *backendPending.seenRef.BlockNumber)

	hashRef := rpc.BlockNumberOrHashWithHash(common.HexToHash("0x1234"), false)
	backendHash := &estimateRefBackendMock{backendMock: newBackendMock(), stateErr: errors.New("state failed")}
	apiHash := NewBlockChainAPI(backendHash, nil)
	_, err = apiHash.EstimateGas(context.Background(), refArgs, &hashRef, nil, nil)
	require.ErrorContains(t, err, "state failed")
	require.NotNil(t, backendHash.seenRef)
	require.NotNil(t, backendHash.seenRef.BlockHash)
	require.Equal(t, common.HexToHash("0x1234"), *backendHash.seenRef.BlockHash)
}

func TestCall(t *testing.T) {
	t.Parallel()

	db := rawdb.NewMemoryDatabase()
	genesis := (&core.Genesis{Config: params.MergedTestChainConfig}).MustCommit(db)
	stateDB, err := state.New(genesis.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	callArgs := TransactionArgs{To: &to}

	backend := &callBackendMock{
		backendMock: newBackendMock(),
		stateErr:    errors.New("state failed"),
	}
	api := NewBlockChainAPI(backend, nil)

	_, err = api.Call(context.Background(), callArgs, nil, nil, nil)
	require.ErrorContains(t, err, "state failed")
	require.NotNil(t, backend.seenRef)
	require.NotNil(t, backend.seenRef.BlockNumber)
	require.Equal(t, rpc.LatestBlockNumber, *backend.seenRef.BlockNumber)

	backendNilHeader := &callBackendMock{
		backendMock: newBackendMock(),
		stateDB:     stateDB,
		header:      nil,
	}
	apiNilHeader := NewBlockChainAPI(backendNilHeader, nil)
	_, err = apiNilHeader.Call(context.Background(), callArgs, nil, nil, nil)
	require.ErrorContains(t, err, "nil header in DoCall")

	backendNilBlock := &callBackendMock{
		backendMock: newBackendMock(),
		stateDB:     stateDB,
		header:      genesis.Header(),
		block:       nil,
	}
	apiNilBlock := NewBlockChainAPI(backendNilBlock, nil)
	_, err = apiNilBlock.Call(context.Background(), callArgs, nil, nil, nil)
	require.ErrorContains(t, err, "nil block in DoCall")

	backendBlockErr := &callBackendMock{
		backendMock: newBackendMock(),
		stateDB:     stateDB,
		header:      genesis.Header(),
		blockErr:    errors.New("block lookup failed"),
	}
	apiBlockErr := NewBlockChainAPI(backendBlockErr, nil)
	_, err = apiBlockErr.Call(context.Background(), callArgs, nil, nil, nil)
	require.ErrorContains(t, err, "block lookup failed")

	pending := rpc.BlockNumberOrHashWithNumber(rpc.PendingBlockNumber)
	backendPendingRef := &callBackendMock{
		backendMock: newBackendMock(),
		stateErr:    errors.New("state failed"),
	}
	apiPendingRef := NewBlockChainAPI(backendPendingRef, nil)
	_, err = apiPendingRef.Call(context.Background(), callArgs, &pending, nil, nil)
	require.ErrorContains(t, err, "state failed")
	require.NotNil(t, backendPendingRef.seenRef)
	require.NotNil(t, backendPendingRef.seenRef.BlockNumber)
	require.Equal(t, rpc.PendingBlockNumber, *backendPendingRef.seenRef.BlockNumber)

	hashRef := rpc.BlockNumberOrHashWithHash(common.HexToHash("0x1234"), false)
	backendHashRef := &callBackendMock{
		backendMock: newBackendMock(),
		stateErr:    errors.New("state failed"),
	}
	apiHashRef := NewBlockChainAPI(backendHashRef, nil)
	_, err = apiHashRef.Call(context.Background(), callArgs, &hashRef, nil, nil)
	require.ErrorContains(t, err, "state failed")
	require.NotNil(t, backendHashRef.seenRef)
	require.NotNil(t, backendHashRef.seenRef.BlockHash)
	require.Equal(t, common.HexToHash("0x1234"), *backendHashRef.seenRef.BlockHash)

	invalidOverrides := override.StateOverride{
		to: override.OverrideAccount{
			State: map[common.Hash]common.Hash{
				common.HexToHash("0x1"): common.HexToHash("0x2"),
			},
			StateDiff: map[common.Hash]common.Hash{
				common.HexToHash("0x3"): common.HexToHash("0x4"),
			},
		},
	}
	block := types.NewBlock(genesis.Header(), &types.Body{}, nil, newHasher())
	backendInvalidOverride := &callBackendMock{
		backendMock: newBackendMock(),
		stateDB:     stateDB,
		header:      genesis.Header(),
		block:       block,
	}
	apiInvalidOverride := NewBlockChainAPI(backendInvalidOverride, nil)
	_, err = apiInvalidOverride.Call(context.Background(), TransactionArgs{To: &to}, nil, &invalidOverrides, nil)
	require.ErrorContains(t, err, "has both 'state' and 'stateDiff'")

}

func TestSimulateV1(t *testing.T) {
	t.Parallel()

	api := NewBlockChainAPI(newBackendMock(), nil)

	_, err := api.SimulateV1(context.Background(), simOpts{}, nil)
	if err == nil {
		t.Fatal("expected error for empty simulation input")
	}
	var invalidReqErr *invalidParamsError
	if !errors.As(err, &invalidReqErr) {
		t.Fatalf("expected invalidParamsError for empty simulation input, got %T (%v)", err, err)
	}
	if invalidReqErr.message != "empty input" {
		t.Fatalf("unexpected invalid request message: %q", invalidReqErr.message)
	}

	tooManyBlocks := make([]simBlock, maxSimulateBlocks+1)
	_, err = api.SimulateV1(context.Background(), simOpts{BlockStateCalls: tooManyBlocks}, nil)
	if err == nil {
		t.Fatal("expected error for too many simulated blocks")
	}
	var limitErr *clientLimitExceededError
	if !errors.As(err, &limitErr) {
		t.Fatalf("expected clientLimitExceededError for too many simulated blocks, got %T (%v)", err, err)
	}
	if limitErr.message != "too many blocks" {
		t.Fatalf("unexpected limit exceeded message: %q", limitErr.message)
	}

	// Minimal success path in same-name test: one simulated block with one call.
	var (
		sender    = common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
		recipient = common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	)
	genesis := &core.Genesis{
		Config: params.MergedTestChainConfig,
		Alloc: types.GenesisAlloc{
			sender: {Balance: big.NewInt(params.Ether)},
		},
	}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	if err != nil {
		t.Fatalf("failed to create state db: %v", err)
	}

	backend := &simulateBackendMock{
		estimateBackendMock: &estimateBackendMock{
			backendMock: newBackendMock(),
			stateDB:     stateDB,
			header:      block.Header(),
			engine:      ethash.NewFaker(),
		},
		gasCap: 30_000_000,
	}
	api = NewBlockChainAPI(backend, nil)

	result, err := api.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{{
		Calls: []TransactionArgs{{
			From:  &sender,
			To:    &recipient,
			Value: (*hexutil.Big)(big.NewInt(1)),
		}},
	}}}, nil)
	if err != nil {
		t.Fatalf("unexpected simulate success-path error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 simulated block, got %d", len(result))
	}

	type callSummary struct {
		Status string `json:"status"`
	}
	type blockSummary struct {
		Number string        `json:"number"`
		Calls  []callSummary `json:"calls"`
	}
	b, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal simulate result: %v", err)
	}
	var summary []blockSummary
	if err := json.Unmarshal(b, &summary); err != nil {
		t.Fatalf("failed to decode simulate result: %v", err)
	}
	if len(summary) != 1 || len(summary[0].Calls) != 1 {
		t.Fatalf("unexpected simulate structure: %+v", summary)
	}
	if summary[0].Number != "0x1" {
		t.Fatalf("unexpected simulated block number: %s", summary[0].Number)
	}
	if summary[0].Calls[0].Status != "0x1" {
		t.Fatalf("unexpected call status: %s", summary[0].Calls[0].Status)
	}

	currentNum := (*hexutil.Big)(new(big.Int).Set(block.Number()))
	_, err = api.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{{
		BlockOverrides: &override.BlockOverrides{Number: currentNum},
	}}}, nil)
	if err == nil || !strings.Contains(err.Error(), "block numbers must be in order") {
		t.Fatalf("expected block number ordering error, got %v", err)
	}

	_, err = api.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{{
		Calls: []TransactionArgs{{
			From:  &recipient,
			To:    &sender,
			Value: (*hexutil.Big)(big.NewInt(1000)),
		}},
	}}}, nil)
	require.ErrorContains(t, err, "insufficient funds")

	var txErr *invalidTxError
	require.ErrorAs(t, err, &txErr)
	require.Equal(t, errCodeInsufficientFunds, txErr.Code)

	highNonce := hexutil.Uint64(2)
	_, err = api.SimulateV1(context.Background(), simOpts{
		Validation: true,
		BlockStateCalls: []simBlock{{
			Calls: []TransactionArgs{{
				From:  &sender,
				To:    &recipient,
				Nonce: &highNonce,
			}},
		}},
	}, nil)
	require.ErrorContains(t, err, "nonce too high")
	require.ErrorAs(t, err, &txErr)
	require.Equal(t, errCodeNonceTooHigh, txErr.Code)

	gas := hexutil.Uint64(21000)
	_, err = api.SimulateV1(context.Background(), simOpts{
		Validation: true,
		BlockStateCalls: []simBlock{{
			Calls: []TransactionArgs{{
				From:         &sender,
				To:           &recipient,
				Gas:          &gas,
				GasPrice:     (*hexutil.Big)(big.NewInt(1)),
				MaxFeePerGas: (*hexutil.Big)(big.NewInt(2)),
			}},
		}},
	}, nil)
	require.ErrorContains(t, err, "both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified")

	resValidationOK, err := api.SimulateV1(context.Background(), simOpts{
		Validation: true,
		BlockStateCalls: []simBlock{{
			BlockOverrides: &override.BlockOverrides{BaseFeePerGas: (*hexutil.Big)(big.NewInt(1))},
			Calls: []TransactionArgs{{
				From:                 &sender,
				To:                   &recipient,
				Gas:                  &gas,
				Value:                (*hexutil.Big)(big.NewInt(1000)),
				MaxFeePerGas:         (*hexutil.Big)(big.NewInt(2)),
				MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(1)),
			}},
		}},
	}, nil)
	require.NoError(t, err)

	type validationCallSummary struct {
		Status string `json:"status"`
	}
	type validationBlockSummary struct {
		BaseFeePerGas string                  `json:"baseFeePerGas"`
		Calls         []validationCallSummary `json:"calls"`
	}
	encValidation, err := json.Marshal(resValidationOK)
	require.NoError(t, err)
	var validationSummary []validationBlockSummary
	require.NoError(t, json.Unmarshal(encValidation, &validationSummary))
	require.Len(t, validationSummary, 1)
	require.Equal(t, "0x1", validationSummary[0].BaseFeePerGas)
	require.Len(t, validationSummary[0].Calls, 1)
	require.Equal(t, "0x1", validationSummary[0].Calls[0].Status)

	contractSender := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9")
	nonceOne := hexutil.Uint64(1)
	codeSender := hexutil.Bytes{0x00}
	resContractSender, err := api.SimulateV1(context.Background(), simOpts{
		Validation: true,
		BlockStateCalls: []simBlock{{
			StateOverrides: &override.StateOverride{
				contractSender: override.OverrideAccount{
					Balance: (*hexutil.Big)(big.NewInt(params.Ether)),
					Nonce:   &nonceOne,
					Code:    &codeSender,
				},
			},
			Calls: []TransactionArgs{{
				From:                 &contractSender,
				To:                   &recipient,
				Nonce:                &nonceOne,
				MaxFeePerGas:         (*hexutil.Big)(big.NewInt(2)),
				MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(1)),
			}},
		}},
	}, nil)
	require.NoError(t, err)

	encContract, err := json.Marshal(resContractSender)
	require.NoError(t, err)
	var contractSummary []validationBlockSummary
	require.NoError(t, json.Unmarshal(encContract, &contractSummary))
	require.Len(t, contractSummary, 1)
	require.Len(t, contractSummary[0].Calls, 1)
	require.Equal(t, "0x1", contractSummary[0].Calls[0].Status)

	transferContract := common.HexToAddress("0xcccccccccccccccccccccccccccccccccccccc01")
	codeTransfer := hexutil.Bytes(common.FromHex("0x60003560601c606460008060008084865af160008103601d57600080fd5b505050"))
	transferInput := hexutil.Bytes(recipient.Bytes())
	resTransfers, err := api.SimulateV1(context.Background(), simOpts{
		TraceTransfers: true,
		BlockStateCalls: []simBlock{{
			StateOverrides: &override.StateOverride{
				transferContract: override.OverrideAccount{
					Balance: (*hexutil.Big)(big.NewInt(100)),
					Code:    &codeTransfer,
				},
			},
			Calls: []TransactionArgs{{
				From:  &sender,
				To:    &transferContract,
				Value: (*hexutil.Big)(big.NewInt(50)),
				Input: &transferInput,
			}},
		}},
	}, nil)
	require.NoError(t, err)

	type transferLog struct {
		Address common.Address `json:"address"`
		Topics  []common.Hash  `json:"topics"`
	}
	type transferCallSummary struct {
		Status string        `json:"status"`
		Logs   []transferLog `json:"logs"`
	}
	type transferBlockSummary struct {
		Calls []transferCallSummary `json:"calls"`
	}
	encTransfers, err := json.Marshal(resTransfers)
	require.NoError(t, err)
	var transferSummary []transferBlockSummary
	require.NoError(t, json.Unmarshal(encTransfers, &transferSummary))
	require.Len(t, transferSummary, 1)
	require.Len(t, transferSummary[0].Calls, 1)
	require.Equal(t, "0x1", transferSummary[0].Calls[0].Status)
	require.GreaterOrEqual(t, len(transferSummary[0].Calls[0].Logs), 2)
	require.Equal(t, transferAddress, transferSummary[0].Calls[0].Logs[0].Address)
	require.NotEmpty(t, transferSummary[0].Calls[0].Logs[0].Topics)
	require.Equal(t, transferTopic, transferSummary[0].Calls[0].Logs[0].Topics[0])

	storageContract := common.HexToAddress("0xcccccccccccccccccccccccccccccccccccccc02")
	codeStorage := hexutil.Bytes(common.FromHex("0x608060405234801561001057600080fd5b50600436106100365760003560e01c80632e64cec11461003b5780636057361d14610059575b600080fd5b610043610075565b60405161005091906100d9565b60405180910390f35b610073600480360381019061006e919061009d565b61007e565b005b60008054905090565b8060008190555050565b60008135905061009781610103565b92915050565b6000602082840312156100b3576100b26100fe565b5b60006100c184828501610088565b91505092915050565b6100d3816100f4565b82525050565b60006020820190506100ee60008301846100ca565b92915050565b6000819050919050565b600080fd5b61010c816100f4565b811461011757600080fd5b5056fea2646970667358221220404e37f487a89a932dca5e77faaf6ca2de3b991f93d230604b1b8daaef64766264736f6c63430008070033"))
	setInput := hexutil.Bytes(common.FromHex("0x6057361d0000000000000000000000000000000000000000000000000000000000000005"))
	getInput := hexutil.Bytes(common.FromHex("0x2e64cec1"))
	resStorage, err := api.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{{
		StateOverrides: &override.StateOverride{
			storageContract: override.OverrideAccount{Code: &codeStorage},
		},
		Calls: []TransactionArgs{{
			From:  &sender,
			To:    &storageContract,
			Input: &setInput,
		}, {
			From:  &sender,
			To:    &storageContract,
			Input: &getInput,
		}},
	}}}, nil)
	require.NoError(t, err)

	type storageCallSummary struct {
		Status      string `json:"status"`
		ReturnValue string `json:"returnData"`
	}
	type storageBlockSummary struct {
		Calls []storageCallSummary `json:"calls"`
	}
	encStorage, err := json.Marshal(resStorage)
	require.NoError(t, err)
	var storageSummary []storageBlockSummary
	require.NoError(t, json.Unmarshal(encStorage, &storageSummary))
	require.Len(t, storageSummary, 1)
	require.Len(t, storageSummary[0].Calls, 2)
	require.Equal(t, "0x1", storageSummary[0].Calls[0].Status)
	require.Equal(t, "0x1", storageSummary[0].Calls[1].Status)
	require.Equal(t, "0x0000000000000000000000000000000000000000000000000000000000000005", storageSummary[0].Calls[1].ReturnValue)

	ecrecoverInvoker := common.HexToAddress("0xcccccccccccccccccccccccccccccccccccccc03")
	codeInvoker := hexutil.Bytes(common.FromHex("0x6040516000815260006020820152600060408201526000606082015260208160808360015afa60008103603157600080fd5b601482f3"))
	codePrecompileCaller := hexutil.Bytes(common.FromHex("0x33806000526014600cf3"))
	ecrecoverAddr := common.BytesToAddress([]byte{0x01})
	resEcrecover, err := api.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{{
		StateOverrides: &override.StateOverride{
			ecrecoverInvoker: override.OverrideAccount{Code: &codeInvoker},
			ecrecoverAddr:    override.OverrideAccount{Code: &codePrecompileCaller},
		},
		Calls: []TransactionArgs{{
			From: &sender,
			To:   &ecrecoverInvoker,
		}},
	}}}, nil)
	require.NoError(t, err)

	type ecrecoverCallSummary struct {
		Status      string `json:"status"`
		ReturnValue string `json:"returnData"`
	}
	type ecrecoverBlockSummary struct {
		Calls []ecrecoverCallSummary `json:"calls"`
	}
	encEcrecover, err := json.Marshal(resEcrecover)
	require.NoError(t, err)
	var ecrecoverSummary []ecrecoverBlockSummary
	require.NoError(t, json.Unmarshal(encEcrecover, &ecrecoverSummary))
	require.Len(t, ecrecoverSummary, 1)
	require.Len(t, ecrecoverSummary[0].Calls, 1)
	require.Equal(t, "0x1", ecrecoverSummary[0].Calls[0].Status)
	expectedInvoker := strings.ToLower(ecrecoverInvoker.String())
	expectedInvoker = strings.TrimPrefix(expectedInvoker, "xdc")
	expectedInvoker = strings.TrimPrefix(expectedInvoker, "0x")
	require.Equal(t, "0x"+expectedInvoker, ecrecoverSummary[0].Calls[0].ReturnValue)

	numberContract := common.HexToAddress("0xcccccccccccccccccccccccccccccccccccccc04")
	codeNumber := hexutil.Bytes(common.FromHex("0x4360005260206000f3"))
	n11 := (*hexutil.Big)(big.NewInt(11))
	n12 := (*hexutil.Big)(big.NewInt(12))
	resBlockOverride, err := api.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{
		{
			BlockOverrides: &override.BlockOverrides{Number: n11},
			StateOverrides: &override.StateOverride{
				numberContract: override.OverrideAccount{Code: &codeNumber},
			},
			Calls: []TransactionArgs{{From: &sender, To: &numberContract}},
		},
		{
			BlockOverrides: &override.BlockOverrides{Number: n12},
			Calls:          []TransactionArgs{{From: &sender, To: &numberContract}},
		},
	}}, nil)
	require.NoError(t, err)

	type blockOverrideCallSummary struct {
		ReturnValue string `json:"returnData"`
		Status      string `json:"status"`
	}
	type blockOverrideSummary struct {
		Number string                     `json:"number"`
		Calls  []blockOverrideCallSummary `json:"calls"`
	}
	encBlockOverride, err := json.Marshal(resBlockOverride)
	require.NoError(t, err)
	var blockOverrideResult []blockOverrideSummary
	require.NoError(t, json.Unmarshal(encBlockOverride, &blockOverrideResult))
	require.GreaterOrEqual(t, len(blockOverrideResult), 12)
	first := blockOverrideResult[len(blockOverrideResult)-2]
	second := blockOverrideResult[len(blockOverrideResult)-1]
	require.Equal(t, "0xb", first.Number)
	require.Equal(t, "0xc", second.Number)
	require.Len(t, first.Calls, 1)
	require.Len(t, second.Calls, 1)
	require.Equal(t, "0x1", first.Calls[0].Status)
	require.Equal(t, "0x1", second.Calls[0].Status)
	require.Equal(t, "0x000000000000000000000000000000000000000000000000000000000000000b", first.Calls[0].ReturnValue)
	require.Equal(t, "0x000000000000000000000000000000000000000000000000000000000000000c", second.Calls[0].ReturnValue)

	logContract := common.HexToAddress("0xcccccccccccccccccccccccccccccccccccccc05")
	codeLog := hexutil.Bytes(common.FromHex("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80600080a1600080f3"))
	resLogs, err := api.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{{
		StateOverrides: &override.StateOverride{
			logContract: override.OverrideAccount{Code: &codeLog},
		},
		Calls: []TransactionArgs{{
			From: &sender,
			To:   &logContract,
		}},
	}}}, nil)
	require.NoError(t, err)

	type simLogSummary struct {
		Address common.Address `json:"address"`
		Topics  []common.Hash  `json:"topics"`
		Data    hexutil.Bytes  `json:"data"`
	}
	type logCallSummary struct {
		Status string          `json:"status"`
		Logs   []simLogSummary `json:"logs"`
	}
	type logBlockSummary struct {
		Calls []logCallSummary `json:"calls"`
	}
	encLogs, err := json.Marshal(resLogs)
	require.NoError(t, err)
	var logsSummary []logBlockSummary
	require.NoError(t, json.Unmarshal(encLogs, &logsSummary))
	require.Len(t, logsSummary, 1)
	require.Len(t, logsSummary[0].Calls, 1)
	require.Equal(t, "0x1", logsSummary[0].Calls[0].Status)
	require.Len(t, logsSummary[0].Calls[0].Logs, 1)
	require.Equal(t, logContract, logsSummary[0].Calls[0].Logs[0].Address)
	require.Equal(t, []common.Hash{common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")}, logsSummary[0].Calls[0].Logs[0].Topics)
	require.Empty(t, logsSummary[0].Calls[0].Logs[0].Data)

	sha256Addr := common.BytesToAddress([]byte{0x2})
	movedPrecompile := common.HexToAddress("0xcccccccccccccccccccccccccccccccccccccc06")
	codePassthrough := hexutil.Bytes(common.FromHex("0x365981600082378181f3"))
	precompileInput := hexutil.Bytes(common.FromHex("0x0000000000000000000000000000000000000000000000000000000000000001"))
	resPrecompileMove, err := api.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{{
		StateOverrides: &override.StateOverride{
			sha256Addr: override.OverrideAccount{
				Code:             &codePassthrough,
				MovePrecompileTo: &movedPrecompile,
			},
		},
		Calls: []TransactionArgs{{
			From:  &sender,
			To:    &movedPrecompile,
			Input: &precompileInput,
		}, {
			From:  &sender,
			To:    &sha256Addr,
			Input: &precompileInput,
		}},
	}}}, nil)
	require.NoError(t, err)

	type precompileMoveCallSummary struct {
		Status      string `json:"status"`
		ReturnValue string `json:"returnData"`
	}
	type precompileMoveBlockSummary struct {
		Calls []precompileMoveCallSummary `json:"calls"`
	}
	encPrecompileMove, err := json.Marshal(resPrecompileMove)
	require.NoError(t, err)
	var precompileMoveSummary []precompileMoveBlockSummary
	require.NoError(t, json.Unmarshal(encPrecompileMove, &precompileMoveSummary))
	require.Len(t, precompileMoveSummary, 1)
	require.Len(t, precompileMoveSummary[0].Calls, 2)
	require.Equal(t, "0x1", precompileMoveSummary[0].Calls[0].Status)
	require.Equal(t, "0x1", precompileMoveSummary[0].Calls[1].Status)
	require.Equal(t, "0xec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5", precompileMoveSummary[0].Calls[0].ReturnValue)
	require.Equal(t, "0x0000000000000000000000000000000000000000000000000000000000000001", precompileMoveSummary[0].Calls[1].ReturnValue)

	faulty := common.HexToAddress("0xdddddddddddddddddddddddddddddddddddddddd")
	codeFaulty := hexutil.Bytes{0xf3}
	resEVMErr, err := api.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{{
		StateOverrides: &override.StateOverride{
			faulty: override.OverrideAccount{Code: &codeFaulty},
		},
		Calls: []TransactionArgs{{
			From: &sender,
			To:   &faulty,
		}},
	}}}, nil)
	require.NoError(t, err)

	type evmCallSummary struct {
		Status string `json:"status"`
		Error  struct {
			Message string `json:"message"`
			Code    int    `json:"code"`
		} `json:"error"`
	}
	type evmBlockSummary struct {
		Calls []evmCallSummary `json:"calls"`
	}
	encErr, err := json.Marshal(resEVMErr)
	require.NoError(t, err)
	var evmSummary []evmBlockSummary
	require.NoError(t, json.Unmarshal(encErr, &evmSummary))
	require.Len(t, evmSummary, 1)
	require.Len(t, evmSummary[0].Calls, 1)
	require.Equal(t, "0x0", evmSummary[0].Calls[0].Status)
	require.Equal(t, errCodeVMError, evmSummary[0].Calls[0].Error.Code)
	require.Contains(t, evmSummary[0].Calls[0].Error.Message, "stack underflow")

	tooFar := new(big.Int).Add(block.Number(), big.NewInt(maxSimulateBlocks+1))
	_, err = api.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{{
		BlockOverrides: &override.BlockOverrides{Number: (*hexutil.Big)(tooFar)},
	}}}, nil)
	require.ErrorContains(t, err, "too many blocks")
}

func TestSimulateV1ChainLinkage(t *testing.T) {
	t.Parallel()

	genesis := &core.Genesis{Config: params.MergedTestChainConfig}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	backend := &estimateBackendMock{
		backendMock: newBackendMock(),
		stateDB:     stateDB,
		header:      block.Header(),
		engine:      ethash.NewFaker(),
	}
	api := NewBlockChainAPI(backend, nil)

	currentNum := (*hexutil.Big)(new(big.Int).Set(block.Number()))
	_, err = api.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{{
		BlockOverrides: &override.BlockOverrides{Number: currentNum},
	}}}, nil)
	require.ErrorContains(t, err, "block numbers must be in order")
}

func TestSimulateV1TxSender(t *testing.T) {
	t.Parallel()

	var (
		sender1   = common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
		sender2   = common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2")
		sender3   = common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3")
		recipient = common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	)

	genesis := &core.Genesis{
		Config: params.MergedTestChainConfig,
		Alloc: types.GenesisAlloc{
			sender1: {Balance: big.NewInt(params.Ether)},
			sender2: {Balance: big.NewInt(params.Ether)},
			sender3: {Balance: big.NewInt(params.Ether)},
		},
	}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	backend := &simulateBackendMock{
		estimateBackendMock: &estimateBackendMock{
			backendMock: newBackendMock(),
			stateDB:     stateDB,
			header:      block.Header(),
			engine:      ethash.NewFaker(),
		},
		gasCap: 30_000_000,
	}
	api := NewBlockChainAPI(backend, nil)

	results, err := api.SimulateV1(context.Background(), simOpts{
		ReturnFullTransactions: true,
		BlockStateCalls: []simBlock{
			{Calls: []TransactionArgs{
				{From: &sender1, To: &recipient, Value: (*hexutil.Big)(big.NewInt(1000))},
				{From: &sender2, To: &recipient, Value: (*hexutil.Big)(big.NewInt(2000))},
				{From: &sender3, To: &recipient, Value: (*hexutil.Big)(big.NewInt(3000))},
			}},
			{Calls: []TransactionArgs{
				{From: &sender2, To: &recipient, Value: (*hexutil.Big)(big.NewInt(4000))},
			}},
		},
	}, nil)
	require.NoError(t, err)
	require.Len(t, results, 2)

	enc, err := json.Marshal(results)
	require.NoError(t, err)

	type txSummary struct {
		From common.Address `json:"from"`
	}
	type blockSummary struct {
		Transactions []txSummary `json:"transactions"`
	}
	var summary []blockSummary
	require.NoError(t, json.Unmarshal(enc, &summary))
	require.Len(t, summary, 2)
	require.Len(t, summary[0].Transactions, 3)
	require.Equal(t, common.Address{}, summary[0].Transactions[0].From)
	require.Equal(t, common.Address{}, summary[0].Transactions[1].From)
	require.Equal(t, common.Address{}, summary[0].Transactions[2].From)
	require.Len(t, summary[1].Transactions, 1)
	require.Equal(t, common.Address{}, summary[1].Transactions[0].From)
}

func TestSignTransaction(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)

	password := "test-pass"
	ks := keystore.NewKeyStore(t.TempDir(), keystore.LightScryptN, keystore.LightScryptP)
	account, err := ks.ImportECDSA(key, password)
	require.NoError(t, err)
	require.NoError(t, ks.Unlock(account, password))

	manager := accounts.NewManager(nil, ks)
	defer manager.Close()

	backend := &signingBackendMock{
		backendMock: newBackendMock(),
		manager:     manager,
	}
	api := NewTransactionAPI(backend, new(AddrLocker))

	to := common.HexToAddress("0x703c4b2bd70c169f5717101caee543299fc946c7")
	fillRes, err := api.FillTransaction(context.Background(), TransactionArgs{
		From:  &account.Address,
		To:    &to,
		Value: (*hexutil.Big)(big.NewInt(1)),
	})
	require.NoError(t, err)
	require.NotNil(t, fillRes)
	require.NotNil(t, fillRes.Tx)

	nonce := hexutil.Uint64(fillRes.Tx.Nonce())
	gas := hexutil.Uint64(fillRes.Tx.Gas())
	value := (*hexutil.Big)(fillRes.Tx.Value())
	maxFee := (*hexutil.Big)(fillRes.Tx.GasFeeCap())
	maxTip := (*hexutil.Big)(fillRes.Tx.GasTipCap())
	chainID := (*hexutil.Big)(fillRes.Tx.ChainId())
	input := hexutil.Bytes(fillRes.Tx.Data())
	accessList := fillRes.Tx.AccessList()

	signRes, err := api.SignTransaction(context.Background(), TransactionArgs{
		From:                 &account.Address,
		To:                   fillRes.Tx.To(),
		Gas:                  &gas,
		Nonce:                &nonce,
		Value:                value,
		Input:                &input,
		AccessList:           &accessList,
		ChainID:              chainID,
		MaxFeePerGas:         maxFee,
		MaxPriorityFeePerGas: maxTip,
	})
	require.NoError(t, err)
	require.NotNil(t, signRes)
	require.NotNil(t, signRes.Tx)

	var tx2 types.Transaction
	require.NoError(t, tx2.UnmarshalBinary(signRes.Raw))
	require.Equal(t, fillRes.Tx.Type(), tx2.Type())
	require.Equal(t, fillRes.Tx.Nonce(), tx2.Nonce())
	require.Equal(t, fillRes.Tx.Gas(), tx2.Gas())
	require.Equal(t, fillRes.Tx.Value(), tx2.Value())
	require.Equal(t, fillRes.Tx.To(), tx2.To())

	signer := types.MakeSigner(backend.ChainConfig(), backend.CurrentBlock().Number)
	from, err := types.Sender(signer, &tx2)
	require.NoError(t, err)
	require.Equal(t, account.Address, from)

	// Same-name coverage extension: keep a compact set of validation checks here.
	plainBackend := newBackendMock()
	plainAPI := NewTransactionAPI(plainBackend, new(AddrLocker))
	fromAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	toAddr := common.HexToAddress("0x2222222222222222222222222222222222222222")
	testGas := hexutil.Uint64(21000)
	testNonce := hexutil.Uint64(0)

	_, err = plainAPI.SignTransaction(context.Background(), TransactionArgs{
		From:     &fromAddr,
		To:       &toAddr,
		GasPrice: (*hexutil.Big)(big.NewInt(1)),
		Nonce:    &testNonce,
	})
	require.ErrorContains(t, err, "not specify Gas")

	_, err = plainAPI.SignTransaction(context.Background(), TransactionArgs{
		From:                 &fromAddr,
		To:                   &toAddr,
		Gas:                  &testGas,
		Nonce:                &testNonce,
		GasPrice:             (*hexutil.Big)(big.NewInt(1)),
		MaxFeePerGas:         (*hexutil.Big)(big.NewInt(2)),
		MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(1)),
	})
	require.ErrorContains(t, err, "both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified")

	_, err = plainAPI.SignTransaction(context.Background(), TransactionArgs{
		From:     &fromAddr,
		To:       &toAddr,
		Gas:      &testGas,
		Nonce:    &testNonce,
		GasPrice: (*hexutil.Big)(big.NewInt(1)),
		ChainID:  (*hexutil.Big)(big.NewInt(1)),
	})
	require.ErrorContains(t, err, "chainId does not match node's")

	_, err = plainAPI.SignTransaction(context.Background(), TransactionArgs{
		From:                 &fromAddr,
		To:                   &toAddr,
		Gas:                  &testGas,
		Nonce:                &testNonce,
		MaxFeePerGas:         (*hexutil.Big)(big.NewInt(1)),
		MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(2)),
	})
	require.ErrorContains(t, err, "maxFeePerGas")
}

func TestRPCGetBlockOrHeader(t *testing.T) {
	t.Parallel()

	errNotFound := errors.New("not found")
	block := types.NewBlock(
		&types.Header{Number: big.NewInt(7), GasLimit: 10_000_000},
		&types.Body{},
		nil,
		newHasher(),
	)
	header := block.Header()

	backend := &blockLookupBackendMock{
		backendMock:     newBackendMock(),
		headersByNumber: map[rpc.BlockNumber]*types.Header{rpc.BlockNumber(7): header, rpc.PendingBlockNumber: header},
		headersByHash:   map[common.Hash]*types.Header{header.Hash(): header},
		blocksByNumber:  map[rpc.BlockNumber]*types.Block{rpc.BlockNumber(7): block, rpc.PendingBlockNumber: block},
		blocksByHash:    map[common.Hash]*types.Block{block.Hash(): block},
		notFoundErr:     errNotFound,
	}
	api := NewBlockChainAPI(backend, nil)

	gotHeaderByNumber, err := api.GetHeaderByNumber(context.Background(), rpc.BlockNumber(7))
	require.NoError(t, err)
	require.Equal(t, header.Hash(), gotHeaderByNumber["hash"])
	gotHeaderByHash := api.GetHeaderByHash(context.Background(), header.Hash())
	require.NotNil(t, gotHeaderByHash)
	require.Equal(t, header.Hash(), gotHeaderByHash["hash"])
	gotBlockByNumber, err := api.GetBlockByNumber(context.Background(), rpc.BlockNumber(7), false)
	require.NoError(t, err)
	require.NotNil(t, gotBlockByNumber)
	require.Equal(t, block.Hash(), gotBlockByNumber["hash"])

	gotBlockByHash, err := api.GetBlockByHash(context.Background(), block.Hash(), false)
	require.NoError(t, err)
	require.Equal(t, block.Hash(), gotBlockByHash["hash"])

	missingHeader, err := api.GetHeaderByNumber(context.Background(), rpc.BlockNumber(8))
	require.ErrorIs(t, err, errNotFound)
	require.Nil(t, missingHeader)
	missingBlock, err := api.GetBlockByNumber(context.Background(), rpc.BlockNumber(8), false)
	require.ErrorIs(t, err, errNotFound)
	require.Nil(t, missingBlock)

	missingHeaderByHash := api.GetHeaderByHash(context.Background(), common.Hash{0xff})
	require.Nil(t, missingHeaderByHash)

	missingBlockByHash, err := api.GetBlockByHash(context.Background(), common.Hash{0xee}, false)
	require.ErrorIs(t, err, errNotFound)
	require.Nil(t, missingBlockByHash)

	pendingHeader, err := api.GetHeaderByNumber(context.Background(), rpc.PendingBlockNumber)
	require.NoError(t, err)
	require.Nil(t, pendingHeader["hash"])
	require.Nil(t, pendingHeader["nonce"])
	require.Nil(t, pendingHeader["miner"])

	pendingBlock, err := api.GetBlockByNumber(context.Background(), rpc.PendingBlockNumber, false)
	require.NoError(t, err)
	require.Nil(t, pendingBlock["hash"])
	require.Nil(t, pendingBlock["nonce"])
	require.Nil(t, pendingBlock["miner"])
	require.Nil(t, pendingBlock["number"])
}

func TestRPCGetTransactionReceipt(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	require.NoError(t, err)
	signer := types.LatestSigner(params.TestChainConfig)
	to := common.Address{0xab}

	tx, err := types.SignNewTx(key, signer, &types.LegacyTx{
		Nonce:    1,
		GasPrice: big.NewInt(2),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(3),
	})
	require.NoError(t, err)

	block := types.NewBlock(
		&types.Header{Number: big.NewInt(9), GasLimit: 8_000_000},
		&types.Body{Transactions: []*types.Transaction{tx}},
		nil,
		newHasher(),
	)
	receipts := types.Receipts{{
		Status:            types.ReceiptStatusSuccessful,
		CumulativeGasUsed: 21000,
		GasUsed:           21000,
		EffectiveGasPrice: big.NewInt(2),
	}}

	db := rawdb.NewMemoryDatabase()
	rawdb.WriteBlock(db, block)
	rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	rawdb.WriteTxLookupEntriesByBlock(db, block)

	backend := &receiptBackendMock{backendMock: newBackendMock(), db: db, block: block, receipts: receipts}
	api := NewTransactionAPI(backend, nil)

	got, err := api.GetTransactionReceipt(context.Background(), tx.Hash())
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, tx.Hash(), got["transactionHash"])
	require.Equal(t, block.Hash(), got["blockHash"])

	missing, err := api.GetTransactionReceipt(context.Background(), common.Hash{0xff})
	require.NoError(t, err)
	require.Nil(t, missing)

	backend.receipts = types.Receipts{{
		PostState:         []byte{0x01, 0x02, 0x03},
		CumulativeGasUsed: 21000,
		GasUsed:           21000,
		EffectiveGasPrice: big.NewInt(2),
	}}
	gotPostState, err := api.GetTransactionReceipt(context.Background(), tx.Hash())
	require.NoError(t, err)
	require.NotNil(t, gotPostState)
	require.Equal(t, hexutil.Bytes{0x01, 0x02, 0x03}, gotPostState["root"])
	_, hasStatus := gotPostState["status"]
	require.False(t, hasStatus)

	backend.receipts = types.Receipts{{
		Status:            types.ReceiptStatusFailed,
		CumulativeGasUsed: 21000,
		GasUsed:           21000,
		EffectiveGasPrice: big.NewInt(2),
	}}
	gotFailed, err := api.GetTransactionReceipt(context.Background(), tx.Hash())
	require.NoError(t, err)
	require.NotNil(t, gotFailed)
	require.Equal(t, hexutil.Uint(types.ReceiptStatusFailed), gotFailed["status"])
	_, hasRoot := gotFailed["root"]
	require.False(t, hasRoot)

	contractTx, err := types.SignNewTx(key, signer, &types.LegacyTx{
		Nonce:    2,
		GasPrice: big.NewInt(3),
		Gas:      53000,
		To:       nil,
		Data:     []byte{0x60, 0x00},
	})
	require.NoError(t, err)

	contractBlock := types.NewBlock(
		&types.Header{Number: big.NewInt(10), GasLimit: 8_000_000},
		&types.Body{Transactions: []*types.Transaction{contractTx}},
		nil,
		newHasher(),
	)
	contractAddr := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	contractReceipts := types.Receipts{{
		Status:            types.ReceiptStatusSuccessful,
		CumulativeGasUsed: 53000,
		GasUsed:           53000,
		ContractAddress:   contractAddr,
		EffectiveGasPrice: big.NewInt(3),
	}}

	db2 := rawdb.NewMemoryDatabase()
	rawdb.WriteBlock(db2, contractBlock)
	rawdb.WriteCanonicalHash(db2, contractBlock.Hash(), contractBlock.NumberU64())
	rawdb.WriteTxLookupEntriesByBlock(db2, contractBlock)

	backend2 := &receiptBackendMock{backendMock: newBackendMock(), db: db2, block: contractBlock, receipts: contractReceipts}
	api2 := NewTransactionAPI(backend2, nil)

	gotContract, err := api2.GetTransactionReceipt(context.Background(), contractTx.Hash())
	require.NoError(t, err)
	require.NotNil(t, gotContract)
	require.Equal(t, contractAddr, gotContract["contractAddress"])
	require.Nil(t, gotContract["to"])
}

func TestRPCGetBlockReceipts(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	require.NoError(t, err)
	signer := types.LatestSigner(params.TestChainConfig)
	to := common.Address{0xcd}

	tx, err := types.SignNewTx(key, signer, &types.LegacyTx{
		Nonce:    2,
		GasPrice: big.NewInt(5),
		Gas:      22000,
		To:       &to,
		Value:    big.NewInt(7),
	})
	require.NoError(t, err)

	block := types.NewBlock(
		&types.Header{Number: big.NewInt(11), GasLimit: 8_000_000},
		&types.Body{Transactions: []*types.Transaction{tx}},
		nil,
		newHasher(),
	)
	receipts := types.Receipts{{
		Status:            types.ReceiptStatusSuccessful,
		CumulativeGasUsed: 22000,
		GasUsed:           22000,
		EffectiveGasPrice: big.NewInt(5),
	}}

	backend := &receiptBackendMock{backendMock: newBackendMock(), block: block, receipts: receipts}
	api := NewBlockChainAPI(backend, nil)

	got, err := api.GetBlockReceipts(context.Background(), rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(11)))
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, tx.Hash(), got[0]["transactionHash"])
	require.Equal(t, block.Hash(), got[0]["blockHash"])

	gotByHash, err := api.GetBlockReceipts(context.Background(), rpc.BlockNumberOrHashWithHash(block.Hash(), false))
	require.NoError(t, err)
	require.Len(t, gotByHash, 1)
	require.Equal(t, tx.Hash(), gotByHash[0]["transactionHash"])
	require.Equal(t, block.Hash(), gotByHash[0]["blockHash"])

	gotLatest, err := api.GetBlockReceipts(context.Background(), rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber))
	require.NoError(t, err)
	require.Len(t, gotLatest, 1)
	require.Equal(t, tx.Hash(), gotLatest[0]["transactionHash"])

	gotPending, err := api.GetBlockReceipts(context.Background(), rpc.BlockNumberOrHashWithNumber(rpc.PendingBlockNumber))
	require.NoError(t, err)
	require.Len(t, gotPending, 1)
	require.Equal(t, tx.Hash(), gotPending[0]["transactionHash"])

	missingByNumber, err := api.GetBlockReceipts(context.Background(), rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(12)))
	require.NoError(t, err)
	require.Nil(t, missingByNumber)

	missingByHash, err := api.GetBlockReceipts(context.Background(), rpc.BlockNumberOrHashWithHash(common.Hash{0xff}, false))
	require.NoError(t, err)
	require.Nil(t, missingByHash)

	emptyByHash, err := api.GetBlockReceipts(context.Background(), rpc.BlockNumberOrHashWithHash(common.Hash{}, false))
	require.NoError(t, err)
	require.Nil(t, emptyByHash)

	backend.err = errors.New("receipts backend failed")
	_, err = api.GetBlockReceipts(context.Background(), rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(11)))
	require.ErrorContains(t, err, "receipts backend failed")

	backend.err = nil
	backend.blockErr = errors.New("block backend failed")
	_, err = api.GetBlockReceipts(context.Background(), rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(11)))
	require.ErrorContains(t, err, "block backend failed")

	backend.blockErr = nil
	backend.receipts = nil
	_, err = api.GetBlockReceipts(context.Background(), rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(11)))
	require.ErrorContains(t, err, "receipts length mismatch")
}

type blockLookupBackendMock struct {
	*backendMock
	headersByNumber map[rpc.BlockNumber]*types.Header
	headersByHash   map[common.Hash]*types.Header
	blocksByNumber  map[rpc.BlockNumber]*types.Block
	blocksByHash    map[common.Hash]*types.Block
	notFoundErr     error
}

type accessListStateOverrideBackendMock struct {
	*createAccessListBackendMock
	xdcx *XDCx.XDCX
}

type accessListChainContext struct {
	header *types.Header
	engine consensus.Engine
}

func (c accessListChainContext) Engine() consensus.Engine {
	return c.engine
}

func (c accessListChainContext) GetHeader(hash common.Hash, number uint64) *types.Header {
	if c.header == nil {
		return nil
	}
	if c.header.Hash() == hash && c.header.Number.Uint64() == number {
		return c.header
	}
	return nil
}

func (b *accessListStateOverrideBackendMock) XDCxService() *XDCx.XDCX {
	return b.xdcx
}

func (b *accessListStateOverrideBackendMock) GetEVM(ctx context.Context, state *state.StateDB, XDCxState *tradingstate.TradingStateDB, header *types.Header, vmConfig *vm.Config, blockContext *vm.BlockContext) (*vm.EVM, func() error, error) {
	if vmConfig == nil {
		vmConfig = new(vm.Config)
	}
	chainCtx := accessListChainContext{header: header, engine: b.Engine()}
	context := core.NewEVMBlockContext(header, chainCtx, nil)
	if blockContext != nil {
		context = *blockContext
	}
	ev := vm.NewEVM(context, state, XDCxState, b.ChainConfig(), *vmConfig)
	return ev, func() error { return nil }, nil
}

func TestCreateAccessListWithStateOverrides(t *testing.T) {
	// Initialize test backend
	genesis := &core.Genesis{
		Config: params.TestChainConfig,
		Alloc: types.GenesisAlloc{
			common.HexToAddress("0x71562b71999873db5b286df957af199ec94617f7"): {Balance: big.NewInt(1000000000000000000)},
		},
	}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	backend := &accessListStateOverrideBackendMock{
		createAccessListBackendMock: &createAccessListBackendMock{
			estimateBackendMock: &estimateBackendMock{
				backendMock: newBackendMock(),
				stateDB:     stateDB,
				header:      block.Header(),
				engine:      ethash.NewFaker(),
			},
			block: block,
		},
		xdcx: &XDCx.XDCX{StateCache: tradingstate.NewDatabase(rawdb.NewMemoryDatabase())},
	}

	// Create a new BlockChainAPI instance
	api := NewBlockChainAPI(backend, nil)

	// Create test contract code - a simple storage contract
	//
	// SPDX-License-Identifier: MIT
	// pragma solidity ^0.8.0;
	//
	// contract SimpleStorage {
	//     uint256 private value;
	//
	//     function retrieve() public view returns (uint256) {
	//         return value;
	//     }
	// }
	var (
		contractCode = hexutil.Bytes(common.Hex2Bytes("6080604052348015600f57600080fd5b506004361060285760003560e01c80632e64cec114602d575b600080fd5b60336047565b604051603e91906067565b60405180910390f35b60008054905090565b6000819050919050565b6061816050565b82525050565b6000602082019050607a6000830184605a565b9291505056"))
		// Create state overrides with more complete state
		contractAddr = common.HexToAddress("0x1234567890123456789012345678901234567890")
		nonce        = hexutil.Uint64(1)
		overrides    = &override.StateOverride{
			contractAddr: override.OverrideAccount{
				Code:    &contractCode,
				Balance: (*hexutil.Big)(big.NewInt(1000000000000000000)),
				Nonce:   &nonce,
				State: map[common.Hash]common.Hash{
					{}: common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000002a"),
				},
			},
		}
	)

	// Create transaction arguments with gas and value
	var (
		from = common.HexToAddress("0x71562b71999873db5b286df957af199ec94617f7")
		data = hexutil.Bytes(common.Hex2Bytes("2e64cec1")) // retrieve()
		gas  = hexutil.Uint64(100000)
		args = TransactionArgs{
			From:     &from,
			To:       &contractAddr,
			Data:     &data,
			Gas:      &gas,
			GasPrice: (*hexutil.Big)(big.NewInt(1)),
			Value:    new(hexutil.Big),
		}
	)
	// Call CreateAccessList
	result, err := api.CreateAccessList(context.Background(), args, nil, overrides)
	if err != nil {
		t.Fatalf("Failed to create access list: %v", err)
	}
	if result == nil {
		t.Fatalf("Failed to create access list: result is nil")
	}
	require.NotNil(t, result.Accesslist)

	// Verify access list contains the contract address and storage slot
	expected := &types.AccessList{{
		Address:     contractAddr,
		StorageKeys: []common.Hash{{}},
	}}
	require.Equal(t, expected, result.Accesslist)
}

func TestCreateAccessListWithMovePrecompile(t *testing.T) {
	t.Parallel()

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	sha256Addr := common.BytesToAddress([]byte{0x2})
	newSha256Addr := common.BytesToAddress([]byte{0x10, 0})
	sha256Input := hexutil.Bytes([]byte("hello"))

	genesis := &core.Genesis{
		Config: params.MergedTestChainConfig,
		Alloc: types.GenesisAlloc{
			from: {Balance: big.NewInt(params.Ether)},
		},
	}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	backend := &accessListStateOverrideBackendMock{
		createAccessListBackendMock: &createAccessListBackendMock{
			estimateBackendMock: &estimateBackendMock{
				backendMock: newBackendMock(),
				stateDB:     stateDB,
				header:      block.Header(),
				engine:      ethash.NewFaker(),
			},
			block: block,
		},
		xdcx: &XDCx.XDCX{StateCache: tradingstate.NewDatabase(rawdb.NewMemoryDatabase())},
	}
	api := NewBlockChainAPI(backend, nil)

	overrides := &override.StateOverride{
		sha256Addr: override.OverrideAccount{MovePrecompileTo: &newSha256Addr},
	}
	gas := hexutil.Uint64(100000)

	result, err := api.CreateAccessList(context.Background(), TransactionArgs{
		From:     &from,
		To:       &newSha256Addr,
		Data:     &sha256Input,
		Gas:      &gas,
		GasPrice: (*hexutil.Big)(big.NewInt(1)),
	}, nil, overrides)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Accesslist)
}

func TestEstimateGasWithMovePrecompile(t *testing.T) {
	t.Parallel()

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	sha256Addr := common.BytesToAddress([]byte{0x2})
	newSha256Addr := common.BytesToAddress([]byte{0x10, 0})
	sha256Input := hexutil.Bytes([]byte("hello"))

	genesis := &core.Genesis{
		Config: params.MergedTestChainConfig,
		Alloc: types.GenesisAlloc{
			from: {Balance: big.NewInt(params.Ether)},
		},
	}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	backend := &estimateBackendMock{
		backendMock: newBackendMock(),
		stateDB:     stateDB,
		header:      block.Header(),
		engine:      ethash.NewFaker(),
	}
	api := NewBlockChainAPI(backend, nil)

	overrides := &override.StateOverride{
		sha256Addr: override.OverrideAccount{MovePrecompileTo: &newSha256Addr},
	}
	_, err = api.EstimateGas(context.Background(), TransactionArgs{
		From: &from,
		To:   &newSha256Addr,
		Data: &sha256Input,
	}, nil, overrides, nil)
	require.ErrorContains(t, err, "is not a precompile")
}

type receiptBackendMock struct {
	*backendMock
	db       ethdb.Database
	block    *types.Block
	receipts types.Receipts
	blockErr error
	err      error
}

func TestNetAPIListeningAndVersion(t *testing.T) {
	t.Parallel()

	api := NewNetAPI(&p2p.Server{}, 12345)
	require.True(t, api.Listening())
	require.Equal(t, "12345", api.Version())
}

func TestNewRPCTransactionLegacyMined(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	require.NoError(t, err)
	config := params.TestChainConfig
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	tx, err := types.SignNewTx(key, types.LatestSigner(config), &types.LegacyTx{
		Nonce:    5,
		GasPrice: big.NewInt(7),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(3),
	})
	require.NoError(t, err)

	blockHash := common.HexToHash("0x1234")
	rpcTx := newRPCTransaction(tx, blockHash, 99, 1, big.NewInt(10), config)
	require.NotNil(t, rpcTx)
	require.NotNil(t, rpcTx.BlockHash)
	require.Equal(t, blockHash, *rpcTx.BlockHash)
	require.NotNil(t, rpcTx.BlockNumber)
	require.Equal(t, (*hexutil.Big)(big.NewInt(99)), rpcTx.BlockNumber)
	require.NotNil(t, rpcTx.TransactionIndex)
	require.Equal(t, hexutil.Uint64(1), *rpcTx.TransactionIndex)
	require.Equal(t, tx.Hash(), rpcTx.Hash)
	require.Equal(t, (*hexutil.Big)(tx.GasPrice()), rpcTx.GasPrice)
	require.Equal(t, (*hexutil.Big)(tx.ChainId()), rpcTx.ChainID)
	require.Nil(t, rpcTx.GasFeeCap)
	require.Nil(t, rpcTx.GasTipCap)
}

func TestNewRPCTransactionLegacyPending(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	require.NoError(t, err)
	config := params.TestChainConfig
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	tx, err := types.SignNewTx(key, types.LatestSigner(config), &types.LegacyTx{
		Nonce:    6,
		GasPrice: big.NewInt(9),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(4),
	})
	require.NoError(t, err)

	rpcTx := newRPCTransaction(tx, common.Hash{}, 0, 0, nil, config)
	require.NotNil(t, rpcTx)
	require.Nil(t, rpcTx.BlockHash)
	require.Nil(t, rpcTx.BlockNumber)
	require.Nil(t, rpcTx.TransactionIndex)
	require.Equal(t, tx.Hash(), rpcTx.Hash)
	require.Equal(t, (*hexutil.Big)(tx.GasPrice()), rpcTx.GasPrice)
	require.Equal(t, (*hexutil.Big)(tx.ChainId()), rpcTx.ChainID)
	require.Nil(t, rpcTx.GasFeeCap)
	require.Nil(t, rpcTx.GasTipCap)
}

func TestNewRPCTransactionDynamicPending(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)
	config := params.TestChainConfig
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	tx, err := types.SignNewTx(key, types.LatestSigner(config), &types.DynamicFeeTx{
		ChainID:   config.ChainID,
		Nonce:     7,
		GasTipCap: big.NewInt(3),
		GasFeeCap: big.NewInt(18),
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(5),
	})
	require.NoError(t, err)

	rpcTx := newRPCTransaction(tx, common.Hash{}, 0, 0, big.NewInt(10), config)
	require.NotNil(t, rpcTx)
	require.Nil(t, rpcTx.BlockHash)
	require.Nil(t, rpcTx.BlockNumber)
	require.Nil(t, rpcTx.TransactionIndex)
	require.Equal(t, tx.Hash(), rpcTx.Hash)
	require.Equal(t, (*hexutil.Big)(tx.GasFeeCap()), rpcTx.GasPrice)
	require.Equal(t, (*hexutil.Big)(tx.GasFeeCap()), rpcTx.GasFeeCap)
	require.Equal(t, (*hexutil.Big)(tx.GasTipCap()), rpcTx.GasTipCap)
	require.NotNil(t, rpcTx.ChainID)
	require.NotNil(t, rpcTx.YParity)
}

func TestNewRPCTransactionAccessListPending(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)
	config := params.TestChainConfig
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	accessList := types.AccessList{{Address: to, StorageKeys: []common.Hash{common.HexToHash("0x1")}}}
	tx, err := types.SignNewTx(key, types.LatestSigner(config), &types.AccessListTx{
		ChainID:    config.ChainID,
		Nonce:      8,
		GasPrice:   big.NewInt(13),
		Gas:        25000,
		To:         &to,
		Value:      big.NewInt(6),
		AccessList: accessList,
	})
	require.NoError(t, err)

	rpcTx := newRPCTransaction(tx, common.Hash{}, 0, 0, nil, config)
	require.NotNil(t, rpcTx)
	require.EqualValues(t, types.AccessListTxType, rpcTx.Type)
	require.Equal(t, (*hexutil.Big)(tx.GasPrice()), rpcTx.GasPrice)
	require.NotNil(t, rpcTx.Accesses)
	require.Equal(t, accessList, *rpcTx.Accesses)
	require.NotNil(t, rpcTx.ChainID)
	require.NotNil(t, rpcTx.YParity)
	require.Nil(t, rpcTx.BlockHash)
	require.Nil(t, rpcTx.BlockNumber)
	require.Nil(t, rpcTx.TransactionIndex)
}

func TestNewRPCTransactionDynamicMinedFeeCapClamp(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)
	config := params.TestChainConfig
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	tx, err := types.SignNewTx(key, types.LatestSigner(config), &types.DynamicFeeTx{
		ChainID:   config.ChainID,
		Nonce:     9,
		GasTipCap: big.NewInt(5),
		GasFeeCap: big.NewInt(12),
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(7),
	})
	require.NoError(t, err)

	blockHash := common.HexToHash("0x5678")
	rpcTx := newRPCTransaction(tx, blockHash, 1200, 0, big.NewInt(20), config)
	require.NotNil(t, rpcTx)
	require.NotNil(t, rpcTx.BlockHash)
	require.Equal(t, blockHash, *rpcTx.BlockHash)
	require.Equal(t, (*hexutil.Big)(big.NewInt(12)), rpcTx.GasPrice)
	require.Equal(t, (*hexutil.Big)(tx.GasFeeCap()), rpcTx.GasFeeCap)
	require.Equal(t, (*hexutil.Big)(tx.GasTipCap()), rpcTx.GasTipCap)
}

func (b *blockLookupBackendMock) HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error) {
	if header, ok := b.headersByNumber[number]; ok {
		return header, nil
	}
	return nil, b.notFoundErr
}

func (b *blockLookupBackendMock) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	if header, ok := b.headersByHash[hash]; ok {
		return header, nil
	}
	return nil, b.notFoundErr
}

func (b *blockLookupBackendMock) BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error) {
	if block, ok := b.blocksByNumber[number]; ok {
		return block, nil
	}
	return nil, b.notFoundErr
}

func (b *blockLookupBackendMock) GetBlock(ctx context.Context, hash common.Hash) (*types.Block, error) {
	if block, ok := b.blocksByHash[hash]; ok {
		return block, nil
	}
	return nil, b.notFoundErr
}

func (b *blockLookupBackendMock) GetTd(ctx context.Context, hash common.Hash) *big.Int {
	return big.NewInt(123)
}

func (b *receiptBackendMock) ChainDb() ethdb.Database {
	return b.db
}

func (b *receiptBackendMock) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	if b.err != nil {
		return nil, b.err
	}
	if b.block != nil && b.block.Hash() == hash {
		return b.receipts, nil
	}
	return nil, nil
}

func (b *receiptBackendMock) BlockByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Block, error) {
	if b.blockErr != nil {
		return nil, b.blockErr
	}
	if b.block == nil {
		return nil, nil
	}
	if num, ok := blockNrOrHash.Number(); ok {
		if num == rpc.LatestBlockNumber || num == rpc.PendingBlockNumber {
			return b.block, nil
		}
		if num.Int64() >= 0 && uint64(num.Int64()) == b.block.NumberU64() {
			return b.block, nil
		}
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		if hash == b.block.Hash() {
			return b.block, nil
		}
	}
	return nil, nil
}

func TestRPCGetBlockOrHeaderBasic(t *testing.T) {
	t.Parallel()

	errNotFound := errors.New("not found")
	block := types.NewBlock(
		&types.Header{Number: big.NewInt(7), GasLimit: 10_000_000},
		&types.Body{},
		nil,
		newHasher(),
	)
	header := block.Header()

	backend := &blockLookupBackendMock{
		backendMock:     newBackendMock(),
		headersByNumber: map[rpc.BlockNumber]*types.Header{rpc.BlockNumber(7): header, rpc.PendingBlockNumber: header},
		headersByHash:   map[common.Hash]*types.Header{header.Hash(): header},
		blocksByNumber:  map[rpc.BlockNumber]*types.Block{rpc.BlockNumber(7): block, rpc.PendingBlockNumber: block},
		blocksByHash:    map[common.Hash]*types.Block{block.Hash(): block},
		notFoundErr:     errNotFound,
	}
	api := NewBlockChainAPI(backend, nil)

	gotHeaderByNumber, err := api.GetHeaderByNumber(context.Background(), rpc.BlockNumber(7))
	require.NoError(t, err)
	require.NotNil(t, gotHeaderByNumber)
	require.Equal(t, header.Hash(), gotHeaderByNumber["hash"])

	gotHeaderByHash := api.GetHeaderByHash(context.Background(), header.Hash())
	require.NotNil(t, gotHeaderByHash)
	require.Equal(t, header.Hash(), gotHeaderByHash["hash"])

	gotBlockByNumber, err := api.GetBlockByNumber(context.Background(), rpc.BlockNumber(7), false)
	require.NoError(t, err)
	require.NotNil(t, gotBlockByNumber)
	require.Equal(t, block.Hash(), gotBlockByNumber["hash"])

	gotBlockByHash, err := api.GetBlockByHash(context.Background(), block.Hash(), false)
	require.NoError(t, err)
	require.NotNil(t, gotBlockByHash)
	require.Equal(t, block.Hash(), gotBlockByHash["hash"])

	missingHeader, err := api.GetHeaderByNumber(context.Background(), rpc.BlockNumber(8))
	require.ErrorIs(t, err, errNotFound)
	require.Nil(t, missingHeader)

	missingBlock, err := api.GetBlockByNumber(context.Background(), rpc.BlockNumber(8), false)
	require.ErrorIs(t, err, errNotFound)
	require.Nil(t, missingBlock)

	missingHeaderByHash := api.GetHeaderByHash(context.Background(), common.Hash{0xff})
	require.Nil(t, missingHeaderByHash)
	emptyHeaderByHash := api.GetHeaderByHash(context.Background(), common.Hash{})
	require.Nil(t, emptyHeaderByHash)

	missingBlockByHash, err := api.GetBlockByHash(context.Background(), common.Hash{0xee}, false)
	require.ErrorIs(t, err, errNotFound)
	require.Nil(t, missingBlockByHash)
	emptyBlockByHash, err := api.GetBlockByHash(context.Background(), common.Hash{}, false)
	require.ErrorIs(t, err, errNotFound)
	require.Nil(t, emptyBlockByHash)

	pendingHeader, err := api.GetHeaderByNumber(context.Background(), rpc.PendingBlockNumber)
	require.NoError(t, err)
	require.Nil(t, pendingHeader["hash"])
	require.Nil(t, pendingHeader["nonce"])
	require.Nil(t, pendingHeader["miner"])

	pendingBlock, err := api.GetBlockByNumber(context.Background(), rpc.PendingBlockNumber, false)
	require.NoError(t, err)
	require.Nil(t, pendingBlock["hash"])
	require.Nil(t, pendingBlock["nonce"])
	require.Nil(t, pendingBlock["miner"])
	require.Nil(t, pendingBlock["number"])
}

func TestRPCGetBlockOrHeaderPendingFullTxMode(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)
	to := common.HexToAddress("0x703c4b2bd70c169f5717101caee543299fc946c7")
	tx, err := types.SignNewTx(key, types.LatestSigner(params.TestChainConfig), &types.LegacyTx{
		Nonce:    1,
		GasPrice: big.NewInt(7),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(3),
	})
	require.NoError(t, err)

	errNotFound := errors.New("not found")
	block := types.NewBlock(
		&types.Header{Number: big.NewInt(77), GasLimit: 10_000_000},
		&types.Body{Transactions: []*types.Transaction{tx}},
		nil,
		newHasher(),
	)
	backend := &blockLookupBackendMock{
		backendMock: newBackendMock(),
		headersByNumber: map[rpc.BlockNumber]*types.Header{
			rpc.BlockNumber(77):    block.Header(),
			rpc.PendingBlockNumber: block.Header(),
		},
		headersByHash: map[common.Hash]*types.Header{block.Hash(): block.Header()},
		blocksByNumber: map[rpc.BlockNumber]*types.Block{
			rpc.BlockNumber(77):    block,
			rpc.PendingBlockNumber: block,
		},
		blocksByHash: map[common.Hash]*types.Block{block.Hash(): block},
		notFoundErr:  errNotFound,
	}
	api := NewBlockChainAPI(backend, nil)

	pendingFullTx, err := api.GetBlockByNumber(context.Background(), rpc.PendingBlockNumber, true)
	require.NoError(t, err)
	require.NotNil(t, pendingFullTx)
	require.Nil(t, pendingFullTx["hash"])
	require.Nil(t, pendingFullTx["number"])

	pendingJSON, err := json.Marshal(pendingFullTx)
	require.NoError(t, err)
	require.Contains(t, string(pendingJSON), `"transactions":[{`)
	require.Contains(t, string(pendingJSON), tx.Hash().Hex())

	byHashFullTx, err := api.GetBlockByHash(context.Background(), block.Hash(), true)
	require.NoError(t, err)
	require.NotNil(t, byHashFullTx)
	require.Equal(t, block.Hash(), byHashFullTx["hash"])

	byHashJSON, err := json.Marshal(byHashFullTx)
	require.NoError(t, err)
	require.Contains(t, string(byHashJSON), `"transactions":[{`)
	require.Contains(t, string(byHashJSON), tx.Hash().Hex())
}

func TestGetBlockFullTxModes(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)
	to := common.HexToAddress("0x703c4b2bd70c169f5717101caee543299fc946c7")
	tx, err := types.SignNewTx(key, types.LatestSigner(params.TestChainConfig), &types.LegacyTx{
		Nonce:    1,
		GasPrice: big.NewInt(7),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(3),
	})
	require.NoError(t, err)

	block := types.NewBlock(
		&types.Header{Number: big.NewInt(55), GasLimit: 10_000_000},
		&types.Body{Transactions: []*types.Transaction{tx}},
		nil,
		newHasher(),
	)
	backend := &blockLookupBackendMock{
		backendMock:     newBackendMock(),
		headersByNumber: map[rpc.BlockNumber]*types.Header{rpc.BlockNumber(55): block.Header()},
		headersByHash:   map[common.Hash]*types.Header{block.Hash(): block.Header()},
		blocksByNumber:  map[rpc.BlockNumber]*types.Block{rpc.BlockNumber(55): block},
		blocksByHash:    map[common.Hash]*types.Block{block.Hash(): block},
		notFoundErr:     errors.New("not found"),
	}
	api := NewBlockChainAPI(backend, nil)

	fullByNumber, err := api.GetBlockByNumber(context.Background(), rpc.BlockNumber(55), true)
	require.NoError(t, err)
	require.NotNil(t, fullByNumber)
	fullByNumberJSON, err := json.Marshal(fullByNumber)
	require.NoError(t, err)
	require.Contains(t, string(fullByNumberJSON), `"transactions":[{`)
	require.Contains(t, string(fullByNumberJSON), tx.Hash().Hex())

	hashOnlyByNumber, err := api.GetBlockByNumber(context.Background(), rpc.BlockNumber(55), false)
	require.NoError(t, err)
	hashOnlyByNumberJSON, err := json.Marshal(hashOnlyByNumber)
	require.NoError(t, err)
	require.Contains(t, string(hashOnlyByNumberJSON), `"transactions":["`)
	require.Contains(t, string(hashOnlyByNumberJSON), tx.Hash().Hex())

	fullByHash, err := api.GetBlockByHash(context.Background(), block.Hash(), true)
	require.NoError(t, err)
	fullByHashJSON, err := json.Marshal(fullByHash)
	require.NoError(t, err)
	require.Contains(t, string(fullByHashJSON), `"transactions":[{`)
	require.Contains(t, string(fullByHashJSON), tx.Hash().Hex())
}

func TestGetUncleCountBasic(t *testing.T) {
	t.Parallel()

	block := types.NewBlock(
		&types.Header{Number: big.NewInt(33), GasLimit: 10_000_000},
		&types.Body{Uncles: []*types.Header{{Number: big.NewInt(31)}, {Number: big.NewInt(32)}}},
		nil,
		newHasher(),
	)
	backend := &blockLookupBackendMock{
		backendMock:     newBackendMock(),
		headersByNumber: map[rpc.BlockNumber]*types.Header{rpc.BlockNumber(33): block.Header()},
		headersByHash:   map[common.Hash]*types.Header{block.Hash(): block.Header()},
		blocksByNumber:  map[rpc.BlockNumber]*types.Block{rpc.BlockNumber(33): block},
		blocksByHash:    map[common.Hash]*types.Block{block.Hash(): block},
		notFoundErr:     errors.New("not found"),
	}
	api := NewBlockChainAPI(backend, nil)

	countByNumber := api.GetUncleCountByBlockNumber(context.Background(), rpc.BlockNumber(33))
	require.NotNil(t, countByNumber)
	require.Equal(t, hexutil.Uint(2), *countByNumber)

	countByHash := api.GetUncleCountByBlockHash(context.Background(), block.Hash())
	require.NotNil(t, countByHash)
	require.Equal(t, hexutil.Uint(2), *countByHash)

	missingByNumber := api.GetUncleCountByBlockNumber(context.Background(), rpc.BlockNumber(34))
	require.Nil(t, missingByNumber)

	missingByHash := api.GetUncleCountByBlockHash(context.Background(), common.Hash{0xaa})
	require.Nil(t, missingByHash)
}

func TestGetUncleByBlockSelectorsBasic(t *testing.T) {
	t.Parallel()

	uncle0 := &types.Header{Number: big.NewInt(41), GasLimit: 9_000_000}
	uncle1 := &types.Header{Number: big.NewInt(42), GasLimit: 9_500_000}
	block := types.NewBlock(
		&types.Header{Number: big.NewInt(43), GasLimit: 10_000_000},
		&types.Body{Uncles: []*types.Header{uncle0, uncle1}},
		nil,
		newHasher(),
	)
	errNotFound := errors.New("not found")
	backend := &blockLookupBackendMock{
		backendMock:     newBackendMock(),
		headersByNumber: map[rpc.BlockNumber]*types.Header{rpc.BlockNumber(43): block.Header()},
		headersByHash:   map[common.Hash]*types.Header{block.Hash(): block.Header()},
		blocksByNumber:  map[rpc.BlockNumber]*types.Block{rpc.BlockNumber(43): block},
		blocksByHash:    map[common.Hash]*types.Block{block.Hash(): block},
		notFoundErr:     errNotFound,
	}
	api := NewBlockChainAPI(backend, nil)

	gotByNumber, err := api.GetUncleByBlockNumberAndIndex(context.Background(), rpc.BlockNumber(43), hexutil.Uint(1))
	require.NoError(t, err)
	require.NotNil(t, gotByNumber)
	outByNumber, err := json.Marshal(gotByNumber)
	require.NoError(t, err)
	require.Contains(t, string(outByNumber), `"number":"0x2a"`)

	gotByHash, err := api.GetUncleByBlockHashAndIndex(context.Background(), block.Hash(), hexutil.Uint(0))
	require.NoError(t, err)
	require.NotNil(t, gotByHash)
	outByHash, err := json.Marshal(gotByHash)
	require.NoError(t, err)
	require.Contains(t, string(outByHash), `"number":"0x29"`)

	outOfRangeByNumber, err := api.GetUncleByBlockNumberAndIndex(context.Background(), rpc.BlockNumber(43), hexutil.Uint(2))
	require.NoError(t, err)
	require.Nil(t, outOfRangeByNumber)

	outOfRangeByHash, err := api.GetUncleByBlockHashAndIndex(context.Background(), block.Hash(), hexutil.Uint(2))
	require.NoError(t, err)
	require.Nil(t, outOfRangeByHash)

	missingByNumber, err := api.GetUncleByBlockNumberAndIndex(context.Background(), rpc.BlockNumber(44), hexutil.Uint(0))
	require.ErrorIs(t, err, errNotFound)
	require.Nil(t, missingByNumber)

	missingByHash, err := api.GetUncleByBlockHashAndIndex(context.Background(), common.Hash{0xbb}, hexutil.Uint(0))
	require.ErrorIs(t, err, errNotFound)
	require.Nil(t, missingByHash)
}

type signingBackendMock struct {
	*backendMock
	manager *accounts.Manager
}

func TestTransactionByBlockSelectorsBasic(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)
	signer := types.LatestSigner(params.TestChainConfig)
	to := common.Address{0x99}

	tx0, err := types.SignNewTx(key, signer, &types.LegacyTx{
		Nonce:    1,
		GasPrice: big.NewInt(2),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(1),
	})
	require.NoError(t, err)
	tx1, err := types.SignNewTx(key, signer, &types.LegacyTx{
		Nonce:    2,
		GasPrice: big.NewInt(3),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(2),
	})
	require.NoError(t, err)

	block := types.NewBlock(
		&types.Header{Number: big.NewInt(21), GasLimit: 8_000_000},
		&types.Body{Transactions: []*types.Transaction{tx0, tx1}},
		nil,
		newHasher(),
	)

	backend := &blockLookupBackendMock{
		backendMock:     newBackendMock(),
		headersByNumber: map[rpc.BlockNumber]*types.Header{rpc.BlockNumber(21): block.Header()},
		headersByHash:   map[common.Hash]*types.Header{block.Hash(): block.Header()},
		blocksByNumber:  map[rpc.BlockNumber]*types.Block{rpc.BlockNumber(21): block},
		blocksByHash:    map[common.Hash]*types.Block{block.Hash(): block},
	}
	api := NewTransactionAPI(backend, nil)

	countByNumber := api.GetBlockTransactionCountByNumber(context.Background(), rpc.BlockNumber(21))
	require.NotNil(t, countByNumber)
	require.Equal(t, hexutil.Uint(2), *countByNumber)

	countByHash := api.GetBlockTransactionCountByHash(context.Background(), block.Hash())
	require.NotNil(t, countByHash)
	require.Equal(t, hexutil.Uint(2), *countByHash)

	missingCount := api.GetBlockTransactionCountByNumber(context.Background(), rpc.BlockNumber(22))
	require.Nil(t, missingCount)
	missingCountByHash := api.GetBlockTransactionCountByHash(context.Background(), common.Hash{0xfe})
	require.Nil(t, missingCountByHash)

	rpcTxByNumber := api.GetTransactionByBlockNumberAndIndex(context.Background(), rpc.BlockNumber(21), hexutil.Uint(1))
	require.NotNil(t, rpcTxByNumber)
	require.Equal(t, tx1.Hash(), rpcTxByNumber.Hash)

	rpcTxByHash := api.GetTransactionByBlockHashAndIndex(context.Background(), block.Hash(), hexutil.Uint(0))
	require.NotNil(t, rpcTxByHash)
	require.Equal(t, tx0.Hash(), rpcTxByHash.Hash)

	missingTxByNumber := api.GetTransactionByBlockNumberAndIndex(context.Background(), rpc.BlockNumber(25), hexutil.Uint(0))
	require.Nil(t, missingTxByNumber)

	missingTxByHash := api.GetTransactionByBlockHashAndIndex(context.Background(), common.Hash{0xfd}, hexutil.Uint(0))
	require.Nil(t, missingTxByHash)

	outOfRange := api.GetTransactionByBlockNumberAndIndex(context.Background(), rpc.BlockNumber(21), hexutil.Uint(2))
	require.Nil(t, outOfRange)
	outOfRangeByHash := api.GetTransactionByBlockHashAndIndex(context.Background(), block.Hash(), hexutil.Uint(2))
	require.Nil(t, outOfRangeByHash)

	rawByNumber := api.GetRawTransactionByBlockNumberAndIndex(context.Background(), rpc.BlockNumber(21), hexutil.Uint(0))
	encodedTx0, err := tx0.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, hexutil.Bytes(encodedTx0), rawByNumber)

	rawByHash := api.GetRawTransactionByBlockHashAndIndex(context.Background(), block.Hash(), hexutil.Uint(1))
	encodedTx1, err := tx1.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, hexutil.Bytes(encodedTx1), rawByHash)

	rawMissingByNumber := api.GetRawTransactionByBlockNumberAndIndex(context.Background(), rpc.BlockNumber(25), hexutil.Uint(0))
	require.Nil(t, rawMissingByNumber)
	rawOutOfRangeByNumber := api.GetRawTransactionByBlockNumberAndIndex(context.Background(), rpc.BlockNumber(21), hexutil.Uint(3))
	require.Nil(t, rawOutOfRangeByNumber)

	rawMissingByHash := api.GetRawTransactionByBlockHashAndIndex(context.Background(), common.Hash{0xfc}, hexutil.Uint(0))
	require.Nil(t, rawMissingByHash)

	rawOutOfRange := api.GetRawTransactionByBlockHashAndIndex(context.Background(), block.Hash(), hexutil.Uint(3))
	require.Nil(t, rawOutOfRange)

	dynTx, err := types.SignNewTx(key, signer, &types.DynamicFeeTx{
		ChainID:   params.TestChainConfig.ChainID,
		Nonce:     3,
		GasTipCap: big.NewInt(4),
		GasFeeCap: big.NewInt(30),
		Gas:       30000,
		To:        &to,
		Value:     big.NewInt(3),
	})
	require.NoError(t, err)

	dynBlock := types.NewBlock(
		&types.Header{Number: big.NewInt(22), GasLimit: 8_000_000, BaseFee: big.NewInt(10)},
		&types.Body{Transactions: []*types.Transaction{dynTx}},
		nil,
		newHasher(),
	)
	backend.blocksByNumber[rpc.BlockNumber(22)] = dynBlock
	backend.blocksByHash[dynBlock.Hash()] = dynBlock

	rpcDyn := api.GetTransactionByBlockNumberAndIndex(context.Background(), rpc.BlockNumber(22), hexutil.Uint(0))
	require.NotNil(t, rpcDyn)
	require.Equal(t, dynTx.Hash(), rpcDyn.Hash)
	require.Equal(t, hexutil.Uint64(types.DynamicFeeTxType), rpcDyn.Type)
	require.Equal(t, (*hexutil.Big)(big.NewInt(30)), rpcDyn.GasFeeCap)
	require.Equal(t, (*hexutil.Big)(big.NewInt(4)), rpcDyn.GasTipCap)
	require.Equal(t, (*hexutil.Big)(big.NewInt(14)), rpcDyn.GasPrice)

	rpcDynByHash := api.GetTransactionByBlockHashAndIndex(context.Background(), dynBlock.Hash(), hexutil.Uint(0))
	require.NotNil(t, rpcDynByHash)
	require.Equal(t, dynTx.Hash(), rpcDynByHash.Hash)
	require.Equal(t, hexutil.Uint64(types.DynamicFeeTxType), rpcDynByHash.Type)
	require.Equal(t, (*hexutil.Big)(big.NewInt(30)), rpcDynByHash.GasFeeCap)
	require.Equal(t, (*hexutil.Big)(big.NewInt(4)), rpcDynByHash.GasTipCap)
	require.Equal(t, (*hexutil.Big)(big.NewInt(14)), rpcDynByHash.GasPrice)
}

func TestGetTransactionReceiptBasic(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	require.NoError(t, err)
	signer := types.LatestSigner(params.TestChainConfig)
	to := common.Address{0xab}

	tx, err := types.SignNewTx(key, signer, &types.LegacyTx{
		Nonce:    1,
		GasPrice: big.NewInt(2),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(3),
	})
	require.NoError(t, err)

	block := types.NewBlock(
		&types.Header{Number: big.NewInt(9), GasLimit: 8_000_000},
		&types.Body{Transactions: []*types.Transaction{tx}},
		nil,
		newHasher(),
	)
	receipts := types.Receipts{{
		Status:            types.ReceiptStatusSuccessful,
		CumulativeGasUsed: 21000,
		GasUsed:           21000,
		EffectiveGasPrice: big.NewInt(2),
	}}

	db := rawdb.NewMemoryDatabase()
	rawdb.WriteBlock(db, block)
	rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	rawdb.WriteTxLookupEntriesByBlock(db, block)

	backend := &receiptBackendMock{backendMock: newBackendMock(), db: db, block: block, receipts: receipts}
	api := NewTransactionAPI(backend, nil)

	got, err := api.GetTransactionReceipt(context.Background(), tx.Hash())
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, tx.Hash(), got["transactionHash"])
	require.Equal(t, block.Hash(), got["blockHash"])
	require.Equal(t, hexutil.Uint64(0), got["transactionIndex"])
	require.Equal(t, hexutil.Uint64(block.NumberU64()), got["blockNumber"])
	require.Equal(t, []*types.Log{}, got["logs"])

	backend.err = errors.New("receipt lookup failed")
	_, err = api.GetTransactionReceipt(context.Background(), tx.Hash())
	require.ErrorContains(t, err, "receipt lookup failed")

	backend.err = nil
	backend.receipts = nil
	outOfRange, err := api.GetTransactionReceipt(context.Background(), tx.Hash())
	require.NoError(t, err)
	require.Nil(t, outOfRange)

	missing, err := api.GetTransactionReceipt(context.Background(), common.Hash{0xff})
	require.NoError(t, err)
	require.Nil(t, missing)

	empty, err := api.GetTransactionReceipt(context.Background(), common.Hash{})
	require.NoError(t, err)
	require.Nil(t, empty)
}

type txFeeCapBackendMock struct {
	*backendMock
	feeCap float64
}

func TestGetTransactionReceiptIndexedTransaction(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	require.NoError(t, err)
	signer := types.LatestSigner(params.TestChainConfig)
	to := common.Address{0xbc}

	tx0, err := types.SignNewTx(key, signer, &types.LegacyTx{
		Nonce:    15,
		GasPrice: big.NewInt(2),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(1),
	})
	require.NoError(t, err)
	tx1, err := types.SignNewTx(key, signer, &types.LegacyTx{
		Nonce:    16,
		GasPrice: big.NewInt(3),
		Gas:      22000,
		To:       &to,
		Value:    big.NewInt(2),
	})
	require.NoError(t, err)

	block := types.NewBlock(
		&types.Header{Number: big.NewInt(24), GasLimit: 8_000_000},
		&types.Body{Transactions: []*types.Transaction{tx0, tx1}},
		nil,
		newHasher(),
	)
	receipts := types.Receipts{
		{
			Status:            types.ReceiptStatusSuccessful,
			CumulativeGasUsed: 21000,
			GasUsed:           21000,
			EffectiveGasPrice: big.NewInt(2),
		},
		{
			Status:            types.ReceiptStatusSuccessful,
			CumulativeGasUsed: 43000,
			GasUsed:           22000,
			EffectiveGasPrice: big.NewInt(3),
		},
	}

	db := rawdb.NewMemoryDatabase()
	rawdb.WriteBlock(db, block)
	rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	rawdb.WriteTxLookupEntriesByBlock(db, block)

	backend := &receiptBackendMock{backendMock: newBackendMock(), db: db, block: block, receipts: receipts}
	api := NewTransactionAPI(backend, nil)

	got, err := api.GetTransactionReceipt(context.Background(), tx1.Hash())
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, tx1.Hash(), got["transactionHash"])
	require.Equal(t, hexutil.Uint64(1), got["transactionIndex"])
	require.Equal(t, hexutil.Uint64(43000), got["cumulativeGasUsed"])
}

type sendTxBackendMock struct {
	*backendMock
	sendErr error
	lastTx  *types.Transaction
	feeCap  float64
}

func TestGetTransactionReceiptContractCreation(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	require.NoError(t, err)
	signer := types.LatestSigner(params.TestChainConfig)

	tx, err := types.SignNewTx(key, signer, &types.LegacyTx{
		Nonce:    3,
		GasPrice: big.NewInt(4),
		Gas:      53000,
		To:       nil,
		Data:     []byte{0x60, 0x00},
	})
	require.NoError(t, err)

	block := types.NewBlock(
		&types.Header{Number: big.NewInt(10), GasLimit: 8_000_000},
		&types.Body{Transactions: []*types.Transaction{tx}},
		nil,
		newHasher(),
	)
	contract := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	receipts := types.Receipts{{
		Status:            types.ReceiptStatusSuccessful,
		CumulativeGasUsed: 53000,
		GasUsed:           53000,
		ContractAddress:   contract,
		EffectiveGasPrice: big.NewInt(4),
	}}

	db := rawdb.NewMemoryDatabase()
	rawdb.WriteBlock(db, block)
	rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	rawdb.WriteTxLookupEntriesByBlock(db, block)

	backend := &receiptBackendMock{backendMock: newBackendMock(), db: db, block: block, receipts: receipts}
	api := NewTransactionAPI(backend, nil)

	got, err := api.GetTransactionReceipt(context.Background(), tx.Hash())
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, contract, got["contractAddress"])
	require.Nil(t, got["to"])
}

func TestGetTransactionReceiptPostStateRoot(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	require.NoError(t, err)
	signer := types.LatestSigner(params.TestChainConfig)
	to := common.Address{0xef}

	tx, err := types.SignNewTx(key, signer, &types.LegacyTx{
		Nonce:    12,
		GasPrice: big.NewInt(6),
		Gas:      25000,
		To:       &to,
		Value:    big.NewInt(5),
	})
	require.NoError(t, err)

	block := types.NewBlock(
		&types.Header{Number: big.NewInt(19), GasLimit: 8_000_000},
		&types.Body{Transactions: []*types.Transaction{tx}},
		nil,
		newHasher(),
	)
	receipts := types.Receipts{{
		PostState:         []byte{0x01, 0x02, 0x03},
		CumulativeGasUsed: 25000,
		GasUsed:           25000,
		EffectiveGasPrice: big.NewInt(6),
	}}

	db := rawdb.NewMemoryDatabase()
	rawdb.WriteBlock(db, block)
	rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	rawdb.WriteTxLookupEntriesByBlock(db, block)

	backend := &receiptBackendMock{backendMock: newBackendMock(), db: db, block: block, receipts: receipts}
	api := NewTransactionAPI(backend, nil)

	got, err := api.GetTransactionReceipt(context.Background(), tx.Hash())
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, hexutil.Bytes{0x01, 0x02, 0x03}, got["root"])
	_, hasStatus := got["status"]
	require.False(t, hasStatus)
}

func TestGetTransactionReceiptFailedStatus(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	require.NoError(t, err)
	signer := types.LatestSigner(params.TestChainConfig)
	to := common.Address{0xed}

	tx, err := types.SignNewTx(key, signer, &types.LegacyTx{
		Nonce:    13,
		GasPrice: big.NewInt(6),
		Gas:      26000,
		To:       &to,
		Value:    big.NewInt(5),
	})
	require.NoError(t, err)

	block := types.NewBlock(
		&types.Header{Number: big.NewInt(20), GasLimit: 8_000_000},
		&types.Body{Transactions: []*types.Transaction{tx}},
		nil,
		newHasher(),
	)
	receipts := types.Receipts{{
		Status:            types.ReceiptStatusFailed,
		CumulativeGasUsed: 26000,
		GasUsed:           26000,
		EffectiveGasPrice: big.NewInt(6),
	}}

	db := rawdb.NewMemoryDatabase()
	rawdb.WriteBlock(db, block)
	rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	rawdb.WriteTxLookupEntriesByBlock(db, block)

	backend := &receiptBackendMock{backendMock: newBackendMock(), db: db, block: block, receipts: receipts}
	api := NewTransactionAPI(backend, nil)

	got, err := api.GetTransactionReceipt(context.Background(), tx.Hash())
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, hexutil.Uint(types.ReceiptStatusFailed), got["status"])
	_, hasRoot := got["root"]
	require.False(t, hasRoot)
}

type txLookupBackendMock struct {
	*backendMock
	db        ethdb.Database
	headers   map[common.Hash]*types.Header
	poolTxs   map[common.Hash]*types.Transaction
	current   *types.Header
	headerErr error
}

func TestGetTransactionReceiptWithLogs(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	require.NoError(t, err)
	signer := types.LatestSigner(params.TestChainConfig)
	to := common.Address{0xac}

	tx, err := types.SignNewTx(key, signer, &types.LegacyTx{
		Nonce:    14,
		GasPrice: big.NewInt(7),
		Gas:      27000,
		To:       &to,
		Value:    big.NewInt(6),
	})
	require.NoError(t, err)

	block := types.NewBlock(
		&types.Header{Number: big.NewInt(23), GasLimit: 8_000_000},
		&types.Body{Transactions: []*types.Transaction{tx}},
		nil,
		newHasher(),
	)
	logEntry := &types.Log{Address: to, Topics: []common.Hash{{0x1}}, Data: []byte{0xaa, 0xbb}}
	receipts := types.Receipts{{
		Status:            types.ReceiptStatusSuccessful,
		CumulativeGasUsed: 27000,
		GasUsed:           27000,
		EffectiveGasPrice: big.NewInt(7),
		Logs:              []*types.Log{logEntry},
	}}

	db := rawdb.NewMemoryDatabase()
	rawdb.WriteBlock(db, block)
	rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	rawdb.WriteTxLookupEntriesByBlock(db, block)

	backend := &receiptBackendMock{backendMock: newBackendMock(), db: db, block: block, receipts: receipts}
	api := NewTransactionAPI(backend, nil)

	got, err := api.GetTransactionReceipt(context.Background(), tx.Hash())
	require.NoError(t, err)
	require.NotNil(t, got)
	logs, ok := got["logs"].([]*types.Log)
	require.True(t, ok)
	require.Len(t, logs, 1)
	require.Equal(t, to, logs[0].Address)
	require.Equal(t, []byte{0xaa, 0xbb}, logs[0].Data)
}

func TestGetBlockReceiptsBasic(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	require.NoError(t, err)
	signer := types.LatestSigner(params.TestChainConfig)
	to := common.Address{0xcd}

	tx, err := types.SignNewTx(key, signer, &types.LegacyTx{
		Nonce:    2,
		GasPrice: big.NewInt(5),
		Gas:      22000,
		To:       &to,
		Value:    big.NewInt(7),
	})
	require.NoError(t, err)

	block := types.NewBlock(
		&types.Header{Number: big.NewInt(11), GasLimit: 8_000_000},
		&types.Body{Transactions: []*types.Transaction{tx}},
		nil,
		newHasher(),
	)
	receipts := types.Receipts{{
		Status:            types.ReceiptStatusSuccessful,
		CumulativeGasUsed: 22000,
		GasUsed:           22000,
		EffectiveGasPrice: big.NewInt(5),
	}}

	backend := &receiptBackendMock{backendMock: newBackendMock(), block: block, receipts: receipts}
	api := NewBlockChainAPI(backend, nil)

	got, err := api.GetBlockReceipts(context.Background(), rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(11)))
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, tx.Hash(), got[0]["transactionHash"])
	require.Equal(t, block.Hash(), got[0]["blockHash"])

	gotByHash, err := api.GetBlockReceipts(context.Background(), rpc.BlockNumberOrHashWithHash(block.Hash(), false))
	require.NoError(t, err)
	require.Len(t, gotByHash, 1)
	require.Equal(t, tx.Hash(), gotByHash[0]["transactionHash"])

	gotLatest, err := api.GetBlockReceipts(context.Background(), rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber))
	require.NoError(t, err)
	require.Len(t, gotLatest, 1)

	gotPending, err := api.GetBlockReceipts(context.Background(), rpc.BlockNumberOrHashWithNumber(rpc.PendingBlockNumber))
	require.NoError(t, err)
	require.Len(t, gotPending, 1)

	missing, err := api.GetBlockReceipts(context.Background(), rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(12)))
	require.NoError(t, err)
	require.Nil(t, missing)

	missingByHash, err := api.GetBlockReceipts(context.Background(), rpc.BlockNumberOrHashWithHash(common.Hash{}, false))
	require.NoError(t, err)
	require.Nil(t, missingByHash)

	backend.err = errors.New("receipts backend failed")
	_, err = api.GetBlockReceipts(context.Background(), rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(11)))
	require.ErrorContains(t, err, "receipts backend failed")

	backend.err = nil
	backend.blockErr = errors.New("block backend failed")
	_, err = api.GetBlockReceipts(context.Background(), rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(11)))
	require.ErrorContains(t, err, "block backend failed")

	backend.err = nil
	backend.blockErr = nil
	backend.receipts = nil
	_, err = api.GetBlockReceipts(context.Background(), rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(11)))
	require.ErrorContains(t, err, "receipts length mismatch")
}

func TestGetBlockReceiptsMultipleTransactions(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	require.NoError(t, err)
	signer := types.LatestSigner(params.TestChainConfig)
	to := common.Address{0xaa}

	tx0, err := types.SignNewTx(key, signer, &types.LegacyTx{
		Nonce:    20,
		GasPrice: big.NewInt(7),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(1),
	})
	require.NoError(t, err)
	tx1, err := types.SignNewTx(key, signer, &types.LegacyTx{
		Nonce:    21,
		GasPrice: big.NewInt(8),
		Gas:      22000,
		To:       &to,
		Value:    big.NewInt(2),
	})
	require.NoError(t, err)

	block := types.NewBlock(
		&types.Header{Number: big.NewInt(30), GasLimit: 8_000_000},
		&types.Body{Transactions: []*types.Transaction{tx0, tx1}},
		nil,
		newHasher(),
	)
	receipts := types.Receipts{
		{
			Status:            types.ReceiptStatusSuccessful,
			CumulativeGasUsed: 21000,
			GasUsed:           21000,
			EffectiveGasPrice: big.NewInt(7),
		},
		{
			Status:            types.ReceiptStatusSuccessful,
			CumulativeGasUsed: 43000,
			GasUsed:           22000,
			EffectiveGasPrice: big.NewInt(8),
		},
	}

	backend := &receiptBackendMock{backendMock: newBackendMock(), block: block, receipts: receipts}
	api := NewBlockChainAPI(backend, nil)

	got, err := api.GetBlockReceipts(context.Background(), rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(30)))
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Equal(t, tx0.Hash(), got[0]["transactionHash"])
	require.Equal(t, tx1.Hash(), got[1]["transactionHash"])
	require.Equal(t, hexutil.Uint64(0), got[0]["transactionIndex"])
	require.Equal(t, hexutil.Uint64(1), got[1]["transactionIndex"])
}

func (b *signingBackendMock) AccountManager() *accounts.Manager {
	return b.manager
}

type nonceBackendMock struct {
	*backendMock
	poolNonce uint64
	poolErr   error
	stateDB   *state.StateDB
	header    *types.Header
	stateErr  error
}

func (b *signingBackendMock) CurrentBlock() *types.Header {
	return b.current
}

func (b *txFeeCapBackendMock) RPCTxFeeCap() float64 {
	return b.feeCap
}

type txPoolBackendMock struct {
	*backendMock
	manager *accounts.Manager
	poolTxs types.Transactions
	poolErr error
	sendErr error
	lastTx  *types.Transaction
	current *types.Header
}

func (b *sendTxBackendMock) SendTx(ctx context.Context, signedTx *types.Transaction) error {
	b.lastTx = signedTx
	if b.sendErr != nil {
		return b.sendErr
	}
	return nil
}

func (b *sendTxBackendMock) CurrentBlock() *types.Header {
	return b.current
}

func (b *sendTxBackendMock) RPCTxFeeCap() float64 {
	return b.feeCap
}

func (b *txLookupBackendMock) ChainDb() ethdb.Database {
	return b.db
}

func (b *txLookupBackendMock) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	if b.headerErr != nil {
		return nil, b.headerErr
	}
	if h, ok := b.headers[hash]; ok {
		return h, nil
	}
	return nil, nil
}

type txPoolFeeCapBackendMock struct {
	*txPoolBackendMock
	feeCap float64
}

func (b *txLookupBackendMock) GetPoolTransaction(txHash common.Hash) *types.Transaction {
	if tx, ok := b.poolTxs[txHash]; ok {
		return tx
	}
	return nil
}

type txPoolContentBackendMock struct {
	*backendMock
	pendingContent map[common.Address][]*types.Transaction
	queuedContent  map[common.Address][]*types.Transaction
	current        *types.Header
	pendingCount   int
	queuedCount    int
}

func (b *txLookupBackendMock) CurrentHeader() *types.Header {
	return b.current
}

func (b *nonceBackendMock) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
	if b.poolErr != nil {
		return 0, b.poolErr
	}
	return b.poolNonce, nil
}

func (b *nonceBackendMock) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	if b.stateErr != nil {
		return nil, nil, b.stateErr
	}
	return b.stateDB, b.header, nil
}

func (b *txPoolBackendMock) AccountManager() *accounts.Manager {
	return b.manager
}

type ethereumAPIBackendMock struct {
	*backendMock
	tipCap          *big.Int
	tipErr          error
	feeOldest       *big.Int
	feeReward       [][]*big.Int
	feeBaseFee      []*big.Int
	feeGasUsedRatio []float64
	feeErr          error
	protocolVersion int
	dl              *downloader.Downloader
}

func (b *txPoolBackendMock) GetPoolTransactions() (types.Transactions, error) {
	if b.poolErr != nil {
		return nil, b.poolErr
	}
	return b.poolTxs, nil
}

func (b *txPoolBackendMock) SendTx(ctx context.Context, signedTx *types.Transaction) error {
	b.lastTx = signedTx
	if b.sendErr != nil {
		return b.sendErr
	}
	return nil
}

func (b *txPoolBackendMock) CurrentHeader() *types.Header {
	return b.current
}

func (b *txPoolBackendMock) CurrentBlock() *types.Header {
	return b.current
}

type proofBackendMock struct {
	*backendMock
	db             ethdb.Database
	blockByHash    map[common.Hash]*types.Block
	receiptsByHash map[common.Hash]types.Receipts
	blockErr       error
	receiptErr     error
}

func (b *txPoolFeeCapBackendMock) RPCTxFeeCap() float64 {
	return b.feeCap
}

func (b *txPoolContentBackendMock) TxPoolContent() (map[common.Address][]*types.Transaction, map[common.Address][]*types.Transaction) {
	return b.pendingContent, b.queuedContent
}

func (b *txPoolContentBackendMock) TxPoolContentFrom(addr common.Address) ([]*types.Transaction, []*types.Transaction) {
	return b.pendingContent[addr], b.queuedContent[addr]
}

func (b *txPoolContentBackendMock) CurrentHeader() *types.Header {
	return b.current
}

func (b *txPoolContentBackendMock) Stats() (pending int, queued int) {
	return b.pendingCount, b.queuedCount
}

func (b *ethereumAPIBackendMock) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	if b.tipErr != nil {
		return nil, b.tipErr
	}
	return new(big.Int).Set(b.tipCap), nil
}

func (b *ethereumAPIBackendMock) FeeHistory(ctx context.Context, blockCount uint64, lastBlock rpc.BlockNumber, rewardPercentiles []float64) (*big.Int, [][]*big.Int, []*big.Int, []float64, error) {
	if b.feeErr != nil {
		return nil, nil, nil, nil, b.feeErr
	}
	return b.feeOldest, b.feeReward, b.feeBaseFee, b.feeGasUsedRatio, nil
}

func (b *ethereumAPIBackendMock) ProtocolVersion() int {
	return b.protocolVersion
}

func (b *ethereumAPIBackendMock) Downloader() *downloader.Downloader {
	return b.dl
}

func (b *proofBackendMock) ChainDb() ethdb.Database {
	return b.db
}

func (b *proofBackendMock) GetBlock(ctx context.Context, hash common.Hash) (*types.Block, error) {
	if b.blockErr != nil {
		return nil, b.blockErr
	}
	if blk, ok := b.blockByHash[hash]; ok {
		return blk, nil
	}
	return nil, nil
}

func (b *proofBackendMock) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	if b.receiptErr != nil {
		return nil, b.receiptErr
	}
	if r, ok := b.receiptsByHash[hash]; ok {
		return r, nil
	}
	return nil, nil
}

func TestSendRawTransactionBasic(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)

	backend := &sendTxBackendMock{backendMock: newBackendMock()}
	api := NewTransactionAPI(backend, nil)

	to := common.Address{0x12}
	tx, err := types.SignNewTx(key, types.LatestSigner(backend.ChainConfig()), &types.LegacyTx{
		Nonce:    9,
		GasPrice: big.NewInt(2),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(1),
	})
	require.NoError(t, err)

	raw, err := tx.MarshalBinary()
	require.NoError(t, err)

	hash, err := api.SendRawTransaction(context.Background(), raw)
	require.NoError(t, err)
	require.Equal(t, tx.Hash(), hash)
	require.NotNil(t, backend.lastTx)
	require.Equal(t, tx.Hash(), backend.lastTx.Hash())

	_, err = api.SendRawTransaction(context.Background(), hexutil.Bytes{0x01, 0x02, 0x03})
	require.Error(t, err)

	backend.sendErr = errors.New("pool rejected tx")
	_, err = api.SendRawTransaction(context.Background(), raw)
	require.ErrorContains(t, err, "pool rejected tx")
}

func TestSendRawTransactionRejectUnprotected(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)

	backend := &sendTxBackendMock{backendMock: newBackendMock()}
	api := NewTransactionAPI(backend, nil)

	to := common.Address{0x34}
	tx, err := types.SignTx(types.NewTransaction(1, to, big.NewInt(1), 21000, big.NewInt(2), nil), types.HomesteadSigner{}, key)
	require.NoError(t, err)

	raw, err := tx.MarshalBinary()
	require.NoError(t, err)

	_, err = api.SendRawTransaction(context.Background(), raw)
	require.ErrorContains(t, err, "only replay-protected (EIP-155) transactions allowed over RPC")
}

func TestSendRawTransactionFeeCapExceeded(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)

	backend := &sendTxBackendMock{backendMock: newBackendMock(), feeCap: 1}
	api := NewTransactionAPI(backend, nil)

	to := common.Address{0x45}
	tx, err := types.SignNewTx(key, types.LatestSigner(backend.ChainConfig()), &types.LegacyTx{
		Nonce:    10,
		GasPrice: big.NewInt(params.Ether),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(1),
	})
	require.NoError(t, err)

	raw, err := tx.MarshalBinary()
	require.NoError(t, err)

	_, err = api.SendRawTransaction(context.Background(), raw)
	require.ErrorContains(t, err, "exceeds the configured cap")
}

func TestGetTransactionByHashBasic(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)
	backend := &txLookupBackendMock{
		backendMock: newBackendMock(),
		db:          rawdb.NewMemoryDatabase(),
		headers:     make(map[common.Hash]*types.Header),
		poolTxs:     make(map[common.Hash]*types.Transaction),
		current:     &types.Header{Number: big.NewInt(100), BaseFee: big.NewInt(10)},
	}
	api := NewTransactionAPI(backend, nil)

	to := common.Address{0x56}
	minedTx, err := types.SignNewTx(key, types.LatestSigner(backend.ChainConfig()), &types.LegacyTx{
		Nonce:    4,
		GasPrice: big.NewInt(2),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(8),
	})
	require.NoError(t, err)

	block := types.NewBlock(
		&types.Header{Number: big.NewInt(15), GasLimit: 8_000_000, BaseFee: big.NewInt(9)},
		&types.Body{Transactions: []*types.Transaction{minedTx}},
		nil,
		newHasher(),
	)
	rawdb.WriteBlock(backend.db, block)
	rawdb.WriteCanonicalHash(backend.db, block.Hash(), block.NumberU64())
	rawdb.WriteTxLookupEntriesByBlock(backend.db, block)
	backend.headers[block.Hash()] = block.Header()

	gotMined, err := api.GetTransactionByHash(context.Background(), minedTx.Hash())
	require.NoError(t, err)
	require.NotNil(t, gotMined)
	require.Equal(t, minedTx.Hash(), gotMined.Hash)
	require.NotNil(t, gotMined.BlockHash)
	require.Equal(t, block.Hash(), *gotMined.BlockHash)

	dynTx, err := types.SignNewTx(key, types.LatestSigner(backend.ChainConfig()), &types.DynamicFeeTx{
		ChainID:   backend.ChainConfig().ChainID,
		Nonce:     6,
		GasTipCap: big.NewInt(3),
		GasFeeCap: big.NewInt(20),
		Gas:       30000,
		To:        &to,
		Value:     big.NewInt(4),
	})
	require.NoError(t, err)

	dynBlock := types.NewBlock(
		&types.Header{Number: big.NewInt(17), GasLimit: 8_000_000, BaseFee: big.NewInt(9)},
		&types.Body{Transactions: []*types.Transaction{dynTx}},
		nil,
		newHasher(),
	)
	rawdb.WriteBlock(backend.db, dynBlock)
	rawdb.WriteCanonicalHash(backend.db, dynBlock.Hash(), dynBlock.NumberU64())
	rawdb.WriteTxLookupEntriesByBlock(backend.db, dynBlock)
	backend.headers[dynBlock.Hash()] = dynBlock.Header()

	gotDyn, err := api.GetTransactionByHash(context.Background(), dynTx.Hash())
	require.NoError(t, err)
	require.NotNil(t, gotDyn)
	require.Equal(t, dynTx.Hash(), gotDyn.Hash)
	require.Equal(t, hexutil.Uint64(types.DynamicFeeTxType), gotDyn.Type)
	require.Equal(t, (*hexutil.Big)(big.NewInt(20)), gotDyn.GasFeeCap)
	require.Equal(t, (*hexutil.Big)(big.NewInt(3)), gotDyn.GasTipCap)
	require.Equal(t, (*hexutil.Big)(big.NewInt(12)), gotDyn.GasPrice)

	accessList := types.AccessList{{Address: to, StorageKeys: []common.Hash{{0x2}}}}
	accessTx, err := types.SignNewTx(key, types.LatestSigner(backend.ChainConfig()), &types.AccessListTx{
		ChainID:    backend.ChainConfig().ChainID,
		Nonce:      8,
		GasPrice:   big.NewInt(9),
		Gas:        28000,
		To:         &to,
		Value:      big.NewInt(6),
		AccessList: accessList,
	})
	require.NoError(t, err)

	accessBlock := types.NewBlock(
		&types.Header{Number: big.NewInt(18), GasLimit: 8_000_000, BaseFee: big.NewInt(9)},
		&types.Body{Transactions: []*types.Transaction{accessTx}},
		nil,
		newHasher(),
	)
	rawdb.WriteBlock(backend.db, accessBlock)
	rawdb.WriteCanonicalHash(backend.db, accessBlock.Hash(), accessBlock.NumberU64())
	rawdb.WriteTxLookupEntriesByBlock(backend.db, accessBlock)
	backend.headers[accessBlock.Hash()] = accessBlock.Header()

	gotAccess, err := api.GetTransactionByHash(context.Background(), accessTx.Hash())
	require.NoError(t, err)
	require.NotNil(t, gotAccess)
	require.Equal(t, accessTx.Hash(), gotAccess.Hash)
	require.Equal(t, hexutil.Uint64(types.AccessListTxType), gotAccess.Type)
	require.NotNil(t, gotAccess.Accesses)
	require.Equal(t, accessList, *gotAccess.Accesses)

	poolTx, err := types.SignNewTx(key, types.LatestSigner(backend.ChainConfig()), &types.LegacyTx{
		Nonce:    5,
		GasPrice: big.NewInt(3),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(9),
	})
	require.NoError(t, err)
	backend.poolTxs[poolTx.Hash()] = poolTx

	gotPool, err := api.GetTransactionByHash(context.Background(), poolTx.Hash())
	require.NoError(t, err)
	require.NotNil(t, gotPool)
	require.Equal(t, poolTx.Hash(), gotPool.Hash)
	require.Nil(t, gotPool.BlockHash)

	backend.current = &types.Header{Number: big.NewInt(1100), GasLimit: 10_000_000, GasUsed: 5_000_000, BaseFee: big.NewInt(10)}
	pendingDynTx, err := types.SignNewTx(key, types.LatestSigner(backend.ChainConfig()), &types.DynamicFeeTx{
		ChainID:   backend.ChainConfig().ChainID,
		Nonce:     7,
		GasTipCap: big.NewInt(3),
		GasFeeCap: big.NewInt(20),
		Gas:       30000,
		To:        &to,
		Value:     big.NewInt(5),
	})
	require.NoError(t, err)
	backend.poolTxs[pendingDynTx.Hash()] = pendingDynTx

	gotPendingDyn, err := api.GetTransactionByHash(context.Background(), pendingDynTx.Hash())
	require.NoError(t, err)
	require.NotNil(t, gotPendingDyn)
	require.Nil(t, gotPendingDyn.BlockHash)
	require.Equal(t, hexutil.Uint64(types.DynamicFeeTxType), gotPendingDyn.Type)
	require.Equal(t, (*hexutil.Big)(big.NewInt(20)), gotPendingDyn.GasFeeCap)
	require.Equal(t, (*hexutil.Big)(big.NewInt(3)), gotPendingDyn.GasTipCap)
	require.Equal(t, (*hexutil.Big)(big.NewInt(20)), gotPendingDyn.GasPrice)

	missing, err := api.GetTransactionByHash(context.Background(), common.Hash{0xee})
	require.NoError(t, err)
	require.Nil(t, missing)

	backend.headerErr = errors.New("header lookup failed")
	_, err = api.GetTransactionByHash(context.Background(), minedTx.Hash())
	require.ErrorContains(t, err, "header lookup failed")
}

func TestGetRawTransactionByHashBasic(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)
	backend := &txLookupBackendMock{
		backendMock: newBackendMock(),
		db:          rawdb.NewMemoryDatabase(),
		headers:     make(map[common.Hash]*types.Header),
		poolTxs:     make(map[common.Hash]*types.Transaction),
		current:     &types.Header{Number: big.NewInt(100), BaseFee: big.NewInt(10)},
	}
	api := NewTransactionAPI(backend, nil)

	to := common.Address{0x78}
	minedTx, err := types.SignNewTx(key, types.LatestSigner(backend.ChainConfig()), &types.LegacyTx{
		Nonce:    6,
		GasPrice: big.NewInt(2),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(10),
	})
	require.NoError(t, err)

	block := types.NewBlock(
		&types.Header{Number: big.NewInt(16), GasLimit: 8_000_000, BaseFee: big.NewInt(9)},
		&types.Body{Transactions: []*types.Transaction{minedTx}},
		nil,
		newHasher(),
	)
	rawdb.WriteBlock(backend.db, block)
	rawdb.WriteCanonicalHash(backend.db, block.Hash(), block.NumberU64())
	rawdb.WriteTxLookupEntriesByBlock(backend.db, block)

	wantMinedRaw, err := minedTx.MarshalBinary()
	require.NoError(t, err)

	gotMinedRaw, err := api.GetRawTransactionByHash(context.Background(), minedTx.Hash())
	require.NoError(t, err)
	require.Equal(t, hexutil.Bytes(wantMinedRaw), gotMinedRaw)

	poolTx, err := types.SignNewTx(key, types.LatestSigner(backend.ChainConfig()), &types.LegacyTx{
		Nonce:    7,
		GasPrice: big.NewInt(3),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(11),
	})
	require.NoError(t, err)
	backend.poolTxs[poolTx.Hash()] = poolTx
	wantPoolRaw, err := poolTx.MarshalBinary()
	require.NoError(t, err)

	gotPoolRaw, err := api.GetRawTransactionByHash(context.Background(), poolTx.Hash())
	require.NoError(t, err)
	require.Equal(t, hexutil.Bytes(wantPoolRaw), gotPoolRaw)

	missing, err := api.GetRawTransactionByHash(context.Background(), common.Hash{0xff})
	require.NoError(t, err)
	require.Nil(t, missing)
}

func TestGetTransactionCountBasic(t *testing.T) {
	t.Parallel()

	addr := common.HexToAddress("0x0000000000000000000000000000000000000123")
	genesis := &core.Genesis{
		Config: params.MergedTestChainConfig,
		Alloc: types.GenesisAlloc{
			addr: {
				Balance: big.NewInt(params.Ether),
				Nonce:   7,
			},
		},
	}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	backend := &nonceBackendMock{
		backendMock: newBackendMock(),
		poolNonce:   12,
		stateDB:     stateDB,
		header:      block.Header(),
	}
	api := NewTransactionAPI(backend, nil)

	pending := rpc.BlockNumberOrHashWithNumber(rpc.PendingBlockNumber)
	pendingNonce, err := api.GetTransactionCount(context.Background(), addr, pending)
	require.NoError(t, err)
	require.NotNil(t, pendingNonce)
	require.Equal(t, hexutil.Uint64(12), *pendingNonce)

	latest := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	latestNonce, err := api.GetTransactionCount(context.Background(), addr, latest)
	require.NoError(t, err)
	require.NotNil(t, latestNonce)
	require.Equal(t, hexutil.Uint64(7), *latestNonce)

	byHash := rpc.BlockNumberOrHashWithHash(block.Hash(), false)
	hashNonce, err := api.GetTransactionCount(context.Background(), addr, byHash)
	require.NoError(t, err)
	require.NotNil(t, hashNonce)
	require.Equal(t, hexutil.Uint64(7), *hashNonce)

	backend.poolErr = errors.New("pool nonce failed")
	_, err = api.GetTransactionCount(context.Background(), addr, pending)
	require.ErrorContains(t, err, "pool nonce failed")
	backend.poolErr = nil

	backend.stateErr = errors.New("state lookup failed")
	_, err = api.GetTransactionCount(context.Background(), addr, latest)
	require.ErrorContains(t, err, "state lookup failed")
}

func TestPendingTransactionsBasic(t *testing.T) {
	t.Parallel()

	key1, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)
	key2, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	require.NoError(t, err)

	password := "test-pass"
	ks := keystore.NewKeyStore(t.TempDir(), keystore.LightScryptN, keystore.LightScryptP)
	account1, err := ks.ImportECDSA(key1, password)
	require.NoError(t, err)
	require.NoError(t, ks.Unlock(account1, password))
	manager := accounts.NewManager(nil, ks)
	defer manager.Close()
	backendBase := newBackendMock()

	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	tx1, err := types.SignNewTx(key1, types.LatestSigner(backendBase.ChainConfig()), &types.DynamicFeeTx{
		ChainID:   backendBase.ChainConfig().ChainID,
		Nonce:     1,
		GasTipCap: big.NewInt(2),
		GasFeeCap: big.NewInt(20),
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(1),
	})
	require.NoError(t, err)
	tx2, err := types.SignNewTx(key2, types.LatestSigner(backendBase.ChainConfig()), &types.DynamicFeeTx{
		ChainID:   backendBase.ChainConfig().ChainID,
		Nonce:     2,
		GasTipCap: big.NewInt(3),
		GasFeeCap: big.NewInt(21),
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(2),
	})
	require.NoError(t, err)

	backend := &txPoolBackendMock{
		backendMock: backendBase,
		manager:     manager,
		poolTxs:     types.Transactions{tx1, tx2},
		current:     &types.Header{Number: big.NewInt(1100), GasLimit: 10_000_000, GasUsed: 5_000_000, BaseFee: big.NewInt(10)},
	}
	api := NewTransactionAPI(backend, new(AddrLocker))

	got, err := api.PendingTransactions()
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, tx1.Hash(), got[0].Hash)
	require.Nil(t, got[0].BlockHash)

	backend.poolErr = errors.New("pool unavailable")
	_, err = api.PendingTransactions()
	require.ErrorContains(t, err, "pool unavailable")
}

func TestResendBasic(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)

	password := "test-pass"
	ks := keystore.NewKeyStore(t.TempDir(), keystore.LightScryptN, keystore.LightScryptP)
	account, err := ks.ImportECDSA(key, password)
	require.NoError(t, err)
	require.NoError(t, ks.Unlock(account, password))
	manager := accounts.NewManager(nil, ks)
	defer manager.Close()
	backendBase := newBackendMock()

	to := common.HexToAddress("0x703c4b2bd70c169f5717101caee543299fc946c7")
	oldTx, err := types.SignNewTx(key, types.LatestSigner(backendBase.ChainConfig()), &types.LegacyTx{
		Nonce:    5,
		GasPrice: big.NewInt(7),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(3),
	})
	require.NoError(t, err)

	backend := &txPoolBackendMock{
		backendMock: backendBase,
		manager:     manager,
		poolTxs:     types.Transactions{oldTx},
		current:     &types.Header{Number: big.NewInt(1100), BaseFee: big.NewInt(10)},
	}
	api := NewTransactionAPI(backend, new(AddrLocker))

	from := account.Address
	gas := hexutil.Uint64(21000)
	nonce := hexutil.Uint64(5)
	value := (*hexutil.Big)(big.NewInt(3))
	oldPrice := (*hexutil.Big)(big.NewInt(7))
	newPrice := (*hexutil.Big)(big.NewInt(11))
	newGas := hexutil.Uint64(25000)

	hash, err := api.Resend(context.Background(), TransactionArgs{
		From:     &from,
		To:       &to,
		Gas:      &gas,
		Nonce:    &nonce,
		GasPrice: oldPrice,
		Value:    value,
	}, newPrice, &newGas)
	require.NoError(t, err)
	require.NotNil(t, backend.lastTx)
	require.Equal(t, backend.lastTx.Hash(), hash)
	require.Equal(t, uint64(newGas), backend.lastTx.Gas())
	require.Equal(t, big.NewInt(11), backend.lastTx.GasPrice())

	missingNonce := hexutil.Uint64(6)
	_, err = api.Resend(context.Background(), TransactionArgs{
		From:     &from,
		To:       &to,
		Gas:      &gas,
		Nonce:    &missingNonce,
		GasPrice: oldPrice,
		Value:    value,
	}, newPrice, &newGas)
	require.ErrorContains(t, err, "not found")

	_, err = api.Resend(context.Background(), TransactionArgs{
		From:     &from,
		To:       &to,
		Gas:      &gas,
		GasPrice: oldPrice,
		Value:    value,
	}, newPrice, &newGas)
	require.ErrorContains(t, err, "missing transaction nonce")

	backend.poolErr = errors.New("pool query failed")
	_, err = api.Resend(context.Background(), TransactionArgs{
		From:     &from,
		To:       &to,
		Gas:      &gas,
		Nonce:    &nonce,
		GasPrice: oldPrice,
		Value:    value,
	}, newPrice, &newGas)
	require.ErrorContains(t, err, "pool query failed")
	backend.poolErr = nil

	backend.sendErr = errors.New("resend rejected")
	_, err = api.Resend(context.Background(), TransactionArgs{
		From:     &from,
		To:       &to,
		Gas:      &gas,
		Nonce:    &nonce,
		GasPrice: oldPrice,
		Value:    value,
	}, newPrice, &newGas)
	require.ErrorContains(t, err, "resend rejected")
	backend.sendErr = nil
}

func TestResendFeeCapExceeded(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)

	password := "test-pass"
	ks := keystore.NewKeyStore(t.TempDir(), keystore.LightScryptN, keystore.LightScryptP)
	account, err := ks.ImportECDSA(key, password)
	require.NoError(t, err)
	require.NoError(t, ks.Unlock(account, password))
	manager := accounts.NewManager(nil, ks)
	defer manager.Close()

	backendBase := newBackendMock()
	to := common.HexToAddress("0x703c4b2bd70c169f5717101caee543299fc946c7")
	oldTx, err := types.SignNewTx(key, types.LatestSigner(backendBase.ChainConfig()), &types.LegacyTx{
		Nonce:    8,
		GasPrice: big.NewInt(7),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(3),
	})
	require.NoError(t, err)

	backend := &txPoolFeeCapBackendMock{
		txPoolBackendMock: &txPoolBackendMock{
			backendMock: backendBase,
			manager:     manager,
			poolTxs:     types.Transactions{oldTx},
			current:     &types.Header{Number: big.NewInt(1100), BaseFee: big.NewInt(10)},
		},
		feeCap: 1,
	}
	api := NewTransactionAPI(backend, new(AddrLocker))

	from := account.Address
	gas := hexutil.Uint64(21000)
	nonce := hexutil.Uint64(8)
	value := (*hexutil.Big)(big.NewInt(3))
	oldPrice := (*hexutil.Big)(big.NewInt(7))
	tooHighPrice := (*hexutil.Big)(big.NewInt(params.Ether))

	_, err = api.Resend(context.Background(), TransactionArgs{
		From:     &from,
		To:       &to,
		Gas:      &gas,
		Nonce:    &nonce,
		GasPrice: oldPrice,
		Value:    value,
	}, tooHighPrice, nil)
	require.ErrorContains(t, err, "exceeds the configured cap")
}

func TestResendWithoutOverrides(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)

	password := "test-pass"
	ks := keystore.NewKeyStore(t.TempDir(), keystore.LightScryptN, keystore.LightScryptP)
	account, err := ks.ImportECDSA(key, password)
	require.NoError(t, err)
	require.NoError(t, ks.Unlock(account, password))
	manager := accounts.NewManager(nil, ks)
	defer manager.Close()

	backendBase := newBackendMock()
	to := common.HexToAddress("0x703c4b2bd70c169f5717101caee543299fc946c7")
	oldTx, err := types.SignNewTx(key, types.LatestSigner(backendBase.ChainConfig()), &types.LegacyTx{
		Nonce:    9,
		GasPrice: big.NewInt(7),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(3),
	})
	require.NoError(t, err)

	backend := &txPoolBackendMock{
		backendMock: backendBase,
		manager:     manager,
		poolTxs:     types.Transactions{oldTx},
		current:     &types.Header{Number: big.NewInt(1100), BaseFee: big.NewInt(10)},
	}
	api := NewTransactionAPI(backend, new(AddrLocker))

	from := account.Address
	gas := hexutil.Uint64(21000)
	nonce := hexutil.Uint64(9)
	value := (*hexutil.Big)(big.NewInt(3))
	oldPrice := (*hexutil.Big)(big.NewInt(7))

	hash, err := api.Resend(context.Background(), TransactionArgs{
		From:     &from,
		To:       &to,
		Gas:      &gas,
		Nonce:    &nonce,
		GasPrice: oldPrice,
		Value:    value,
	}, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, backend.lastTx)
	require.Equal(t, backend.lastTx.Hash(), hash)
	require.Equal(t, uint64(gas), backend.lastTx.Gas())
	require.Equal(t, big.NewInt(7), backend.lastTx.GasPrice())

	zeroPrice := (*hexutil.Big)(big.NewInt(0))
	zeroGas := hexutil.Uint64(0)
	hash, err = api.Resend(context.Background(), TransactionArgs{
		From:     &from,
		To:       &to,
		Gas:      &gas,
		Nonce:    &nonce,
		GasPrice: oldPrice,
		Value:    value,
	}, zeroPrice, &zeroGas)
	require.NoError(t, err)
	require.NotNil(t, backend.lastTx)
	require.Equal(t, backend.lastTx.Hash(), hash)
	require.Equal(t, uint64(gas), backend.lastTx.Gas())
	require.Equal(t, big.NewInt(7), backend.lastTx.GasPrice())
}

func TestTxPoolAPIContentAndInspect(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)
	backendBase := newBackendMock()
	signer := types.LatestSigner(backendBase.ChainConfig())

	addr1 := crypto.PubkeyToAddress(key.PublicKey)
	addr2 := common.HexToAddress("0x2222222222222222222222222222222222222222")
	to := common.HexToAddress("0x3333333333333333333333333333333333333333")

	pendingTx, err := types.SignNewTx(key, signer, &types.DynamicFeeTx{
		ChainID:   backendBase.ChainConfig().ChainID,
		Nonce:     1,
		GasTipCap: big.NewInt(2),
		GasFeeCap: big.NewInt(20),
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(5),
	})
	require.NoError(t, err)
	queuedTx, err := types.SignNewTx(key, signer, &types.LegacyTx{
		Nonce:    2,
		GasPrice: big.NewInt(7),
		Gas:      53000,
		To:       nil,
		Value:    big.NewInt(6),
		Data:     []byte{0x60, 0x00},
	})
	require.NoError(t, err)

	backend := &txPoolContentBackendMock{
		backendMock: newBackendMock(),
		pendingContent: map[common.Address][]*types.Transaction{
			addr1: {pendingTx},
		},
		queuedContent: map[common.Address][]*types.Transaction{
			addr2: {queuedTx},
		},
		current:      &types.Header{Number: big.NewInt(1100), GasLimit: 10_000_000, GasUsed: 5_000_000, BaseFee: big.NewInt(10)},
		pendingCount: 1,
		queuedCount:  1,
	}
	api := NewTxPoolAPI(backend)

	content := api.Content()
	require.Contains(t, content["pending"], addr1.Hex())
	require.Contains(t, content["queued"], addr2.Hex())
	require.Equal(t, pendingTx.Hash(), content["pending"][addr1.Hex()]["1"].Hash)
	require.Equal(t, queuedTx.Hash(), content["queued"][addr2.Hex()]["2"].Hash)

	contentFrom := api.ContentFrom(addr1)
	require.Contains(t, contentFrom["pending"], "1")
	require.Equal(t, pendingTx.Hash(), contentFrom["pending"]["1"].Hash)
	require.Empty(t, contentFrom["queued"])

	emptyContentFrom := api.ContentFrom(common.HexToAddress("0x9999999999999999999999999999999999999999"))
	require.Empty(t, emptyContentFrom["pending"])
	require.Empty(t, emptyContentFrom["queued"])

	status := api.Status()
	require.Equal(t, hexutil.Uint(1), status["pending"])
	require.Equal(t, hexutil.Uint(1), status["queued"])

	inspect := api.Inspect()
	require.Contains(t, inspect["pending"], addr1.Hex())
	require.Contains(t, inspect["pending"][addr1.Hex()]["1"], "3333333333333333333333333333333333333333")
	require.Contains(t, inspect["queued"][addr2.Hex()]["2"], "contract creation")
}

func TestTxPoolAPIStatusEmpty(t *testing.T) {
	t.Parallel()

	backend := &txPoolContentBackendMock{
		backendMock:    newBackendMock(),
		pendingContent: map[common.Address][]*types.Transaction{},
		queuedContent:  map[common.Address][]*types.Transaction{},
		current:        &types.Header{Number: big.NewInt(1100), BaseFee: big.NewInt(10)},
		pendingCount:   0,
		queuedCount:    0,
	}
	api := NewTxPoolAPI(backend)

	status := api.Status()
	require.Equal(t, hexutil.Uint(0), status["pending"])
	require.Equal(t, hexutil.Uint(0), status["queued"])

	content := api.Content()
	require.Empty(t, content["pending"])
	require.Empty(t, content["queued"])

	contentFrom := api.ContentFrom(common.HexToAddress("0x9999999999999999999999999999999999999999"))
	require.Empty(t, contentFrom["pending"])
	require.Empty(t, contentFrom["queued"])

	inspect := api.Inspect()
	require.Empty(t, inspect["pending"])
	require.Empty(t, inspect["queued"])
}

func TestEthereumAPIBasic(t *testing.T) {
	t.Parallel()

	backend := &ethereumAPIBackendMock{
		backendMock:     newBackendMock(),
		tipCap:          big.NewInt(42),
		feeOldest:       big.NewInt(100),
		feeReward:       [][]*big.Int{{big.NewInt(1), big.NewInt(2)}},
		feeBaseFee:      []*big.Int{big.NewInt(10), big.NewInt(11)},
		feeGasUsedRatio: []float64{0.5, 0.75},
		protocolVersion: 66,
		dl:              &downloader.Downloader{},
	}
	backend.current = &types.Header{Number: big.NewInt(1100), BaseFee: big.NewInt(10)}
	api := NewEthereumAPI(backend)

	gasPrice, err := api.GasPrice(context.Background())
	require.NoError(t, err)
	require.Equal(t, (*hexutil.Big)(big.NewInt(52)), gasPrice)

	tip, err := api.MaxPriorityFeePerGas(context.Background())
	require.NoError(t, err)
	require.Equal(t, (*hexutil.Big)(big.NewInt(42)), tip)

	history, err := api.FeeHistory(context.Background(), 2, rpc.LatestBlockNumber, []float64{10, 50})
	require.NoError(t, err)
	require.Equal(t, (*hexutil.Big)(big.NewInt(100)), history.OldestBlock)
	require.Len(t, history.Reward, 1)
	require.Equal(t, (*hexutil.Big)(big.NewInt(1)), history.Reward[0][0])
	require.Equal(t, (*hexutil.Big)(big.NewInt(10)), history.BaseFee[0])
	require.Equal(t, []float64{0.5, 0.75}, history.GasUsedRatio)

	require.Equal(t, (*hexutil.Big)(big.NewInt(0)), api.BlobBaseFee(context.Background()))
	require.Equal(t, hexutil.Uint(66), api.ProtocolVersion())

	syncing, err := api.Syncing()
	require.NoError(t, err)
	require.Equal(t, false, syncing)

	backend.tipErr = errors.New("tip unavailable")
	_, err = api.GasPrice(context.Background())
	require.ErrorContains(t, err, "tip unavailable")
	_, err = api.MaxPriorityFeePerGas(context.Background())
	require.ErrorContains(t, err, "tip unavailable")
	backend.tipErr = nil

	backend.feeErr = errors.New("fee history unavailable")
	_, err = api.FeeHistory(context.Background(), 1, rpc.LatestBlockNumber, nil)
	require.ErrorContains(t, err, "fee history unavailable")

	backend.feeErr = nil
	backend.feeReward = nil
	backend.feeBaseFee = nil
	backend.feeGasUsedRatio = []float64{}
	history, err = api.FeeHistory(context.Background(), 0, rpc.LatestBlockNumber, nil)
	require.NoError(t, err)
	require.Nil(t, history.Reward)
	require.Nil(t, history.BaseFee)
	require.Empty(t, history.GasUsedRatio)
}

func TestEthereumAPIGasPriceWithoutBaseFee(t *testing.T) {
	t.Parallel()

	backend := &ethereumAPIBackendMock{
		backendMock: newBackendMock(),
		tipCap:      big.NewInt(42),
		dl:          &downloader.Downloader{},
	}
	backend.current = &types.Header{Number: big.NewInt(900), BaseFee: nil}
	api := NewEthereumAPI(backend)

	gasPrice, err := api.GasPrice(context.Background())
	require.NoError(t, err)
	require.Equal(t, (*hexutil.Big)(big.NewInt(42)), gasPrice)
}

func TestEthereumAccountAPIAccounts(t *testing.T) {
	t.Parallel()

	key1, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)
	key2, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	require.NoError(t, err)

	ks := keystore.NewKeyStore(t.TempDir(), keystore.LightScryptN, keystore.LightScryptP)
	account1, err := ks.ImportECDSA(key1, "pass")
	require.NoError(t, err)
	account2, err := ks.ImportECDSA(key2, "pass")
	require.NoError(t, err)

	manager := accounts.NewManager(nil, ks)
	defer manager.Close()

	api := NewEthereumAccountAPI(manager)
	got := api.Accounts()
	require.ElementsMatch(t, []common.Address{account1.Address, account2.Address}, got)
}

func TestEthereumAccountAPIAccountsEmpty(t *testing.T) {
	t.Parallel()

	ks := keystore.NewKeyStore(t.TempDir(), keystore.LightScryptN, keystore.LightScryptP)
	manager := accounts.NewManager(nil, ks)
	defer manager.Close()

	api := NewEthereumAccountAPI(manager)
	got := api.Accounts()
	require.Empty(t, got)
}

func TestSignTransactionBasic(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)

	password := "test-pass"
	ks := keystore.NewKeyStore(t.TempDir(), keystore.LightScryptN, keystore.LightScryptP)
	account, err := ks.ImportECDSA(key, password)
	require.NoError(t, err)
	require.NoError(t, ks.Unlock(account, password))

	manager := accounts.NewManager(nil, ks)
	defer manager.Close()

	backend := &signingBackendMock{
		backendMock: newBackendMock(),
		manager:     manager,
	}
	api := NewTransactionAPI(backend, new(AddrLocker))

	to := common.HexToAddress("0x703c4b2bd70c169f5717101caee543299fc946c7")
	gas := hexutil.Uint64(21000)
	nonce := hexutil.Uint64(0)
	gasPrice := (*hexutil.Big)(big.NewInt(1))
	value := (*hexutil.Big)(big.NewInt(1))

	res, err := api.SignTransaction(context.Background(), TransactionArgs{
		From:     &account.Address,
		To:       &to,
		Gas:      &gas,
		GasPrice: gasPrice,
		Value:    value,
		Nonce:    &nonce,
	})
	require.NoError(t, err)
	require.NotEmpty(t, res.Raw)
	require.NotNil(t, res.Tx)
	require.Equal(t, uint64(nonce), res.Tx.Nonce())
	require.Equal(t, uint64(gas), res.Tx.Gas())
	require.Equal(t, big.NewInt(1), res.Tx.Value())
	require.Equal(t, to, *res.Tx.To())

	var signedTx types.Transaction
	require.NoError(t, signedTx.UnmarshalBinary(res.Raw))

	signer := types.MakeSigner(backend.ChainConfig(), backend.CurrentBlock().Number)
	from, err := types.Sender(signer, &signedTx)
	require.NoError(t, err)
	require.Equal(t, account.Address, from)
	require.Equal(t, uint64(nonce), signedTx.Nonce())
	require.Equal(t, uint64(gas), signedTx.Gas())
	require.Equal(t, big.NewInt(1), signedTx.Value())
	require.NotNil(t, signedTx.To())
	require.Equal(t, to, *signedTx.To())
	require.True(t, signedTx.Protected())

	// Same-name coverage extension: add a compact set of validation checks.
	plainBackend := newBackendMock()
	plainAPI := NewTransactionAPI(plainBackend, new(AddrLocker))
	fromAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	toAddr := common.HexToAddress("0x2222222222222222222222222222222222222222")
	testGas := hexutil.Uint64(21000)
	testNonce := hexutil.Uint64(0)

	_, err = plainAPI.SignTransaction(context.Background(), TransactionArgs{
		From:     &fromAddr,
		To:       &toAddr,
		Gas:      &testGas,
		Nonce:    &testNonce,
		GasPrice: (*hexutil.Big)(big.NewInt(1)),
		ChainID:  (*hexutil.Big)(big.NewInt(1)),
	})
	require.ErrorContains(t, err, "chainId does not match node's")

	data := hexutil.Bytes{0x01}
	input := hexutil.Bytes{0x02}
	_, err = plainAPI.SignTransaction(context.Background(), TransactionArgs{
		From:     &fromAddr,
		To:       &toAddr,
		Gas:      &testGas,
		Nonce:    &testNonce,
		GasPrice: (*hexutil.Big)(big.NewInt(1)),
		Data:     &data,
		Input:    &input,
	})
	require.ErrorContains(t, err, `both "data" and "input" are set and not equal`)
}

func TestSignTransactionValidationErrors(t *testing.T) {
	t.Parallel()

	backend := newBackendMock()
	api := NewTransactionAPI(backend, new(AddrLocker))

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	gas := hexutil.Uint64(21000)
	nonce := hexutil.Uint64(0)

	_, err := api.SignTransaction(context.Background(), TransactionArgs{
		From:     &from,
		To:       &to,
		GasPrice: (*hexutil.Big)(big.NewInt(1)),
		Nonce:    &nonce,
	})
	require.ErrorContains(t, err, "not specify Gas")

	_, err = api.SignTransaction(context.Background(), TransactionArgs{
		From:  &from,
		To:    &to,
		Gas:   &gas,
		Nonce: &nonce,
	})
	require.ErrorContains(t, err, "missing gasPrice or maxFeePerGas/maxPriorityFeePerGas")

	_, err = api.SignTransaction(context.Background(), TransactionArgs{
		From:     &from,
		To:       &to,
		Gas:      &gas,
		GasPrice: (*hexutil.Big)(big.NewInt(1)),
	})
	require.ErrorContains(t, err, "not specify Nonce")

	_, err = api.SignTransaction(context.Background(), TransactionArgs{
		From:                 &from,
		To:                   &to,
		Gas:                  &gas,
		Nonce:                &nonce,
		GasPrice:             (*hexutil.Big)(big.NewInt(1)),
		MaxFeePerGas:         (*hexutil.Big)(big.NewInt(2)),
		MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(1)),
	})
	require.ErrorContains(t, err, "both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified")

	_, err = api.SignTransaction(context.Background(), TransactionArgs{
		From:     &from,
		To:       &to,
		Gas:      &gas,
		Nonce:    &nonce,
		GasPrice: (*hexutil.Big)(big.NewInt(1)),
		ChainID:  (*hexutil.Big)(big.NewInt(1)),
	})
	require.ErrorContains(t, err, "chainId does not match node's")

	_, err = api.SignTransaction(context.Background(), TransactionArgs{
		From:                 &from,
		To:                   &to,
		Gas:                  &gas,
		Nonce:                &nonce,
		MaxFeePerGas:         (*hexutil.Big)(big.NewInt(1)),
		MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(2)),
	})
	require.ErrorContains(t, err, "maxFeePerGas")

	_, err = api.SignTransaction(context.Background(), TransactionArgs{
		From:                 &from,
		To:                   &to,
		Gas:                  &gas,
		Nonce:                &nonce,
		MaxFeePerGas:         (*hexutil.Big)(big.NewInt(0)),
		MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(1)),
	})
	require.ErrorContains(t, err, "maxFeePerGas must be non-zero")

	_, err = api.SignTransaction(context.Background(), TransactionArgs{
		From:     &from,
		To:       &to,
		Gas:      &gas,
		Nonce:    &nonce,
		GasPrice: (*hexutil.Big)(big.NewInt(0)),
	})
	require.ErrorContains(t, err, "gasPrice must be non-zero after EIP-1559 fork")

	data := hexutil.Bytes{0x01}
	input := hexutil.Bytes{0x02}
	_, err = api.SignTransaction(context.Background(), TransactionArgs{
		From:     &from,
		To:       &to,
		Gas:      &gas,
		Nonce:    &nonce,
		GasPrice: (*hexutil.Big)(big.NewInt(1)),
		Data:     &data,
		Input:    &input,
	})
	require.ErrorContains(t, err, `both "data" and "input" are set and not equal`)

	_, err = api.SignTransaction(context.Background(), TransactionArgs{
		From:     &from,
		To:       nil,
		Gas:      &gas,
		Nonce:    &nonce,
		GasPrice: (*hexutil.Big)(big.NewInt(1)),
	})
	require.ErrorContains(t, err, "contract creation without any data provided")

	_, err = api.SignTransaction(context.Background(), TransactionArgs{
		From:              &from,
		To:                nil,
		Gas:               &gas,
		Nonce:             &nonce,
		GasPrice:          (*hexutil.Big)(big.NewInt(1)),
		AuthorizationList: []types.SetCodeAuthorization{},
	})
	require.ErrorContains(t, err, "eip7702 set code transaction requires a destination address")
}

func TestSignTransactionFeeCapExceeded(t *testing.T) {
	t.Parallel()

	backend := &txFeeCapBackendMock{
		backendMock: newBackendMock(),
		feeCap:      1,
	}
	api := NewTransactionAPI(backend, new(AddrLocker))

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	gas := hexutil.Uint64(21000)
	nonce := hexutil.Uint64(0)

	_, err := api.SignTransaction(context.Background(), TransactionArgs{
		From:     &from,
		To:       &to,
		Gas:      &gas,
		Nonce:    &nonce,
		GasPrice: (*hexutil.Big)(big.NewInt(params.Ether)),
	})
	require.ErrorContains(t, err, "exceeds the configured cap")
}

type estimateBackendMock struct {
	*backendMock
	stateDB *state.StateDB
	header  *types.Header
	engine  consensus.Engine
}

func TestSignTransactionDynamicFeeBasic(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)

	password := "test-pass"
	ks := keystore.NewKeyStore(t.TempDir(), keystore.LightScryptN, keystore.LightScryptP)
	account, err := ks.ImportECDSA(key, password)
	require.NoError(t, err)
	require.NoError(t, ks.Unlock(account, password))

	manager := accounts.NewManager(nil, ks)
	defer manager.Close()

	backend := &signingBackendMock{
		backendMock: newBackendMock(),
		manager:     manager,
	}
	api := NewTransactionAPI(backend, new(AddrLocker))

	to := common.HexToAddress("0x703c4b2bd70c169f5717101caee543299fc946c7")
	gas := hexutil.Uint64(21000)
	nonce := hexutil.Uint64(0)

	res, err := api.SignTransaction(context.Background(), TransactionArgs{
		From:                 &account.Address,
		To:                   &to,
		Gas:                  &gas,
		Nonce:                &nonce,
		MaxFeePerGas:         (*hexutil.Big)(big.NewInt(20)),
		MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(2)),
		Value:                (*hexutil.Big)(big.NewInt(1)),
	})
	require.NoError(t, err)
	require.NotNil(t, res.Tx)
	require.EqualValues(t, types.DynamicFeeTxType, res.Tx.Type())

	var signedTx types.Transaction
	require.NoError(t, signedTx.UnmarshalBinary(res.Raw))
	require.EqualValues(t, types.DynamicFeeTxType, signedTx.Type())
	require.Equal(t, big.NewInt(20), signedTx.GasFeeCap())
	require.Equal(t, big.NewInt(2), signedTx.GasTipCap())

	signer := types.MakeSigner(backend.ChainConfig(), backend.CurrentBlock().Number)
	from, err := types.Sender(signer, &signedTx)
	require.NoError(t, err)
	require.Equal(t, account.Address, from)
}

func TestSignTransactionAccessListBasic(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)

	password := "test-pass"
	ks := keystore.NewKeyStore(t.TempDir(), keystore.LightScryptN, keystore.LightScryptP)
	account, err := ks.ImportECDSA(key, password)
	require.NoError(t, err)
	require.NoError(t, ks.Unlock(account, password))

	manager := accounts.NewManager(nil, ks)
	defer manager.Close()

	backend := &signingBackendMock{
		backendMock: newBackendMock(),
		manager:     manager,
	}
	api := NewTransactionAPI(backend, new(AddrLocker))

	to := common.HexToAddress("0x703c4b2bd70c169f5717101caee543299fc946c7")
	gas := hexutil.Uint64(25000)
	nonce := hexutil.Uint64(1)
	accessList := types.AccessList{{Address: to, StorageKeys: []common.Hash{{0x1}}}}

	res, err := api.SignTransaction(context.Background(), TransactionArgs{
		From:                 &account.Address,
		To:                   &to,
		Gas:                  &gas,
		Nonce:                &nonce,
		MaxFeePerGas:         (*hexutil.Big)(big.NewInt(25)),
		MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(5)),
		AccessList:           &accessList,
		Value:                (*hexutil.Big)(big.NewInt(2)),
	})
	require.NoError(t, err)
	require.NotNil(t, res.Tx)
	require.EqualValues(t, types.DynamicFeeTxType, res.Tx.Type())
	require.Equal(t, accessList, res.Tx.AccessList())

	var signedTx types.Transaction
	require.NoError(t, signedTx.UnmarshalBinary(res.Raw))
	require.EqualValues(t, types.DynamicFeeTxType, signedTx.Type())
	require.Equal(t, accessList, signedTx.AccessList())

	signer := types.MakeSigner(backend.ChainConfig(), backend.CurrentBlock().Number)
	from, err := types.Sender(signer, &signedTx)
	require.NoError(t, err)
	require.Equal(t, account.Address, from)
}

type simulateBackendMock struct {
	*estimateBackendMock
	gasCap uint64
}

func TestSignTransactionSetCodeBasic(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)

	password := "test-pass"
	ks := keystore.NewKeyStore(t.TempDir(), keystore.LightScryptN, keystore.LightScryptP)
	account, err := ks.ImportECDSA(key, password)
	require.NoError(t, err)
	require.NoError(t, ks.Unlock(account, password))

	manager := accounts.NewManager(nil, ks)
	defer manager.Close()

	backend := &signingBackendMock{
		backendMock: newBackendMock(),
		manager:     manager,
	}
	api := NewTransactionAPI(backend, new(AddrLocker))

	to := common.HexToAddress("0x703c4b2bd70c169f5717101caee543299fc946c7")
	gas := hexutil.Uint64(30000)
	nonce := hexutil.Uint64(2)
	auth, err := types.SignSetCode(key, types.SetCodeAuthorization{
		ChainID: *uint256.MustFromBig(backend.ChainConfig().ChainID),
		Address: account.Address,
		Nonce:   0,
	})
	require.NoError(t, err)

	res, err := api.SignTransaction(context.Background(), TransactionArgs{
		From:                 &account.Address,
		To:                   &to,
		Gas:                  &gas,
		Nonce:                &nonce,
		MaxFeePerGas:         (*hexutil.Big)(big.NewInt(30)),
		MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(3)),
		AuthorizationList:    []types.SetCodeAuthorization{auth},
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotNil(t, res.Tx)
	require.EqualValues(t, types.SetCodeTxType, res.Tx.Type())
	require.Len(t, res.Tx.SetCodeAuthorizations(), 1)
	require.Equal(t, account.Address, res.Tx.SetCodeAuthorizations()[0].Address)

	var signedTx types.Transaction
	require.NoError(t, signedTx.UnmarshalBinary(res.Raw))
	require.EqualValues(t, types.SetCodeTxType, signedTx.Type())
	require.Len(t, signedTx.SetCodeAuthorizations(), 1)
	require.Equal(t, account.Address, signedTx.SetCodeAuthorizations()[0].Address)
}

type estimateRefBackendMock struct {
	*backendMock
	stateErr error
	seenRef  *rpc.BlockNumberOrHash
}

func TestFillTransactionBasic(t *testing.T) {
	t.Parallel()

	backend := newBackendMock()
	api := NewTransactionAPI(backend, new(AddrLocker))

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	gas := hexutil.Uint64(21000)
	value := (*hexutil.Big)(big.NewInt(5))

	res, err := api.FillTransaction(context.Background(), TransactionArgs{
		From:  &from,
		To:    &to,
		Gas:   &gas,
		Value: value,
	})
	require.NoError(t, err)
	require.NotEmpty(t, res.Raw)
	require.NotNil(t, res.Tx)

	require.EqualValues(t, types.DynamicFeeTxType, res.Tx.Type())
	require.Equal(t, uint64(0), res.Tx.Nonce())
	require.Equal(t, uint64(gas), res.Tx.Gas())
	require.Equal(t, big.NewInt(5), res.Tx.Value())
	require.NotNil(t, res.Tx.To())
	require.Equal(t, to, *res.Tx.To())
	require.Equal(t, backend.config.ChainID, res.Tx.ChainId())
	require.Equal(t, big.NewInt(42), res.Tx.GasTipCap())
	require.Equal(t, big.NewInt(62), res.Tx.GasFeeCap())

	var filledTx types.Transaction
	require.NoError(t, filledTx.UnmarshalBinary(res.Raw))
	require.Equal(t, res.Tx.Hash(), filledTx.Hash())
	require.EqualValues(t, types.DynamicFeeTxType, filledTx.Type())
	require.Equal(t, backend.config.ChainID, filledTx.ChainId())
	require.Equal(t, big.NewInt(42), filledTx.GasTipCap())
	require.Equal(t, big.NewInt(62), filledTx.GasFeeCap())

	_, err = api.FillTransaction(context.Background(), TransactionArgs{
		From:    &from,
		To:      &to,
		Gas:     &gas,
		ChainID: (*hexutil.Big)(big.NewInt(1)),
	})
	require.ErrorContains(t, err, "chainId does not match node's")

	_, err = api.FillTransaction(context.Background(), TransactionArgs{
		From:                 &from,
		To:                   &to,
		Gas:                  &gas,
		MaxFeePerGas:         (*hexutil.Big)(big.NewInt(1)),
		MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(2)),
	})
	require.ErrorContains(t, err, "maxFeePerGas")

	data := hexutil.Bytes{0x01}
	input := hexutil.Bytes{0x02}
	_, err = api.FillTransaction(context.Background(), TransactionArgs{
		From:  &from,
		To:    &to,
		Gas:   &gas,
		Data:  &data,
		Input: &input,
	})
	require.ErrorContains(t, err, `both "data" and "input" are set and not equal`)
}

type createAccessListBackendMock struct {
	*estimateBackendMock
	block    *types.Block
	blockErr error
}

func TestFillTransactionValidationErrors(t *testing.T) {
	t.Parallel()

	backend := newBackendMock()
	api := NewTransactionAPI(backend, new(AddrLocker))

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	gas := hexutil.Uint64(21000)
	data := hexutil.Bytes{0x01}
	input := hexutil.Bytes{0x02}

	_, err := api.FillTransaction(context.Background(), TransactionArgs{
		From:  &from,
		To:    &to,
		Gas:   &gas,
		Data:  &data,
		Input: &input,
	})
	require.ErrorContains(t, err, `both "data" and "input" are set and not equal`)

	_, err = api.FillTransaction(context.Background(), TransactionArgs{
		From: &from,
		To:   nil,
		Gas:  &gas,
	})
	require.ErrorContains(t, err, "contract creation without any data provided")

	_, err = api.FillTransaction(context.Background(), TransactionArgs{
		From:              &from,
		To:                nil,
		Gas:               &gas,
		AuthorizationList: []types.SetCodeAuthorization{},
	})
	require.ErrorContains(t, err, "eip7702 set code transaction requires a destination address")

	_, err = api.FillTransaction(context.Background(), TransactionArgs{
		From:    &from,
		To:      &to,
		Gas:     &gas,
		ChainID: (*hexutil.Big)(big.NewInt(1)),
	})
	require.ErrorContains(t, err, "chainId does not match node's")

	_, err = api.FillTransaction(context.Background(), TransactionArgs{
		From:                 &from,
		To:                   &to,
		Gas:                  &gas,
		MaxFeePerGas:         (*hexutil.Big)(big.NewInt(1)),
		MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(2)),
	})
	require.ErrorContains(t, err, "maxFeePerGas")

	_, err = api.FillTransaction(context.Background(), TransactionArgs{
		From:                 &from,
		To:                   &to,
		Gas:                  &gas,
		MaxFeePerGas:         (*hexutil.Big)(big.NewInt(0)),
		MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(1)),
	})
	require.ErrorContains(t, err, "maxFeePerGas must be non-zero")

	_, err = api.FillTransaction(context.Background(), TransactionArgs{
		From:     &from,
		To:       &to,
		Gas:      &gas,
		GasPrice: (*hexutil.Big)(big.NewInt(0)),
	})
	require.ErrorContains(t, err, "gasPrice must be non-zero after EIP-1559 fork")
}

type chainContextBackendMock struct {
	header *types.Header
	engine consensus.Engine
	err    error
	last   rpc.BlockNumber
}

func TestFillTransactionLegacyWhenGasPriceProvided(t *testing.T) {
	t.Parallel()

	backend := newBackendMock()
	api := NewTransactionAPI(backend, new(AddrLocker))

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	gas := hexutil.Uint64(21000)

	res, err := api.FillTransaction(context.Background(), TransactionArgs{
		From:     &from,
		To:       &to,
		Gas:      &gas,
		GasPrice: (*hexutil.Big)(big.NewInt(7)),
		Value:    (*hexutil.Big)(big.NewInt(3)),
	})
	require.NoError(t, err)
	require.NotNil(t, res.Tx)
	require.EqualValues(t, types.LegacyTxType, res.Tx.Type())
	require.Equal(t, big.NewInt(7), res.Tx.GasPrice())
	require.Equal(t, big.NewInt(3), res.Tx.Value())

	var tx2 types.Transaction
	require.NoError(t, tx2.UnmarshalBinary(res.Raw))
	require.EqualValues(t, types.LegacyTxType, tx2.Type())
	require.Equal(t, big.NewInt(7), tx2.GasPrice())
}

func TestFillTransactionDynamicFeeExplicit(t *testing.T) {
	t.Parallel()

	backend := newBackendMock()
	api := NewTransactionAPI(backend, new(AddrLocker))

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	gas := hexutil.Uint64(25000)
	accessList := types.AccessList{{Address: to, StorageKeys: []common.Hash{{0x2}}}}

	res, err := api.FillTransaction(context.Background(), TransactionArgs{
		From:                 &from,
		To:                   &to,
		Gas:                  &gas,
		MaxFeePerGas:         (*hexutil.Big)(big.NewInt(25)),
		MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(5)),
		AccessList:           &accessList,
		Value:                (*hexutil.Big)(big.NewInt(4)),
	})
	require.NoError(t, err)
	require.NotNil(t, res.Tx)
	require.EqualValues(t, types.DynamicFeeTxType, res.Tx.Type())
	require.Equal(t, big.NewInt(25), res.Tx.GasFeeCap())
	require.Equal(t, big.NewInt(5), res.Tx.GasTipCap())
	require.Equal(t, accessList, res.Tx.AccessList())

	var tx2 types.Transaction
	require.NoError(t, tx2.UnmarshalBinary(res.Raw))
	require.EqualValues(t, types.DynamicFeeTxType, tx2.Type())
	require.Equal(t, big.NewInt(25), tx2.GasFeeCap())
	require.Equal(t, big.NewInt(5), tx2.GasTipCap())
	require.Equal(t, accessList, tx2.AccessList())
}

func TestFillTransactionSetCodeBasic(t *testing.T) {
	t.Parallel()

	backend := newBackendMock()
	api := NewTransactionAPI(backend, new(AddrLocker))

	key, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)
	from := crypto.PubkeyToAddress(key.PublicKey)
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	gas := hexutil.Uint64(32000)
	auth, err := types.SignSetCode(key, types.SetCodeAuthorization{
		ChainID: *uint256.MustFromBig(backend.ChainConfig().ChainID),
		Address: from,
		Nonce:   0,
	})
	require.NoError(t, err)

	res, err := api.FillTransaction(context.Background(), TransactionArgs{
		From:              &from,
		To:                &to,
		Gas:               &gas,
		AuthorizationList: []types.SetCodeAuthorization{auth},
	})
	require.NoError(t, err)
	require.NotNil(t, res.Tx)
	require.EqualValues(t, types.SetCodeTxType, res.Tx.Type())
	require.Len(t, res.Tx.SetCodeAuthorizations(), 1)
	require.Equal(t, from, res.Tx.SetCodeAuthorizations()[0].Address)

	var tx2 types.Transaction
	require.NoError(t, tx2.UnmarshalBinary(res.Raw))
	require.EqualValues(t, types.SetCodeTxType, tx2.Type())
	require.Len(t, tx2.SetCodeAuthorizations(), 1)
	require.Equal(t, from, tx2.SetCodeAuthorizations()[0].Address)
}

func (b *estimateBackendMock) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	return b.stateDB, b.header, nil
}

func (b *estimateBackendMock) Engine() consensus.Engine {
	return b.engine
}

func (b *simulateBackendMock) RPCGasCap() uint64 {
	if b.gasCap != 0 {
		return b.gasCap
	}
	return 30_000_000
}

func (b *estimateRefBackendMock) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	ref := blockNrOrHash
	b.seenRef = &ref
	return nil, nil, b.stateErr
}

func (b *createAccessListBackendMock) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	if b.blockErr != nil {
		return nil, b.blockErr
	}
	if b.block != nil && b.block.Hash() == hash {
		return b.block, nil
	}
	return nil, nil
}

func (b *chainContextBackendMock) Engine() consensus.Engine {
	if b.engine != nil {
		return b.engine
	}
	return ethash.NewFaker()
}

func (b *chainContextBackendMock) HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error) {
	b.last = number
	if b.err != nil {
		return nil, b.err
	}
	return b.header, nil
}

func TestEstimateGasBasic(t *testing.T) {
	t.Parallel()

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	poor := common.HexToAddress("0x3333333333333333333333333333333333333333")

	genesis := &core.Genesis{
		Config: params.MergedTestChainConfig,
		Alloc: types.GenesisAlloc{
			from: {Balance: big.NewInt(params.Ether)},
			to:   {Balance: big.NewInt(params.Ether)},
		},
	}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	backend := &estimateBackendMock{
		backendMock: newBackendMock(),
		stateDB:     stateDB,
		header:      block.Header(),
		engine:      ethash.NewFaker(),
	}
	api := NewBlockChainAPI(backend, nil)
	blockRef := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	var overrides override.StateOverride

	gas, err := api.EstimateGas(context.Background(), TransactionArgs{
		From:  &from,
		To:    &to,
		Value: (*hexutil.Big)(big.NewInt(1000)),
	}, &blockRef, nil, nil)
	require.NoError(t, err)
	require.EqualValues(t, 21000, gas)

	gas, err = api.EstimateGas(context.Background(), TransactionArgs{
		From:                 &from,
		To:                   &to,
		Value:                (*hexutil.Big)(big.NewInt(1000)),
		MaxFeePerGas:         (*hexutil.Big)(big.NewInt(10)),
		MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(1)),
	}, &blockRef, nil, nil)
	require.NoError(t, err)
	require.EqualValues(t, 21000, gas)
	gas, err = api.EstimateGas(context.Background(), TransactionArgs{
		From:     &from,
		To:       &to,
		Value:    (*hexutil.Big)(big.NewInt(1000)),
		GasPrice: (*hexutil.Big)(big.NewInt(1_000_000_000)),
	}, &blockRef, nil, nil)
	require.NoError(t, err)
	require.EqualValues(t, 21000, gas)

	gas, err = api.EstimateGas(context.Background(), TransactionArgs{
		From:         &from,
		To:           &to,
		Value:        (*hexutil.Big)(big.NewInt(1000)),
		MaxFeePerGas: (*hexutil.Big)(big.NewInt(1_000_000_000)),
	}, &blockRef, nil, nil)
	require.NoError(t, err)
	require.EqualValues(t, 21000, gas)

	_, err = api.EstimateGas(context.Background(), TransactionArgs{
		From:                 &from,
		To:                   &to,
		Value:                (*hexutil.Big)(big.NewInt(1000)),
		GasPrice:             (*hexutil.Big)(big.NewInt(1_000_000_000)),
		MaxFeePerGas:         (*hexutil.Big)(big.NewInt(1_000_000_000)),
		MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(1)),
	}, &blockRef, nil, nil)
	require.ErrorContains(t, err, "both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified")

	gas, err = api.EstimateGas(context.Background(), TransactionArgs{
		From:                 &from,
		To:                   &to,
		Value:                (*hexutil.Big)(big.NewInt(1000)),
		MaxFeePerGas:         (*hexutil.Big)(big.NewInt(10)),
		MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(11)),
	}, &blockRef, nil, nil)
	require.NoError(t, err)
	require.EqualValues(t, 21000, gas)

	gas, err = api.EstimateGas(context.Background(), TransactionArgs{
		From:     &from,
		To:       &to,
		Value:    (*hexutil.Big)(big.NewInt(1000)),
		GasPrice: (*hexutil.Big)(big.NewInt(0)),
	}, &blockRef, nil, nil)
	require.NoError(t, err)
	require.EqualValues(t, 21000, gas)

	_, err = api.EstimateGas(context.Background(), TransactionArgs{
		From:    &from,
		To:      &to,
		Value:   (*hexutil.Big)(big.NewInt(1000)),
		ChainID: (*hexutil.Big)(big.NewInt(1)),
	}, &blockRef, nil, nil)
	require.ErrorContains(t, err, "chainId does not match node's")

	gas, err = api.EstimateGas(context.Background(), TransactionArgs{From: &from}, &blockRef, nil, nil)
	require.NoError(t, err)
	require.EqualValues(t, 53000, gas)

	_, err = api.EstimateGas(context.Background(), TransactionArgs{
		From:  &poor,
		To:    &to,
		Value: (*hexutil.Big)(big.NewInt(1000)),
	}, &blockRef, nil, nil)
	require.ErrorIs(t, err, core.ErrInsufficientFunds)

	overrides = override.StateOverride{
		poor: override.OverrideAccount{Balance: (*hexutil.Big)(big.NewInt(params.Ether))},
	}
	gas, err = api.EstimateGas(context.Background(), TransactionArgs{From: &poor}, &blockRef, &overrides, nil)
	require.NoError(t, err)
	require.EqualValues(t, 53000, gas)

	overrides = override.StateOverride{
		poor: override.OverrideAccount{Balance: (*hexutil.Big)(big.NewInt(params.Ether))},
	}
	gas, err = api.EstimateGas(context.Background(), TransactionArgs{
		From:  &poor,
		To:    &to,
		Value: (*hexutil.Big)(big.NewInt(1000)),
	}, &blockRef, &overrides, nil)
	require.NoError(t, err)
	require.EqualValues(t, 21000, gas)
}

func TestChainContextGetHeader(t *testing.T) {
	t.Parallel()

	header := &types.Header{Number: big.NewInt(7), GasLimit: 10_000_000}
	backend := &chainContextBackendMock{header: header}
	ctx := NewChainContext(context.Background(), backend)

	got := ctx.GetHeader(header.Hash(), 7)
	require.NotNil(t, got)
	require.Equal(t, header.Hash(), got.Hash())

	missing := ctx.GetHeader(common.HexToHash("0x1234"), 7)
	require.Nil(t, missing)

	backend.err = errors.New("header lookup failed")
	errResult := ctx.GetHeader(header.Hash(), 7)
	require.Nil(t, errResult)
}

func TestChainContextGetHeaderForwardsNumber(t *testing.T) {
	t.Parallel()

	header := &types.Header{Number: big.NewInt(12), GasLimit: 10_000_000}
	backend := &chainContextBackendMock{header: header}
	ctx := NewChainContext(context.Background(), backend)

	got := ctx.GetHeader(header.Hash(), 12)
	require.NotNil(t, got)
	require.Equal(t, rpc.BlockNumber(12), backend.last)
}

func TestChainContextEngine(t *testing.T) {
	t.Parallel()

	eng := ethash.NewFaker()
	backend := &chainContextBackendMock{engine: eng}
	ctx := NewChainContext(context.Background(), backend)

	require.Equal(t, eng, ctx.Engine())
}

func TestEstimateGasBlockRefSelection(t *testing.T) {
	t.Parallel()

	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	callArgs := TransactionArgs{To: &to}

	backendDefault := &estimateRefBackendMock{
		backendMock: newBackendMock(),
		stateErr:    errors.New("state failed"),
	}
	apiDefault := NewBlockChainAPI(backendDefault, nil)
	_, err := apiDefault.EstimateGas(context.Background(), callArgs, nil, nil, nil)
	require.ErrorContains(t, err, "state failed")
	require.NotNil(t, backendDefault.seenRef)
	require.NotNil(t, backendDefault.seenRef.BlockNumber)
	require.Equal(t, rpc.LatestBlockNumber, *backendDefault.seenRef.BlockNumber)

	pending := rpc.BlockNumberOrHashWithNumber(rpc.PendingBlockNumber)
	backendExplicit := &estimateRefBackendMock{
		backendMock: newBackendMock(),
		stateErr:    errors.New("state failed"),
	}
	apiExplicit := NewBlockChainAPI(backendExplicit, nil)
	_, err = apiExplicit.EstimateGas(context.Background(), callArgs, &pending, nil, nil)
	require.ErrorContains(t, err, "state failed")
	require.NotNil(t, backendExplicit.seenRef)
	require.NotNil(t, backendExplicit.seenRef.BlockNumber)
	require.Equal(t, rpc.PendingBlockNumber, *backendExplicit.seenRef.BlockNumber)

	hashRef := rpc.BlockNumberOrHashWithHash(common.HexToHash("0x1234"), false)
	backendHash := &estimateRefBackendMock{
		backendMock: newBackendMock(),
		stateErr:    errors.New("state failed"),
	}
	apiHash := NewBlockChainAPI(backendHash, nil)
	_, err = apiHash.EstimateGas(context.Background(), callArgs, &hashRef, nil, nil)
	require.ErrorContains(t, err, "state failed")
	require.NotNil(t, backendHash.seenRef)
	require.NotNil(t, backendHash.seenRef.BlockHash)
	require.Equal(t, common.HexToHash("0x1234"), *backendHash.seenRef.BlockHash)
}

func TestEstimateGasInvalidStateOverride(t *testing.T) {
	t.Parallel()

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")

	genesis := &core.Genesis{
		Config: params.MergedTestChainConfig,
		Alloc: types.GenesisAlloc{
			from: {Balance: big.NewInt(params.Ether)},
			to:   {Balance: big.NewInt(params.Ether)},
		},
	}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	backend := &estimateBackendMock{
		backendMock: newBackendMock(),
		stateDB:     stateDB,
		header:      block.Header(),
		engine:      ethash.NewFaker(),
	}
	api := NewBlockChainAPI(backend, nil)
	blockRef := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)

	overrides := override.StateOverride{
		to: override.OverrideAccount{
			State: map[common.Hash]common.Hash{
				common.HexToHash("0x1"): common.HexToHash("0x2"),
			},
			StateDiff: map[common.Hash]common.Hash{
				common.HexToHash("0x3"): common.HexToHash("0x4"),
			},
		},
	}

	_, err = api.EstimateGas(context.Background(), TransactionArgs{
		From:  &from,
		To:    &to,
		Value: (*hexutil.Big)(big.NewInt(1)),
	}, &blockRef, &overrides, nil)
	require.ErrorContains(t, err, "has both 'state' and 'stateDiff'")
}

func TestDoEstimateGasBasic(t *testing.T) {
	t.Parallel()

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")

	genesis := &core.Genesis{
		Config: params.MergedTestChainConfig,
		Alloc: types.GenesisAlloc{
			from: {Balance: big.NewInt(params.Ether)},
			to:   {Balance: big.NewInt(params.Ether)},
		},
	}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	backend := &estimateBackendMock{
		backendMock: newBackendMock(),
		stateDB:     stateDB,
		header:      block.Header(),
		engine:      ethash.NewFaker(),
	}

	gas, err := DoEstimateGas(
		context.Background(),
		backend,
		TransactionArgs{From: &from, To: &to, Value: (*hexutil.Big)(big.NewInt(1))},
		rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber),
		nil,
		nil,
		0,
	)
	require.NoError(t, err)
	require.EqualValues(t, 21000, gas)
}

func TestDoEstimateGasStateLookupError(t *testing.T) {
	t.Parallel()

	backend := &estimateRefBackendMock{
		backendMock: newBackendMock(),
		stateErr:    errors.New("state failed"),
	}
	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")

	_, err := DoEstimateGas(
		context.Background(),
		backend,
		TransactionArgs{From: &from, To: &to},
		rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber),
		nil,
		nil,
		0,
	)
	require.ErrorContains(t, err, "state failed")
}

func TestDoEstimateGasInvalidStateOverride(t *testing.T) {
	t.Parallel()

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")

	genesis := &core.Genesis{
		Config: params.MergedTestChainConfig,
		Alloc: types.GenesisAlloc{
			from: {Balance: big.NewInt(params.Ether)},
			to:   {Balance: big.NewInt(params.Ether)},
		},
	}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	backend := &estimateBackendMock{
		backendMock: newBackendMock(),
		stateDB:     stateDB,
		header:      block.Header(),
		engine:      ethash.NewFaker(),
	}
	overrides := override.StateOverride{
		to: override.OverrideAccount{
			State: map[common.Hash]common.Hash{
				common.HexToHash("0x1"): common.HexToHash("0x2"),
			},
			StateDiff: map[common.Hash]common.Hash{
				common.HexToHash("0x3"): common.HexToHash("0x4"),
			},
		},
	}

	_, err = DoEstimateGas(
		context.Background(),
		backend,
		TransactionArgs{From: &from, To: &to, Value: (*hexutil.Big)(big.NewInt(1))},
		rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber),
		&overrides,
		nil,
		0,
	)
	require.ErrorContains(t, err, "has both 'state' and 'stateDiff'")
}

type callBackendMock struct {
	*backendMock
	stateDB  *state.StateDB
	header   *types.Header
	stateErr error
	block    *types.Block
	blockErr error
	seenRef  *rpc.BlockNumberOrHash
}

func TestDoEstimateGasChainIDMismatch(t *testing.T) {
	t.Parallel()

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")

	genesis := &core.Genesis{
		Config: params.MergedTestChainConfig,
		Alloc: types.GenesisAlloc{
			from: {Balance: big.NewInt(params.Ether)},
			to:   {Balance: big.NewInt(params.Ether)},
		},
	}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	backend := &estimateBackendMock{
		backendMock: newBackendMock(),
		stateDB:     stateDB,
		header:      block.Header(),
		engine:      ethash.NewFaker(),
	}

	_, err = DoEstimateGas(
		context.Background(),
		backend,
		TransactionArgs{From: &from, To: &to, ChainID: (*hexutil.Big)(big.NewInt(1))},
		rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber),
		nil,
		nil,
		0,
	)
	require.ErrorContains(t, err, "chainId does not match node's")
}

func TestDoEstimateGasMixedGasPricingError(t *testing.T) {
	t.Parallel()

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")

	genesis := &core.Genesis{
		Config: params.MergedTestChainConfig,
		Alloc: types.GenesisAlloc{
			from: {Balance: big.NewInt(params.Ether)},
			to:   {Balance: big.NewInt(params.Ether)},
		},
	}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	backend := &estimateBackendMock{
		backendMock: newBackendMock(),
		stateDB:     stateDB,
		header:      block.Header(),
		engine:      ethash.NewFaker(),
	}

	_, err = DoEstimateGas(
		context.Background(),
		backend,
		TransactionArgs{
			From:                 &from,
			To:                   &to,
			GasPrice:             (*hexutil.Big)(big.NewInt(1_000_000_000)),
			MaxFeePerGas:         (*hexutil.Big)(big.NewInt(1_000_000_000)),
			MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(1)),
		},
		rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber),
		nil,
		nil,
		0,
	)
	require.ErrorContains(t, err, "both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified")
}

func TestDoEstimateGasNilStateBehavior(t *testing.T) {
	t.Parallel()

	backend := &estimateRefBackendMock{backendMock: newBackendMock()}
	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")

	gas, err := DoEstimateGas(
		context.Background(),
		backend,
		TransactionArgs{From: &from, To: &to},
		rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber),
		nil,
		nil,
		0,
	)
	require.NoError(t, err)
	require.EqualValues(t, 0, gas)
}

func TestCreateAccessListBlockRefSelection(t *testing.T) {
	t.Parallel()

	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	callArgs := TransactionArgs{To: &to}

	backendDefault := &estimateRefBackendMock{
		backendMock: newBackendMock(),
		stateErr:    errors.New("state failed"),
	}
	apiDefault := NewBlockChainAPI(backendDefault, nil)
	result, err := apiDefault.CreateAccessList(context.Background(), callArgs, nil, nil)
	require.ErrorContains(t, err, "state failed")
	require.Nil(t, result)
	require.NotNil(t, backendDefault.seenRef)
	require.NotNil(t, backendDefault.seenRef.BlockNumber)
	require.Equal(t, rpc.LatestBlockNumber, *backendDefault.seenRef.BlockNumber)

	pending := rpc.BlockNumberOrHashWithNumber(rpc.PendingBlockNumber)
	backendExplicit := &estimateRefBackendMock{
		backendMock: newBackendMock(),
		stateErr:    errors.New("state failed"),
	}
	apiExplicit := NewBlockChainAPI(backendExplicit, nil)
	result, err = apiExplicit.CreateAccessList(context.Background(), callArgs, &pending, nil)
	require.ErrorContains(t, err, "state failed")
	require.Nil(t, result)
	require.NotNil(t, backendExplicit.seenRef)
	require.NotNil(t, backendExplicit.seenRef.BlockNumber)
	require.Equal(t, rpc.PendingBlockNumber, *backendExplicit.seenRef.BlockNumber)

	hashRef := rpc.BlockNumberOrHashWithHash(common.HexToHash("0x1234"), false)
	backendHash := &estimateRefBackendMock{
		backendMock: newBackendMock(),
		stateErr:    errors.New("state failed"),
	}
	apiHash := NewBlockChainAPI(backendHash, nil)
	result, err = apiHash.CreateAccessList(context.Background(), callArgs, &hashRef, nil)
	require.ErrorContains(t, err, "state failed")
	require.Nil(t, result)
	require.NotNil(t, backendHash.seenRef)
	require.NotNil(t, backendHash.seenRef.BlockHash)
	require.Equal(t, common.HexToHash("0x1234"), *backendHash.seenRef.BlockHash)
}

func TestCreateAccessListNilBlockError(t *testing.T) {
	t.Parallel()

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")

	genesis := &core.Genesis{
		Config: params.MergedTestChainConfig,
		Alloc: types.GenesisAlloc{
			from: {Balance: big.NewInt(params.Ether)},
			to:   {Balance: big.NewInt(params.Ether)},
		},
	}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	backend := &estimateBackendMock{
		backendMock: newBackendMock(),
		stateDB:     stateDB,
		header:      block.Header(),
		engine:      ethash.NewFaker(),
	}
	api := NewBlockChainAPI(backend, nil)
	latest := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)

	_, err = api.CreateAccessList(context.Background(), TransactionArgs{From: &from, To: &to}, &latest, nil)
	require.ErrorContains(t, err, "nil block in AccessList")
}

func TestCreateAccessListBlockLookupError(t *testing.T) {
	t.Parallel()

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")

	genesis := &core.Genesis{
		Config: params.MergedTestChainConfig,
		Alloc: types.GenesisAlloc{
			from: {Balance: big.NewInt(params.Ether)},
			to:   {Balance: big.NewInt(params.Ether)},
		},
	}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	backend := &createAccessListBackendMock{
		estimateBackendMock: &estimateBackendMock{
			backendMock: newBackendMock(),
			stateDB:     stateDB,
			header:      block.Header(),
			engine:      ethash.NewFaker(),
		},
		blockErr: errors.New("block lookup failed"),
	}
	api := NewBlockChainAPI(backend, nil)
	latest := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)

	result, err := api.CreateAccessList(context.Background(), TransactionArgs{From: &from, To: &to}, &latest, nil)
	require.ErrorContains(t, err, "block lookup failed")
	require.Nil(t, result)
}

func TestCreateAccessListNilStateBehavior(t *testing.T) {
	t.Parallel()

	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	backend := &estimateRefBackendMock{backendMock: newBackendMock()}
	api := NewBlockChainAPI(backend, nil)

	result, err := api.CreateAccessList(context.Background(), TransactionArgs{To: &to}, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Accesslist)
	require.Len(t, *result.Accesslist, 0)
	require.EqualValues(t, 0, result.GasUsed)
	require.Empty(t, result.Error)
}

func (b *callBackendMock) HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error) {
	return b.header, nil
}

func (b *callBackendMock) Engine() consensus.Engine {
	return ethash.NewFaker()
}

func (b *callBackendMock) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	ref := blockNrOrHash
	b.seenRef = &ref
	return b.stateDB, b.header, b.stateErr
}

func (b *callBackendMock) BlockByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Block, error) {
	return b.block, b.blockErr
}

func TestCallBlockRefSelection(t *testing.T) {
	t.Parallel()

	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	callArgs := TransactionArgs{To: &to}

	backendDefault := &callBackendMock{
		backendMock: newBackendMock(),
		stateErr:    errors.New("state failed"),
	}
	apiDefault := NewBlockChainAPI(backendDefault, nil)
	_, err := apiDefault.Call(context.Background(), callArgs, nil, nil, nil)
	require.ErrorContains(t, err, "state failed")
	require.NotNil(t, backendDefault.seenRef)
	require.NotNil(t, backendDefault.seenRef.BlockNumber)
	require.Equal(t, rpc.LatestBlockNumber, *backendDefault.seenRef.BlockNumber)

	pending := rpc.BlockNumberOrHashWithNumber(rpc.PendingBlockNumber)
	backendExplicit := &callBackendMock{
		backendMock: newBackendMock(),
		stateErr:    errors.New("state failed"),
	}
	apiExplicit := NewBlockChainAPI(backendExplicit, nil)
	_, err = apiExplicit.Call(context.Background(), callArgs, &pending, nil, nil)
	require.ErrorContains(t, err, "state failed")
	require.NotNil(t, backendExplicit.seenRef)
	require.NotNil(t, backendExplicit.seenRef.BlockNumber)
	require.Equal(t, rpc.PendingBlockNumber, *backendExplicit.seenRef.BlockNumber)

	hashRef := rpc.BlockNumberOrHashWithHash(common.HexToHash("0x1234"), false)
	backendHash := &callBackendMock{
		backendMock: newBackendMock(),
		stateErr:    errors.New("state failed"),
	}
	apiHash := NewBlockChainAPI(backendHash, nil)
	_, err = apiHash.Call(context.Background(), callArgs, &hashRef, nil, nil)
	require.ErrorContains(t, err, "state failed")
	require.NotNil(t, backendHash.seenRef)
	require.NotNil(t, backendHash.seenRef.BlockHash)
	require.Equal(t, common.HexToHash("0x1234"), *backendHash.seenRef.BlockHash)
}

func TestCallBasicErrors(t *testing.T) {
	t.Parallel()

	db := rawdb.NewMemoryDatabase()
	genesis := (&core.Genesis{Config: params.MergedTestChainConfig}).MustCommit(db)
	stateDB, err := state.New(genesis.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	callArgs := TransactionArgs{To: &to}

	backendStateErr := &callBackendMock{
		backendMock: newBackendMock(),
		stateErr:    errors.New("state failed"),
	}
	apiStateErr := NewBlockChainAPI(backendStateErr, nil)
	_, err = apiStateErr.Call(context.Background(), callArgs, nil, nil, nil)
	require.ErrorContains(t, err, "state failed")

	backendNilHeader := &callBackendMock{
		backendMock: newBackendMock(),
		stateDB:     stateDB,
		header:      nil,
	}
	apiNilHeader := NewBlockChainAPI(backendNilHeader, nil)
	_, err = apiNilHeader.Call(context.Background(), callArgs, nil, nil, nil)
	require.ErrorContains(t, err, "nil header in DoCall")

	backendNilBlock := &callBackendMock{
		backendMock: newBackendMock(),
		stateDB:     stateDB,
		header:      genesis.Header(),
		block:       nil,
	}
	apiNilBlock := NewBlockChainAPI(backendNilBlock, nil)
	_, err = apiNilBlock.Call(context.Background(), callArgs, nil, nil, nil)
	require.ErrorContains(t, err, "nil block in DoCall")

	backendBlockErr := &callBackendMock{
		backendMock: newBackendMock(),
		stateDB:     stateDB,
		header:      genesis.Header(),
		blockErr:    errors.New("block lookup failed"),
	}
	apiBlockErr := NewBlockChainAPI(backendBlockErr, nil)
	_, err = apiBlockErr.Call(context.Background(), callArgs, nil, nil, nil)
	require.ErrorContains(t, err, "block lookup failed")
}

func TestCallInvalidStateOverride(t *testing.T) {
	t.Parallel()

	db := rawdb.NewMemoryDatabase()
	genesis := (&core.Genesis{Config: params.MergedTestChainConfig}).MustCommit(db)
	stateDB, err := state.New(genesis.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	block := types.NewBlock(genesis.Header(), &types.Body{}, nil, newHasher())
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	overrides := override.StateOverride{
		to: override.OverrideAccount{
			State: map[common.Hash]common.Hash{
				common.HexToHash("0x1"): common.HexToHash("0x2"),
			},
			StateDiff: map[common.Hash]common.Hash{
				common.HexToHash("0x3"): common.HexToHash("0x4"),
			},
		},
	}

	backend := &callBackendMock{
		backendMock: newBackendMock(),
		stateDB:     stateDB,
		header:      genesis.Header(),
		block:       block,
	}
	api := NewBlockChainAPI(backend, nil)

	_, err = api.Call(context.Background(), TransactionArgs{To: &to}, nil, &overrides, nil)
	require.ErrorContains(t, err, "has both 'state' and 'stateDiff'")
}

func TestDoCallInvalidStateOverride(t *testing.T) {
	t.Parallel()

	db := rawdb.NewMemoryDatabase()
	genesis := (&core.Genesis{Config: params.MergedTestChainConfig}).MustCommit(db)
	stateDB, err := state.New(genesis.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	block := types.NewBlock(genesis.Header(), &types.Body{}, nil, newHasher())
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	overrides := override.StateOverride{
		to: override.OverrideAccount{
			State: map[common.Hash]common.Hash{
				common.HexToHash("0x1"): common.HexToHash("0x2"),
			},
			StateDiff: map[common.Hash]common.Hash{
				common.HexToHash("0x3"): common.HexToHash("0x4"),
			},
		},
	}

	backend := &callBackendMock{
		backendMock: newBackendMock(),
		stateDB:     stateDB,
		header:      genesis.Header(),
		block:       block,
	}
	latest := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)

	_, err = DoCall(context.Background(), backend, TransactionArgs{To: &to}, latest, &overrides, nil, 0, 0)
	require.ErrorContains(t, err, "has both 'state' and 'stateDiff'")
}

func TestRPCMarshalHeaderBaseFeeField(t *testing.T) {
	t.Parallel()

	headerWithoutBaseFee := &types.Header{
		Number:     big.NewInt(1),
		GasLimit:   10_000_000,
		GasUsed:    21_000,
		Time:       1,
		Difficulty: big.NewInt(1),
	}
	resultWithoutBaseFee := RPCMarshalHeader(headerWithoutBaseFee)
	_, hasBaseFee := resultWithoutBaseFee["baseFeePerGas"]
	require.False(t, hasBaseFee)

	headerWithBaseFee := types.CopyHeader(headerWithoutBaseFee)
	headerWithBaseFee.BaseFee = big.NewInt(123456789)
	resultWithBaseFee := RPCMarshalHeader(headerWithBaseFee)
	baseFeeValue, hasBaseFee := resultWithBaseFee["baseFeePerGas"]
	require.True(t, hasBaseFee)
	require.Equal(t, (*hexutil.Big)(headerWithBaseFee.BaseFee), baseFeeValue)
}

func TestRPCMarshalHeaderCoreFields(t *testing.T) {
	t.Parallel()

	header := &types.Header{
		ParentHash:  common.HexToHash("0x01"),
		UncleHash:   common.HexToHash("0x02"),
		Coinbase:    common.HexToAddress("0x00000000000000000000000000000000000000ab"),
		Root:        common.HexToHash("0x03"),
		TxHash:      common.HexToHash("0x04"),
		ReceiptHash: common.HexToHash("0x05"),
		Bloom:       types.Bloom{0xaa},
		Difficulty:  big.NewInt(99),
		Number:      big.NewInt(123),
		GasLimit:    10_000_000,
		GasUsed:     21_000,
		Time:        77,
		Extra:       []byte{0x01, 0x02},
		MixDigest:   common.HexToHash("0x06"),
		Nonce:       types.BlockNonce{0x07},
		Validators:  []byte{0x08},
		Validator:   []byte{0x09},
		Penalties:   []byte{0x0a},
	}

	result := RPCMarshalHeader(header)
	require.Equal(t, header.Hash(), result["hash"])
	require.Equal(t, header.ParentHash, result["parentHash"])
	require.Equal(t, header.Coinbase, result["miner"])
	require.Equal(t, header.Root, result["stateRoot"])
	require.Equal(t, header.TxHash, result["transactionsRoot"])
	require.Equal(t, header.ReceiptHash, result["receiptsRoot"])
	require.Equal(t, header.MixDigest, result["mixHash"])
	require.Equal(t, header.Nonce, result["nonce"])
	require.Equal(t, (*hexutil.Big)(header.Number), result["number"])
	require.Equal(t, hexutil.Uint64(header.GasLimit), result["gasLimit"])
	require.Equal(t, hexutil.Uint64(header.GasUsed), result["gasUsed"])
	require.Equal(t, hexutil.Uint64(header.Time), result["timestamp"])
	require.Equal(t, hexutil.Bytes(header.Extra), result["extraData"])
	require.Equal(t, hexutil.Bytes(header.Validators), result["validators"])
	require.Equal(t, hexutil.Bytes(header.Validator), result["validator"])
	require.Equal(t, hexutil.Bytes(header.Penalties), result["penalties"])
}

func TestEffectiveGasPrice(t *testing.T) {
	t.Parallel()

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   big.NewInt(42),
		Nonce:     1,
		GasTipCap: big.NewInt(2),
		GasFeeCap: big.NewInt(10),
		Gas:       21000,
		To:        &common.Address{},
		Value:     big.NewInt(1),
	})

	price := effectiveGasPrice(tx, big.NewInt(5))
	require.Equal(t, big.NewInt(7), price)

	price = effectiveGasPrice(tx, big.NewInt(20))
	require.Equal(t, big.NewInt(10), price)

	// Ensure helper does not mutate tx fee fields.
	require.Equal(t, big.NewInt(2), tx.GasTipCap())
	require.Equal(t, big.NewInt(10), tx.GasFeeCap())
}

func TestNewRPCPendingTransactionDynamicFee(t *testing.T) {
	t.Parallel()

	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   big.NewInt(42),
		Nonce:     3,
		GasTipCap: big.NewInt(2),
		GasFeeCap: big.NewInt(15),
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(9),
	})

	rpcTx := newRPCPendingTransaction(tx, nil, params.TestChainConfig)
	require.NotNil(t, rpcTx)
	require.EqualValues(t, types.DynamicFeeTxType, rpcTx.Type)
	require.Nil(t, rpcTx.BlockHash)
	require.Nil(t, rpcTx.BlockNumber)
	require.Nil(t, rpcTx.TransactionIndex)
	require.Equal(t, tx.Hash(), rpcTx.Hash)
	require.Equal(t, (*hexutil.Big)(tx.GasFeeCap()), rpcTx.GasPrice)
	require.Equal(t, (*hexutil.Big)(tx.GasFeeCap()), rpcTx.GasFeeCap)
	require.Equal(t, (*hexutil.Big)(tx.GasTipCap()), rpcTx.GasTipCap)
}

func TestNewRPCPendingTransactionWithCurrentHeader(t *testing.T) {
	t.Parallel()

	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   params.TestChainConfig.ChainID,
		Nonce:     4,
		GasTipCap: big.NewInt(3),
		GasFeeCap: big.NewInt(25),
		Gas:       22000,
		To:        &to,
		Value:     big.NewInt(11),
	})
	current := &types.Header{Number: big.NewInt(1100), GasLimit: 10_000_000, BaseFee: big.NewInt(10)}

	rpcTx := newRPCPendingTransaction(tx, current, params.TestChainConfig)
	require.NotNil(t, rpcTx)
	require.Nil(t, rpcTx.BlockHash)
	require.Nil(t, rpcTx.BlockNumber)
	require.Nil(t, rpcTx.TransactionIndex)
	require.Equal(t, (*hexutil.Big)(tx.GasFeeCap()), rpcTx.GasPrice)
	require.Equal(t, (*hexutil.Big)(tx.GasFeeCap()), rpcTx.GasFeeCap)
	require.Equal(t, (*hexutil.Big)(tx.GasTipCap()), rpcTx.GasTipCap)
}

func TestNewRPCPendingTransactionLegacyNilCurrent(t *testing.T) {
	t.Parallel()

	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    10,
		GasPrice: big.NewInt(17),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(12),
	})

	rpcTx := newRPCPendingTransaction(tx, nil, params.TestChainConfig)
	require.NotNil(t, rpcTx)
	require.EqualValues(t, types.LegacyTxType, rpcTx.Type)
	require.Nil(t, rpcTx.BlockHash)
	require.Nil(t, rpcTx.BlockNumber)
	require.Nil(t, rpcTx.TransactionIndex)
	require.Equal(t, (*hexutil.Big)(tx.GasPrice()), rpcTx.GasPrice)
	require.Nil(t, rpcTx.GasFeeCap)
	require.Nil(t, rpcTx.GasTipCap)
}
func TestRPCTransactionHelpersOutOfRange(t *testing.T) {
	t.Parallel()

	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    1,
		GasPrice: big.NewInt(7),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(1),
	})
	block := types.NewBlock(
		&types.Header{Number: big.NewInt(10), GasLimit: 10_000_000},
		&types.Body{Transactions: []*types.Transaction{tx}},
		nil,
		newHasher(),
	)

	rpcTx := newRPCTransactionFromBlockIndex(block, 1, params.TestChainConfig)
	require.Nil(t, rpcTx)

	raw := newRPCRawTransactionFromBlockIndex(block, 1)
	require.Nil(t, raw)
}
func TestRPCTransactionHelpersFromBlockIndex(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	tx, err := types.SignNewTx(key, types.LatestSigner(params.TestChainConfig), &types.DynamicFeeTx{
		ChainID:   params.TestChainConfig.ChainID,
		Nonce:     1,
		GasTipCap: big.NewInt(2),
		GasFeeCap: big.NewInt(20),
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(5),
	})
	require.NoError(t, err)

	block := types.NewBlock(
		&types.Header{Number: big.NewInt(1100), GasLimit: 10_000_000, BaseFee: big.NewInt(10)},
		&types.Body{Transactions: []*types.Transaction{tx}},
		nil,
		newHasher(),
	)

	rpcTx := newRPCTransactionFromBlockIndex(block, 0, params.TestChainConfig)
	require.NotNil(t, rpcTx)
	require.NotNil(t, rpcTx.BlockHash)
	require.Equal(t, block.Hash(), *rpcTx.BlockHash)
	require.NotNil(t, rpcTx.BlockNumber)
	require.Equal(t, (*hexutil.Big)(new(big.Int).SetUint64(block.NumberU64())), rpcTx.BlockNumber)
	require.NotNil(t, rpcTx.TransactionIndex)
	require.Equal(t, hexutil.Uint64(0), *rpcTx.TransactionIndex)
	require.Equal(t, tx.Hash(), rpcTx.Hash)
	require.Equal(t, (*hexutil.Big)(big.NewInt(12)), rpcTx.GasPrice)
	require.Equal(t, (*hexutil.Big)(tx.GasFeeCap()), rpcTx.GasFeeCap)
	require.Equal(t, (*hexutil.Big)(tx.GasTipCap()), rpcTx.GasTipCap)

	wantRaw, err := tx.MarshalBinary()
	require.NoError(t, err)
	raw := newRPCRawTransactionFromBlockIndex(block, 0)
	require.Equal(t, hexutil.Bytes(wantRaw), raw)
}
func TestCheckTxFee(t *testing.T) {
	t.Parallel()

	// cap disabled
	require.NoError(t, checkTxFee(big.NewInt(params.Ether), 21000, 0))

	// under cap
	require.NoError(t, checkTxFee(big.NewInt(1_000_000_000), 21000, 1))

	// exactly at cap should pass
	require.NoError(t, checkTxFee(big.NewInt(params.Ether), 1, 1))

	// zero gas means zero fee and should pass any positive cap
	require.NoError(t, checkTxFee(big.NewInt(params.Ether), 0, 0.000001))

	// exceed cap
	err := checkTxFee(big.NewInt(params.Ether), 1, 0.5)
	require.Error(t, err)
	require.ErrorContains(t, err, "exceeds the configured cap")
}
func TestRPCMarshalBlockUncles(t *testing.T) {
	t.Parallel()

	uncle := &types.Header{Number: big.NewInt(99), GasLimit: 1}
	block := types.NewBlock(
		&types.Header{Number: big.NewInt(100), GasLimit: 10_000_000},
		&types.Body{Uncles: []*types.Header{uncle}},
		nil,
		newHasher(),
	)

	resp := RPCMarshalBlock(block, false, false, params.MainnetChainConfig)
	uncles, ok := resp["uncles"].([]common.Hash)
	require.True(t, ok)
	require.Len(t, uncles, 1)
	require.Equal(t, uncle.Hash(), uncles[0])
}

func TestBlockChainAPIBasic(t *testing.T) {
	t.Parallel()

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	genesis := &core.Genesis{
		Config: params.MergedTestChainConfig,
		Alloc: types.GenesisAlloc{
			addr: {
				Balance: big.NewInt(12345),
			},
		},
	}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	backend := &storageBackendMock{
		backendMock: newBackendMock(),
		stateDB:     stateDB,
		header:      block.Header(),
	}
	api := NewBlockChainAPI(backend, nil)

	require.Equal(t, (*hexutil.Big)(backend.ChainConfig().ChainID), api.ChainId())
	require.Equal(t, hexutil.Uint64(block.NumberU64()), api.BlockNumber())

	latest := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	balance, err := api.GetBalance(context.Background(), addr, latest)
	require.NoError(t, err)
	require.Equal(t, (*hexutil.Big)(big.NewInt(12345)), balance)

	zeroBalance, err := api.GetBalance(context.Background(), common.HexToAddress("0x9999999999999999999999999999999999999999"), latest)
	require.NoError(t, err)
	require.Equal(t, (*hexutil.Big)(big.NewInt(0)), zeroBalance)

	backend.err = errors.New("state unavailable")
	_, err = api.GetBalance(context.Background(), addr, latest)
	require.ErrorContains(t, err, "state unavailable")
}

func TestBlockChainAPIGetRewardByHash(t *testing.T) {
	t.Parallel()

	reward := map[string]map[string]map[string]*big.Int{
		"epoch": {
			"validator": {
				"xdcabc": big.NewInt(99),
			},
		},
	}
	backend := &storageBackendMock{
		backendMock: newBackendMock(),
		reward:      reward,
	}
	api := NewBlockChainAPI(backend, nil)

	got := api.GetRewardByHash(common.HexToHash("0x1234"))
	require.Equal(t, reward, got)
}

func TestGetTransactionAndReceiptProofBasicErrors(t *testing.T) {
	t.Parallel()

	// tx not found -> nil, nil
	emptyBackend := &proofBackendMock{
		backendMock: newBackendMock(),
		db:          rawdb.NewMemoryDatabase(),
		blockByHash: map[common.Hash]*types.Block{},
	}
	emptyAPI := NewBlockChainAPI(emptyBackend, nil)
	proof, err := emptyAPI.GetTransactionAndReceiptProof(context.Background(), common.HexToHash("0xdeadbeef"))
	require.NoError(t, err)
	require.Nil(t, proof)

	// tx found but block lookup fails -> error propagated
	key, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)
	to := common.HexToAddress("0x703c4b2bd70c169f5717101caee543299fc946c7")
	tx, err := types.SignNewTx(key, types.LatestSigner(params.TestChainConfig), &types.LegacyTx{
		Nonce:    1,
		GasPrice: big.NewInt(7),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(3),
	})
	require.NoError(t, err)

	block := types.NewBlock(
		&types.Header{Number: big.NewInt(66), GasLimit: 10_000_000},
		&types.Body{Transactions: []*types.Transaction{tx}},
		nil,
		newHasher(),
	)
	db := rawdb.NewMemoryDatabase()
	rawdb.WriteBlock(db, block)
	rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	rawdb.WriteTxLookupEntriesByBlock(db, block)

	errBackend := &proofBackendMock{
		backendMock: newBackendMock(),
		db:          db,
		blockByHash: map[common.Hash]*types.Block{},
		blockErr:    errors.New("block lookup failed"),
	}
	errAPI := NewBlockChainAPI(errBackend, nil)
	_, err = errAPI.GetTransactionAndReceiptProof(context.Background(), tx.Hash())
	require.ErrorContains(t, err, "block lookup failed")

	// tx found and block found, but receipts lookup fails -> error propagated
	receiptErrBackend := &proofBackendMock{
		backendMock: newBackendMock(),
		db:          db,
		blockByHash: map[common.Hash]*types.Block{block.Hash(): block},
		receiptErr:  errors.New("receipt lookup failed"),
	}
	receiptErrAPI := NewBlockChainAPI(receiptErrBackend, nil)
	_, err = receiptErrAPI.GetTransactionAndReceiptProof(context.Background(), tx.Hash())
	require.ErrorContains(t, err, "receipt lookup failed")

	// tx found and block found, but receipts missing target index -> nil, nil
	tx2, err := types.SignNewTx(key, types.LatestSigner(params.TestChainConfig), &types.LegacyTx{
		Nonce:    2,
		GasPrice: big.NewInt(8),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(4),
	})
	require.NoError(t, err)

	block2 := types.NewBlock(
		&types.Header{Number: big.NewInt(67), GasLimit: 10_000_000},
		&types.Body{Transactions: []*types.Transaction{tx, tx2}},
		nil,
		newHasher(),
	)
	db2 := rawdb.NewMemoryDatabase()
	rawdb.WriteBlock(db2, block2)
	rawdb.WriteCanonicalHash(db2, block2.Hash(), block2.NumberU64())
	rawdb.WriteTxLookupEntriesByBlock(db2, block2)
	rawdb.WriteReceipts(db2, block2.Hash(), block2.NumberU64(), types.Receipts{{Status: types.ReceiptStatusSuccessful}})

	shortReceiptsBackend := &proofBackendMock{
		backendMock: newBackendMock(),
		db:          db2,
		blockByHash: map[common.Hash]*types.Block{block2.Hash(): block2},
	}
	shortReceiptsAPI := NewBlockChainAPI(shortReceiptsBackend, nil)
	proof, err = shortReceiptsAPI.GetTransactionAndReceiptProof(context.Background(), tx2.Hash())
	require.NoError(t, err)
	require.Nil(t, proof)
}

func TestGetTransactionAndReceiptProofSuccess(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	require.NoError(t, err)
	to := common.HexToAddress("0x703c4b2bd70c169f5717101caee543299fc946c7")
	tx, err := types.SignNewTx(key, types.LatestSigner(params.TestChainConfig), &types.LegacyTx{
		Nonce:    3,
		GasPrice: big.NewInt(9),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(5),
	})
	require.NoError(t, err)

	block := types.NewBlock(
		&types.Header{Number: big.NewInt(68), GasLimit: 10_000_000},
		&types.Body{Transactions: []*types.Transaction{tx}},
		nil,
		newHasher(),
	)
	receipts := types.Receipts{{
		Status:            types.ReceiptStatusSuccessful,
		CumulativeGasUsed: 21000,
		GasUsed:           21000,
		EffectiveGasPrice: big.NewInt(9),
	}}

	db := rawdb.NewMemoryDatabase()
	rawdb.WriteBlock(db, block)
	rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	rawdb.WriteTxLookupEntriesByBlock(db, block)

	backend := &proofBackendMock{
		backendMock:    newBackendMock(),
		db:             db,
		blockByHash:    map[common.Hash]*types.Block{block.Hash(): block},
		receiptsByHash: map[common.Hash]types.Receipts{block.Hash(): receipts},
	}
	api := NewBlockChainAPI(backend, nil)

	proof, err := api.GetTransactionAndReceiptProof(context.Background(), tx.Hash())
	require.NoError(t, err)
	require.NotNil(t, proof)
	require.Equal(t, block.Hash(), proof["blockHash"])
	require.NotEmpty(t, proof["key"])
	require.NotEmpty(t, proof["txProofKeys"])
	require.NotEmpty(t, proof["txProofValues"])
	require.NotEmpty(t, proof["receiptProofKeys"])
	require.NotEmpty(t, proof["receiptProofValues"])
}

func TestBlockChainAPIGetCodeAndStorageAt(t *testing.T) {
	t.Parallel()

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	slot := common.BigToHash(big.NewInt(7))
	val := common.BigToHash(big.NewInt(99))
	code := hexutil.MustDecode("0x6001600055")

	genesis := &core.Genesis{
		Config: params.MergedTestChainConfig,
		Alloc: types.GenesisAlloc{
			addr: {
				Balance: big.NewInt(params.Ether),
				Code:    code,
				Storage: map[common.Hash]common.Hash{slot: val},
			},
		},
	}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	backend := &storageBackendMock{
		backendMock: newBackendMock(),
		stateDB:     stateDB,
		header:      block.Header(),
	}
	api := NewBlockChainAPI(backend, nil)
	latest := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)

	gotCode, err := api.GetCode(context.Background(), addr, latest)
	require.NoError(t, err)
	require.Equal(t, hexutil.Bytes(code), gotCode)

	gotStorage, err := api.GetStorageAt(context.Background(), addr, slot.Hex(), latest)
	require.NoError(t, err)
	require.Equal(t, val[:], []byte(gotStorage))

	missingCode, err := api.GetCode(context.Background(), common.HexToAddress("0x9999999999999999999999999999999999999999"), latest)
	require.NoError(t, err)
	require.Empty(t, missingCode)

	missingStorage, err := api.GetStorageAt(context.Background(), addr, common.HexToHash("0xff").Hex(), latest)
	require.NoError(t, err)
	require.Equal(t, common.Hash{}.Bytes(), []byte(missingStorage))

	backend.err = errors.New("state unavailable")
	_, err = api.GetCode(context.Background(), addr, latest)
	require.ErrorContains(t, err, "state unavailable")
	_, err = api.GetStorageAt(context.Background(), addr, slot.Hex(), latest)
	require.ErrorContains(t, err, "state unavailable")
}

func TestBlockChainAPIGetAccountInfo(t *testing.T) {
	t.Parallel()

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	code := hexutil.MustDecode("0x6001600055")
	genesis := &core.Genesis{
		Config: params.MergedTestChainConfig,
		Alloc: types.GenesisAlloc{
			addr: {
				Balance: big.NewInt(500),
				Nonce:   3,
				Code:    code,
			},
		},
	}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	backend := &storageBackendMock{
		backendMock: newBackendMock(),
		stateDB:     stateDB,
		header:      block.Header(),
	}
	api := NewBlockChainAPI(backend, nil)
	latest := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)

	info, err := api.GetAccountInfo(context.Background(), addr, latest)
	require.NoError(t, err)
	require.Equal(t, addr, info["address"])
	require.Equal(t, (*hexutil.Big)(big.NewInt(500)), info["balance"])
	require.Equal(t, uint64(3), info["nonce"])
	require.Equal(t, len(code), info["codeSize"])
	require.Equal(t, crypto.Keccak256Hash(code), info["codeHash"])

	backend.err = errors.New("state unavailable")
	_, err = api.GetAccountInfo(context.Background(), addr, latest)
	require.ErrorContains(t, err, "state unavailable")
}

func TestSimulateV1StateBuildUpAcrossBlocks(t *testing.T) {
	t.Parallel()

	var (
		sender    = common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
		receiver  = common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
		benefitTo = common.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")
	)

	genesis := &core.Genesis{Config: params.MergedTestChainConfig}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	backend := &simulateBackendMock{
		estimateBackendMock: &estimateBackendMock{
			backendMock: newBackendMock(),
			stateDB:     stateDB,
			header:      block.Header(),
			engine:      ethash.NewFaker(),
		},
		gasCap: 30_000_000,
	}
	api := NewBlockChainAPI(backend, nil)

	results, err := api.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{
		{
			StateOverrides: &override.StateOverride{
				sender: override.OverrideAccount{Balance: (*hexutil.Big)(big.NewInt(2000))},
			},
			Calls: []TransactionArgs{{
				From:  &sender,
				To:    &receiver,
				Value: (*hexutil.Big)(big.NewInt(1000)),
			}},
		},
		{
			Calls: []TransactionArgs{{
				From:  &receiver,
				To:    &benefitTo,
				Value: (*hexutil.Big)(big.NewInt(1000)),
			}},
		},
	}}, nil)
	require.NoError(t, err)
	require.Len(t, results, 2)

	type callSummary struct {
		Status string `json:"status"`
	}
	type blockSummary struct {
		Number string        `json:"number"`
		Calls  []callSummary `json:"calls"`
	}

	enc, err := json.Marshal(results)
	require.NoError(t, err)
	t.Log(string(enc))
	var summary []blockSummary
	require.NoError(t, json.Unmarshal(enc, &summary))
	require.Len(t, summary, 2)
	require.Equal(t, "0x1", summary[0].Number)
	require.Equal(t, "0x2", summary[1].Number)
	require.Len(t, summary[0].Calls, 1)
	require.Len(t, summary[1].Calls, 1)
	require.Equal(t, "0x1", summary[0].Calls[0].Status)
	require.Equal(t, "0x1", summary[1].Calls[0].Status)
}

func TestSimulateV1FillsBlockNumberGaps(t *testing.T) {
	t.Parallel()

	genesis := &core.Genesis{Config: params.MergedTestChainConfig}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	backend := &simulateBackendMock{
		estimateBackendMock: &estimateBackendMock{
			backendMock: newBackendMock(),
			stateDB:     stateDB,
			header:      block.Header(),
			engine:      ethash.NewFaker(),
		},
		gasCap: 30_000_000,
	}
	api := NewBlockChainAPI(backend, nil)

	farNumber := (*hexutil.Big)(big.NewInt(3))
	results, err := api.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{{
		BlockOverrides: &override.BlockOverrides{Number: farNumber},
	}}}, nil)
	require.NoError(t, err)
	require.Len(t, results, 3)

	type blockSummary struct {
		Number string `json:"number"`
	}
	enc, err := json.Marshal(results)
	require.NoError(t, err)
	var summary []blockSummary
	require.NoError(t, json.Unmarshal(enc, &summary))
	require.Equal(t, []blockSummary{{Number: "0x1"}, {Number: "0x2"}, {Number: "0x3"}}, summary)
}

func TestSimulateV1ValidationRejectsHighNonce(t *testing.T) {
	t.Parallel()

	var (
		sender    = common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
		recipient = common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
		nonceHigh = hexutil.Uint64(2)
	)

	genesis := &core.Genesis{
		Config: params.MergedTestChainConfig,
		Alloc: types.GenesisAlloc{
			sender: {Balance: big.NewInt(params.Ether)},
		},
	}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	backend := &simulateBackendMock{
		estimateBackendMock: &estimateBackendMock{
			backendMock: newBackendMock(),
			stateDB:     stateDB,
			header:      block.Header(),
			engine:      ethash.NewFaker(),
		},
		gasCap: 30_000_000,
	}
	api := NewBlockChainAPI(backend, nil)

	_, err = api.SimulateV1(context.Background(), simOpts{
		Validation: true,
		BlockStateCalls: []simBlock{{
			Calls: []TransactionArgs{{
				From:  &sender,
				To:    &recipient,
				Nonce: &nonceHigh,
			}},
		}},
	}, nil)
	require.ErrorContains(t, err, "nonce too high")

	var txErr *invalidTxError
	require.ErrorAs(t, err, &txErr)
	require.Equal(t, errCodeNonceTooHigh, txErr.Code)
}

func TestSimulateV1ValidationFeeCapsSuccess(t *testing.T) {
	t.Parallel()

	var (
		sender    = common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
		recipient = common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
		gas       = hexutil.Uint64(21000)
	)

	genesis := &core.Genesis{
		Config: params.MergedTestChainConfig,
		Alloc: types.GenesisAlloc{
			sender: {Balance: big.NewInt(params.Ether)},
		},
	}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	backend := &simulateBackendMock{
		estimateBackendMock: &estimateBackendMock{
			backendMock: newBackendMock(),
			stateDB:     stateDB,
			header:      block.Header(),
			engine:      ethash.NewFaker(),
		},
		gasCap: 30_000_000,
	}
	api := NewBlockChainAPI(backend, nil)

	results, err := api.SimulateV1(context.Background(), simOpts{
		Validation: true,
		BlockStateCalls: []simBlock{{
			BlockOverrides: &override.BlockOverrides{BaseFeePerGas: (*hexutil.Big)(big.NewInt(1))},
			Calls: []TransactionArgs{{
				From:                 &sender,
				To:                   &recipient,
				Gas:                  &gas,
				Value:                (*hexutil.Big)(big.NewInt(1000)),
				MaxFeePerGas:         (*hexutil.Big)(big.NewInt(2)),
				MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(1)),
			}},
		}},
	}, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)

	type callSummary struct {
		Status string `json:"status"`
	}
	type blockSummary struct {
		BaseFeePerGas string        `json:"baseFeePerGas"`
		Calls         []callSummary `json:"calls"`
	}

	enc, err := json.Marshal(results)
	require.NoError(t, err)
	var summary []blockSummary
	require.NoError(t, json.Unmarshal(enc, &summary))
	require.Len(t, summary, 1)
	require.Equal(t, "0x1", summary[0].BaseFeePerGas)
	require.Len(t, summary[0].Calls, 1)
	require.Equal(t, "0x1", summary[0].Calls[0].Status)
}

func TestSimulateV1ValidationRejectsMixedFeeStyle(t *testing.T) {
	t.Parallel()

	var (
		sender    = common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
		recipient = common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
		gas       = hexutil.Uint64(21000)
	)

	genesis := &core.Genesis{
		Config: params.MergedTestChainConfig,
		Alloc: types.GenesisAlloc{
			sender: {Balance: big.NewInt(params.Ether)},
		},
	}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	backend := &simulateBackendMock{
		estimateBackendMock: &estimateBackendMock{
			backendMock: newBackendMock(),
			stateDB:     stateDB,
			header:      block.Header(),
			engine:      ethash.NewFaker(),
		},
		gasCap: 30_000_000,
	}
	api := NewBlockChainAPI(backend, nil)

	_, err = api.SimulateV1(context.Background(), simOpts{
		Validation: true,
		BlockStateCalls: []simBlock{{
			Calls: []TransactionArgs{{
				From:         &sender,
				To:           &recipient,
				Gas:          &gas,
				GasPrice:     (*hexutil.Big)(big.NewInt(1)),
				MaxFeePerGas: (*hexutil.Big)(big.NewInt(2)),
			}},
		}},
	}, nil)
	require.ErrorContains(t, err, "both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified")
}

func TestSimulateV1BaseFeeNonValidationMode(t *testing.T) {
	t.Parallel()

	var (
		sender   = common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")
		contract = common.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")
		gas      = hexutil.Uint64(100000)
	)

	genesis := &core.Genesis{
		Config: params.MergedTestChainConfig,
		Alloc: types.GenesisAlloc{
			sender: {Balance: big.NewInt(params.Ether)},
		},
	}
	db := rawdb.NewMemoryDatabase()
	block := genesis.MustCommit(db)
	stateDB, err := state.New(block.Root(), state.NewDatabase(db))
	require.NoError(t, err)

	backend := &simulateBackendMock{
		estimateBackendMock: &estimateBackendMock{
			backendMock: newBackendMock(),
			stateDB:     stateDB,
			header:      block.Header(),
			engine:      ethash.NewFaker(),
		},
		gasCap: 30_000_000,
	}
	api := NewBlockChainAPI(backend, nil)

	code := hexutil.Bytes(common.FromHex("0x3a489060005260205260406000f3"))
	results, err := api.SimulateV1(context.Background(), simOpts{BlockStateCalls: []simBlock{
		{
			StateOverrides: &override.StateOverride{
				contract: override.OverrideAccount{Code: &code},
			},
			Calls: []TransactionArgs{{
				From: &sender,
				To:   &contract,
				Gas:  &gas,
			}, {
				From:                 &sender,
				To:                   &contract,
				Gas:                  &gas,
				MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(1)),
				MaxFeePerGas:         (*hexutil.Big)(big.NewInt(2)),
			}},
		},
		{
			BlockOverrides: &override.BlockOverrides{BaseFeePerGas: (*hexutil.Big)(big.NewInt(1))},
			Calls: []TransactionArgs{{
				From: &sender,
				To:   &contract,
				Gas:  &gas,
			}, {
				From:                 &sender,
				To:                   &contract,
				Gas:                  &gas,
				MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(1)),
				MaxFeePerGas:         (*hexutil.Big)(big.NewInt(2)),
			}},
		},
	}}, nil)
	require.NoError(t, err)
	require.Len(t, results, 2)

	type callSummary struct {
		ReturnValue string `json:"returnData"`
		Status      string `json:"status"`
		Error       struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	type blockSummary struct {
		BaseFeePerGas string        `json:"baseFeePerGas"`
		Calls         []callSummary `json:"calls"`
	}

	enc, err := json.Marshal(results)
	require.NoError(t, err)
	var summary []blockSummary
	require.NoError(t, json.Unmarshal(enc, &summary))
	require.Len(t, summary, 2)

	require.Empty(t, summary[0].BaseFeePerGas)
	require.Equal(t, "0x1", summary[1].BaseFeePerGas)
	require.Len(t, summary[0].Calls, 2)
	require.Len(t, summary[1].Calls, 2)

	require.Equal(t, "0x", summary[0].Calls[0].ReturnValue)
	require.Equal(t, "0x", summary[0].Calls[1].ReturnValue)
	require.Equal(t, "0x", summary[1].Calls[0].ReturnValue)
	require.Equal(t, "0x", summary[1].Calls[1].ReturnValue)
	require.Equal(t, "0x0", summary[0].Calls[0].Status)
	require.Equal(t, "0x0", summary[0].Calls[1].Status)
	require.Equal(t, "0x0", summary[1].Calls[0].Status)
	require.Equal(t, "0x0", summary[1].Calls[1].Status)
	require.Equal(t, "invalid opcode: BASEFEE", summary[0].Calls[0].Error.Message)
	require.Equal(t, "invalid opcode: BASEFEE", summary[0].Calls[1].Error.Message)
	require.Equal(t, "invalid opcode: BASEFEE", summary[1].Calls[0].Error.Message)
	require.Equal(t, "invalid opcode: BASEFEE", summary[1].Calls[1].Error.Message)
}

func TestSimulateV1InvalidTimestampOrder(t *testing.T) {
	t.Parallel()

	base := &types.Header{Number: big.NewInt(10), Time: 100, GasLimit: 10_000_000}
	sim := &simulator{base: base}

	_, err := sim.sanitizeChain([]simBlock{
		{BlockOverrides: &override.BlockOverrides{Number: (*hexutil.Big)(big.NewInt(11)), Time: (*hexutil.Uint64)(new(uint64))}},
	})
	require.ErrorContains(t, err, "block timestamps must be in order")
}

func TestSimulateV1TooManyBlocksByOverrideNumber(t *testing.T) {
	t.Parallel()

	base := &types.Header{Number: big.NewInt(10), Time: 100, GasLimit: 10_000_000}
	sim := &simulator{base: base}

	tooFar := new(big.Int).Add(base.Number, big.NewInt(maxSimulateBlocks+1))
	_, err := sim.sanitizeChain([]simBlock{
		{BlockOverrides: &override.BlockOverrides{Number: (*hexutil.Big)(tooFar)}},
	})
	require.ErrorContains(t, err, "too many blocks")
}
