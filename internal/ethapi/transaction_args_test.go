// Copyright 2022 The go-ethereum Authors
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
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain"
	"github.com/XinFinOrg/XDPoSChain/accounts"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/hexutil"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/beacon"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/filtermaps"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/event"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rpc"
	"github.com/holiman/uint256"
)

// TestSetFeeDefaults tests the logic for filling in default fee values works as expected.
func TestSetFeeDefaults(t *testing.T) {
	t.Parallel()

	type test struct {
		name string
		fork string // options: legacy, london, cancun
		in   *TransactionArgs
		want *TransactionArgs
		err  error
	}

	var (
		b        = newBackendMock()
		zero     = (*hexutil.Big)(big.NewInt(0))
		fortytwo = (*hexutil.Big)(big.NewInt(42))
		maxFee   = (*hexutil.Big)(new(big.Int).Add(new(big.Int).Mul(b.current.BaseFee, big.NewInt(2)), fortytwo.ToInt()))
		al       = &types.AccessList{types.AccessTuple{Address: common.Address{0xaa}, StorageKeys: []common.Hash{{0x01}}}}
		authList = []types.SetCodeAuthorization{{Address: common.Address{0xbb}}}
	)

	tests := []test{
		// Legacy txs
		{
			"legacy tx pre-London",
			"legacy",
			&TransactionArgs{},
			&TransactionArgs{GasPrice: fortytwo},
			nil,
		},
		{
			"legacy tx pre-London with zero price",
			"legacy",
			&TransactionArgs{GasPrice: zero},
			&TransactionArgs{GasPrice: zero},
			nil,
		},
		{
			"legacy tx post-London, explicit gas price",
			"london",
			&TransactionArgs{GasPrice: fortytwo},
			&TransactionArgs{GasPrice: fortytwo},
			nil,
		},
		{
			"legacy tx post-London with zero price",
			"london",
			&TransactionArgs{GasPrice: zero},
			nil,
			errors.New("gasPrice must be non-zero after london fork"),
		},

		// Access list txs
		{
			"access list tx pre-London",
			"legacy",
			&TransactionArgs{AccessList: al},
			&TransactionArgs{AccessList: al, GasPrice: fortytwo},
			nil,
		},
		{
			"access list tx post-London, explicit gas price",
			"legacy",
			&TransactionArgs{AccessList: al, GasPrice: fortytwo},
			&TransactionArgs{AccessList: al, GasPrice: fortytwo},
			nil,
		},
		{
			"access list tx post-London",
			"london",
			&TransactionArgs{AccessList: al},
			&TransactionArgs{AccessList: al, MaxFeePerGas: maxFee, MaxPriorityFeePerGas: fortytwo},
			nil,
		},
		{
			"access list tx post-London, only max fee",
			"london",
			&TransactionArgs{AccessList: al, MaxFeePerGas: maxFee},
			&TransactionArgs{AccessList: al, MaxFeePerGas: maxFee, MaxPriorityFeePerGas: fortytwo},
			nil,
		},
		{
			"access list tx post-London, only priority fee",
			"london",
			&TransactionArgs{AccessList: al, MaxFeePerGas: maxFee},
			&TransactionArgs{AccessList: al, MaxFeePerGas: maxFee, MaxPriorityFeePerGas: fortytwo},
			nil,
		},

		// Dynamic fee txs
		{
			"dynamic tx post-London",
			"london",
			&TransactionArgs{},
			&TransactionArgs{MaxFeePerGas: maxFee, MaxPriorityFeePerGas: fortytwo},
			nil,
		},
		{
			"dynamic tx post-London, only max fee",
			"london",
			&TransactionArgs{MaxFeePerGas: maxFee},
			&TransactionArgs{MaxFeePerGas: maxFee, MaxPriorityFeePerGas: fortytwo},
			nil,
		},
		{
			"dynamic tx post-London, only priority fee",
			"london",
			&TransactionArgs{MaxFeePerGas: maxFee},
			&TransactionArgs{MaxFeePerGas: maxFee, MaxPriorityFeePerGas: fortytwo},
			nil,
		},
		{
			"dynamic fee tx pre-London, maxFee set",
			"legacy",
			&TransactionArgs{MaxFeePerGas: maxFee},
			nil,
			errors.New("maxFeePerGas and maxPriorityFeePerGas are not valid before London is active"),
		},
		{
			"dynamic fee tx pre-London, priorityFee set",
			"legacy",
			&TransactionArgs{MaxPriorityFeePerGas: fortytwo},
			nil,
			errors.New("maxFeePerGas and maxPriorityFeePerGas are not valid before London is active"),
		},
		{
			"dynamic fee tx, maxFee < priorityFee",
			"london",
			&TransactionArgs{MaxFeePerGas: maxFee, MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(1000))},
			nil,
			errors.New("maxFeePerGas (0x3e) < maxPriorityFeePerGas (0x3e8)"),
		},
		{
			"dynamic fee tx, maxFee < priorityFee while setting default",
			"london",
			&TransactionArgs{MaxFeePerGas: (*hexutil.Big)(big.NewInt(7))},
			nil,
			errors.New("maxFeePerGas (0x7) < maxPriorityFeePerGas (0x2a)"),
		},
		{
			"dynamic fee tx post-London, explicit gas price",
			"london",
			&TransactionArgs{MaxFeePerGas: zero, MaxPriorityFeePerGas: zero},
			nil,
			errors.New("maxFeePerGas must be non-zero"),
		},

		// Misc
		{
			"set all fee parameters",
			"legacy",
			&TransactionArgs{GasPrice: fortytwo, MaxFeePerGas: maxFee, MaxPriorityFeePerGas: fortytwo},
			nil,
			errors.New("both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified"),
		},
		{
			"set gas price and maxPriorityFee",
			"legacy",
			&TransactionArgs{GasPrice: fortytwo, MaxPriorityFeePerGas: fortytwo},
			nil,
			errors.New("both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified"),
		},
		{
			"set gas price and maxFee",
			"london",
			&TransactionArgs{GasPrice: fortytwo, MaxFeePerGas: maxFee},
			nil,
			errors.New("both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified"),
		},
		{
			"set gas price and authorization list",
			"london",
			&TransactionArgs{GasPrice: fortytwo, AuthorizationList: authList},
			nil,
			errors.New("both gasPrice and authorizationList specified"),
		},
		// EIP-4844
		{
			"set gas price and maxFee for blob transaction",
			"cancun",
			&TransactionArgs{GasPrice: fortytwo, MaxFeePerGas: maxFee, BlobHashes: []common.Hash{}},
			nil,
			errors.New("both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified"),
		},
		{
			"fill maxFeePerBlobGas",
			"cancun",
			&TransactionArgs{BlobHashes: []common.Hash{}},
			&TransactionArgs{BlobHashes: []common.Hash{}, BlobFeeCap: (*hexutil.Big)(big.NewInt(4)), MaxFeePerGas: maxFee, MaxPriorityFeePerGas: fortytwo},
			nil,
		},
		{
			"fill maxFeePerBlobGas when dynamic fees are set",
			"cancun",
			&TransactionArgs{BlobHashes: []common.Hash{}, MaxFeePerGas: maxFee, MaxPriorityFeePerGas: fortytwo},
			&TransactionArgs{BlobHashes: []common.Hash{}, BlobFeeCap: (*hexutil.Big)(big.NewInt(4)), MaxFeePerGas: maxFee, MaxPriorityFeePerGas: fortytwo},
			nil,
		},
	}

	ctx := context.Background()
	for i, test := range tests {
		if err := b.setFork(test.fork); err != nil {
			t.Fatalf("failed to set fork: %v", err)
		}
		got := test.in
		err := got.setFeeDefaults(ctx, b, b.CurrentHeader())
		if err != nil {
			if test.err == nil {
				t.Fatalf("test %d (%s): unexpected error: %s", i, test.name, err)
			} else if err.Error() != test.err.Error() {
				t.Fatalf("test %d (%s): unexpected error: (got: %s, want: %s)", i, test.name, err, test.err)
			}
			// Matching error.
			continue
		} else if test.err != nil {
			t.Fatalf("test %d (%s): expected error: %s", i, test.name, test.err)
		}
		if !reflect.DeepEqual(got, test.want) {
			t.Fatalf("test %d (%s): did not fill defaults as expected: (got: %v, want: %v)", i, test.name, got, test.want)
		}
	}
}

type backendMock struct {
	current *types.Header
	config  *params.ChainConfig
}

func newBackendMock() *backendMock {
	var cancunTime uint64 = 600
	config := &params.ChainConfig{
		ChainID:             big.NewInt(42),
		HomesteadBlock:      big.NewInt(0),
		DAOForkBlock:        nil,
		DAOForkSupport:      true,
		EIP150Block:         big.NewInt(0),
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    big.NewInt(0),
		BerlinBlock:         big.NewInt(0),
		LondonBlock:         big.NewInt(1000),
		CancunTime:          &cancunTime,
		BlobScheduleConfig:  params.DefaultBlobSchedule,
	}
	return &backendMock{
		current: &types.Header{
			Difficulty: big.NewInt(10000000000),
			Number:     big.NewInt(1100),
			GasLimit:   8_000_000,
			GasUsed:    8_000_000,
			Time:       555,
			Extra:      make([]byte, 32),
			BaseFee:    big.NewInt(10),
		},
		config: config,
	}
}

func (b *backendMock) setFork(fork string) error {
	if fork == "legacy" {
		b.current.Number = big.NewInt(900)
		b.current.Time = 555
	} else if fork == "london" {
		b.current.Number = big.NewInt(1100)
		b.current.Time = 555
	} else if fork == "cancun" {
		b.current.Number = big.NewInt(1100)
		b.current.Time = 700
		// Blob base fee will be 2
		excess := uint64(2314058)
		b.current.ExcessBlobGas = &excess
	} else {
		return errors.New("invalid fork")
	}
	return nil
}

func (b *backendMock) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	return big.NewInt(42), nil
}
func (b *backendMock) BlobBaseFee(ctx context.Context) *big.Int { return big.NewInt(42) }
func (b *backendMock) BaseFee(ctx context.Context) *big.Int     { return big.NewInt(42) }

func (b *backendMock) CurrentHeader() *types.Header     { return b.current }
func (b *backendMock) ChainConfig() *params.ChainConfig { return b.config }

// Other methods needed to implement Backend interface.
func (b *backendMock) SyncProgress(ctx context.Context) ethereum.SyncProgress {
	return ethereum.SyncProgress{}
}
func (b *backendMock) FeeHistory(ctx context.Context, blockCount uint64, lastBlock rpc.BlockNumber, rewardPercentiles []float64) (*big.Int, [][]*big.Int, []*big.Int, []float64, []*big.Int, []float64, error) {
	return nil, nil, nil, nil, nil, nil, nil
}
func (b *backendMock) ChainDb() ethdb.Database           { return nil }
func (b *backendMock) AccountManager() *accounts.Manager { return nil }
func (b *backendMock) ExtRPCEnabled() bool               { return false }
func (b *backendMock) RPCGasCap() uint64                 { return 0 }
func (b *backendMock) RPCEVMTimeout() time.Duration      { return time.Second }
func (b *backendMock) RPCTxFeeCap() float64              { return 0 }
func (b *backendMock) UnprotectedAllowed() bool          { return false }
func (b *backendMock) SetHead(number uint64) error       { return nil }
func (b *backendMock) HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error) {
	return nil, nil
}
func (b *backendMock) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	return nil, nil
}
func (b *backendMock) HeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Header, error) {
	return nil, nil
}
func (b *backendMock) CurrentBlock() *types.Header { return nil }
func (b *backendMock) BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error) {
	return nil, nil
}
func (b *backendMock) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	return nil, nil
}
func (b *backendMock) BlockByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Block, error) {
	return nil, nil
}
func (b *backendMock) GetBody(ctx context.Context, hash common.Hash, number rpc.BlockNumber) (*types.Body, error) {
	return nil, nil
}
func (b *backendMock) StateAndHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	return nil, nil, nil
}
func (b *backendMock) StateAndHeaderByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	return nil, nil, nil
}
func (b *backendMock) Pending() (*types.Block, types.Receipts, *state.StateDB) { return nil, nil, nil }
func (b *backendMock) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	return nil, nil
}
func (b *backendMock) GetCanonicalReceipt(tx *types.Transaction, blockHash common.Hash, blockNumber, blockIndex uint64) (*types.Receipt, error) {
	return nil, nil
}
func (b *backendMock) GetLogs(ctx context.Context, blockHash common.Hash, number uint64) ([][]*types.Log, error) {
	return nil, nil
}
func (b *backendMock) GetEVM(ctx context.Context, state *state.StateDB, header *types.Header, vmConfig *vm.Config, blockCtx *vm.BlockContext) *vm.EVM {
	return nil
}
func (b *backendMock) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription { return nil }
func (b *backendMock) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	return nil
}
func (b *backendMock) SendTx(ctx context.Context, signedTx *types.Transaction) error { return nil }
func (b *backendMock) GetCanonicalTransaction(txHash common.Hash) (bool, *types.Transaction, common.Hash, uint64, uint64) {
	return false, nil, [32]byte{}, 0, 0
}
func (b *backendMock) TxIndexDone() bool                                        { return true }
func (b *backendMock) GetPoolTransactions() (types.Transactions, error)         { return nil, nil }
func (b *backendMock) GetPoolTransaction(txHash common.Hash) *types.Transaction { return nil }
func (b *backendMock) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
	return 0, nil
}
func (b *backendMock) Stats() (pending int, queued int) { return 0, 0 }
func (b *backendMock) TxPoolContent() (map[common.Address][]*types.Transaction, map[common.Address][]*types.Transaction) {
	return nil, nil
}
func (b *backendMock) TxPoolContentFrom(addr common.Address) ([]*types.Transaction, []*types.Transaction) {
	return nil, nil
}
func (b *backendMock) SubscribeNewTxsEvent(chan<- core.NewTxsEvent) event.Subscription { return nil }
func (b *backendMock) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription    { return nil }
func (b *backendMock) SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription {
	return nil
}

func (b *backendMock) Engine() consensus.Engine { return nil }

func (b *backendMock) CurrentView() *filtermaps.ChainView           { return nil }
func (b *backendMock) NewMatcherBackend() filtermaps.MatcherBackend { return nil }

func (b *backendMock) HistoryPruningCutoff() uint64       { return 0 }
func (b *backendMock) HistoryRetention() HistoryRetention { return HistoryRetention{} }

// XDC-specific methods required by the Backend interface.
func (b *backendMock) GetRewardByHash(hash common.Hash) map[string]map[string]map[string]*big.Int {
	return nil
}
func (b *backendMock) BlockChain() *core.BlockChain               { return nil }
func (b *backendMock) SnapHealStatus() *core.SnapHealStatusFields { return nil }

// TestTransactionArgsFrameTx exercises the EIP-8141 frame transaction paths
// of the RPC argument handling: JSON parsing, transaction construction, and
// argument validation.
func TestTransactionArgsFrameTx(t *testing.T) {
	sender := common.HexToAddress("0x627306090abab3a6e1400e9345bc60c78a8bef57")

	validFrame := func() types.Frame {
		return types.Frame{
			Mode:   types.FrameModeVerify,
			Limits: types.FrameLimits{Execution: 50000, State: 10000},
			Value:  uint256.NewInt(0),
			Data:   []byte{0x01, 0x02},
		}
	}

	t.Run("json parses frame fields", func(t *testing.T) {
		raw := `{
			"sender":"0x627306090abab3a6e1400e9345bc60c78a8bef57",
			"frames":[{"mode":"0x1","flags":"0x0","limits":{"execution":"0xc350","state":"0x2710"},"value":"0x0","data":"0x1234"}],
			"signatures":[{"scheme":"0x0","signer":"0x","msg":"0x","signature":"0xabcd"}],
			"maxFeePerGas":"0x64","maxPriorityFeePerGas":"0x1"
		}`
		var args TransactionArgs
		if err := json.Unmarshal([]byte(raw), &args); err != nil {
			t.Fatalf("parse failed: %v", err)
		}
		if args.Sender == nil || *args.Sender != sender {
			t.Fatalf("sender not parsed: %v", args.Sender)
		}
		if len(args.Frames) != 1 {
			t.Fatalf("frames not parsed: %d", len(args.Frames))
		}
		frame := args.Frames[0]
		if frame.Mode != types.FrameModeVerify || frame.Flags != 0 {
			t.Fatalf("frame mode/flags mismatch: %d/%d", frame.Mode, frame.Flags)
		}
		if frame.Limits.Execution != 50000 || frame.Limits.State != 10000 {
			t.Fatalf("frame limits mismatch: %+v", frame.Limits)
		}
		if len(frame.Data) != 2 || frame.Data[0] != 0x12 {
			t.Fatalf("frame data mismatch: %x", frame.Data)
		}
		if len(args.Signatures) != 1 || args.Signatures[0].Scheme != types.FrameSigSchemeArbitrary {
			t.Fatalf("signatures not parsed: %+v", args.Signatures)
		}
		if len(args.Signatures[0].Signature) != 2 {
			t.Fatalf("signature bytes not parsed: %x", args.Signatures[0].Signature)
		}
	})

	t.Run("to transaction builds frame tx", func(t *testing.T) {
		gas := hexutil.Uint64(21000)
		nonce := hexutil.Uint64(3)
		args := TransactionArgs{
			From:                 &sender,
			Sender:               &sender,
			Frames:               []types.Frame{validFrame()},
			Gas:                  &gas,
			Nonce:                &nonce,
			MaxFeePerGas:         (*hexutil.Big)(big.NewInt(100)),
			MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(1)),
			ChainID:              (*hexutil.Big)(big.NewInt(20118)),
		}
		tx := args.ToTransaction(types.LegacyTxType)
		if tx.Type() != types.FrameTxType {
			t.Fatalf("wrong tx type %d", tx.Type())
		}
		if tx.ChainId().Cmp(big.NewInt(20118)) != 0 || tx.Nonce() != 3 {
			t.Fatal("scalar fields mismatch")
		}
		if tx.Gas() == 0 {
			t.Fatal("derived gas is zero")
		}
		out, err := json.Marshal(tx)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}
		if !strings.Contains(string(out), `"frames"`) || !strings.Contains(string(out), `"sender"`) {
			t.Fatalf("frame fields missing in JSON: %s", out)
		}
		// The produced transaction must round-trip through the typed codec.
		if _, err := tx.MarshalBinary(); err != nil {
			t.Fatalf("binary marshal failed: %v", err)
		}
	})

	t.Run("call defaults rejects frames", func(t *testing.T) {
		args := TransactionArgs{Frames: []types.Frame{validFrame()}}
		if err := args.CallDefaults(0, nil, big.NewInt(1)); err == nil {
			t.Fatal("CallDefaults accepted frame args")
		}
	})

	// The remaining cases go through setDefaults, which needs a backend.
	backend := newTestBackend(t, 1, &core.Genesis{
		Config: params.AllDevChainProtocolChanges,
		Alloc:  core.GenesisAlloc{},
	}, beacon.New(ethash.NewFaker()), nil)

	baseArgs := func() *TransactionArgs {
		gas := hexutil.Uint64(21000)
		nonce := hexutil.Uint64(3)
		return &TransactionArgs{
			From:                 &sender,
			Sender:               &sender,
			Frames:               []types.Frame{validFrame()},
			Gas:                  &gas,
			Nonce:                &nonce,
			MaxFeePerGas:         (*hexutil.Big)(big.NewInt(100)),
			MaxPriorityFeePerGas: (*hexutil.Big)(big.NewInt(1)),
		}
	}

	t.Run("setDefaults accepts valid frame args", func(t *testing.T) {
		args := baseArgs()
		if err := args.setDefaults(context.Background(), backend, sidecarConfig{}); err != nil {
			t.Fatalf("valid frame args rejected: %v", err)
		}
	})

	t.Run("setDefaults rejects gasPrice with frames", func(t *testing.T) {
		args := baseArgs()
		args.GasPrice = (*hexutil.Big)(big.NewInt(5))
		if err := args.setDefaults(context.Background(), backend, sidecarConfig{}); err == nil {
			t.Fatal("gasPrice with frames accepted")
		}
	})

	t.Run("setDefaults rejects missing sender", func(t *testing.T) {
		args := baseArgs()
		args.Sender = nil
		if err := args.setDefaults(context.Background(), backend, sidecarConfig{}); err == nil {
			t.Fatal("frame args without sender accepted")
		}
	})

	t.Run("setDefaults rejects empty frames", func(t *testing.T) {
		args := baseArgs()
		args.Frames = []types.Frame{}
		if err := args.setDefaults(context.Background(), backend, sidecarConfig{}); err == nil {
			t.Fatal("empty frames accepted")
		}
	})

	t.Run("setDefaults rejects invalid frame payload", func(t *testing.T) {
		args := baseArgs()
		bad := validFrame()
		bad.Mode = 0x3
		args.Frames = []types.Frame{bad}
		if err := args.setDefaults(context.Background(), backend, sidecarConfig{}); err == nil {
			t.Fatal("invalid frame payload accepted")
		}
	})

	t.Run("setDefaults rejects blob fee without blobs", func(t *testing.T) {
		args := baseArgs()
		args.BlobFeeCap = (*hexutil.Big)(big.NewInt(7))
		if err := args.setDefaults(context.Background(), backend, sidecarConfig{}); err == nil {
			t.Fatal("blob fee without blobs accepted")
		}
	})
}
