// Copyright 2016 The go-ethereum Authors
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

package filters

import (
	"context"
	"errors"
	"math/big"
	"reflect"
	"runtime"
	"testing"
	"time"

	ethereum "github.com/XinFinOrg/XDPoSChain"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/filtermaps"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/event"
	"github.com/XinFinOrg/XDPoSChain/internal/ethapi"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rpc"
)

type testBackend struct {
	db              ethdb.Database
	fm              *filtermaps.FilterMaps
	txFeed          event.Feed
	logsFeed        event.Feed
	rmLogsFeed      event.Feed
	chainFeed       event.Feed
	pendingBlock    *types.Block
	pendingReceipts types.Receipts
}

func (b *testBackend) ChainConfig() *params.ChainConfig {
	return params.TestChainConfig
}

func (b *testBackend) CurrentHeader() *types.Header {
	hdr, _ := b.HeaderByNumber(context.TODO(), rpc.LatestBlockNumber)
	return hdr
}

func (b *testBackend) CurrentBlock() *types.Header {
	return b.CurrentHeader()
}

func (b *testBackend) ChainDb() ethdb.Database {
	return b.db
}

func (b *testBackend) GetCanonicalHash(number uint64) common.Hash {
	return rawdb.ReadCanonicalHash(b.db, number)
}

func (b *testBackend) GetHeader(hash common.Hash, number uint64) *types.Header {
	hdr, _ := b.HeaderByHash(context.Background(), hash)
	return hdr
}

func (b *testBackend) GetReceiptsByHash(hash common.Hash) types.Receipts {
	r, _ := b.GetReceipts(context.Background(), hash)
	return r
}

func (b *testBackend) HeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Header, error) {
	var (
		hash common.Hash
		num  uint64
	)
	switch blockNr {
	case rpc.LatestBlockNumber:
		hash = rawdb.ReadHeadBlockHash(b.db)
		number := rawdb.ReadHeaderNumber(b.db, hash)
		if number == nil {
			return nil, nil
		}
		num = *number
	default:
		num = uint64(blockNr)
		hash = rawdb.ReadCanonicalHash(b.db, num)
	}
	return rawdb.ReadHeader(b.db, hash, num), nil
}

func (b *testBackend) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	number := rawdb.ReadHeaderNumber(b.db, hash)
	if number == nil {
		return nil, nil
	}
	return rawdb.ReadHeader(b.db, hash, *number), nil
}

func (b *testBackend) GetBody(ctx context.Context, hash common.Hash, number rpc.BlockNumber) (*types.Body, error) {
	if body := rawdb.ReadBody(b.db, hash, uint64(number)); body != nil {
		return body, nil
	}
	return nil, errors.New("block body not found")
}

func (b *testBackend) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	if number := rawdb.ReadHeaderNumber(b.db, hash); number != nil {
		if header := rawdb.ReadHeader(b.db, hash, *number); header != nil {
			return rawdb.ReadReceipts(b.db, hash, *number, params.TestChainConfig), nil
		}
	}
	return nil, nil
}

func (b *testBackend) GetRawReceipts(hash common.Hash, number uint64) types.Receipts {
	return rawdb.ReadRawReceipts(b.db, hash, number)
}

func (b *testBackend) GetLogs(ctx context.Context, hash common.Hash, number uint64) ([][]*types.Log, error) {
	logs := rawdb.ReadLogs(b.db, hash, number)
	return logs, nil
}

func (b *testBackend) SubscribeNewTxsEvent(ch chan<- core.NewTxsEvent) event.Subscription {
	return b.txFeed.Subscribe(ch)
}

func (b *testBackend) SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription {
	return b.rmLogsFeed.Subscribe(ch)
}

func (b *testBackend) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return b.logsFeed.Subscribe(ch)
}

func (b *testBackend) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription {
	return b.chainFeed.Subscribe(ch)
}

func (b *testBackend) NewMatcherBackend() filtermaps.MatcherBackend {
	return b.fm.NewMatcherBackend()
}

func (b *testBackend) startFilterMaps(history uint64, disabled bool, params filtermaps.Params) {
	head := b.CurrentBlock()
	chainView := filtermaps.NewChainView(b, head.Number.Uint64(), head.Hash())
	config := filtermaps.Config{
		History:        history,
		Disabled:       disabled,
		ExportFileName: "",
	}
	b.fm, _ = filtermaps.NewFilterMaps(b.db, chainView, 0, 0, params, config)
	b.fm.Start()
	b.fm.WaitIdle()
}

func (b *testBackend) stopFilterMaps() {
	b.fm.Stop()
	b.fm = nil
}

func (b *testBackend) setPending(block *types.Block, receipts types.Receipts) {
	b.pendingBlock = block
	b.pendingReceipts = receipts
}

func newTestFilterSystem(db ethdb.Database, cfg Config) (*testBackend, *FilterSystem) {
	backend := &testBackend{db: db}
	sys := NewFilterSystem(backend, cfg)
	return backend, sys
}

// TestBlockSubscription tests if a block subscription returns block hashes for posted chain events.
// It creates multiple subscriptions:
// - one at the start and should receive all posted chain events and a second (blockHashes)
// - one that is created after a cutoff moment and uninstalled after a second cutoff moment (blockHashes[cutoff1:cutoff2])
// - one that is created after the second cutoff moment (blockHashes[cutoff2:])
func TestBlockSubscription(t *testing.T) {
	t.Parallel()

	var (
		db           = rawdb.NewMemoryDatabase()
		backend, sys = newTestFilterSystem(db, Config{})
		api          = NewFilterAPI(sys)
		genesis      = &core.Genesis{
			Config:  params.TestChainConfig,
			BaseFee: big.NewInt(params.InitialBaseFee),
		}
		_, chain, _ = core.GenerateChainWithGenesis(genesis, ethash.NewFaker(), 10, func(i int, gen *core.BlockGen) {})
		chainEvents []core.ChainEvent
	)

	for _, blk := range chain {
		chainEvents = append(chainEvents, core.ChainEvent{Block: blk})
	}

	chan0 := make(chan *types.Header)
	sub0 := api.events.SubscribeNewHeads(chan0)
	chan1 := make(chan *types.Header)
	sub1 := api.events.SubscribeNewHeads(chan1)

	go func() { // simulate client
		i1, i2 := 0, 0
		for i1 != len(chainEvents) || i2 != len(chainEvents) {
			select {
			case header := <-chan0:
				if chainEvents[i1].Block.Hash() != header.Hash() {
					t.Errorf("sub0 received invalid hash on index %d, want %x, got %x", i1, chainEvents[i1].Block.Hash(), header.Hash())
				}
				i1++
			case header := <-chan1:
				if chainEvents[i2].Block.Hash() != header.Hash() {
					t.Errorf("sub1 received invalid hash on index %d, want %x, got %x", i2, chainEvents[i2].Block.Hash(), header.Hash())
				}
				i2++
			}
		}

		sub0.Unsubscribe()
		sub1.Unsubscribe()
	}()

	time.Sleep(1 * time.Second)
	for _, e := range chainEvents {
		backend.chainFeed.Send(e)
	}

	<-sub0.Err()
	<-sub1.Err()
}

// TestPendingTxFilter tests whether pending tx filters retrieve all pending transactions that are posted to the event mux.
func TestPendingTxFilter(t *testing.T) {
	t.Parallel()

	var (
		db           = rawdb.NewMemoryDatabase()
		backend, sys = newTestFilterSystem(db, Config{})
		api          = NewFilterAPI(sys)

		transactions = []*types.Transaction{
			types.NewTransaction(0, common.HexToAddress("0xb794f5ea0ba39494ce83a213fffba74279579268"), new(big.Int), 0, new(big.Int), nil),
			types.NewTransaction(1, common.HexToAddress("0xb794f5ea0ba39494ce83a213fffba74279579268"), new(big.Int), 0, new(big.Int), nil),
			types.NewTransaction(2, common.HexToAddress("0xb794f5ea0ba39494ce83a213fffba74279579268"), new(big.Int), 0, new(big.Int), nil),
			types.NewTransaction(3, common.HexToAddress("0xb794f5ea0ba39494ce83a213fffba74279579268"), new(big.Int), 0, new(big.Int), nil),
			types.NewTransaction(4, common.HexToAddress("0xb794f5ea0ba39494ce83a213fffba74279579268"), new(big.Int), 0, new(big.Int), nil),
		}

		hashes []common.Hash
	)

	fid0 := api.NewPendingTransactionFilter(nil)

	time.Sleep(1 * time.Second)
	backend.txFeed.Send(core.NewTxsEvent{Txs: transactions})

	timeout := time.Now().Add(1 * time.Second)
	for {
		results, err := api.GetFilterChanges(fid0)
		if err != nil {
			t.Fatalf("Unable to retrieve logs: %v", err)
		}

		h := results.([]common.Hash)
		hashes = append(hashes, h...)
		if len(hashes) >= len(transactions) {
			break
		}
		// check timeout
		if time.Now().After(timeout) {
			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	if len(hashes) != len(transactions) {
		t.Errorf("invalid number of transactions, want %d transactions(s), got %d", len(transactions), len(hashes))
		return
	}
	for i := range hashes {
		if hashes[i] != transactions[i].Hash() {
			t.Errorf("hashes[%d] invalid, want %x, got %x", i, transactions[i].Hash(), hashes[i])
		}
	}
}

// TestPendingTxFilterFullTx tests whether pending tx filters retrieve all pending transactions that are posted to the event mux.
func TestPendingTxFilterFullTx(t *testing.T) {
	t.Parallel()

	var (
		db           = rawdb.NewMemoryDatabase()
		backend, sys = newTestFilterSystem(db, Config{})
		api          = NewFilterAPI(sys)

		transactions = []*types.Transaction{
			types.NewTransaction(0, common.HexToAddress("0xb794f5ea0ba39494ce83a213fffba74279579268"), new(big.Int), 0, new(big.Int), nil),
			types.NewTransaction(1, common.HexToAddress("0xb794f5ea0ba39494ce83a213fffba74279579268"), new(big.Int), 0, new(big.Int), nil),
			types.NewTransaction(2, common.HexToAddress("0xb794f5ea0ba39494ce83a213fffba74279579268"), new(big.Int), 0, new(big.Int), nil),
			types.NewTransaction(3, common.HexToAddress("0xb794f5ea0ba39494ce83a213fffba74279579268"), new(big.Int), 0, new(big.Int), nil),
			types.NewTransaction(4, common.HexToAddress("0xb794f5ea0ba39494ce83a213fffba74279579268"), new(big.Int), 0, new(big.Int), nil),
		}

		txs []*ethapi.RPCTransaction
	)

	fullTx := true
	fid0 := api.NewPendingTransactionFilter(&fullTx)

	time.Sleep(1 * time.Second)
	backend.txFeed.Send(core.NewTxsEvent{Txs: transactions})

	timeout := time.Now().Add(1 * time.Second)
	for {
		results, err := api.GetFilterChanges(fid0)
		if err != nil {
			t.Fatalf("Unable to retrieve logs: %v", err)
		}

		tx := results.([]*ethapi.RPCTransaction)
		txs = append(txs, tx...)
		if len(txs) >= len(transactions) {
			break
		}
		// check timeout
		if time.Now().After(timeout) {
			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	if len(txs) != len(transactions) {
		t.Errorf("invalid number of transactions, want %d transactions(s), got %d", len(transactions), len(txs))
		return
	}
	for i := range txs {
		if txs[i].Hash != transactions[i].Hash() {
			t.Errorf("hashes[%d] invalid, want %x, got %x", i, transactions[i].Hash(), txs[i].Hash)
		}
	}
}

// TestLogFilterCreation test whether a given filter criteria makes sense.
// If not it must return an error.
func TestLogFilterCreation(t *testing.T) {
	var (
		db     = rawdb.NewMemoryDatabase()
		_, sys = newTestFilterSystem(db, Config{})
		api    = NewFilterAPI(sys)

		testCases = []struct {
			crit    FilterCriteria
			success bool
		}{
			// defaults
			{FilterCriteria{}, true},
			// valid block number range
			{FilterCriteria{FromBlock: big.NewInt(1), ToBlock: big.NewInt(2)}, true},
			// "mined" block range to pending
			{FilterCriteria{FromBlock: big.NewInt(1), ToBlock: big.NewInt(rpc.LatestBlockNumber.Int64())}, true},
			// from block "higher" than to block
			{FilterCriteria{FromBlock: big.NewInt(2), ToBlock: big.NewInt(1)}, false},
			// from block "higher" than to block
			{FilterCriteria{FromBlock: big.NewInt(rpc.LatestBlockNumber.Int64()), ToBlock: big.NewInt(100)}, false},
			// from block "higher" than to block
			{FilterCriteria{FromBlock: big.NewInt(rpc.PendingBlockNumber.Int64()), ToBlock: big.NewInt(100)}, false},
			// from block "higher" than to block
			{FilterCriteria{FromBlock: big.NewInt(rpc.PendingBlockNumber.Int64()), ToBlock: big.NewInt(rpc.LatestBlockNumber.Int64())}, false},
			// topics more than 4
			{FilterCriteria{Topics: [][]common.Hash{{}, {}, {}, {}, {}}}, false},
		}
	)

	for i, test := range testCases {
		id, err := api.NewFilter(test.crit)
		if err != nil && test.success {
			t.Errorf("expected filter creation for case %d to success, got %v", i, err)
		}
		if err == nil {
			api.UninstallFilter(id)
			if !test.success {
				t.Errorf("expected testcase %d to fail with an error", i)
			}
		}
	}
}

// TestInvalidLogFilterCreation tests whether invalid filter log criteria results in an error
// when the filter is created.
func TestInvalidLogFilterCreation(t *testing.T) {
	t.Parallel()

	var (
		db     = rawdb.NewMemoryDatabase()
		_, sys = newTestFilterSystem(db, Config{})
		api    = NewFilterAPI(sys)
	)

	// different situations where log filter creation should fail.
	// Reason: fromBlock > toBlock
	testCases := []FilterCriteria{
		0: {FromBlock: big.NewInt(rpc.PendingBlockNumber.Int64()), ToBlock: big.NewInt(rpc.LatestBlockNumber.Int64())},
		1: {FromBlock: big.NewInt(rpc.PendingBlockNumber.Int64()), ToBlock: big.NewInt(100)},
		2: {FromBlock: big.NewInt(rpc.LatestBlockNumber.Int64()), ToBlock: big.NewInt(100)},
		3: {Topics: [][]common.Hash{{}, {}, {}, {}, {}}},
	}

	for i, test := range testCases {
		if _, err := api.NewFilter(test); err == nil {
			t.Errorf("Expected NewFilter for case #%d to fail", i)
		}
	}
}

// TestInvalidGetLogsRequest tests invalid getLogs requests
func TestInvalidGetLogsRequest(t *testing.T) {
	t.Parallel()

	var (
		db        = rawdb.NewMemoryDatabase()
		_, sys    = newTestFilterSystem(db, Config{})
		api       = NewFilterAPI(sys)
		blockHash = common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
	)

	// Reason: Cannot specify both BlockHash and FromBlock/ToBlock)
	testCases := []FilterCriteria{
		0: {BlockHash: &blockHash, FromBlock: big.NewInt(100)},
		1: {BlockHash: &blockHash, ToBlock: big.NewInt(500)},
		2: {BlockHash: &blockHash, FromBlock: big.NewInt(rpc.LatestBlockNumber.Int64())},
		3: {BlockHash: &blockHash, Topics: [][]common.Hash{{}, {}, {}, {}, {}}},
	}

	for i, test := range testCases {
		if _, err := api.GetLogs(context.Background(), test); err == nil {
			t.Errorf("Expected Logs for case #%d to fail", i)
		}
	}
}

// TestInvalidGetRangeLogsRequest tests getLogs with invalid block range
func TestInvalidGetRangeLogsRequest(t *testing.T) {
	t.Parallel()

	var (
		db     = rawdb.NewMemoryDatabase()
		_, sys = newTestFilterSystem(db, Config{})
		api    = NewFilterAPI(sys)
	)

	if _, err := api.GetLogs(context.Background(), FilterCriteria{FromBlock: big.NewInt(2), ToBlock: big.NewInt(1)}); err != errInvalidBlockRange {
		t.Errorf("Expected Logs for invalid range return error, but got: %v", err)
	}
	// A range that starts after genesis but ends at block 0 must be rejected as well.
	if _, err := api.GetLogs(context.Background(), FilterCriteria{FromBlock: big.NewInt(5), ToBlock: big.NewInt(0)}); err != errInvalidBlockRange {
		t.Errorf("Expected Logs for range ending at genesis return error, but got: %v", err)
	}
}

// TestRangeLimit tests that a range query wider than the configured limit is
// rejected with the invalid params error code.
func TestRangeLimit(t *testing.T) {
	t.Parallel()

	var (
		db     = rawdb.NewMemoryDatabase()
		_, sys = newTestFilterSystem(db, Config{RangeLimit: 5})
		api    = NewFilterAPI(sys)
	)
	defer db.Close()

	_, err := api.GetLogs(context.Background(), FilterCriteria{FromBlock: big.NewInt(0), ToBlock: big.NewInt(9)})
	if err == nil {
		t.Fatal("expected range limit error, got nil")
	}
	var rpcErr rpc.Error
	if !errors.As(err, &rpcErr) {
		t.Fatalf("expected rpc.Error, got %T", err)
	}
	if rpcErr.ErrorCode() != -32602 {
		t.Fatalf("expected error code -32602, got %d", rpcErr.ErrorCode())
	}

	// A "latest" end must not bypass the limit: with the head above the limit,
	// the effective range [0, head] exceeds it.
	header := &types.Header{Number: big.NewInt(10)}
	rawdb.WriteHeader(db, header)
	rawdb.WriteCanonicalHash(db, header.Hash(), 10)
	rawdb.WriteHeadBlockHash(db, header.Hash())

	_, err = api.GetLogs(context.Background(), FilterCriteria{FromBlock: big.NewInt(0), ToBlock: big.NewInt(int64(rpc.LatestBlockNumber))})
	if err == nil {
		t.Fatal("expected range limit error for latest end, got nil")
	}
	if !errors.As(err, &rpcErr) || rpcErr.ErrorCode() != -32602 {
		t.Fatalf("expected error code -32602 for latest end, got %v", err)
	}
}

// TestLogFilter tests whether log filters match the correct logs that are posted to the event feed.
func TestLogFilter(t *testing.T) {
	t.Parallel()

	var (
		db           = rawdb.NewMemoryDatabase()
		backend, sys = newTestFilterSystem(db, Config{})
		api          = NewFilterAPI(sys)

		firstAddr      = common.HexToAddress("0x1111111111111111111111111111111111111111")
		secondAddr     = common.HexToAddress("0x2222222222222222222222222222222222222222")
		thirdAddress   = common.HexToAddress("0x3333333333333333333333333333333333333333")
		notUsedAddress = common.HexToAddress("0x9999999999999999999999999999999999999999")
		firstTopic     = common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
		secondTopic    = common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")
		notUsedTopic   = common.HexToHash("0x9999999999999999999999999999999999999999999999999999999999999999")

		// posted twice, once as regular logs and once as pending logs.
		allLogs = []*types.Log{
			{Address: firstAddr},
			{Address: firstAddr, Topics: []common.Hash{firstTopic}, BlockNumber: 1},
			{Address: secondAddr, Topics: []common.Hash{firstTopic}, BlockNumber: 1},
			{Address: thirdAddress, Topics: []common.Hash{secondTopic}, BlockNumber: 2},
			{Address: thirdAddress, Topics: []common.Hash{secondTopic}, BlockNumber: 3},
		}

		testCases = []struct {
			crit     FilterCriteria
			expected []*types.Log
			id       rpc.ID
		}{
			// match all
			0: {FilterCriteria{}, allLogs, ""},
			// match none due to no matching addresses
			1: {FilterCriteria{Addresses: []common.Address{{}, notUsedAddress}, Topics: [][]common.Hash{nil}}, []*types.Log{}, ""},
			// match logs based on addresses, ignore topics
			2: {FilterCriteria{Addresses: []common.Address{firstAddr}}, allLogs[:2], ""},
			// match none due to no matching topics (match with address)
			3: {FilterCriteria{Addresses: []common.Address{secondAddr}, Topics: [][]common.Hash{{notUsedTopic}}}, []*types.Log{}, ""},
			// match logs based on addresses and topics
			4: {FilterCriteria{Addresses: []common.Address{thirdAddress}, Topics: [][]common.Hash{{firstTopic, secondTopic}}}, allLogs[3:5], ""},
			// match logs based on multiple addresses and "or" topics
			5: {FilterCriteria{Addresses: []common.Address{secondAddr, thirdAddress}, Topics: [][]common.Hash{{firstTopic, secondTopic}}}, allLogs[2:5], ""},
			// all "mined" logs with block num >= 2
			6: {FilterCriteria{FromBlock: big.NewInt(2), ToBlock: big.NewInt(rpc.LatestBlockNumber.Int64())}, allLogs[3:], ""},
			// all "mined" logs
			7: {FilterCriteria{ToBlock: big.NewInt(rpc.LatestBlockNumber.Int64())}, allLogs, ""},
			// all "mined" logs with 1>= block num <=2 and topic secondTopic
			8: {FilterCriteria{FromBlock: big.NewInt(1), ToBlock: big.NewInt(2), Topics: [][]common.Hash{{secondTopic}}}, allLogs[3:4], ""},
			// match all logs due to wildcard topic
			9: {FilterCriteria{Topics: [][]common.Hash{nil}}, allLogs[1:], ""},
		}
	)

	// create all filters
	for i := range testCases {
		testCases[i].id, _ = api.NewFilter(testCases[i].crit)
	}

	// raise events
	time.Sleep(1 * time.Second)
	if nsend := backend.logsFeed.Send(allLogs); nsend == 0 {
		t.Fatal("Logs event not delivered")
	}

	for i, tt := range testCases {
		var fetched []*types.Log
		timeout := time.Now().Add(1 * time.Second)
		for { // fetch all expected logs
			results, err := api.GetFilterChanges(tt.id)
			if err != nil {
				t.Fatalf("test %d: unable to fetch logs: %v", i, err)
			}

			fetched = append(fetched, results.([]*types.Log)...)
			if len(fetched) >= len(tt.expected) {
				break
			}
			// check timeout
			if time.Now().After(timeout) {
				break
			}

			time.Sleep(100 * time.Millisecond)
		}

		if len(fetched) != len(tt.expected) {
			t.Errorf("invalid number of logs for case %d, want %d log(s), got %d", i, len(tt.expected), len(fetched))
			return
		}

		for l := range fetched {
			if fetched[l].Removed {
				t.Errorf("expected log not to be removed for log %d in case %d", l, i)
			}
			if !reflect.DeepEqual(fetched[l], tt.expected[l]) {
				t.Errorf("invalid log on index %d for case %d", l, i)
			}
		}
	}
}

// TestSubscribeLogsQueryLimit tests that live log subscriptions enforce the
// configured log query limit before installing the filter.
func TestSubscribeLogsQueryLimit(t *testing.T) {
	t.Parallel()

	var (
		db     = rawdb.NewMemoryDatabase()
		_, sys = newTestFilterSystem(db, Config{LogQueryLimit: 2})
		api    = NewFilterAPI(sys)
		addr1  = common.HexToAddress("0x1111111111111111111111111111111111111111")
		addr2  = common.HexToAddress("0x2222222222222222222222222222222222222222")
		addr3  = common.HexToAddress("0x3333333333333333333333333333333333333333")
		logs   = make(chan []*types.Log)
	)
	defer db.Close()

	sub, err := api.events.SubscribeLogs(ethereum.FilterQuery{Addresses: []common.Address{addr1, addr2}}, logs)
	if err != nil {
		t.Fatalf("subscription with 2 addresses returned error: %v", err)
	}
	sub.Unsubscribe()

	if _, err := api.events.SubscribeLogs(ethereum.FilterQuery{Addresses: []common.Address{addr1, addr2, addr3}}, logs); err != errExceedLogQueryLimit {
		t.Fatalf("subscription with 3 addresses returned error %v, want %v", err, errExceedLogQueryLimit)
	}
}

// TestGetLogsStartBeyondHead tests that an explicit range starting after the
// chain head returns no logs instead of searching the head block.
func TestGetLogsStartBeyondHead(t *testing.T) {
	t.Parallel()

	var (
		db           = rawdb.NewMemoryDatabase()
		backend, sys = newTestFilterSystem(db, Config{})
		addr         = common.HexToAddress("0x1111111111111111111111111111111111111111")
		gspec        = &core.Genesis{
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.TestChainConfig,
		}
	)
	defer db.Close()

	_, chain, receipts := core.GenerateChainWithGenesis(gspec, ethash.NewFaker(), 3, func(i int, gen *core.BlockGen) {
		if i == 2 {
			receipt := makeReceipt(addr)
			gen.AddUncheckedReceipt(receipt)
			gen.AddUncheckedTx(types.NewTransaction(999, common.HexToAddress("0x999"), big.NewInt(999), 999, gen.BaseFee(), nil))
		}
	})
	gspec.MustCommit(db)
	for i, block := range chain {
		rawdb.WriteBlock(db, block)
		rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
		rawdb.WriteHeadBlockHash(db, block.Hash())
		rawdb.WriteReceipts(db, block.Hash(), block.NumberU64(), receipts[i])
	}
	backend.startFilterMaps(0, true, filtermaps.DefaultParams)
	defer backend.stopFilterMaps()

	api := NewFilterAPI(sys)
	logs, err := api.GetLogs(context.Background(), FilterCriteria{FromBlock: big.NewInt(4), ToBlock: big.NewInt(5)})
	if err != nil {
		t.Fatalf("GetLogs beyond head returned error: %v", err)
	}
	if len(logs) != 0 {
		t.Fatalf("expected no logs for range beyond head, got %d", len(logs))
	}

	// A "latest" start must be resolved to the head before the range is checked
	// for inversion, not compared as the MaxUint64 sentinel.
	logs, err = api.GetLogs(context.Background(), FilterCriteria{FromBlock: big.NewInt(int64(rpc.LatestBlockNumber)), ToBlock: big.NewInt(3)})
	if err != nil {
		t.Fatalf("GetLogs [latest, 3] returned error: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("expected 1 log for [latest, 3], got %d", len(logs))
	}
	if _, err := api.GetLogs(context.Background(), FilterCriteria{FromBlock: big.NewInt(int64(rpc.LatestBlockNumber)), ToBlock: big.NewInt(2)}); err != errInvalidBlockRange {
		t.Fatalf("expected invalid block range for [latest, 2], got %v", err)
	}
}

// TestSearchSessionRewindClearsMatches tests that a head rewind which discards
// the whole search range does not return results collected before the rewind.
func TestSearchSessionRewindClearsMatches(t *testing.T) {
	t.Parallel()

	var (
		db           = rawdb.NewMemoryDatabase()
		backend, sys = newTestFilterSystem(db, Config{})
	)
	defer db.Close()

	header := &types.Header{Number: big.NewInt(99)}
	rawdb.WriteHeader(db, header)
	rawdb.WriteCanonicalHash(db, header.Hash(), 99)
	rawdb.WriteHeadBlockHash(db, header.Hash())

	backend.startFilterMaps(0, true, filtermaps.DefaultParams)
	defer backend.stopFilterMaps()

	mb := backend.NewMatcherBackend()
	defer mb.Close()

	s := &searchSession{
		ctx:        context.Background(),
		filter:     sys.NewRangeFilter(100, 100, nil, nil, 0),
		mb:         mb,
		firstBlock: 100,
		lastBlock:  100,
	}
	s.matchRange = common.NewRange[uint64](100, 1)
	s.matches = []*types.Log{{BlockNumber: 100}}

	if err := s.syncMatcher(0); err != nil {
		t.Fatalf("syncMatcher returned error: %v", err)
	}
	if len(s.matches) != 0 {
		t.Fatalf("expected matches to be discarded after rewind, got %d", len(s.matches))
	}
}

// TestPendingTxFilterDeadlock tests if the event loop hangs when pending
// txes arrive at the same time that one of multiple filters is timing out.
// Please refer to #22131 for more details.
func TestPendingTxFilterDeadlock(t *testing.T) {
	t.Parallel()
	timeout := 100 * time.Millisecond

	var (
		db           = rawdb.NewMemoryDatabase()
		backend, sys = newTestFilterSystem(db, Config{Timeout: timeout})
		api          = NewFilterAPI(sys)
		done         = make(chan struct{})
	)
	defer close(done)

	go func() {
		// Bombard feed with txes until signal was received to stop
		i := uint64(0)
		for {
			select {
			case <-done:
				return
			default:
			}

			tx := types.NewTransaction(i, common.HexToAddress("0xb794f5ea0ba39494ce83a213fffba74279579268"), new(big.Int), 0, new(big.Int), nil)
			backend.txFeed.Send(core.NewTxsEvent{Txs: []*types.Transaction{tx}})
			i++
		}
	}()

	// Create a bunch of filters that will
	// timeout either in 100ms or 200ms
	subs := make([]*Subscription, 20)
	for i := range subs {
		fid := api.NewPendingTransactionFilter(nil)
		api.filtersMu.Lock()
		f, ok := api.filters[fid]
		api.filtersMu.Unlock()
		if !ok {
			t.Fatalf("Filter %s should exist", fid)
		}
		subs[i] = f.s
		// Wait for at least one tx to arrive in filter
		for {
			hashes, err := api.GetFilterChanges(fid)
			if err != nil {
				t.Fatalf("Filter should exist: %v\n", err)
			}
			if len(hashes.([]common.Hash)) > 0 {
				break
			}
			runtime.Gosched()
		}
	}

	// Wait until filters have timed out and have been uninstalled.
	for _, sub := range subs {
		select {
		case <-sub.Err():
		case <-time.After(1 * time.Second):
			t.Fatalf("Filter timeout is hanging")
		}
	}
}
