// Copyright (c) 2018 XDPoSChain
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package blocksigner

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	ethereum "github.com/XinFinOrg/XDPoSChain"
	"github.com/XinFinOrg/XDPoSChain/accounts/abi/bind"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/contracts/blocksigner/contract"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/event"
)

// fakeLogFilterer hands the logs a test pushes to the binding's watch loop and
// keeps the subscription open until the test unsubscribes.
type fakeLogFilterer struct {
	logs chan<- types.Log
}

func (f *fakeLogFilterer) FilterLogs(context.Context, ethereum.FilterQuery) ([]types.Log, error) {
	return nil, nil
}

func (f *fakeLogFilterer) SubscribeFilterLogs(_ context.Context, _ ethereum.FilterQuery, ch chan<- types.Log) (ethereum.Subscription, error) {
	f.logs = ch
	return event.NewSubscription(func(quit <-chan struct{}) error {
		<-quit
		return nil
	}), nil
}

// TestWatchSignIgnoresMismatch pins the generated WatchSign loop: a log whose
// signature does not match must be skipped instead of ending the subscription,
// and the valid Sign events that follow must still be delivered.
func TestWatchSignIgnoresMismatch(t *testing.T) {
	filterer := new(fakeLogFilterer)
	f, err := contract.NewBlockSignerFilterer(common.Address{}, filterer)
	if err != nil {
		t.Fatalf("can't create filterer: %v", err)
	}
	sink := make(chan *contract.BlockSignerSign, 2)
	sub, err := f.WatchSign(&bind.WatchOpts{Context: context.Background()}, sink)
	if err != nil {
		t.Fatalf("can't watch Sign: %v", err)
	}
	defer sub.Unsubscribe()

	contractABI, err := contract.BlockSignerMetaData.GetAbi()
	if err != nil {
		t.Fatalf("can't parse the binding ABI: %v", err)
	}
	eventABI, ok := contractABI.Events["Sign"]
	if !ok {
		t.Fatal("Sign event is missing from the binding ABI")
	}

	signer := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	pack := func(blockNumber int64, blockHash common.Hash) []byte {
		t.Helper()
		data, err := eventABI.Inputs.Pack(signer, big.NewInt(blockNumber), blockHash)
		if err != nil {
			t.Fatalf("can't pack Sign arguments: %v", err)
		}
		return data
	}
	expect := func(blockNumber int64, blockHash common.Hash) {
		t.Helper()
		timeout := time.NewTimer(5 * time.Second)
		defer timeout.Stop()
		select {
		case ev := <-sink:
			if ev == nil {
				t.Fatal("received a nil Sign event")
			}
			if ev.Signer != signer {
				t.Fatalf("signer mismatch: have %v, want %v", ev.Signer, signer)
			}
			if ev.BlockNumber == nil || ev.BlockNumber.Int64() != blockNumber {
				t.Fatalf("block number mismatch: have %v, want %d", ev.BlockNumber, blockNumber)
			}
			if ev.BlockHash != blockHash {
				t.Fatalf("block hash mismatch: have %v, want %v", ev.BlockHash, blockHash)
			}
		case err := <-sub.Err():
			t.Fatalf("subscription failed after a mismatched log: %v", err)
		case <-timeout.C:
			t.Fatal("timeout waiting for the Sign event")
		}
	}

	firstHash := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	secondHash := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000002")

	// A foreign log whose topic0 does not match must be dropped, not forwarded
	// and not treated as a reason to tear the subscription down.
	filterer.logs <- types.Log{
		Topics: []common.Hash{common.HexToHash("0xdeadbeef00000000000000000000000000000000000000000000000000000000")},
		Data:   pack(1, firstHash),
	}
	filterer.logs <- types.Log{Topics: []common.Hash{eventABI.ID}, Data: pack(2, firstHash)}
	expect(2, firstHash)

	// The loop has to stay alive after the skipped log and deliver the next one.
	filterer.logs <- types.Log{Topics: []common.Hash{eventABI.ID}, Data: pack(3, secondHash)}
	expect(3, secondHash)

	select {
	case ev := <-sink:
		t.Fatalf("received an extra event: %+v", ev)
	default:
	}
	select {
	case err := <-sub.Err():
		t.Fatalf("subscription terminated unexpectedly: %v", err)
	default:
	}
}

// TestWatchSignFailsOnBrokenPayload pins the other half of the skip branch:
// only a signature mismatch may be tolerated. A log carrying the right topic
// but a payload the ABI cannot decode has to end the subscription and surface
// the error instead of being dropped the same way.
func TestWatchSignFailsOnBrokenPayload(t *testing.T) {
	filterer := new(fakeLogFilterer)
	f, err := contract.NewBlockSignerFilterer(common.Address{}, filterer)
	if err != nil {
		t.Fatalf("can't create filterer: %v", err)
	}
	sink := make(chan *contract.BlockSignerSign, 1)
	sub, err := f.WatchSign(&bind.WatchOpts{Context: context.Background()}, sink)
	if err != nil {
		t.Fatalf("can't watch Sign: %v", err)
	}
	defer sub.Unsubscribe()

	contractABI, err := contract.BlockSignerMetaData.GetAbi()
	if err != nil {
		t.Fatalf("can't parse the binding ABI: %v", err)
	}
	eventABI, ok := contractABI.Events["Sign"]
	if !ok {
		t.Fatal("Sign event is missing from the binding ABI")
	}

	// Correct topic, truncated payload: the three non-indexed arguments need
	// 96 bytes of data, so this log is undecodable for reasons other than its
	// signature.
	filterer.logs <- types.Log{Topics: []common.Hash{eventABI.ID}, Data: []byte{0x01}}

	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	select {
	case err := <-sub.Err():
		if err == nil {
			t.Fatal("subscription ended without surfacing the decode error")
		}
		if errors.Is(err, bind.ErrEventSignatureMismatch) {
			t.Fatalf("decode error was misclassified as a signature mismatch: %v", err)
		}
	case ev := <-sink:
		t.Fatalf("forwarded an undecodable log as %+v", ev)
	case <-timeout.C:
		t.Fatal("subscription stayed alive on an undecodable payload")
	}
}
