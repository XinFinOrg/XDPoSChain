// Copyright 2026 The go-ethereum Authors
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

package core

import (
	"testing"
	"time"
)

// TestCheckpointSignalNeverBlocks pins the coalescing contract of SignalCheckpoint: the
// signal is sent while the chain mutex is held, so it must never wait for the staking loop.
// The receiver re-reads the chain head when it runs, which is what makes dropping a signal
// whose slot is already taken harmless.
func TestCheckpointSignalNeverBlocks(t *testing.T) {
	// Take the receiver's role: drain what an earlier test left pending, and leave the channel
	// empty on the way out so the next one starts clean.
	drain := func() {
		for len(CheckpointCh) > 0 {
			<-CheckpointCh
		}
	}
	drain()
	t.Cleanup(drain)

	// Fill the single slot through the sanctioned sender: a second signal arriving before the
	// receiver drains it has to be dropped and must not wait for the staking loop.
	SignalCheckpoint()

	done := make(chan struct{})
	go func() {
		defer close(done)
		SignalCheckpoint()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SignalCheckpoint blocked on a full channel, it must coalesce instead")
	}
	// The signal that was already pending is the one the receiver will read.
	select {
	case <-CheckpointCh:
	default:
		t.Fatal("the pending signal was consumed by the sender")
	}
}
