// Copyright 2021 The go-ethereum Authors
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

package tracker

import (
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/metrics"
)

func TestMain(m *testing.M) {
	// The subprocess test below re-runs this binary with tracking kept on and
	// metrics kept off, so the switch must be controllable from the outside.
	if os.Getenv("TRACKER_TEST_METRICS") != "off" {
		metrics.Enable()
	}
	os.Exit(m.Run())
}

func pendingCount(tr *Tracker) int {
	tr.lock.Lock()
	defer tr.lock.Unlock()
	return len(tr.pending)
}

// track registers a request on peer1 and fails the test if the tracker rejects it.
func track(t *testing.T, tr *Tracker, id uint64) {
	t.Helper()
	if err := tr.Track("peer1", 1, 166, 0x03, 0x04, id); err != nil {
		t.Fatalf("failed to track request %d: %v", id, err)
	}
}

// TestFulfilRemovesPending checks that a fulfilled request is untracked, so the
// pending map cannot grow without bound and a duplicate response stays harmless.
func TestFulfilRemovesPending(t *testing.T) {
	tr := New("eth", time.Minute)
	track(t, tr, 1)

	if n := pendingCount(tr); n != 1 {
		t.Fatalf("pending count mismatch: have %d, want 1", n)
	}
	tr.Fulfil("peer1", 1, 166, 0x04, 1, time.Now())
	if n := pendingCount(tr); n != 0 {
		t.Fatalf("fulfilled request still tracked: %d", n)
	}
	// A duplicate response must be reported as stale instead of panicking.
	tr.Fulfil("peer1", 1, 166, 0x04, 1, time.Now())
}

// TestPeersTrackSameRequestID checks that identical request ids from different
// peers are tracked independently by the shared tracker.
func TestPeersTrackSameRequestID(t *testing.T) {
	tr := New("eth", time.Minute)
	for _, peer := range []string{"peerA", "peerB"} {
		if err := tr.Track(peer, 1, 166, 0x03, 0x04, 1); err != nil {
			t.Fatalf("failed to track request on %s: %v", peer, err)
		}
	}
	if n := pendingCount(tr); n != 2 {
		t.Fatalf("pending count mismatch: have %d, want 2", n)
	}
	tr.Fulfil("peerA", 1, 166, 0x04, 1, time.Now())
	tr.Fulfil("peerB", 1, 166, 0x04, 1, time.Now())
	if n := pendingCount(tr); n != 0 {
		t.Fatalf("pending count after fulfilment: have %d, want 0", n)
	}
}

// TestFulfilNonHeadKeepsTimer checks that only fulfilling the head request
// re-arms the expiration timer.
func TestFulfilNonHeadKeepsTimer(t *testing.T) {
	tr := New("eth", time.Minute)
	track(t, tr, 1)
	track(t, tr, 2)

	if tr.wake == nil {
		t.Fatal("wake timer not armed")
	}
	wake := tr.wake
	tr.Fulfil("peer1", 1, 166, 0x04, 2, time.Now())
	if tr.wake != wake {
		t.Fatal("fulfilling a non-head request rescheduled the timer")
	}
	tr.Fulfil("peer1", 1, 166, 0x04, 1, time.Now())
	if tr.wake != nil {
		t.Fatal("wake timer not cleared after the last request was fulfilled")
	}
}

// TestFulfilUsesReceiptTime checks that the wait sample is measured from the
// request timestamp to the packet receipt time, not to the moment the
// dispatcher got around to processing the packet.
func TestFulfilUsesReceiptTime(t *testing.T) {
	wait := metrics.GetOrRegisterHistogramLazy("p2p/wait/eth/166/0x03", nil, func() metrics.Sample {
		return metrics.NewExpDecaySample(1028, 0.015)
	})
	wait.Clear()

	tr := New("eth", time.Hour)
	track(t, tr, 1)

	// Pretend the request was tracked two hours ago and its reply was received
	// one hour ago: the sample must be about one hour, not two.
	now := time.Now()
	tr.lock.Lock()
	tr.pending[requestKey{peer: "peer1", conn: 1, id: 1}].time = now.Add(-2 * time.Hour)
	tr.lock.Unlock()
	tr.Fulfil("peer1", 1, 166, 0x04, 1, now.Add(-time.Hour))

	snap := wait.Snapshot()
	if n := snap.Count(); n != 1 {
		t.Fatalf("wait sample count mismatch: have %d, want 1", n)
	}
	if got, want := snap.Max(), time.Hour.Microseconds(); got < want*55/60 || got > want*65/60 {
		t.Fatalf("wait sample mismatch: have %d us, want about %d us", got, want)
	}
}

// TestCleanExpiresRequest checks that an unfulfilled request is dropped once
// its timeout elapses, and that the expiry is reported as a lost request.
func TestCleanExpiresRequest(t *testing.T) {
	lost := metrics.GetOrRegisterMeter("p2p/lost/eth/166/0x03", nil)
	base := lost.Snapshot().Count()

	tr := New("eth", 20*time.Millisecond)
	track(t, tr, 1)

	deadline := time.Now().Add(2 * time.Second)
	for pendingCount(tr) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("request was not expired")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := lost.Snapshot().Count() - base; got != 1 {
		t.Fatalf("expired request not reported as lost: have %d, want 1", got)
	}
}

// TestCancelReservesPending checks that a request abandoned locally keeps its
// tracker entry, and thus its wire id, until the reply arrives.
func TestCancelReservesPending(t *testing.T) {
	tr := New("eth", time.Minute)
	gauge := metrics.GetOrRegisterGauge("p2p/tracked/eth/166/0x03", nil)
	base := int64(gauge.Snapshot())
	lost := metrics.GetOrRegisterMeter("p2p/lost/eth/166/0x03", nil)
	lostBase := lost.Snapshot().Count()
	stale := metrics.GetOrRegisterMeter("p2p/stale/eth/166/0x04", nil)
	staleBase := stale.Snapshot().Count()
	wait := metrics.GetOrRegisterHistogramLazy("p2p/wait/eth/166/0x03", nil, func() metrics.Sample {
		return metrics.NewExpDecaySample(1028, 0.015)
	})
	// The histogram uses a resetting sample: clear it so the post-fulfilment
	// count only reflects this test.
	wait.Clear()

	track(t, tr, 1)
	if n := pendingCount(tr); n != 1 {
		t.Fatalf("pending count mismatch: have %d, want 1", n)
	}
	if got := int64(gauge.Snapshot()) - base; got != 1 {
		t.Fatalf("tracked gauge mismatch after track: have %d, want 1", got)
	}
	wake := tr.wake
	tr.Cancel("peer1", 1, 1)
	// The entry and the gauge are kept: the id is still reserved.
	if n := pendingCount(tr); n != 1 {
		t.Fatalf("cancelled request untracked too early: %d", n)
	}
	if got := int64(gauge.Snapshot()) - base; got != 1 {
		t.Fatalf("tracked gauge mismatch after cancel: have %d, want 1", got)
	}
	if tr.wake != wake {
		t.Fatal("cancelling a request rescheduled the timer")
	}
	if got := lost.Snapshot().Count() - lostBase; got != 0 {
		t.Fatalf("cancelled request reported as lost: have %d, want 0", got)
	}
	// The late reply releases the id, but counts as a stale response instead
	// of entering the wait histogram: the local side already gave up on it.
	tr.Fulfil("peer1", 1, 166, 0x04, 1, time.Now())
	if n := pendingCount(tr); n != 0 {
		t.Fatalf("fulfilled request still tracked: %d", n)
	}
	if got := int64(gauge.Snapshot()) - base; got != 0 {
		t.Fatalf("tracked gauge mismatch after fulfilment: have %d, want 0", got)
	}
	if got := stale.Snapshot().Count() - staleBase; got != 1 {
		t.Fatalf("late reply to a cancelled request not counted stale: have %d, want 1", got)
	}
	if got := wait.Snapshot().Count(); got != 0 {
		t.Fatalf("late reply to a cancelled request entered the wait histogram: have %d new samples, want 0", got)
	}
	// Cancelling an unknown request must be a no-op.
	tr.Cancel("peer1", 1, 1)
}

// TestCancelledRequestExpiresWithoutLost checks that a cancelled request is
// dropped on expiry without being reported as a remote timeout.
func TestCancelledRequestExpiresWithoutLost(t *testing.T) {
	lost := metrics.GetOrRegisterMeter("p2p/lost/eth/166/0x03", nil)
	lostBase := lost.Snapshot().Count()
	gauge := metrics.GetOrRegisterGauge("p2p/tracked/eth/166/0x03", nil)
	gaugeBase := int64(gauge.Snapshot())

	// Use a long timeout so the expiry timer cannot race the cancellation, then
	// make the cancelled entry due under the tracker lock and expire it
	// directly. TestCleanExpiresRequest keeps the timer-callback path covered.
	tr := New("eth", time.Hour)
	track(t, tr, 1)
	tr.Cancel("peer1", 1, 1)

	tr.lock.Lock()
	tr.pending[requestKey{peer: "peer1", conn: 1, id: 1}].time = time.Now().Add(-2 * time.Hour)
	tr.lock.Unlock()
	tr.clean()

	if n := pendingCount(tr); n != 0 {
		t.Fatalf("cancelled request still tracked after expiry: %d", n)
	}
	if tr.wake != nil {
		t.Fatal("wake timer not cleared after the cancelled request expired")
	}
	if got := lost.Snapshot().Count() - lostBase; got != 0 {
		t.Fatalf("cancelled request reported as lost: have %d, want 0", got)
	}
	if got := int64(gauge.Snapshot()) - gaugeBase; got != 0 {
		t.Fatalf("tracked gauge mismatch after expiry: have %d, want 0", got)
	}
}

// TestDropRemovesPending checks that a request which can never be answered is
// untracked immediately, so its id is free again.
func TestDropRemovesPending(t *testing.T) {
	tr := New("eth", time.Minute)
	gauge := metrics.GetOrRegisterGauge("p2p/tracked/eth/166/0x03", nil)
	base := int64(gauge.Snapshot())
	lost := metrics.GetOrRegisterMeter("p2p/lost/eth/166/0x03", nil)
	lostBase := lost.Snapshot().Count()

	track(t, tr, 1)
	tr.Drop("peer1", 1, 1)
	if n := pendingCount(tr); n != 0 {
		t.Fatalf("dropped request still tracked: %d", n)
	}
	if got := int64(gauge.Snapshot()) - base; got != 0 {
		t.Fatalf("tracked gauge mismatch after drop: have %d, want 0", got)
	}
	if tr.wake != nil {
		t.Fatal("wake timer not cleared after the last request was dropped")
	}
	if got := lost.Snapshot().Count() - lostBase; got != 0 {
		t.Fatalf("dropped request reported as lost: have %d, want 0", got)
	}
	// Dropping an unknown request must be a no-op.
	tr.Drop("peer1", 1, 1)
}

// TestDropNonHeadKeepsTimer checks that only dropping the head request
// re-arms the expiration timer.
func TestDropNonHeadKeepsTimer(t *testing.T) {
	tr := New("eth", time.Minute)
	track(t, tr, 1)
	track(t, tr, 2)

	wake := tr.wake
	tr.Drop("peer1", 1, 2)
	if tr.wake != wake {
		t.Fatal("dropping a non-head request rescheduled the timer")
	}
	tr.Drop("peer1", 1, 1)
	if tr.wake != nil {
		t.Fatal("wake timer not cleared after the last request was dropped")
	}
}

// TestDropConnectionScoped checks that tearing a connection down releases every
// request tracked for it, including cancelled ones whose reply can no longer
// arrive, without touching another connection of the same peer or other peers.
func TestDropConnectionScoped(t *testing.T) {
	tr := New("eth", time.Minute)
	// The test ends with live entries; drop them here so a leftover expiry
	// timer cannot change the shared gauge during a later test.
	t.Cleanup(func() {
		tr.DropConnection("peer1", 1)
		tr.DropConnection("peer1", 2)
		tr.DropConnection("peer2", 3)
	})
	gauge := metrics.GetOrRegisterGauge("p2p/tracked/eth/166/0x03", nil)
	base := int64(gauge.Snapshot())
	lost := metrics.GetOrRegisterMeter("p2p/lost/eth/166/0x03", nil)
	lostBase := lost.Snapshot().Count()

	track(t, tr, 1)
	track(t, tr, 2)
	// A reconnect under the same peer string owns a fresh id scope.
	if err := tr.Track("peer1", 2, 166, 0x03, 0x04, 3); err != nil {
		t.Fatalf("failed to track on the reconnected connection: %v", err)
	}
	if err := tr.Track("peer2", 3, 166, 0x03, 0x04, 4); err != nil {
		t.Fatalf("failed to track request on peer2: %v", err)
	}
	tr.Cancel("peer1", 1, 2)
	tr.DropConnection("peer1", 1)

	// The old connection's requests are gone; the reconnected connection and
	// peer2 keep theirs.
	if n := pendingCount(tr); n != 2 {
		t.Fatalf("pending count mismatch after dropping a connection: have %d, want 2", n)
	}
	if got := int64(gauge.Snapshot()) - base; got != 2 {
		t.Fatalf("tracked gauge mismatch after dropping a connection: have %d, want 2", got)
	}
	if got := lost.Snapshot().Count() - lostBase; got != 0 {
		t.Fatalf("dropped requests reported as lost: have %d, want 0", got)
	}
	if tr.wake == nil {
		t.Fatal("wake timer cleared while other connections still have requests")
	}
	// The old connection's ids are free again, including the cancelled one.
	if err := tr.Track("peer1", 1, 166, 0x03, 0x04, 1); err != nil {
		t.Fatalf("failed to reuse a dropped id: %v", err)
	}
	if err := tr.Track("peer1", 1, 166, 0x03, 0x04, 2); err != nil {
		t.Fatalf("failed to reuse a dropped cancelled id: %v", err)
	}
	// The reconnected connection's reservation and peer2's are untouched.
	if err := tr.Track("peer1", 2, 166, 0x03, 0x04, 3); !errors.Is(err, ErrCollision) {
		t.Fatalf("dropping the old connection released a new-connection id: have %v, want %v", err, ErrCollision)
	}
	if err := tr.Track("peer2", 3, 166, 0x03, 0x04, 4); !errors.Is(err, ErrCollision) {
		t.Fatalf("dropping peer1 released a peer2 id: have %v, want %v", err, ErrCollision)
	}
	// Dropping an unknown connection must be a no-op.
	tr.DropConnection("peer3", 9)
}

// TestTrackDuplicateReturnsCollision checks that a tracked id, including one
// whose request was cancelled locally, cannot be tracked a second time.
func TestTrackDuplicateReturnsCollision(t *testing.T) {
	tr := New("eth", time.Minute)
	// The test ends with live entries; drop them here so a leftover expiry
	// timer cannot change the shared gauge during a later test.
	t.Cleanup(func() {
		tr.DropConnection("peer1", 1)
		tr.DropConnection("peer2", 1)
	})
	track(t, tr, 1)

	if err := tr.Track("peer1", 1, 166, 0x03, 0x04, 1); !errors.Is(err, ErrCollision) {
		t.Fatalf("duplicate track mismatch: have %v, want %v", err, ErrCollision)
	}
	// The same id on another peer is still fine.
	if err := tr.Track("peer2", 1, 166, 0x03, 0x04, 1); err != nil {
		t.Fatalf("failed to track the same id on another peer: %v", err)
	}
	// A cancelled id stays reserved until its reply arrives.
	tr.Cancel("peer1", 1, 1)
	if err := tr.Track("peer1", 1, 166, 0x03, 0x04, 1); !errors.Is(err, ErrCollision) {
		t.Fatalf("cancelled id reuse mismatch: have %v, want %v", err, ErrCollision)
	}
}

// TestTrackWithoutMetricsReservesID re-runs this test binary with metrics
// disabled and checks that tracking, and thus duplicate rejection, does not
// depend on the metrics switch.
func TestTrackWithoutMetricsReservesID(t *testing.T) {
	if os.Getenv("TRACKER_TEST_METRICS") == "off" {
		tr := New("eth", time.Minute)
		if err := tr.Track("peer1", 1, 166, 0x03, 0x04, 1); err != nil {
			t.Fatalf("failed to track request without metrics: %v", err)
		}
		if n := pendingCount(tr); n != 1 {
			t.Fatalf("pending count without metrics: have %d, want 1", n)
		}
		if err := tr.Track("peer1", 1, 166, 0x03, 0x04, 1); !errors.Is(err, ErrCollision) {
			t.Fatalf("duplicate track without metrics: have %v, want %v", err, ErrCollision)
		}
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to locate the test binary: %v", err)
	}
	cmd := exec.Command(exe, "-test.run=^TestTrackWithoutMetricsReservesID$", "-test.v")
	cmd.Env = append(os.Environ(), "TRACKER_TEST_METRICS=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("tracking without metrics failed: %v\n%s", err, out)
	}
}
