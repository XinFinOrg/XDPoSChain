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
	"container/list"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/metrics"
)

const (
	// trackedGaugeName is the prefix of the per-packet request tracking.
	trackedGaugeName = "p2p/tracked"

	// lostMeterName is the prefix of the per-packet request expirations.
	lostMeterName = "p2p/lost"

	// staleMeterName is the prefix of the per-packet stale responses.
	staleMeterName = "p2p/stale"

	// waitHistName is the prefix of the per-packet (req only) waiting time histograms.
	waitHistName = "p2p/wait"

	// maxTrackedPackets is a huge number to act as a failsafe on the number of
	// pending requests the node will track. It should never be hit unless an
	// attacker figures out a way to spin requests.
	maxTrackedPackets = 100000

	// expirationGrace is the slack added to the timeout when arming the wake
	// timer and when checking expiry, so a callback that fires slightly early
	// does not re-arm a timer for a deadline that already passed.
	expirationGrace = 5 * time.Millisecond
)

var (
	// ErrCollision is returned when a request id is still tracked. The id may
	// belong to an in-flight request or to one that was cancelled locally and
	// is waiting for its late reply or its expiry, both of which reserve it.
	ErrCollision = errors.New("request id collision")

	// ErrLimitReached is returned when the tracker already holds the maximum
	// number of requests and refuses to track another one.
	ErrLimitReached = errors.New("request tracker limit reached")
)

// requestKey identifies a pending request. The tracker is shared by all peers,
// but request ids are only unique within a single connection: a reconnect with
// the same peer id starts a fresh connection and may reuse its wire ids, while
// a late teardown of the old connection must not touch the new one.
type requestKey struct {
	peer string
	conn uint64
	id   uint64
}

// request tracks sent network requests which have not yet received a response.
type request struct {
	peer    string
	version uint // Protocol version

	reqCode uint64 // Protocol message code of the request
	resCode uint64 // Protocol message code of the expected response

	time      time.Time     // Timestamp when the request was made
	expire    *list.Element // Expiration marker to untrack it
	cancelled bool          // Request abandoned locally, id reserved until reply or expiry
}

// Tracker is a pending network request tracker to measure how much time it takes
// a remote peer to respond.
type Tracker struct {
	protocol string        // Protocol capability identifier for the metrics
	timeout  time.Duration // Global timeout after which to drop a tracked packet

	pending map[requestKey]*request // Currently pending requests
	expire  *list.List              // Linked list tracking the expiration order
	wake    *time.Timer             // Timer tracking the expiration of the next item

	lock sync.Mutex // Lock protecting from concurrent updates
}

// New creates a new network request tracker to monitor how much time it takes to
// fill certain requests and how individual peers perform.
func New(protocol string, timeout time.Duration) *Tracker {
	return &Tracker{
		protocol: protocol,
		timeout:  timeout,
		pending:  make(map[requestKey]*request),
		expire:   list.New(),
	}
}

// Track adds a network request to the tracker to wait for a response to arrive
// or until the request is cancelled or times out. The id stays reserved until
// the response arrives or the request expires, so a request that was cancelled
// locally cannot have its id reused while a late reply may still be on the wire.
// The reservation is scoped to conn: a reconnect with the same peer id may
// reuse the id right away.
//
// The reservation is a safety net, not a reuse licence: expiry only frees the
// entry, it does not make the id safe to reuse on the same connection, because
// a late reply carries nothing but the id and the packet type. Callers must
// draw ids that do not repeat within a connection and treat a reconnect as a
// fresh id scope.
func (t *Tracker) Track(peer string, conn uint64, version uint, reqCode uint64, resCode uint64, id uint64) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	key := requestKey{peer: peer, conn: conn, id: id}
	// If there's a duplicate request, we've just random-collided (or more probably,
	// we have a bug), report it. We could also add a metric, but we're not really
	// expecting ourselves to be buggy, so a noisy warning should be enough.
	if _, ok := t.pending[key]; ok {
		log.Error("Network request id collision", "protocol", t.protocol, "conn", conn, "version", version, "code", reqCode, "id", id)
		return ErrCollision
	}
	// If we have too many pending requests, bail out instead of leaking memory
	if pending := len(t.pending); pending >= maxTrackedPackets {
		log.Error("Request tracker exceeded allowance", "pending", pending, "peer", peer, "conn", conn, "protocol", t.protocol, "version", version, "code", reqCode)
		return ErrLimitReached
	}
	// Id doesn't exist yet, start tracking it
	t.pending[key] = &request{
		peer:    peer,
		version: version,
		reqCode: reqCode,
		resCode: resCode,
		time:    time.Now(),
		expire:  t.expire.PushBack(key),
	}
	if metrics.Enabled() {
		g := fmt.Sprintf("%s/%s/%d/%#02x", trackedGaugeName, t.protocol, version, reqCode)
		metrics.GetOrRegisterGauge(g, nil).Inc(1)
	}

	// If we've just inserted the first item, start the expiration timer
	if t.wake == nil {
		t.schedule()
	}
	return nil
}

// clean is called automatically when a preset time passes without a response
// being delivered for the first network request.
func (t *Tracker) clean() {
	t.lock.Lock()
	defer t.lock.Unlock()

	// Expire anything within a certain threshold (might be no items at all if
	// we raced with the delivery)
	for t.expire.Len() > 0 {
		// Stop iterating if the next pending request is still alive
		var (
			head = t.expire.Front()
			key  = head.Value.(requestKey)
			req  = t.pending[key]
		)
		if time.Since(req.time) < t.timeout+expirationGrace {
			break
		}
		// Nope, dead, drop it
		t.expire.Remove(head)
		delete(t.pending, key)

		if metrics.Enabled() {
			g := fmt.Sprintf("%s/%s/%d/%#02x", trackedGaugeName, t.protocol, req.version, req.reqCode)
			metrics.GetOrRegisterGauge(g, nil).Dec(1)

			// A cancelled request was abandoned by the local side, so its
			// expiry must not be reported as a remote timeout.
			if !req.cancelled {
				m := fmt.Sprintf("%s/%s/%d/%#02x", lostMeterName, t.protocol, req.version, req.reqCode)
				metrics.GetOrRegisterMeter(m, nil).Mark(1)
			}
		}
	}
	t.schedule()
}

// schedule starts a timer to trigger on the expiration of the first network
// packet.
func (t *Tracker) schedule() {
	if t.expire.Len() == 0 {
		t.wake = nil
		return
	}
	key := t.expire.Front().Value.(requestKey)
	t.wake = time.AfterFunc(time.Until(t.pending[key].time.Add(t.timeout+expirationGrace)), t.clean)
}

// Fulfil fills a pending request, if any is available, reporting on various
// metrics. recv is the time the response packet was received, so the wait
// sample measures the peer's round trip and not how long the packet sat in a
// local queue before the dispatcher processed it.
func (t *Tracker) Fulfil(peer string, conn uint64, version uint, code uint64, id uint64, recv time.Time) {
	t.lock.Lock()
	defer t.lock.Unlock()

	key := requestKey{peer: peer, conn: conn, id: id}
	// If it's a non existing request, track as stale response
	req, ok := t.pending[key]
	if !ok {
		if metrics.Enabled() {
			m := fmt.Sprintf("%s/%s/%d/%#02x", staleMeterName, t.protocol, version, code)
			metrics.GetOrRegisterMeter(m, nil).Mark(1)
		}
		return
	}
	// If the response is funky, it might be some active attack
	if req.peer != peer || req.version != version || req.resCode != code {
		log.Warn("Network response id collision",
			"have", fmt.Sprintf("%s:%s/%d:%d", peer, t.protocol, version, code),
			"want", fmt.Sprintf("%s:%s/%d:%d", peer, t.protocol, req.version, req.resCode),
		)
		return
	}
	// Everything matches, mark the request serviced and meter it
	wasHead := req.expire.Prev() == nil
	t.expire.Remove(req.expire)
	delete(t.pending, key)
	if wasHead && t.wake != nil && t.wake.Stop() {
		t.schedule()
	}
	if metrics.Enabled() {
		g := fmt.Sprintf("%s/%s/%d/%#02x", trackedGaugeName, t.protocol, req.version, req.reqCode)
		metrics.GetOrRegisterGauge(g, nil).Dec(1)

		// A cancelled request was abandoned locally, so its late reply is a
		// stale response, not a round trip the caller can use: meter it as
		// such and keep it out of the wait histogram.
		if req.cancelled {
			m := fmt.Sprintf("%s/%s/%d/%#02x", staleMeterName, t.protocol, version, code)
			metrics.GetOrRegisterMeter(m, nil).Mark(1)
			return
		}
		h := fmt.Sprintf("%s/%s/%d/%#02x", waitHistName, t.protocol, req.version, req.reqCode)
		sampler := func() metrics.Sample {
			return metrics.ResettingSample(
				metrics.NewExpDecaySample(1028, 0.015),
			)
		}
		metrics.GetOrRegisterHistogramLazy(h, nil, sampler).Update(recv.Sub(req.time).Microseconds())
	}
}

// Cancel marks a pending request as abandoned locally. The tracker entry is
// kept, and the request id stays reserved, until the reply arrives or the
// request expires: a late reply carries only the id and the packet type, so
// releasing the id now would let a new request claim it and receive the old
// reply. The cancellation itself records no latency, a late reply is metered
// as stale instead of entering the wait histogram, and unlike the expiry path
// the request is not reported as lost: the local side gave up, so the peer
// never timed out.
func (t *Tracker) Cancel(peer string, conn uint64, id uint64) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if req, ok := t.pending[requestKey{peer: peer, conn: conn, id: id}]; ok {
		req.cancelled = true
	}
}

// Drop stops tracking a pending request that can no longer be answered, either
// because it never reached the wire or because its connection is gone. Unlike
// Cancel it releases the id immediately, since no reply can arrive for it
// anymore.
func (t *Tracker) Drop(peer string, conn uint64, id uint64) {
	t.lock.Lock()
	defer t.lock.Unlock()

	key := requestKey{peer: peer, conn: conn, id: id}
	req, ok := t.pending[key]
	if !ok {
		return
	}
	wasHead := req.expire.Prev() == nil
	t.expire.Remove(req.expire)
	delete(t.pending, key)

	if wasHead && t.wake != nil && t.wake.Stop() {
		t.schedule()
	}
	if metrics.Enabled() {
		g := fmt.Sprintf("%s/%s/%d/%#02x", trackedGaugeName, t.protocol, req.version, req.reqCode)
		metrics.GetOrRegisterGauge(g, nil).Dec(1)
	}
}

// DropConnection stops tracking every request of a connection that is gone,
// releasing all of its wire ids at once. Cancelled requests are dropped too:
// their reply can no longer arrive on a closed connection, and keeping the
// reservation would be pointless once a reconnect starts a new id scope.
// Unlike the expiry path none of the requests is reported as lost: the peer
// never timed out.
func (t *Tracker) DropConnection(peer string, conn uint64) {
	t.lock.Lock()
	defer t.lock.Unlock()

	removedHead := false
	for key, req := range t.pending {
		if key.peer != peer || key.conn != conn {
			continue
		}
		if req.expire.Prev() == nil {
			removedHead = true
		}
		t.expire.Remove(req.expire)
		delete(t.pending, key)

		if metrics.Enabled() {
			g := fmt.Sprintf("%s/%s/%d/%#02x", trackedGaugeName, t.protocol, req.version, req.reqCode)
			metrics.GetOrRegisterGauge(g, nil).Dec(1)
		}
	}
	if removedHead && t.wake != nil && t.wake.Stop() {
		t.schedule()
	}
}
