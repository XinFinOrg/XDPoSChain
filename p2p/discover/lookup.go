// Copyright 2019 The go-ethereum Authors
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

package discover

import (
	"context"
	"time"

	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
)

// lookup performs a network search for nodes close to the given target. It approaches the
// target by querying nodes that are closer to it on each iteration. The given target does
// not need to be an actual node identifier.
// lookup on an empty table will return immediately with no nodes.
type lookup struct {
	tab         *Table
	queryfunc   func(*node) ([]*node, error)
	replyCh     chan []*node
	cancelCh    <-chan struct{}
	asked, seen map[enode.ID]bool
	result      nodesByDistance
	replyBuffer []*node
	queries     int
}

type queryFunc func(*node) ([]*node, error)

func newLookup(ctx context.Context, tab *Table, target enode.ID, q queryFunc) *lookup {
	it := &lookup{
		tab:       tab,
		queryfunc: q,
		asked:     make(map[enode.ID]bool),
		seen:      make(map[enode.ID]bool),
		result:    nodesByDistance{target: target},
		replyCh:   make(chan []*node, alpha),
		cancelCh:  ctx.Done(),
	}
	// Don't query further if we hit ourself.
	// Unlikely to happen often in practice.
	it.asked[tab.self().ID()] = true
	it.seen[tab.self().ID()] = true

	// Initialize the lookup with nodes from table.
	closest := it.tab.findnodeByID(it.result.target, bucketSize, false)
	it.addNodes(closest.entries)
	return it
}

// run runs the lookup to completion and returns the closest nodes found.
func (it *lookup) run() []*enode.Node {
	for it.advance() {
	}
	return unwrapNodes(it.result.entries)
}

func (it *lookup) empty() bool {
	return len(it.replyBuffer) == 0
}

// advance advances the lookup until any new nodes have been found.
// It returns false when the lookup has ended.
func (it *lookup) advance() bool {
	for it.startQueries() {
		select {
		case nodes := <-it.replyCh:
			it.queries--
			it.addNodes(nodes)
			if !it.empty() {
				return true
			}
		case <-it.cancelCh:
			it.shutdown()
		}
	}
	return false
}

func (it *lookup) addNodes(nodes []*node) {
	it.replyBuffer = it.replyBuffer[:0]
	for _, n := range nodes {
		if n != nil && !it.seen[n.ID()] {
			it.seen[n.ID()] = true
			it.result.push(n, bucketSize)
			it.replyBuffer = append(it.replyBuffer, n)
		}
	}
}

func (it *lookup) shutdown() {
	for it.queries > 0 {
		<-it.replyCh
		it.queries--
	}
	it.queryfunc = nil
	it.replyBuffer = nil
}

// startQueries asks the closest nodes that we haven't asked yet.
func (it *lookup) startQueries() bool {
	if it.queryfunc == nil {
		return false
	}

	// Ask the closest nodes that we haven't asked yet.
	for i := 0; i < len(it.result.entries) && it.queries < alpha; i++ {
		n := it.result.entries[i]
		if !it.asked[n.ID()] {
			it.asked[n.ID()] = true
			it.queries++
			go it.query(n, it.replyCh)
		}
	}
	// The lookup ends when no more nodes can be asked.
	return it.queries > 0
}

func (it *lookup) query(n *node, reply chan<- []*node) {
	fails := it.tab.db.FindFails(n.ID(), n.IP())
	r, err := it.queryfunc(n)
	if err == errClosed {
		// Avoid recording failures on shutdown.
		reply <- nil
		return
	} else if len(r) == 0 {
		fails++
		it.tab.db.UpdateFindFails(n.ID(), n.IP(), fails)
		// Remove the node from the local table if it fails to return anything useful too
		// many times, but only if there are enough other nodes in the bucket.
		dropped := false
		if fails >= maxFindnodeFailures && it.tab.bucketLen(n.ID()) >= bucketSize/2 {
			dropped = true
			it.tab.delete(n)
		}
		it.tab.log.Trace("FINDNODE failed", "id", n.ID(), "failcount", fails, "dropped", dropped, "err", err)
	} else if fails > 0 {
		// Reset failure counter because it counts _consecutive_ failures.
		it.tab.db.UpdateFindFails(n.ID(), n.IP(), 0)
	}

	// Grab as many nodes as possible. Some of them might not be alive anymore, but we'll
	// just remove those again during revalidation.
	for _, n := range r {
		it.tab.addSeenNode(n)
	}
	reply <- r
}

// lookupIterator performs lookup operations and iterates over all seen nodes.
// When a lookup finishes, a new one is created through nextLookup. The iterator
// waits for table initialization and triggers a table refresh when necessary.
type lookupIterator struct {
	buffer        []*node
	nextLookup    lookupFunc
	ctx           context.Context
	cancel        func()
	lookup        *lookup
	tabRefreshing <-chan struct{}
}

type lookupFunc func(ctx context.Context) *lookup

func newLookupIterator(ctx context.Context, next lookupFunc) *lookupIterator {
	ctx, cancel := context.WithCancel(ctx)
	return &lookupIterator{ctx: ctx, cancel: cancel, nextLookup: next}
}

// Node returns the current node.
func (it *lookupIterator) Node() *enode.Node {
	if len(it.buffer) == 0 {
		return nil
	}
	return unwrapNode(it.buffer[0])
}

// Next moves to the next node.
func (it *lookupIterator) Next() bool {
	// Consume next node in buffer.
	if len(it.buffer) > 0 {
		it.buffer = it.buffer[1:]
	}

	// Advance the lookup to refill the buffer.
	for len(it.buffer) == 0 {
		if it.ctx.Err() != nil {
			it.lookup = nil
			it.buffer = nil
			return false
		}
		if it.lookup == nil {
			it.lookup = it.nextLookup(it.ctx)
			if it.lookup.empty() {
				// If the lookup is empty right after creation, it means the local table
				// is in a degraded state, and we need to wait for it to fill again.
				it.lookupFailed(it.lookup.tab, 1*time.Minute)
				it.lookup = nil
				continue
			}
			// Yield the initial nodes from the iterator before advancing the lookup.
			it.buffer = it.lookup.replyBuffer
			continue
		}

		newNodes := it.lookup.advance()
		it.buffer = it.lookup.replyBuffer
		if !newNodes {
			it.lookup = nil
		}
	}
	return true
}

// lookupFailed handles failed lookup attempts. This can be called when the table has
// exited, or when it runs out of nodes.
func (it *lookupIterator) lookupFailed(tab *Table, timeout time.Duration) {
	tout, cancel := context.WithTimeout(it.ctx, timeout)
	defer cancel()

	// Wait for Table initialization to complete, in case it is still in progress.
	select {
	case <-tab.initDone:
	case <-tout.Done():
		return
	}

	// Wait for ongoing refresh operation, or trigger one.
	if it.tabRefreshing == nil {
		it.tabRefreshing = tab.refresh()
	}
	select {
	case <-it.tabRefreshing:
		it.tabRefreshing = nil
	case <-tout.Done():
		return
	}

	// Wait for the table to fill.
	tab.waitForNodes(tout, 1)
}

// Close ends the iterator.
func (it *lookupIterator) Close() {
	it.cancel()
}
