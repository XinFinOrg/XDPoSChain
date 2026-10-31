// Copyright 2015 The go-ethereum Authors
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

package eth

import (
	"bytes"
	"math"
	"math/big"
	"math/rand"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

// Tests that block headers can be retrieved from a remote chain based on user queries.
func TestGetBlockHeaders100(t *testing.T) { testGetBlockHeaders(t, XDC100) }
func TestGetBlockHeaders164(t *testing.T) { testGetBlockHeaders(t, XDC164) }

// backendPacketRecorder captures the concrete packet type delivered to
// backend.Handle. Over xdc/166 the recorded packet must be the legacy type: the
// *66 response is unwrapped before backend.Handle, otherwise the backend type
// switch silently drops it and the peer stalls.
type backendPacketRecorder struct {
	gotPacket     Packet
	packetHandled chan struct{}
}

func newBackendPacketRecorder(backend *testBackend, protocol uint) *backendPacketRecorder {
	r := &backendPacketRecorder{packetHandled: make(chan struct{}, 1)}
	if protocol >= XDC166 {
		backend.handler = func(_ *Peer, packet Packet, _ uint32) error {
			r.gotPacket = packet
			r.packetHandled <- struct{}{}
			return nil
		}
	}
	return r
}

// waitBackendPacket blocks until the backend received a packet and asserts it
// is of the wanted legacy type; on timeout it fails the test with timeoutMsg.
func waitBackendPacket[T Packet](t *testing.T, r *backendPacketRecorder, timeoutMsg string) T {
	t.Helper()
	select {
	case <-r.packetHandled:
	case <-time.After(5 * time.Second):
		t.Fatal(timeoutMsg)
	}
	packet, ok := r.gotPacket.(T)
	if !ok {
		t.Fatalf("backend received %T, want %T", r.gotPacket, *new(T))
	}
	return packet
}

func TestGetBlockHeaders165(t *testing.T) { testGetBlockHeaders(t, XDC165) }
func TestGetBlockHeaders166(t *testing.T) { testGetBlockHeaders(t, XDC166) }

func testGetBlockHeaders(t *testing.T, protocol uint) {
	backend := newTestBackend(t, 512+15, nil)
	recorder := newBackendPacketRecorder(backend, protocol)
	peer := newTestPeer(t, "peer", protocol, backend)
	chain := backend.chain

	// Create a "random" unknown hash for testing
	var unknown common.Hash
	for i := range unknown {
		unknown[i] = byte(i)
	}
	// Create a batch of tests for various scenarios
	limit := uint64(maxHeadersServe)
	tests := []struct {
		query  *GetBlockHeadersPacket // The query to execute for header retrieval
		expect []common.Hash          // The hashes of the block whose headers are expected
	}{
		// A single random block should be retrievable by hash and number too
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Hash: chain.GetBlockByNumber(limit / 2).Hash()}, Amount: 1},
			[]common.Hash{chain.GetBlockByNumber(limit / 2).Hash()},
		}, {
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: limit / 2}, Amount: 1},
			[]common.Hash{chain.GetBlockByNumber(limit / 2).Hash()},
		},
		// Multiple headers should be retrievable in both directions
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: limit / 2}, Amount: 3},
			[]common.Hash{
				chain.GetBlockByNumber(limit / 2).Hash(),
				chain.GetBlockByNumber(limit/2 + 1).Hash(),
				chain.GetBlockByNumber(limit/2 + 2).Hash(),
			},
		}, {
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: limit / 2}, Amount: 3, Reverse: true},
			[]common.Hash{
				chain.GetBlockByNumber(limit / 2).Hash(),
				chain.GetBlockByNumber(limit/2 - 1).Hash(),
				chain.GetBlockByNumber(limit/2 - 2).Hash(),
			},
		},
		// Multiple headers with skip lists should be retrievable
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: limit / 2}, Skip: 3, Amount: 3},
			[]common.Hash{
				chain.GetBlockByNumber(limit / 2).Hash(),
				chain.GetBlockByNumber(limit/2 + 4).Hash(),
				chain.GetBlockByNumber(limit/2 + 8).Hash(),
			},
		}, {
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: limit / 2}, Skip: 3, Amount: 3, Reverse: true},
			[]common.Hash{
				chain.GetBlockByNumber(limit / 2).Hash(),
				chain.GetBlockByNumber(limit/2 - 4).Hash(),
				chain.GetBlockByNumber(limit/2 - 8).Hash(),
			},
		},
		// The chain endpoints should be retrievable
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: 0}, Amount: 1},
			[]common.Hash{chain.GetBlockByNumber(0).Hash()},
		}, {
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: chain.CurrentBlock().Number.Uint64()}, Amount: 1},
			[]common.Hash{chain.CurrentBlock().Hash()},
		},
		// Ensure protocol limits are honored
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: chain.CurrentBlock().Number.Uint64() - 1}, Amount: limit + 10, Reverse: true},
			headerHashRange(chain, chain.CurrentBlock().Number.Uint64()-1, limit),
		},
		// Check that requesting more than available is handled gracefully
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: chain.CurrentBlock().Number.Uint64() - 4}, Skip: 3, Amount: 3},
			[]common.Hash{
				chain.GetBlockByNumber(chain.CurrentBlock().Number.Uint64() - 4).Hash(),
				chain.GetBlockByNumber(chain.CurrentBlock().Number.Uint64()).Hash(),
			},
		}, {
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: 4}, Skip: 3, Amount: 3, Reverse: true},
			[]common.Hash{
				chain.GetBlockByNumber(4).Hash(),
				chain.GetBlockByNumber(0).Hash(),
			},
		},
		// Check that requesting more than available is handled gracefully, even if mid skip
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: chain.CurrentBlock().Number.Uint64() - 4}, Skip: 2, Amount: 3},
			[]common.Hash{
				chain.GetBlockByNumber(chain.CurrentBlock().Number.Uint64() - 4).Hash(),
				chain.GetBlockByNumber(chain.CurrentBlock().Number.Uint64() - 1).Hash(),
			},
		}, {
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: 4}, Skip: 2, Amount: 3, Reverse: true},
			[]common.Hash{
				chain.GetBlockByNumber(4).Hash(),
				chain.GetBlockByNumber(1).Hash(),
			},
		},
		// Check a corner case where requesting more can iterate past the endpoints
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: 2}, Amount: 5, Reverse: true},
			[]common.Hash{
				chain.GetBlockByNumber(2).Hash(),
				chain.GetBlockByNumber(1).Hash(),
				chain.GetBlockByNumber(0).Hash(),
			},
		},
		// Check a corner case where skipping overflow loops back into the chain start
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Hash: chain.GetBlockByNumber(3).Hash()}, Amount: 2, Reverse: false, Skip: ^uint64(0) - 1},
			[]common.Hash{
				chain.GetBlockByNumber(3).Hash(),
			},
		},
		// Check a corner case where skipping overflow loops back to the same header
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Hash: chain.GetBlockByNumber(1).Hash()}, Amount: 2, Reverse: false, Skip: ^uint64(0)},
			[]common.Hash{
				chain.GetBlockByNumber(1).Hash(),
			},
		},
		// Check a corner case where a reverse skip overflows and stops at the origin
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Hash: chain.GetBlockByNumber(1).Hash()}, Amount: 2, Reverse: true, Skip: ^uint64(0)},
			[]common.Hash{
				chain.GetBlockByNumber(1).Hash(),
			},
		},
		// Check that non existing headers aren't returned
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Hash: unknown}, Amount: 1},
			[]common.Hash{},
		}, {
			&GetBlockHeadersPacket{Origin: HashOrNumber{Number: chain.CurrentBlock().Number.Uint64() + 1}, Amount: 1},
			[]common.Hash{},
		},
		// Check that a request made entirely of hashes the node does not have
		// stops after the origin instead of spending a lookup per header asked
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Hash: unknown}, Amount: math.MaxInt32, Skip: 1},
			[]common.Hash{},
		},
		// Check that a skip on the order of the chain height cannot turn into a
		// reply of that size: the walk stops at the first header it cannot resolve
		{
			&GetBlockHeadersPacket{Origin: HashOrNumber{Hash: chain.CurrentBlock().Hash()}, Skip: chain.CurrentBlock().Number.Uint64(), Amount: math.MaxInt32},
			[]common.Hash{chain.CurrentBlock().Hash()},
		},
	}
	// Run each of the tests and verify the results against the chain
	for i, tt := range tests {
		// Collect the headers to expect in the response
		headers := []*types.Header{}
		for _, hash := range tt.expect {
			headers = append(headers, chain.GetBlockByHash(hash).Header())
		}
		// Send the hash request and verify the response
		if protocol <= XDC165 {
			p2p.Send(peer.app, GetBlockHeadersMsg, tt.query)
			if err := p2p.ExpectMsg(peer.app, BlockHeadersMsg, headers); err != nil {
				t.Errorf("test %d: headers mismatch: %v", i, err)
			}
		} else {
			p2p.Send(peer.app, GetBlockHeadersMsg, GetBlockHeadersPacket66{
				RequestId:             123,
				GetBlockHeadersPacket: tt.query,
			})
			if err := p2p.ExpectMsg(peer.app, BlockHeadersMsg, BlockHeadersPacket66{
				RequestId:          123,
				BlockHeadersPacket: headers,
			}); err != nil {
				t.Errorf("test %d: headers mismatch: %v", i, err)
			}
		}
		// If the test used number origins, repeat with hashes as the too
		if tt.query.Origin.Hash == (common.Hash{}) {
			if origin := chain.GetBlockByNumber(tt.query.Origin.Number); origin != nil {
				tt.query.Origin.Hash, tt.query.Origin.Number = origin.Hash(), 0

				if protocol <= XDC165 {
					p2p.Send(peer.app, GetBlockHeadersMsg, tt.query)
					if err := p2p.ExpectMsg(peer.app, BlockHeadersMsg, headers); err != nil {
						t.Errorf("test %d: headers mismatch: %v", i, err)
					}
				} else {
					p2p.Send(peer.app, GetBlockHeadersMsg, GetBlockHeadersPacket66{
						RequestId:             456,
						GetBlockHeadersPacket: tt.query,
					})
					if err := p2p.ExpectMsg(peer.app, BlockHeadersMsg, BlockHeadersPacket66{
						RequestId:          456,
						BlockHeadersPacket: headers,
					}); err != nil {
						t.Errorf("test %d: headers mismatch: %v", i, err)
					}
				}
			}
		}
	}
	// Over xdc/166, deliver a 66-encoded headers response and assert the
	// backend observed the unwrapped legacy packet, not the *66 wrapper.
	if protocol >= XDC166 {
		headers := []*types.Header{
			chain.GetBlockByNumber(1).Header(),
			chain.GetBlockByNumber(2).Header(),
		}
		p2p.Send(peer.app, BlockHeadersMsg, BlockHeadersPacket66{
			RequestId:          789,
			BlockHeadersPacket: headers,
		})
		waitBackendPacket[*BlockHeadersPacket](t, recorder, "headers response never reached the backend")
	}
}

// TestGetBlockHeadersSkipAllocation checks that a forward hash query whose skip
// is on the order of the chain height does not allocate in proportion to that
// skip. The reply carries two headers whatever the skip is, so serving it may
// not cost a skip-sized hash slice more than a benign query of the same size.
func TestGetBlockHeadersSkipAllocation(t *testing.T) {
	backend := newTestBackend(t, 512+15, nil)
	peer := newTestPeer(t, "peer", XDC165, backend)
	chain := backend.chain

	// A query starting one header above genesis and skipping forward by almost
	// the whole chain height: the header the step lands on exists, so the walk
	// has to resolve where the step came from.
	var (
		height = chain.CurrentBlock().Number.Uint64()
		origin = chain.GetHeaderByNumber(1)
		skip   = height - 2
		target = chain.GetHeaderByNumber(1 + skip + 1)
	)
	if target == nil {
		t.Fatalf("test chain is too short: no header at %d", 1+skip+1)
	}
	hostile := &GetBlockHeadersPacket{Origin: HashOrNumber{Hash: origin.Hash()}, Amount: 3, Skip: skip}
	hostileExpect := []*types.Header{origin, target}

	// The reference request answers three consecutive headers, the same amount
	// of work as the hostile query but without a hash walk behind it.
	benign := &GetBlockHeadersPacket{Origin: HashOrNumber{Number: 1}, Amount: 3}
	benignExpect := []*types.Header{
		chain.GetHeaderByNumber(1),
		chain.GetHeaderByNumber(2),
		chain.GetHeaderByNumber(3),
	}
	// allocatedPerRequest warms the peer, the header caches and the encoders up,
	// then reports how many bytes one round trip allocates.
	allocatedPerRequest := func(query *GetBlockHeadersPacket, expect []*types.Header) uint64 {
		roundTrip := func() {
			if err := p2p.Send(peer.app, GetBlockHeadersMsg, query); err != nil {
				t.Fatalf("headers request failed: %v", err)
			}
			if err := p2p.ExpectMsg(peer.app, BlockHeadersMsg, expect); err != nil {
				t.Fatalf("headers mismatch: %v", err)
			}
		}
		roundTrip()

		const runs = 16
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		for i := 0; i < runs; i++ {
			roundTrip()
		}
		runtime.ReadMemStats(&after)
		return (after.TotalAlloc - before.TotalAlloc) / runs
	}
	var (
		benignAlloc  = allocatedPerRequest(benign, benignExpect)
		hostileAlloc = allocatedPerRequest(hostile, hostileExpect)
		perSkip      = skip * uint64(common.HashLength)
	)
	t.Logf("per request: benign %d bytes, hostile %d bytes, a skip-sized hash slice is %d bytes", benignAlloc, hostileAlloc, perSkip)
	if hostileAlloc > benignAlloc+perSkip/2 {
		t.Fatalf("serving a query with skip %d allocated %d bytes per request, %d more than the benign %d and over half the skip-sized hash slice of %d", skip, hostileAlloc, hostileAlloc-benignAlloc, benignAlloc, perSkip)
	}
}

// writeSideChainHeaders writes a branch of the given length off parent straight
// into the database, without making it canonical: the headers are readable by
// hash and number, but the canonical index still maps their heights to the real
// chain.
func writeSideChainHeaders(db ethdb.Database, parent *types.Header, length int) []*types.Header {
	headers := make([]*types.Header, length)
	for i := range headers {
		headers[i] = &types.Header{
			ParentHash: parent.Hash(),
			Number:     new(big.Int).SetUint64(parent.Number.Uint64() + 1),
			Difficulty: parent.Difficulty,
			GasLimit:   parent.GasLimit,
			Time:       parent.Time + 1,
		}
		rawdb.WriteHeader(db, headers[i])
		parent = headers[i]
	}
	return headers
}

// TestGetBlockHeadersNonCanonicalBudget sends a reverse hash query from the tip
// of a side chain deeper than the non-canonical header budget. The walk back to
// the canonical chain runs out of budget, so the reply stops after the origin
// instead of continuing from wherever the walk happened to land.
func TestGetBlockHeadersNonCanonicalBudget(t *testing.T) {
	backend := newTestBackend(t, 512+15, nil)
	peer := newTestPeer(t, "peer", XDC165, backend)
	chain := backend.chain

	side := writeSideChainHeaders(backend.db, chain.GetHeaderByNumber(100), 120) // heights 101..220
	origin := side[len(side)-1]

	// The walk back to the canonical chain costs one unit per side header, so a
	// skip covering the whole branch spends more than the budget allows.
	query := &GetBlockHeadersPacket{
		Origin:  HashOrNumber{Hash: origin.Hash()},
		Amount:  3,
		Skip:    uint64(len(side) - 1),
		Reverse: true,
	}
	if err := p2p.Send(peer.app, GetBlockHeadersMsg, query); err != nil {
		t.Fatalf("headers request failed: %v", err)
	}
	if err := p2p.ExpectMsg(peer.app, BlockHeadersMsg, []*types.Header{origin}); err != nil {
		t.Fatalf("headers mismatch: %v", err)
	}
}

// TestGetBlockHeadersForwardSideChain sends a forward hash query from a side
// chain whose skip lands on an existing canonical header. Walking back from
// that header reaches the canonical hash at the origin's height rather than
// the origin hash itself, so the walk stops at the origin instead of serving
// canonical headers the peer did not ask for.
func TestGetBlockHeadersForwardSideChain(t *testing.T) {
	backend := newTestBackend(t, 512+15, nil)
	peer := newTestPeer(t, "peer", XDC165, backend)
	chain := backend.chain

	side := writeSideChainHeaders(backend.db, chain.GetHeaderByNumber(100), 5) // heights 101..105
	origin := side[0]
	query := &GetBlockHeadersPacket{
		Origin: HashOrNumber{Hash: origin.Hash()},
		Amount: 3,
		Skip:   3, // the step lands on the canonical header at 105
	}
	if err := p2p.Send(peer.app, GetBlockHeadersMsg, query); err != nil {
		t.Fatalf("headers request failed: %v", err)
	}
	if err := p2p.ExpectMsg(peer.app, BlockHeadersMsg, []*types.Header{origin}); err != nil {
		t.Fatalf("headers mismatch: %v", err)
	}
}

// headerHashRange returns the hashes of the canonical headers at top, top-1, ...,
// down towards genesis, at most count of them. Tests state the expected reply of
// a descending query with it instead of asking the chain for the same slice the
// serving code builds.
func headerHashRange(chain *core.BlockChain, top, count uint64) []common.Hash {
	hashes := make([]common.Hash, 0, count)
	for i := uint64(0); i < count && i <= top; i++ {
		hashes = append(hashes, chain.GetHeaderByNumber(top-i).Hash())
	}
	return hashes
}

// Tests that block contents can be retrieved from a remote chain based on their hashes.
func TestGetBlockBodies100(t *testing.T) { testGetBlockBodies(t, XDC100) }
func TestGetBlockBodies164(t *testing.T) { testGetBlockBodies(t, XDC164) }
func TestGetBlockBodies165(t *testing.T) { testGetBlockBodies(t, XDC165) }
func TestGetBlockBodies166(t *testing.T) { testGetBlockBodies(t, XDC166) }

func testGetBlockBodies(t *testing.T, protocol uint) {
	backend := newTestBackend(t, maxBodiesServe+15, nil)
	recorder := newBackendPacketRecorder(backend, protocol)
	peer := newTestPeer(t, "peer", protocol, backend)
	chain := backend.chain

	// Create a batch of tests for various scenarios
	limit := maxBodiesServe
	tests := []struct {
		random    int           // Number of blocks to fetch randomly from the chain
		explicit  []common.Hash // Explicitly requested blocks
		available []bool        // Availability of explicitly requested blocks
		expected  int           // Total number of existing blocks to expect
	}{
		{1, nil, nil, 1},             // A single random block should be retrievable
		{10, nil, nil, 10},           // Multiple random blocks should be retrievable
		{limit, nil, nil, limit},     // The maximum possible blocks should be retrievable
		{limit + 1, nil, nil, limit}, // No more than the possible block count should be returned
		{0, []common.Hash{chain.Genesis().Hash()}, []bool{true}, 1},      // The genesis block should be retrievable
		{0, []common.Hash{chain.CurrentBlock().Hash()}, []bool{true}, 1}, // The chains head block should be retrievable
		{0, []common.Hash{{}}, []bool{false}, 0},                         // A non existent block should not be returned

		// Existing and non-existing blocks interleaved should not cause problems
		{0, []common.Hash{
			{},
			chain.GetBlockByNumber(1).Hash(),
			{},
			chain.GetBlockByNumber(10).Hash(),
			{},
			chain.GetBlockByNumber(100).Hash(),
			{},
		}, []bool{false, true, false, true, false, true, false}, 3},
	}
	// Run each of the tests and verify the results against the chain
	for i, tt := range tests {
		// Collect the hashes to request, and the response to expect
		hashes, seen := []common.Hash{}, make(map[int64]bool)
		bodies := []*BlockBody{}

		for j := 0; j < tt.random; j++ {
			for {
				num := rand.Int63n(int64(chain.CurrentBlock().Number.Uint64()))
				if !seen[num] {
					seen[num] = true

					block := chain.GetBlockByNumber(uint64(num))
					hashes = append(hashes, block.Hash())
					if len(bodies) < tt.expected {
						bodies = append(bodies, &BlockBody{Transactions: block.Transactions(), Uncles: block.Uncles()})
					}
					break
				}
			}
		}
		for j, hash := range tt.explicit {
			hashes = append(hashes, hash)
			if tt.available[j] && len(bodies) < tt.expected {
				block := chain.GetBlockByHash(hash)
				bodies = append(bodies, &BlockBody{Transactions: block.Transactions(), Uncles: block.Uncles()})
			}
		}
		// Send the hash request and verify the response
		if protocol <= XDC165 {
			p2p.Send(peer.app, GetBlockBodiesMsg, hashes)
			if err := p2p.ExpectMsg(peer.app, BlockBodiesMsg, bodies); err != nil {
				t.Errorf("test %d: bodies mismatch: %v", i, err)
			}
		} else {
			p2p.Send(peer.app, GetBlockBodiesMsg, GetBlockBodiesPacket66{
				RequestId:            123,
				GetBlockBodiesPacket: hashes,
			})
			// The server answers from the already RLP-encoded bodies, so the
			// reply is a BlockBodiesRLPPacket66; it encodes to the same bytes
			// as the decoded wrapper expected here.
			if err := p2p.ExpectMsg(peer.app, BlockBodiesMsg, BlockBodiesPacket66{
				RequestId:         123,
				BlockBodiesPacket: bodies,
			}); err != nil {
				t.Errorf("test %d: bodies mismatch: %v", i, err)
			}
		}
	}
	// Over xdc/166, deliver a 66-encoded bodies response and assert the
	// backend observed the unwrapped legacy packet, not the *66 wrapper.
	if protocol >= XDC166 {
		block := chain.GetBlockByNumber(1)
		p2p.Send(peer.app, BlockBodiesMsg, BlockBodiesPacket66{
			RequestId:         789,
			BlockBodiesPacket: BlockBodiesPacket{{Transactions: block.Transactions(), Uncles: block.Uncles()}},
		})
		waitBackendPacket[*BlockBodiesPacket](t, recorder, "bodies response never reached the backend")
	}
}

// Tests that the lookups a body request may cost are bounded to twice the number
// of bodies served. The request is a known prefix, then a hole of unknown hashes
// that fills the budget up to its last slot, then two known bodies: the one at
// the last budgeted index (2*maxBodiesServe-1) and the one just past it. Only the
// first of the two may come back, which pins the budget at exactly twice the cap:
// a smaller budget drops the boundary body, a larger one serves the body past it.
// The prefix is half of maxBodiesServe, so the serve cap cannot stop the loop.
func TestGetBlockBodiesLookupBudget(t *testing.T) {
	backend := newTestBackend(t, 512+15, nil)
	peer := newTestPeer(t, "peer", XDC165, backend)
	chain := backend.chain

	prefix := maxBodiesServe / 2
	lastInBudget := chain.GetBlockByNumber(uint64(prefix))
	firstOverBudget := chain.GetBlockByNumber(uint64(prefix + 1))

	hashes := make([]common.Hash, 0, 2*maxBodiesServe+2)
	bodies := make([]rlp.RawValue, 0, prefix+1)
	for i := 0; i < prefix; i++ {
		block := chain.GetBlockByNumber(uint64(i))
		hashes = append(hashes, block.Hash())
		bodies = append(bodies, chain.GetBodyRLP(block.Hash()))
	}
	for i := 0; i < 2*maxBodiesServe-prefix-1; i++ {
		hashes = append(hashes, unknownHash(i))
	}
	hashes = append(hashes, lastInBudget.Hash())
	bodies = append(bodies, chain.GetBodyRLP(lastInBudget.Hash()))
	hashes = append(hashes, firstOverBudget.Hash())
	// Send the hash request and verify that the budget stops before the body past it
	if err := p2p.Send(peer.app, GetBlockBodiesMsg, hashes); err != nil {
		t.Fatalf("failed to send bodies request: %v", err)
	}

	msg, err := peer.app.ReadMsg()
	if err != nil {
		t.Fatalf("failed to read bodies response: %v", err)
	}
	if msg.Code != BlockBodiesMsg {
		t.Fatalf("response packet code mismatch: have %x, want %x", msg.Code, BlockBodiesMsg)
	}
	var served []rlp.RawValue
	if err := msg.Decode(&served); err != nil {
		t.Fatalf("failed to decode bodies response: %v", err)
	}
	if len(served) != len(bodies) {
		t.Fatalf("served %d bodies out of %d requested hashes, want %d", len(served), len(hashes), len(bodies))
	}
	for i, want := range bodies {
		if !bytes.Equal(served[i], want) {
			t.Errorf("body %d mismatch: have %x, want %x", i, served[i], want)
		}
	}
}

// unknownHash returns a hash that is not in any test chain, distinct per index.
func unknownHash(i int) common.Hash {
	var hash common.Hash
	hash[0], hash[1] = byte(i), byte(i>>8)
	return hash
}

// Tests that the node state database can be retrieved based on hashes.
func TestGetNodeData100(t *testing.T) { testGetNodeData(t, XDC100) }
func TestGetNodeData164(t *testing.T) { testGetNodeData(t, XDC164) }
func TestGetNodeData165(t *testing.T) { testGetNodeData(t, XDC165) }
func TestGetNodeData166(t *testing.T) { testGetNodeData(t, XDC166) }

func testGetNodeData(t *testing.T, protocol uint) {
	// Define three accounts to simulate transactions with
	acc1Key, _ := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	acc2Key, _ := crypto.HexToECDSA("49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee")
	acc1Addr := crypto.PubkeyToAddress(acc1Key.PublicKey)
	acc2Addr := crypto.PubkeyToAddress(acc2Key.PublicKey)

	signer := types.HomesteadSigner{}
	// Create a chain generator with some simple transactions (blatantly stolen from @fjl/chain_markets_test)
	generator := func(i int, block *core.BlockGen) {
		fee := block.BaseFee()
		if fee == nil {
			fee = big.NewInt(params.InitialBaseFee)
		}
		switch i {
		case 0:
			// In block 1, the test bank sends account #1 some ether.
			tx, _ := types.SignTx(types.NewTransaction(block.TxNonce(testBank), acc1Addr, new(big.Int).SetUint64(1_000_000_000_000_000_000), params.TxGas, fee, nil), signer, testBankKey)
			block.AddTx(tx)
		case 1:
			// In block 2, the test bank sends some more ether to account #1.
			// acc1Addr passes it on to account #2.
			tx1, _ := types.SignTx(types.NewTransaction(block.TxNonce(testBank), acc1Addr, new(big.Int).SetUint64(1_000_000_000_000_000_000), params.TxGas, fee, nil), signer, testBankKey)
			tx2, _ := types.SignTx(types.NewTransaction(block.TxNonce(acc1Addr), acc2Addr, new(big.Int).SetUint64(1_000_000_000_000_000_000), params.TxGas, fee, nil), signer, acc1Key)
			block.AddTx(tx1)
			block.AddTx(tx2)
		case 2:
			// Block 3 is empty but was mined by account #2.
			block.SetCoinbase(acc2Addr)
			block.SetExtra([]byte("yeehaw"))
		case 3:
			// Block 4 includes blocks 2 and 3 as uncle headers (with modified extra data).
			b2 := block.PrevBlock(1).Header()
			b2.Extra = []byte("foo")
			block.AddUncle(b2)
			b3 := block.PrevBlock(2).Header()
			b3.Extra = []byte("foo")
			block.AddUncle(b3)
		}
	}
	// Assemble the test environment
	backend := newTestBackend(t, 4, generator)
	recorder := newBackendPacketRecorder(backend, protocol)
	peer := newTestPeer(t, "peer", protocol, backend)
	db := backend.db

	// Fetch for now the entire chain db
	hashes := []common.Hash{}
	it := db.NewIterator(nil, nil)
	for it.Next() {
		key := it.Key()
		if len(key) == len(common.Hash{}) {
			hashes = append(hashes, common.BytesToHash(key))
		}
	}
	if protocol <= XDC165 {
		p2p.Send(peer.app, GetNodeDataMsg, hashes)
	} else {
		p2p.Send(peer.app, GetNodeDataMsg, GetNodeDataPacket66{
			RequestId:         123,
			GetNodeDataPacket: hashes,
		})
	}
	msg, err := peer.app.ReadMsg()
	if err != nil {
		t.Fatalf("failed to read node data response: %v", err)
	}
	if msg.Code != NodeDataMsg {
		t.Fatalf("response packet code mismatch: have %x, want %x", msg.Code, NodeDataMsg)
	}
	var data [][]byte
	if protocol <= XDC165 {
		if err := msg.Decode(&data); err != nil {
			t.Fatalf("failed to decode response node data: %v", err)
		}
	} else {
		var res NodeDataPacket66
		if err := msg.Decode(&res); err != nil {
			t.Fatalf("failed to decode response node data: %v", err)
		}
		if res.RequestId != 123 {
			t.Fatalf("request id mismatch: have %d, want 123", res.RequestId)
		}
		data = res.NodeDataPacket
	}
	// Verify that all hashes correspond to the requested data, and reconstruct a state tree
	for i, want := range hashes {
		if hash := crypto.Keccak256Hash(data[i]); hash != want {
			t.Errorf("data hash mismatch: have %x, want %x", hash, want)
		}
	}
	statedb := rawdb.NewMemoryDatabase()
	for i := 0; i < len(data); i++ {
		statedb.Put(hashes[i].Bytes(), data[i])
	}
	accounts := []common.Address{testBank, acc1Addr, acc2Addr}
	for i := uint64(0); i <= backend.chain.CurrentBlock().Number.Uint64(); i++ {
		trie, _ := state.New(backend.chain.GetBlockByNumber(i).Root(), state.NewDatabase(statedb))

		for j, acc := range accounts {
			state, _ := backend.chain.State()
			bw := state.GetBalance(acc)
			bh := trie.GetBalance(acc)

			if (bw != nil && bh == nil) || (bw == nil && bh != nil) {
				t.Errorf("test %d, account %d: balance mismatch: have %v, want %v", i, j, bh, bw)
			}
			if bw != nil && bh != nil && bw.Cmp(bw) != 0 {
				t.Errorf("test %d, account %d: balance mismatch: have %v, want %v", i, j, bh, bw)
			}
		}
	}
	// Over xdc/166, deliver a 66-encoded node data response and assert the
	// backend observed the unwrapped legacy packet, not the *66 wrapper.
	if protocol >= XDC166 {
		p2p.Send(peer.app, NodeDataMsg, NodeDataPacket66{
			RequestId:      789,
			NodeDataPacket: NodeDataPacket{{0x01}},
		})
		waitBackendPacket[*NodeDataPacket](t, recorder, "node data response never reached the backend")
	}
}

// Tests that the lookups a node data request may cost are bounded to twice the
// number of trie nodes served, the same way as for block bodies. One known
// self-transfer per block keeps the 32-byte keyspace dense, so the prefix and the
// two boundary hashes all draw on keys the store is known to answer. The hashes
// at the last budgeted index (2*maxNodeDataServe-1) and at the first index past it
// are both answerable, so only the budget decides which of the two comes back.
func TestGetNodeDataLookupBudget(t *testing.T) {
	signer := types.HomesteadSigner{}
	generator := func(i int, block *core.BlockGen) {
		fee := block.BaseFee()
		if fee == nil {
			fee = big.NewInt(params.InitialBaseFee)
		}
		tx, _ := types.SignTx(types.NewTransaction(block.TxNonce(testBank), testBank, big.NewInt(1), params.TxGas, fee, nil), signer, testBankKey)
		block.AddTx(tx)
	}
	backend := newTestBackend(t, 512+15, generator)
	peer := newTestPeer(t, "peer", XDC165, backend)

	// Collect the hashes the store answers, the same iteration testGetNodeData does
	var known []common.Hash
	it := backend.db.NewIterator(nil, nil)
	for it.Next() {
		if key := it.Key(); len(key) == len(common.Hash{}) {
			known = append(known, common.BytesToHash(key))
		}
	}
	it.Release()

	prefix := maxNodeDataServe / 2
	if len(known) < 2*prefix+2 {
		t.Fatalf("test chain exposes %d answerable hashes, want at least %d", len(known), 2*prefix+2)
	}
	hashes := make([]common.Hash, 0, 2*maxNodeDataServe+2)
	hashes = append(hashes, known[:prefix]...)
	for i := range 2*maxNodeDataServe - prefix - 1 {
		hashes = append(hashes, unknownHash(i))
	}
	hashes = append(hashes, known[prefix])   // last budgeted index, must be served
	hashes = append(hashes, known[prefix+1]) // first index past the budget

	// Send the hash request and verify that the budget stops before the second boundary hash
	if err := p2p.Send(peer.app, GetNodeDataMsg, hashes); err != nil {
		t.Fatalf("failed to send node data request: %v", err)
	}
	msg, err := peer.app.ReadMsg()
	if err != nil {
		t.Fatalf("failed to read node data response: %v", err)
	}
	if msg.Code != NodeDataMsg {
		t.Fatalf("response packet code mismatch: have %x, want %x", msg.Code, NodeDataMsg)
	}
	var data [][]byte
	if err := msg.Decode(&data); err != nil {
		t.Fatalf("failed to decode node data response: %v", err)
	}
	if len(data) != prefix+1 {
		t.Fatalf("served %d node data entries out of %d requested hashes, want %d", len(data), len(hashes), prefix+1)
	}
	for i, want := range known[:prefix+1] {
		if hash := crypto.Keccak256Hash(data[i]); hash != want {
			t.Errorf("data hash mismatch: have %x, want %x", hash, want)
		}
	}
}

// Tests that the transaction receipts can be retrieved based on hashes.
func TestGetReceipt100(t *testing.T) { testGetReceipt(t, XDC100) }
func TestGetReceipt164(t *testing.T) { testGetReceipt(t, XDC164) }
func TestGetReceipt165(t *testing.T) { testGetReceipt(t, XDC165) }
func TestGetReceipt166(t *testing.T) { testGetReceipt(t, XDC166) }

func testGetReceipt(t *testing.T, protocol uint) {
	// Define three accounts to simulate transactions with
	acc1Key, _ := crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	acc2Key, _ := crypto.HexToECDSA("49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee")
	acc1Addr := crypto.PubkeyToAddress(acc1Key.PublicKey)
	acc2Addr := crypto.PubkeyToAddress(acc2Key.PublicKey)

	signer := types.HomesteadSigner{}
	// Create a chain generator with some simple transactions (blatantly stolen from @fjl/chain_markets_test)
	generator := func(i int, block *core.BlockGen) {
		fee := block.BaseFee()
		if fee == nil {
			fee = big.NewInt(params.InitialBaseFee)
		}
		switch i {
		case 0:
			// In block 1, the test bank sends account #1 some ether.
			tx, _ := types.SignTx(types.NewTransaction(block.TxNonce(testBank), acc1Addr, new(big.Int).SetUint64(1_000_000_000_000_000_000), params.TxGas, fee, nil), signer, testBankKey)
			block.AddTx(tx)
		case 1:
			// In block 2, the test bank sends some more ether to account #1.
			// acc1Addr passes it on to account #2.
			tx1, _ := types.SignTx(types.NewTransaction(block.TxNonce(testBank), acc1Addr, new(big.Int).SetUint64(1_000_000_000_000_000_000), params.TxGas, fee, nil), signer, testBankKey)
			tx2, _ := types.SignTx(types.NewTransaction(block.TxNonce(acc1Addr), acc2Addr, new(big.Int).SetUint64(1_000_000_000_000_000_000), params.TxGas, fee, nil), signer, acc1Key)
			block.AddTx(tx1)
			block.AddTx(tx2)
		case 2:
			// Block 3 is empty but was mined by account #2.
			block.SetCoinbase(acc2Addr)
			block.SetExtra([]byte("yeehaw"))
		case 3:
			// Block 4 includes blocks 2 and 3 as uncle headers (with modified extra data).
			b2 := block.PrevBlock(1).Header()
			b2.Extra = []byte("foo")
			block.AddUncle(b2)
			b3 := block.PrevBlock(2).Header()
			b3.Extra = []byte("foo")
			block.AddUncle(b3)
		}
	}
	// Assemble the test environment
	backend := newTestBackend(t, 4, generator)
	recorder := newBackendPacketRecorder(backend, protocol)
	peer := newTestPeer(t, "peer", protocol, backend)

	// Collect the hashes to request, and the response to expect
	hashes, receipts := []common.Hash{}, ReceiptsPacket{}
	for i := uint64(0); i <= backend.chain.CurrentBlock().Number.Uint64(); i++ {
		block := backend.chain.GetBlockByNumber(i)

		hashes = append(hashes, block.Hash())
		receipts = append(receipts, backend.chain.GetReceiptsByHash(block.Hash()))
	}
	// Send the hash request and verify the response
	if protocol <= XDC165 {
		p2p.Send(peer.app, GetReceiptsMsg, hashes)
		if err := p2p.ExpectMsg(peer.app, ReceiptsMsg, receipts); err != nil {
			t.Errorf("receipts mismatch: %v", err)
		}
	} else {
		p2p.Send(peer.app, GetReceiptsMsg, GetReceiptsPacket66{
			RequestId:         123,
			GetReceiptsPacket: hashes,
		})
		// The server answers from the already RLP-encoded receipts, so the
		// reply is a ReceiptsRLPPacket66; it encodes to the same bytes as the
		// decoded wrapper expected here.
		if err := p2p.ExpectMsg(peer.app, ReceiptsMsg, ReceiptsPacket66{
			RequestId:      123,
			ReceiptsPacket: receipts,
		}); err != nil {
			t.Errorf("receipts mismatch: %v", err)
		}
	}
	// Over xdc/166, deliver a 66-encoded receipts response and assert the
	// backend observed the unwrapped legacy packet, not the *66 wrapper.
	if protocol >= XDC166 {
		p2p.Send(peer.app, ReceiptsMsg, ReceiptsPacket66{
			RequestId:      789,
			ReceiptsPacket: receipts[:1],
		})
		waitBackendPacket[*ReceiptsPacket](t, recorder, "receipts response never reached the backend")
	}
}

// Tests that the lookups a receipt request may cost are bounded to twice the
// number of receipts served, the same way as for block bodies. The reply length
// is what pins the budget here: every block of the test chain has empty
// receipts, so the served lists are indistinguishable from each other. The two
// boundary blocks sit at the last budgeted index (2*maxReceiptsServe-1) and at
// the first index past it, so only the budget decides which of them comes back.
func TestGetReceiptsLookupBudget(t *testing.T) {
	backend := newTestBackend(t, 512+15, nil)
	peer := newTestPeer(t, "peer", XDC165, backend)
	chain := backend.chain

	prefix := maxReceiptsServe / 2
	hashes := make([]common.Hash, 0, 2*maxReceiptsServe+2)
	for i := 0; i < prefix; i++ {
		hashes = append(hashes, chain.GetBlockByNumber(uint64(i+1)).Hash())
	}
	for i := 0; i < 2*maxReceiptsServe-prefix-1; i++ {
		hashes = append(hashes, unknownHash(i))
	}
	hashes = append(hashes, chain.GetBlockByNumber(uint64(prefix+1)).Hash()) // last budgeted index, must be served
	hashes = append(hashes, chain.GetBlockByNumber(uint64(prefix+2)).Hash()) // first index past the budget
	// Send the hash request and verify that the budget stops before the block past it
	if err := p2p.Send(peer.app, GetReceiptsMsg, hashes); err != nil {
		t.Fatalf("failed to send receipts request: %v", err)
	}

	msg, err := peer.app.ReadMsg()
	if err != nil {
		t.Fatalf("failed to read receipts response: %v", err)
	}
	if msg.Code != ReceiptsMsg {
		t.Fatalf("response packet code mismatch: have %x, want %x", msg.Code, ReceiptsMsg)
	}
	var served []rlp.RawValue
	if err := msg.Decode(&served); err != nil {
		t.Fatalf("failed to decode receipts response: %v", err)
	}
	if len(served) != prefix+1 {
		t.Fatalf("served receipts for %d of %d requested hashes, want %d", len(served), len(hashes), prefix+1)
	}
}

// Tests that a malformed payload is rejected through the decode-error path
// instead of crashing the peer.
func TestMalformedPayload(t *testing.T) {
	backend := newTestBackend(t, 1, nil)
	peer := newTestPeer(t, "peer", XDC165, backend)

	// A header query is a struct, so an integer payload cannot decode into it.
	go p2p.Send(peer.app, GetBlockHeadersMsg, uint64(1))

	select {
	case err := <-peer.errc:
		if err == nil {
			t.Fatal("malformed payload was accepted")
		}
		if want := errCode(ErrDecode).String(); !strings.Contains(err.Error(), want) {
			t.Errorf("wrong error: got %v, want a %q error", err, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("malformed payload was not rejected within 2 seconds")
	}
}

// Tests that a message larger than the protocol cap is rejected without being
// decoded.
func TestOversizeMessage(t *testing.T) {
	backend := newTestBackend(t, 1, nil)
	peer := newTestPeer(t, "peer", XDC165, backend)

	// The payload is larger than the protocol cap, so it is never read by the
	// serving side; send it from a goroutine and let the pipe teardown release it.
	go p2p.Send(peer.app, NodeDataMsg, make([]byte, protocolMaxMsgSize+1))

	select {
	case err := <-peer.errc:
		if err == nil {
			t.Fatal("oversize message was accepted")
		}
		if !strings.Contains(err.Error(), errCode(ErrMsgTooLarge).String()) {
			t.Errorf("wrong error: got %v, want a %q error", err, errCode(ErrMsgTooLarge).String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("oversize message was not rejected within 2 seconds")
	}
}

// sendPropagatedBlock hands a propagated block to the peer's message pipe the
// way the transport layer does, including the frame's arrival stamp.
func sendPropagatedBlock(app *p2p.MsgPipeRW, block *types.Block, td *big.Int, arrived time.Time) error {
	size, payload, err := rlp.EncodeToReader([]any{block, td})
	if err != nil {
		return err
	}
	return app.WriteMsg(p2p.Msg{Code: NewBlockMsg, Size: uint32(size), Payload: payload, ReceivedAt: arrived})
}

// Tests that a propagated block reaches the backend stamped with the transport
// facts and recorded as known for the peer that sent it.
func TestPropagatedBlockReachesBackend(t *testing.T) {
	backend := newTestBackend(t, 1, nil)

	received := make(chan *NewBlockPacket, 1)
	backend.handler = func(peer *Peer, packet Packet, size uint32) error {
		received <- packet.(*NewBlockPacket)
		return nil
	}
	peer := newTestPeer(t, "peer", XDC165, backend)

	block := backend.chain.GetBlockByNumber(1)
	arrived := time.Unix(1700000000, 0)
	go func() { _ = sendPropagatedBlock(peer.app, block, big.NewInt(131136), arrived) }()

	select {
	case packet := <-received:
		if packet.Block.Hash() != block.Hash() {
			t.Fatalf("propagated block mismatch: have %v, want %v", packet.Block.Hash(), block.Hash())
		}
		if packet.Block.ReceivedFrom != peer.Peer {
			t.Errorf("wrong sender stamp: have %v, want %v", packet.Block.ReceivedFrom, peer.Peer)
		}
		if !packet.Block.ReceivedAt.Equal(arrived) {
			t.Errorf("wrong arrival stamp: have %v, want %v", packet.Block.ReceivedAt, arrived)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("propagated block was not handed to the backend within 2 seconds")
	}
	if !peer.Peer.KnownBlock(block.Hash()) {
		t.Error("propagated block was not marked as known for the peer")
	}
}

// Tests that a propagated block with a structurally invalid payload is dropped
// in the wire loop: it never reaches the backend and the peer is not recorded as
// knowing it, while a later valid block still does both.
func TestInvalidPropagatedBlockNotMarked(t *testing.T) {
	backend := newTestBackend(t, 1, nil)

	received := make(chan *NewBlockPacket, 3)
	backend.handler = func(peer *Peer, packet Packet, size uint32) error {
		received <- packet.(*NewBlockPacket)
		return nil
	}
	peer := newTestPeer(t, "peer", XDC165, backend)

	block := backend.chain.GetBlockByNumber(1)
	body := types.Body{Transactions: block.Transactions(), Uncles: block.Uncles()}

	invalidUncles := block.Header()
	invalidUncles.UncleHash[0]++
	invalidBody := block.Header()
	invalidBody.TxHash[0]++

	invalid := []*types.Block{
		types.NewBlockWithHeader(invalidUncles).WithBody(body),
		types.NewBlockWithHeader(invalidBody).WithBody(body),
	}
	arrived := time.Unix(1700000000, 0)
	go func() {
		for _, announced := range append(invalid, block) {
			if err := sendPropagatedBlock(peer.app, announced, big.NewInt(131136), arrived); err != nil {
				return
			}
		}
	}()
	// The pipe is ordered, so the valid block arriving proves the invalid ones
	// before it were already processed and dropped.
	select {
	case packet := <-received:
		if packet.Block.Hash() != block.Hash() {
			t.Fatalf("invalid propagated block reached the backend: %v", packet.Block.Hash())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("valid propagated block was not handed to the backend within 2 seconds")
	}
	for _, dropped := range invalid {
		if peer.Peer.KnownBlock(dropped.Hash()) {
			t.Errorf("invalid propagated block %v was marked as known for the peer", dropped.Hash())
		}
	}
	if !peer.Peer.KnownBlock(block.Hash()) {
		t.Error("valid propagated block was not marked as known for the peer")
	}
}

// Tests that a block bodies payload carrying an oversized uncle is rejected in
// the wire loop, before the backend sees it.
func TestOversizedUncleBlockBodiesRejected(t *testing.T) {
	backend := newTestBackend(t, 1, nil)

	reached := make(chan Packet, 1)
	backend.handler = func(peer *Peer, packet Packet, size uint32) error {
		reached <- packet
		return nil
	}
	peer := newTestPeer(t, "peer", XDC165, backend)

	bodies := BlockBodiesPacket{{Uncles: []*types.Header{{Extra: bytes.Repeat([]byte{0x01}, 20*1024+1)}}}}
	go func() { _ = p2p.Send(peer.app, BlockBodiesMsg, bodies) }()

	select {
	case packet := <-reached:
		t.Fatalf("block bodies with an oversized uncle reached the backend: %v", packet)
	case err := <-peer.errc:
		if err == nil {
			t.Fatal("block bodies with an oversized uncle were accepted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("block bodies with an oversized uncle were not rejected within 2 seconds")
	}
}

// Tests that the xdc/166 response branches keep the hardening the legacy
// branches apply (plan M9c). Two subtests are the red-if-dropped guards:
// oversized_uncle_extra turns red if BlockBodiesPacket.sanityCheck is dropped
// from the 166 bodies branch, and pooled_transactions_gate turns red if the
// AcceptTxs gate is dropped from the 166 pooled branch. The nil body and nil
// pooled transaction subtests are wire-rejection assertions only — RLP
// decoding rejects nil pointers before any check runs, so they cannot detect a
// dropped check; they document the end-to-end teardown path instead. The
// checks themselves stay in the 166 branches regardless, copied from the
// legacy ones.
func TestRejectMalformed166Responses(t *testing.T) {
	// reject asserts that the given 66-wrapped payload is rejected in the wire
	// loop: the peer is torn down with an error and the backend never runs.
	reject := func(t *testing.T, backend *testBackend, code uint64, payload interface{}) {
		t.Helper()
		peer := newTestPeer(t, "peer", XDC166, backend)
		go func() { _ = p2p.Send(peer.app, code, payload) }()

		select {
		case err := <-peer.errc:
			if err == nil {
				t.Fatal("malformed 166 response was accepted")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("malformed 166 response was not rejected within 2 seconds")
		}
	}

	t.Run("oversized uncle extra", func(t *testing.T) {
		backend := newTestBackend(t, 1, nil)
		// The payload decodes cleanly, so the retained sanity check is the only
		// thing that can reject it: dropping the check makes this subtest fail
		// through the backend receipt below.
		bodies := BlockBodiesPacket{{Uncles: []*types.Header{{Extra: bytes.Repeat([]byte{0x01}, 20*1024+1)}}}}
		reject(t, backend, BlockBodiesMsg, BlockBodiesPacket66{
			RequestId:         123,
			BlockBodiesPacket: bodies,
		})
	})
	t.Run("nil block body", func(t *testing.T) {
		backend := newTestBackend(t, 1, nil)
		reject(t, backend, BlockBodiesMsg, BlockBodiesPacket66{
			RequestId:         123,
			BlockBodiesPacket: BlockBodiesPacket{nil},
		})
	})
	t.Run("nil pooled transaction", func(t *testing.T) {
		backend := newTestBackend(t, 1, nil)
		// The pooled transactions response case is gated on the node accepting
		// transactions; lift the gate so the payload is actually decoded and
		// checked instead of being dropped before it.
		backend.accepted.Store(true)
		reject(t, backend, PooledTransactionsMsg, PooledTransactionsPacket66{
			RequestId:                123,
			PooledTransactionsPacket: PooledTransactionsPacket{nil},
		})
	})
	t.Run("pooled transactions gate", func(t *testing.T) {
		backend := newTestBackend(t, 1, nil)
		reached := make(chan Packet, 1)
		backend.handler = func(peer *Peer, packet Packet, size uint32) error {
			reached <- packet
			return nil
		}
		peer := newTestPeer(t, "peer", XDC166, backend)

		// The backend keeps refusing transactions: the pooled transactions
		// response must be dropped in the wire loop, before the backend sees
		// it. Dropping the AcceptTxs gate from the 166 branch lets the payload
		// through and fails this subtest.
		tx := newTestTransaction(testBankKey, 0, 0)
		p2p.Send(peer.app, PooledTransactionsMsg, PooledTransactionsPacket66{
			RequestId:                123,
			PooledTransactionsPacket: PooledTransactionsPacket{tx},
		})
		select {
		case packet := <-reached:
			t.Fatalf("pooled transactions response reached the backend despite the gate: %v", packet)
		case <-time.After(500 * time.Millisecond):
		}
	})
}

// Tests that the XDC-specific packets are decoded and handed to the backend
// instead of being dropped.
func TestXDCPacketsReachBackend(t *testing.T) {
	backend := newTestBackend(t, 1, nil)

	type handled struct {
		name string
		size uint32
	}
	received := make(chan handled, 5)
	backend.handler = func(peer *Peer, packet Packet, size uint32) error {
		received <- handled{name: packet.Name(), size: size}
		return nil
	}
	peer := newTestPeer(t, "peer", XDC165, backend)

	vote := &types.Vote{ProposedBlockInfo: &types.BlockInfo{Hash: common.Hash{0x01}, Round: 1, Number: big.NewInt(2)}, Signature: types.Signature{0x01}}
	timeout := &types.Timeout{Round: 2, Signature: types.Signature{0x02}}
	syncInfo := &types.SyncInfo{
		HighestQuorumCert:  &types.QuorumCert{ProposedBlockInfo: &types.BlockInfo{Hash: common.Hash{0x02}, Round: 1, Number: big.NewInt(2)}, Signatures: []types.Signature{{0x03}}},
		HighestTimeoutCert: &types.TimeoutCert{Round: 3, Signatures: []types.Signature{{0x04}}},
	}
	orderTx := types.NewOrderTransaction(1, big.NewInt(1), big.NewInt(1), common.Address{}, common.Address{}, common.Address{}, common.Address{}, "status", "side", "type", common.Hash{}, 1)
	lendingTx := types.NewLendingTransaction(1, big.NewInt(1), 1, 1, common.Address{}, common.Address{}, common.Address{}, common.Address{}, false, "status", "side", "type", common.Hash{}, 1, 1, "")

	backend.accepted.Store(true)
	sends := []struct {
		name string
		code uint64
		data interface{}
	}{
		{"OrderTransactions", OrderTxMsg, types.OrderTransactions{orderTx}},
		{"LendingTransactions", LendingTxMsg, types.LendingTransactions{lendingTx}},
		{"Vote", VoteMsg, vote},
		{"Timeout", TimeoutMsg, timeout},
		{"SyncInfo", SyncInfoMsg, syncInfo},
	}
	for _, send := range sends {
		sentErr := make(chan error, 1)
		go func() {
			// Only a failed send is news here: the serving loop tears the pipe
			// down when it rejects a packet. A nil error says nothing about
			// delivery, and reporting it would race the received channel below.
			if err := p2p.Send(peer.app, send.code, send.data); err != nil {
				sentErr <- err
			}
		}()

		select {
		case err := <-sentErr:
			t.Fatalf("packet %q was rejected instead of being handed to the backend: %v", send.name, err)
		case got := <-received:
			if got.name != send.name {
				t.Errorf("packet name mismatch: have %q, want %q", got.name, send.name)
			}
			if got.size == 0 {
				t.Errorf("packet %q: reported wire size is zero", got.name)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("packet %q was not handed to the backend within 2 seconds", send.name)
		}
	}
}

// Tests that inbound transaction traffic is ignored while the node is not
// synchronised, and only then handed to the backend.
func TestTransactionGate(t *testing.T) {
	backend := newTestBackend(t, 1, nil)

	received := make(chan Packet, 1)
	backend.handler = func(peer *Peer, packet Packet, size uint32) error {
		received <- packet
		return nil
	}
	peer := newTestPeer(t, "peer", XDC165, backend)

	tx := newTestTransaction(testBankKey, 0, 0)

	// Not synchronised: the transaction must be dropped silently.
	go p2p.Send(peer.app, TransactionMsg, []*types.Transaction{tx})
	select {
	case packet := <-received:
		t.Fatalf("transaction handed to the backend while not synchronised: %v", packet)
	case <-time.After(100 * time.Millisecond):
	}

	// Synchronised: the same transaction must now reach the backend.
	backend.accepted.Store(true)
	go p2p.Send(peer.app, TransactionMsg, []*types.Transaction{tx})
	select {
	case packet := <-received:
		txs, ok := packet.(*TransactionsPacket)
		if !ok {
			t.Fatalf("packet type mismatch: have %T, want *TransactionsPacket", packet)
		}
		if len(*txs) != 1 || (*txs)[0].Hash() != tx.Hash() {
			t.Fatalf("transaction mismatch: have %v, want %v", (*txs)[0].Hash(), tx.Hash())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("transaction was not handed to the backend within 2 seconds")
	}
}

// Tests that transactions are served from the pool on request.
func TestGetPooledTransactions(t *testing.T) { testGetPooledTransactions(t, XDC165) }

// TestGetPooledTransactions166 doubles as the guard for the version bound on
// the pooled transaction cases (plan M5): the wire cases are guarded by
// `peer.version >= XDC165`, so xdc/166 passes the gate automatically, and a
// future edit that moves the bound fails this test instead of silently
// dropping xdc/166 from the pooled transaction service.
func TestGetPooledTransactions166(t *testing.T) { testGetPooledTransactions(t, XDC166) }

func testGetPooledTransactions(t *testing.T, protocol uint) {
	backend := newTestBackend(t, 1, nil)
	tx := newTestTransaction(testBankKey, 0, 0)
	backend.txpool.Add([]*types.Transaction{tx}, false)

	recorder := newBackendPacketRecorder(backend, protocol)
	if protocol >= XDC166 {
		// The pooled transactions response case is gated on the node accepting
		// transactions; the test backend starts out refusing them.
		backend.accepted.Store(true)
	}
	peer := newTestPeer(t, "peer", protocol, backend)

	if protocol <= XDC165 {
		p2p.Send(peer.app, GetPooledTransactionsMsg, []common.Hash{tx.Hash(), {0x02}})
		msg, err := peer.app.ReadMsg()
		if err != nil {
			t.Fatalf("failed to read transactions response: %v", err)
		}
		if msg.Code != PooledTransactionsMsg {
			t.Fatalf("response packet code mismatch: have %x, want %x", msg.Code, PooledTransactionsMsg)
		}
		var sent []*types.Transaction
		if err := msg.Decode(&sent); err != nil {
			t.Fatalf("failed to decode transactions response: %v", err)
		}
		if len(sent) != 1 || sent[0].Hash() != tx.Hash() {
			t.Fatalf("transaction response mismatch: have %v, want %v", sent, []*types.Transaction{tx})
		}
	} else {
		p2p.Send(peer.app, GetPooledTransactionsMsg, GetPooledTransactionsPacket66{
			RequestId:                   123,
			GetPooledTransactionsPacket: []common.Hash{tx.Hash(), {0x02}},
		})
		msg, err := peer.app.ReadMsg()
		if err != nil {
			t.Fatalf("failed to read transactions response: %v", err)
		}
		if msg.Code != PooledTransactionsMsg {
			t.Fatalf("response packet code mismatch: have %x, want %x", msg.Code, PooledTransactionsMsg)
		}
		// The server answers from the already RLP-encoded transactions, so the
		// reply is a PooledTransactionsRLPPacket66; decoding it into the
		// decoded wrapper recovers the same transactions.
		var res PooledTransactionsPacket66
		if err := msg.Decode(&res); err != nil {
			t.Fatalf("failed to decode transactions response: %v", err)
		}
		if res.RequestId != 123 {
			t.Fatalf("request id mismatch: have %d, want 123", res.RequestId)
		}
		if len(res.PooledTransactionsPacket) != 1 || res.PooledTransactionsPacket[0].Hash() != tx.Hash() {
			t.Fatalf("transaction response mismatch: have %v, want %v", res.PooledTransactionsPacket, PooledTransactionsPacket{tx})
		}
	}
	// Over xdc/166, deliver a 66-encoded pooled transactions response and
	// assert the backend observed the unwrapped legacy packet, not the *66
	// wrapper.
	if protocol >= XDC166 {
		p2p.Send(peer.app, PooledTransactionsMsg, PooledTransactionsPacket66{
			RequestId:                789,
			PooledTransactionsPacket: PooledTransactionsPacket{tx},
		})
		waitBackendPacket[*PooledTransactionsPacket](t, recorder, "pooled transactions response never reached the backend")
	}
}

// Tests that the lookups a pooled transaction request may cost are bounded to
// twice the number of transactions served, the same way as for block bodies.
// The pool deliberately holds far fewer transactions than the serve cap: the
// lookup budget is what keeps the known tail out of the reply, and it does not
// care how full the pool is. The transactions at the last budgeted index
// (2*maxPooledTransactionsServe-1) and at the first index past it are both in the
// pool, so only the budget decides which of the two comes back.
// TestPooledTxsMinVersionPinsGate pins the pooled-tx gate bound: the pair was
// introduced with xdc/165 and must stay reachable by xdc/166 peers unchanged.
// TestGetPooledTransactions and TestGetPooledTransactions166 cover both sides
// behaviourally over the wire.
func TestPooledTxsMinVersionPinsGate(t *testing.T) {
	if pooledTxsMinVersion != XDC165 {
		t.Fatalf("pooled-tx gate bound moved off xdc/165: %d", pooledTxsMinVersion)
	}
	if pooledTxsMinVersion > XDC166 {
		t.Fatalf("pooled-tx gate excludes xdc/166: min version %d", pooledTxsMinVersion)
	}
}

func TestGetPooledTransactionsLookupBudget(t *testing.T) {
	backend := newTestBackend(t, 1, nil)
	peer := newTestPeer(t, "peer", XDC165, backend)

	prefix := 64
	known := make([]common.Hash, 0, 2*prefix)
	for i := range 2 * prefix {
		tx := newTestTransaction(testBankKey, uint64(i), 0)
		backend.txpool.Add([]*types.Transaction{tx}, false)
		known = append(known, tx.Hash())
	}
	hashes := make([]common.Hash, 0, 2*maxPooledTransactionsServe+2)
	hashes = append(hashes, known[:prefix]...)
	for i := range 2*maxPooledTransactionsServe - prefix - 1 {
		hashes = append(hashes, unknownHash(i))
	}
	hashes = append(hashes, known[prefix])   // last budgeted index, must be served
	hashes = append(hashes, known[prefix+1]) // first index past the budget

	// Send the hash request and verify that the budget stops before the second boundary hash
	if err := p2p.Send(peer.app, GetPooledTransactionsMsg, hashes); err != nil {
		t.Fatalf("failed to send pooled transactions request: %v", err)
	}
	msg, err := peer.app.ReadMsg()
	if err != nil {
		t.Fatalf("failed to read pooled transactions response: %v", err)
	}
	if msg.Code != PooledTransactionsMsg {
		t.Fatalf("response packet code mismatch: have %x, want %x", msg.Code, PooledTransactionsMsg)
	}
	var sent []*types.Transaction
	if err := msg.Decode(&sent); err != nil {
		t.Fatalf("failed to decode pooled transactions response: %v", err)
	}
	if len(sent) != prefix+1 {
		t.Fatalf("served %d transactions out of %d requested hashes, want %d", len(sent), len(hashes), prefix+1)
	}
	for i, want := range known[:prefix+1] {
		if sent[i].Hash() != want {
			t.Errorf("transaction %d mismatch: have %s, want %s", i, sent[i].Hash(), want)
		}
	}
}

// Tests that a request made entirely of unknown hashes gets an empty reply
// from every data-serving loop of the wire protocol.
func TestAllUnknownHashRequestsGetEmptyReplies(t *testing.T) {
	backend := newTestBackend(t, 4, nil)
	peer := newTestPeer(t, "peer", XDC165, backend)

	tests := []struct {
		request, reply uint64
	}{
		{GetBlockBodiesMsg, BlockBodiesMsg},
		{GetNodeDataMsg, NodeDataMsg},
		{GetReceiptsMsg, ReceiptsMsg},
		{GetPooledTransactionsMsg, PooledTransactionsMsg},
	}
	hashes := make([]common.Hash, 3*maxReceiptsServe/2)
	for i := range hashes {
		hashes[i] = unknownHash(i)
	}
	for _, tt := range tests {
		if err := p2p.Send(peer.app, tt.request, hashes); err != nil {
			t.Fatalf("failed to send request %v: %v", tt.request, err)
		}
		msg, err := peer.app.ReadMsg()
		if err != nil {
			t.Fatalf("failed to read response to %v: %v", tt.request, err)
		}
		if msg.Code != tt.reply {
			t.Fatalf("response packet code mismatch: have %x, want %x", msg.Code, tt.reply)
		}
		var served []rlp.RawValue
		if err := msg.Decode(&served); err != nil {
			t.Fatalf("failed to decode response to %v: %v", tt.request, err)
		}
		if len(served) != 0 {
			t.Fatalf("request %v of %d unknown hashes served %d items", tt.request, len(hashes), len(served))
		}
	}
}
