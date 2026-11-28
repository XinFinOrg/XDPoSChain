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

package eth

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/XinFinOrg/XDPoSChain/p2p"
)

var (
	// errDisconnected is returned if a request is attempted to be made to a peer
	// that was already closed.
	errDisconnected = errors.New("disconnected")

	// errDanglingResponse is returned if a response arrives with a request id
	// which does not match to any existing pending requests.
	errDanglingResponse = errors.New("response to non-existent request")

	// errMismatchingResponseType is returned if the remote peer sent a different
	// packet type as a response to a request than what the local node expected.
	errMismatchingResponseType = errors.New("mismatching response type")

	// errDuplicateRequest is returned if a request id is dispatched while another
	// request with the same id is still in flight towards the same peer.
	errDuplicateRequest = errors.New("duplicate request id")
)

// Request is a pending request to allow tracking it and delivering a response
// back to the requester on their chosen channel.
//
// The id is the wire-level request id: the caller embeds it in the versioned
// request packet and the receive path reads it back out of the response packet,
// so the dispatcher and the protocol share one id space and the dispatcher
// never allocates ids itself. Ids must not repeat within a connection: use a
// non-repeating allocator, for example a per-connection counter with exhaustion
// handling (independent random draws do not guarantee uniqueness). A late reply
// carries only the id and the packet type, so a repeated id would be
// indistinguishable from the new request's reply. A reconnect starts a fresh
// id scope.
//
// Cancellation keeps the wire id reserved until the cancelled request's reply
// arrives or its tracker entry expires: the dispatcher drops the pending entry
// immediately and rejects late replies, while the tracker rejects any attempt
// to reuse the id while the reservation lasts. Expiry only releases that
// reservation; it does not make the id safe to repeat on the same connection,
// and it does not retire the dispatcher's pending entry either. The caller
// owns the request timeout: when it stops waiting it must call Close, which
// removes the pending entry and is the request's terminal outcome.
//
// The sink must be owned by this request alone: the dispatcher decides whether
// the consumer took a response by draining the sink when the request is closed,
// so a channel shared with another request would let it steal that request's
// response.
//
// Once the response has been handed over on the sink, the consumer owns it: it
// must deliver the handler verdict on Response.Done. Close cannot replace that
// verdict, it only releases a response the consumer never took. Closing the
// sink after taking the response counts as taking it, so the verdict is still
// owed on Done.
type Request struct {
	peer *Peer  // Peer to which this request belongs for untracking
	id   uint64 // Wire-level request id, assigned by the caller and echoed back by the peer

	sink      chan *Response // Channel to deliver the response on, owned by this request alone
	cancel    chan struct{}  // Channel to cancel requests ahead of time
	closeOnce sync.Once      // Ensures the cancellation runs exactly once
	closeErr  error          // Verdict of the single cancellation attempt

	code uint64      // Message code of the request packet
	want uint64      // Message code of the response packet
	data interface{} // Data content of the request packet

	Peer string    // Demultiplexer if cross-peer requests are batched together
	Sent time.Time // Timestamp when the request was sent
}

// Close aborts an in-flight request. Although there's no way to notify the
// remote peer about the cancellation, this method notifies the dispatcher to
// discard any late responses. Repeated calls skip the cancellation and return
// the verdict of the first one.
func (r *Request) Close() error {
	if r.peer == nil { // Tests mock out the dispatcher, skip internal cancellation
		return nil
	}
	r.closeOnce.Do(func() {
		cancelOp := &cancel{
			req:  r,
			fail: make(chan error, 1),
		}
		select {
		case r.peer.reqCancel <- cancelOp:
			// Wait for the dispatcher to drop the request, but don't outlive the
			// peer if it is torn down in the meantime.
			select {
			case r.closeErr = <-cancelOp.fail:
			case <-r.peer.term:
				r.closeErr = errDisconnected
			}
		case <-r.peer.term:
			r.closeErr = errDisconnected
		}
		if r.closeErr == nil {
			close(r.cancel)
		}
	})
	return r.closeErr
}

// Terminated returns a channel that is closed once the peer connection tears
// down. A consumer blocked on the response sink must also select on this
// channel: the dispatcher returns on peer teardown without flushing pending
// requests, so otherwise the consumer would wait forever. No response was
// taken on that path, hence no Response.Done verdict is owed. Requests mocked
// in tests have no peer and return a nil channel, which disables the case.
func (r *Request) Terminated() <-chan struct{} {
	if r.peer == nil {
		return nil
	}
	return r.peer.term
}

// request is a wrapper around a client Request that has an error channel to
// signal on if sending the request already failed on a network level.
type request struct {
	req  *Request
	fail chan error
}

// cancel is a maintenance type on the dispatcher to stop tracking a pending
// request.
type cancel struct {
	req  *Request // Request to stop tracking
	fail chan error
}

// Response is a reply packet to a previously created request. It is delivered
// on the channel assigned by the requester subsystem and contains the original
// request embedded to allow uniquely matching it caller side.
type Response struct {
	id   uint64    // Wire-level request id, read back out of the response packet
	recv time.Time // Timestamp when the request was received
	code uint64    // Response packet type to cross validate with request

	Req  *Request      // Original request to cross-reference with
	Res  interface{}   // Remote response for the request query
	Time time.Duration // Time it took for the request to be served
	Done chan error    // Mandatory verdict channel once the consumer takes the response

	accepted chan struct{} // Test hook, closed once dispatchResponse has seen the dispatcher accept
}

// response is a wrapper around a remote Response that has an error channel to
// signal on if processing the response failed.
type response struct {
	res  *Response
	fail chan error
}

// dispatchRequest schedules the request to the dispatcher for tracking and
// network serialization, blocking until it's successfully sent.
//
// The returned Request must either be closed before discarding it, or the reply
// must be waited for and the Response's Done channel signalled.
func (p *Peer) dispatchRequest(req *Request) error {
	reqOp := &request{
		req:  req,
		fail: make(chan error, 1),
	}
	req.cancel = make(chan struct{})
	req.peer = p
	req.Peer = p.id

	select {
	case p.reqDispatch <- reqOp:
		// Wait for the dispatcher's verdict, but don't outlive the peer if it is
		// torn down while the request is still being written to the wire.
		select {
		case err := <-reqOp.fail:
			return err
		case <-p.term:
			return errDisconnected
		}
	case <-p.term:
		return errDisconnected
	}
}

// dispatchResponse fulfils a pending request and delivers it to the requested
// sink.
func (p *Peer) dispatchResponse(res *Response) error {
	resOp := &response{
		res:  res,
		fail: make(chan error, 1),
	}
	res.recv = time.Now()
	res.Done = make(chan error, 1)

	select {
	case p.resDispatch <- resOp:
		// Ensure the response is accepted by the dispatcher. A rejection means
		// the packet was dropped (unknown request id or wrong packet type), which
		// must not tear down the peer: a late reply to a request cancelled
		// locally looks exactly like an unknown id, and both are normal network
		// events. Bailing out on them would let a slow reply disconnect a peer
		// that did nothing wrong.
		select {
		case err := <-resOp.fail:
			if err != nil {
				return nil
			}
		case <-p.term:
			return errDisconnected
		}
		// Signal the test hook once the dispatcher's acceptance is observed and
		// the delivery select below is next.
		if res.accepted != nil {
			close(res.accepted)
		}
		// Deliver the filled out response and wait until it's handled. This
		// path is a bit funky as Go's select has no order, so if a response
		// arrives to an already cancelled request, there's a 50-50% chance
		// of picking one channel or the other. To avoid such cases delivering
		// the packet upstream, check for cancellation first and only after
		// block on delivery.
		select {
		case <-res.Req.cancel:
			return nil // Request cancelled, silently discard response
		default:
			// Request not yet cancelled, attempt to deliver it, but do watch
			// for fresh cancellations too
			select {
			case res.Req.sink <- res:
				// Response delivered, wait for the consumer to acknowledge it,
				// but release the reader if the requester abandons the response
				// or the peer is torn down first.
				select {
				case err := <-res.Done:
					return err
				case <-res.Req.cancel:
					// A non-blocking receive arbitrates ownership atomically: a
					// drained response means the consumer never took it, so drop
					// it and release the reader. An empty or closed sink means
					// the consumer already took the response and owns the
					// verdict, so wait for it instead of returning nil.
					select {
					case _, ok := <-res.Req.sink:
						if ok {
							return nil
						}
					default:
					}
					select {
					case err := <-res.Done:
						return err
					case <-p.term:
						return errDisconnected
					}
				case <-p.term:
					return errDisconnected
				}
			case <-res.Req.cancel:
				return nil // Request cancelled, silently discard response
			case <-p.term:
				return errDisconnected
			}
		}

	case <-p.term:
		return errDisconnected
	}
}

// dispatcher is a loop that accepts requests from higher layer packages, pushes
// it to the network and tracks and dispatches the responses back to the original
// requester.
func (p *Peer) dispatcher() {
	pending := make(map[uint64]*Request)

	for {
		select {
		case reqOp := <-p.reqDispatch:
			req := reqOp.req

			// A request id may only be in flight once: reusing it would overwrite
			// the pending entry and strand the first requester forever.
			if _, ok := pending[req.id]; ok {
				reqOp.fail <- fmt.Errorf("%w: %d", errDuplicateRequest, req.id)
				continue
			}
			req.Sent = time.Now()

			// The tracker also rejects ids that were cancelled locally and whose
			// reply has not arrived yet, so a late reply is rejected while that
			// reservation lasts. Ids never repeat within a connection (see
			// Request), so a late reply cannot land on a newer request.
			if err := requestTracker.Track(p.id, p.conn, p.version, req.code, req.want, req.id); err != nil {
				reqOp.fail <- fmt.Errorf("%w: %d", err, req.id)
				continue
			}
			if err := p2p.Send(p.rw, req.code, req.data); err != nil {
				// The request never hit the wire, so no reply can arrive for
				// it: release the id instead of letting it expire as lost.
				requestTracker.Drop(p.id, p.conn, req.id)
				reqOp.fail <- err
				continue
			}
			pending[req.id] = req
			reqOp.fail <- nil

		case cancelOp := <-p.reqCancel:
			// Only drop the entry if it still belongs to the request that asked
			// for the cancellation: the caller may have closed a request that
			// was already serviced, and a newer one may own the id by now.
			req := pending[cancelOp.req.id]
			if req != cancelOp.req {
				cancelOp.fail <- nil
				continue
			}
			// Drop the pending entry so a late reply is rejected, but keep the
			// tracker entry reserved: if the id were free now, a new request
			// could take it over and receive the old request's late reply.
			// Marking the entry cancelled also keeps its expiry out of the lost
			// meter, since the local side gave up and the peer did not time out.
			delete(pending, cancelOp.req.id)
			requestTracker.Cancel(p.id, p.conn, req.id)
			cancelOp.fail <- nil

		case resOp := <-p.resDispatch:
			res := resOp.res
			res.Req = pending[res.id]

			// Independent if the request exists or not, track this packet
			requestTracker.Fulfil(p.id, p.conn, p.version, res.code, res.id, res.recv)

			switch {
			case res.Req == nil:
				// Response arrived with an untracked ID: either the remote peer
				// implements the protocol badly, or it is a late reply to a
				// request cancelled locally (the tracker matched the reservation
				// above, released the id and counted the reply as stale).
				resOp.fail <- errDanglingResponse

			case res.Req.want != res.code:
				// Response arrived, but it's a different packet type than the
				// one expected by the requester. Either the local code is bad,
				// or the remote peer send junk. In neither cases can we handle
				// the packet.
				resOp.fail <- fmt.Errorf("%w: have %d, want %d", errMismatchingResponseType, res.code, res.Req.want)

			default:
				// All dispatcher checks passed and the response was initialized
				// with the matching request. Signal to the delivery routine that
				// it can wait for a handler response and dispatch the data.
				res.Time = res.recv.Sub(res.Req.Sent)
				resOp.fail <- nil

				// Stop tracking the request, the response dispatcher will deliver
				delete(pending, res.id)
			}

		case <-p.term:
			// The connection is gone, so no reply can arrive anymore: release
			// every outstanding id of this connection, including cancelled
			// requests still reserved in the tracker, instead of letting the
			// shared tracker hold them until they expire. The cleanup is scoped
			// to this connection so a reconnect that already reuses the peer id
			// keeps its own reservations.
			requestTracker.DropConnection(p.id, p.conn)
			return
		}
	}
}
