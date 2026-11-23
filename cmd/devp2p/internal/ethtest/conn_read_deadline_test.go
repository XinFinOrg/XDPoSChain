package ethtest

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/crypto"
	ethproto "github.com/XinFinOrg/XDPoSChain/eth/protocols/eth"
	"github.com/XinFinOrg/XDPoSChain/p2p/rlpx"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

// gateWrites leaves room for the two writes of a single RLPx frame after the
// handshake, so a peer that sends one message can finish before the gate closes
const gateWrites = 16

// gatedConn lets the first allow writes through and blocks the rest until
// released, so a test can stall a peer between a frame header and its body
type gatedConn struct {
	net.Conn
	mu    sync.Mutex
	allow int
	gate  chan struct{}
	once  sync.Once
}

func (g *gatedConn) Write(b []byte) (int, error) {
	g.mu.Lock()
	allowed := g.allow > 0
	if allowed {
		g.allow--
	}
	g.mu.Unlock()
	if !allowed {
		<-g.gate
	}
	return g.Conn.Write(b)
}

func (g *gatedConn) setAllow(n int) {
	g.mu.Lock()
	g.allow = n
	g.mu.Unlock()
}

func (g *gatedConn) release() {
	g.once.Do(func() { close(g.gate) })
}

// newGatedFramePeer returns a client conn and an rlpx peer sharing a pipe; the
// peer side only lets allowWrites writes through until release is called
func newGatedFramePeer(t *testing.T, allowWrites int) (*Conn, *rlpx.Conn, *gatedConn) {
	t.Helper()
	clientPipe, peerPipe := net.Pipe()
	gated := &gatedConn{Conn: peerPipe, allow: gateWrites, gate: make(chan struct{})}
	clientKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	peerKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate peer key: %v", err)
	}
	client := rlpx.NewConn(clientPipe, &peerKey.PublicKey)
	peer := rlpx.NewConn(gated, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := peer.Handshake(peerKey); err != nil {
			t.Errorf("peer handshake failed: %v", err)
		}
	}()
	if _, err := client.Handshake(clientKey); err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	<-done
	t.Cleanup(func() {
		client.Close()
		peer.Close()
	})
	gated.setAllow(allowWrites)
	return &Conn{Conn: client}, peer, gated
}

// assertTimeoutAt checks that err is the timeout of a wait bounded by budget,
// and that elapsed lies between the budget and connTimeout
func assertTimeoutAt(t *testing.T, what string, err error, elapsed, budget time.Duration) {
	t.Helper()
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("%s returned %v, want a timeout", what, err)
	}
	if elapsed < budget-50*time.Millisecond {
		t.Fatalf("%s returned after %v, before the %v deadline", what, elapsed, budget)
	}
	if elapsed >= connTimeout-time.Second {
		t.Fatalf("%s waited %v, want it bounded by the %v deadline", what, elapsed, budget)
	}
}

// The pooled query reads a response frame that can be far larger than a socket
// buffer. An RLPx frame read is not resumable, so a read cut at connTimeout
// would leave the stream mid-frame; the deadline-carrying read must wait out
// the whole remaining budget instead
func TestPooledReadSurvivesMidFrameStall(t *testing.T) {
	conn, peer, gated := newGatedFramePeer(t, 1) // only the frame header leaves
	defer gated.release()
	payload := bytes.Repeat([]byte{0x42}, 64*1024)
	rawTxMsg := protoOffset(ethProto) + ethproto.TransactionMsg
	writeErr := make(chan error, 1)
	go func() {
		_, err := peer.Write(rawTxMsg, payload)
		writeErr <- err
	}()
	// The body lands well after connTimeout
	go func() {
		time.Sleep(connTimeout + 300*time.Millisecond)
		gated.release()
	}()
	code, data, err := conn.readUntil(time.Now().Add(5 * time.Second))
	if err != nil {
		t.Fatalf("read cut at connTimeout instead of the deadline: %v", err)
	}
	if code != rawTxMsg {
		t.Fatalf("got message code %d, want %d", code, rawTxMsg)
	}
	if !bytes.Equal(data, payload) {
		t.Fatalf("got %d payload bytes, want %d", len(data), len(payload))
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("peer write failed: %v", err)
	}
}

// A deadline-carrying read is bounded by the deadline, not by connTimeout
func TestReadUntilHonoursDeadline(t *testing.T) {
	conn, _, _ := newGatedFramePeer(t, 0) // the peer never writes
	budget := 300 * time.Millisecond
	start := time.Now()
	_, _, err := conn.readUntil(time.Now().Add(budget))
	elapsed := time.Since(start)
	assertTimeoutAt(t, "read", err, elapsed, budget)
}

// Serving a header request inside readMsgXdc166Until must not reset the wait to
// connTimeout: then the next read would outlive the deadline
func TestReadMsgXdc166UntilHonoursDeadline(t *testing.T) {
	conn, peer, _ := newGatedFramePeer(t, gateWrites)
	req, err := rlp.EncodeToBytes(&getBlockHeadersPacket166{
		RequestId: 7,
		Request:   &getBlockHeadersData{Origin: hashOrNumber{Number: 1}, Amount: 1},
	})
	if err != nil {
		t.Fatalf("failed to encode header request: %v", err)
	}
	peerErr := make(chan error, 1)
	go func() {
		peer.SetWriteDeadline(time.Now().Add(connTimeout))
		if _, err := peer.Write(protoOffset(ethProto)+ethproto.GetBlockHeadersMsg, req); err != nil {
			peerErr <- fmt.Errorf("failed to write header request: %w", err)
			return
		}
		// Drain the served headers so the reply write does not block, then go quiet
		peer.SetReadDeadline(time.Now().Add(connTimeout))
		if _, _, _, err := peer.Read(); err != nil {
			peerErr <- fmt.Errorf("failed to read served headers: %w", err)
			return
		}
		peerErr <- nil
	}()
	budget := 300 * time.Millisecond
	start := time.Now()
	_, _, err = (&Suite{chain: new(Chain)}).readMsgXdc166Until(conn, time.Now().Add(budget))
	elapsed := time.Since(start)
	select {
	case perr := <-peerErr:
		if perr != nil {
			t.Fatalf("peer side failed: %v", perr)
		}
	case <-time.After(connTimeout):
		t.Fatalf("peer goroutine did not finish")
	}
	assertTimeoutAt(t, "wait", err, elapsed, budget)
}

// A pong reply written while serving a deadline-bounded read must be cut at
// the same deadline; Conn.Write would reset the wait to connTimeout
func TestReadXdc166UntilBoundsPongWrite(t *testing.T) {
	conn, peer, _ := newGatedFramePeer(t, gateWrites) // the peer stops reading after the ping
	peerErr := make(chan error, 1)
	go func() {
		peer.SetWriteDeadline(time.Now().Add(connTimeout))
		if _, err := peer.Write(protoOffset(baseProto)+pingMsg, []byte{}); err != nil {
			peerErr <- fmt.Errorf("failed to write ping: %w", err)
			return
		}
		peerErr <- nil
	}()
	budget := 300 * time.Millisecond
	start := time.Now()
	_, _, err := conn.readXdc166Until(time.Now().Add(budget))
	elapsed := time.Since(start)
	if perr := <-peerErr; perr != nil {
		t.Fatalf("peer side failed: %v", perr)
	}
	assertTimeoutAt(t, "pong write", err, elapsed, budget)
}

// A BlockHeaders reply written while serving a deadline-bounded read must be
// cut at the same deadline; Conn.Write would reset the wait to connTimeout
func TestReadMsgXdc166UntilBoundsHeaderWrite(t *testing.T) {
	conn, peer, _ := newGatedFramePeer(t, gateWrites)
	req, err := rlp.EncodeToBytes(&getBlockHeadersPacket166{
		RequestId: 7,
		Request:   &getBlockHeadersData{Origin: hashOrNumber{Number: 1}, Amount: 1},
	})
	if err != nil {
		t.Fatalf("failed to encode header request: %v", err)
	}
	peerErr := make(chan error, 1)
	go func() {
		peer.SetWriteDeadline(time.Now().Add(connTimeout))
		if _, err := peer.Write(protoOffset(ethProto)+ethproto.GetBlockHeadersMsg, req); err != nil {
			peerErr <- fmt.Errorf("failed to write header request: %w", err)
			return
		}
		peerErr <- nil
	}()
	budget := 300 * time.Millisecond
	start := time.Now()
	_, _, err = (&Suite{chain: new(Chain)}).readMsgXdc166Until(conn, time.Now().Add(budget))
	elapsed := time.Since(start)
	if perr := <-peerErr; perr != nil {
		t.Fatalf("peer side failed: %v", perr)
	}
	assertTimeoutAt(t, "header write", err, elapsed, budget)
}
