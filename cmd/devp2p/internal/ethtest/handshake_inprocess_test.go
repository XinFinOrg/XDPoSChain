package ethtest

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/crypto"
	ethproto "github.com/XinFinOrg/XDPoSChain/eth/protocols/eth"
	"github.com/XinFinOrg/XDPoSChain/internal/utesting"
	"github.com/XinFinOrg/XDPoSChain/p2p"
	"github.com/XinFinOrg/XDPoSChain/p2p/rlpx"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

// handshakeDisconnectCases must disconnect. The node still sends its own Hello
// first because the devp2p handshake is concurrent, so the helpers drain frames
// instead of judging the first message (measured in issue #2967).
var handshakeDisconnectCases = []string{
	"MalformedHello",
	"MalformedHelloShortID",
	"MalformedHelloEmptyID",
	"MalformedHelloLongID",
	"MalformedHelloZeroID",
	"MalformedHelloMismatchedID",
	"HelloWithoutEthCap",
	"HelloWithZeroVersionAndEmptyCaps",
	"HelloWithEmptyCaps",
	"HelloWithEmptyCapName",
	"HelloWithLongCapName",
	"HelloWithNULCapName",
	"HelloWithMismatchedIDAndEmptyCaps",
	"HelloWithUnsortedNonEthCaps",
	"OversizedHelloPayload",
	"EmptyHelloPayload",
	"TruncatedHelloPayload",
	"InvalidHelloRLP",
	"HelloPayloadWrongRLPType",
	"HelloPayloadEmptyList",
	"HelloPayloadShortList",
	"HelloPayloadVersionWrongType",
	"WrongFirstMessageCode",
	"FirstMessageDisconnect",
	"FirstMessageDisconnectInvalidPayload",
	"FirstMessageDisconnectEmptyPayload",
}

// handshakeStayConnectedCases are accepted: the Hello version is not validated
// and capabilities are not deduplicated, matching upstream go-ethereum (issue
// #2967). Move a case to handshakeDisconnectCases if either behavior changes.
var handshakeStayConnectedCases = []string{
	"HelloWithZeroVersion",
	"HelloWithMaxVersion",
	"HelloWithDuplicateEthCaps",
}

// handshakeCasePrefixes identify the handshake cases in EthTests. Every match
// must appear in one of the tables above; cases named outside these prefixes
// are not detected by the guard.
var handshakeCasePrefixes = []string{
	"MalformedHello",
	"HelloWith", // covers HelloWithoutEthCap as well
	"HelloPayload",
	"OversizedHello",
	"EmptyHello",
	"TruncatedHello",
	"InvalidHello",
	"WrongFirstMessage",
	"FirstMessageDisconnect",
}

func isHandshakeCase(name string) bool {
	for _, prefix := range handshakeCasePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// startInProcessHandshakeServer starts a loopback p2p.Server advertising the
// same "eth"@100 capability as the fixture node and returns a Suite for it.
func startInProcessHandshakeServer(t *testing.T) *Suite {
	t.Helper()
	return startInProcessHandshakeServerWithRun(t, func(p *p2p.Peer, rw p2p.MsgReadWriter) error {
		for {
			msg, err := rw.ReadMsg()
			if err != nil {
				return err
			}
			msg.Discard()
		}
	})
}

// startInProcessHandshakeServerWithRun is startInProcessHandshakeServer with a
// caller-supplied protocol handler.
func startInProcessHandshakeServerWithRun(t *testing.T, run func(*p2p.Peer, p2p.MsgReadWriter) error) *Suite {
	t.Helper()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}
	srv := &p2p.Server{
		Config: p2p.Config{
			PrivateKey:      key,
			Name:            "ethtest-inprocess",
			ListenAddr:      "127.0.0.1:0",
			NoDial:          true,
			NoDiscovery:     true,
			MaxPeers:        50,
			MaxPendingPeers: 16,
			Protocols: []p2p.Protocol{{
				Name:    "eth",
				Version: ethProtoVersionXDpos2,
				Length:  ethproto.ProtocolLengths[ethProtoVersionXDpos2],
				Run:     run,
			}},
		},
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start in-process server: %v", err)
	}
	t.Cleanup(srv.Stop)

	// Self reports the bound endpoint, so no port needs to be reserved.
	s, err := NewSuite(srv.Self(), "testdata", "", "")
	if err != nil {
		t.Fatalf("failed to create suite: %v", err)
	}
	return s
}

// TestHandshakeConformanceInProcess replays every handshake case from EthTests
// against an in-process server: 26 must disconnect and 3 must stay connected.
func TestHandshakeConformanceInProcess(t *testing.T) {
	s := startInProcessHandshakeServer(t)

	all := append(append([]string{}, handshakeDisconnectCases...), handshakeStayConnectedCases...)
	registered := make(map[string]bool, len(all))
	for _, name := range all {
		if registered[name] {
			t.Fatalf("duplicate handshake case %s", name)
		}
		registered[name] = true
	}
	registry := make(map[string]utesting.Test)
	for _, tc := range s.EthTests() {
		if _, ok := registry[tc.Name]; ok {
			t.Fatalf("duplicate EthTests entry %s", tc.Name)
		}
		registry[tc.Name] = tc
		if isHandshakeCase(tc.Name) && !registered[tc.Name] {
			t.Fatalf("EthTests contains handshake case %s that is not listed in handshakeDisconnectCases or handshakeStayConnectedCases", tc.Name)
		}
	}
	cases := make([]utesting.Test, 0, len(all))
	for _, name := range all {
		tc, ok := registry[name]
		if !ok {
			t.Fatalf("EthTests does not include %s", name)
		}
		cases = append(cases, tc)
	}

	results := utesting.RunTests(cases, io.Discard)
	for _, r := range results {
		if r.Failed {
			t.Errorf("handshake case %s failed:\n%s", r.Name, r.Output)
		}
	}
}

// TestStayConnectedWindowCatchesLateClose guards the idle-window policy: frames
// stream past one idle window, then the peer closes, which must fail the helper.
func TestStayConnectedWindowCatchesLateClose(t *testing.T) {
	s := startInProcessHandshakeServerWithRun(t, func(p *p2p.Peer, rw p2p.MsgReadWriter) error {
		for i := 0; i < 5; i++ {
			time.Sleep(200 * time.Millisecond)
			if err := p2p.Send(rw, 0x00, []byte{}); err != nil {
				return err
			}
		}
		time.Sleep(300 * time.Millisecond)
		return errors.New("test peer closes after the last frame")
	})

	results := utesting.RunTests([]utesting.Test{{
		Name: "lateClose",
		Fn: func(t *utesting.T) {
			key, err := crypto.GenerateKey()
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}
			conn, err := s.dialConn(key)
			if err != nil {
				t.Fatalf("rlpx handshake failed: %v", err)
			}
			defer conn.Close()

			// Version 4 keeps snappy off, so this raw rlpx client can decode the
			// frames the handler streams; the hello is still accepted.
			hello := &protoHandshake{
				Version: 4,
				Caps:    []p2p.Cap{{Name: "eth", Version: ethProtoVersionXDpos2}},
				ID:      crypto.FromECDSAPub(&key.PublicKey)[1:],
			}
			s.expectStayConnectedAfterHello(t, conn, hello)
		},
	}}, io.Discard)

	if !results[0].Failed {
		t.Fatalf("helper accepted a peer that closed after the idle window")
	}
	if results[0].Duration < idleWindow {
		t.Fatalf("helper failed after %v without draining the frames", results[0].Duration)
	}
}

// TestStayConnectedFirstFrameWaitsForHandshakeTimeout guards the first-frame
// budget: a peer that never sends a Hello must get the full handshake timeout.
func TestStayConnectedFirstFrameWaitsForHandshakeTimeout(t *testing.T) {
	// The scripted peer drains the client's hello and never replies here.
	client, _, _, _, clientID := newScriptedPeer(t)

	hello := &protoHandshake{
		Version: 4,
		Caps:    []p2p.Cap{{Name: "eth", Version: ethProtoVersionXDpos2}},
		ID:      clientID,
	}
	suite := new(Suite)
	results := utesting.RunTests([]utesting.Test{{
		Name: "noFirstFrame",
		Fn:   func(t *utesting.T) { suite.expectStayConnectedAfterHello(t, client, hello) },
	}}, io.Discard)

	if !results[0].Failed {
		t.Fatalf("helper accepted a peer that never sent a frame")
	}
	if results[0].Duration < handshakeTimeout-time.Second {
		t.Fatalf("helper failed after %v, before the handshake timeout", results[0].Duration)
	}
}

// TestStayConnectedRequiresHelloFirstFrame guards first-frame validation: a
// peer that sends a non-Hello frame and stays silent must not be accepted.
func TestStayConnectedRequiresHelloFirstFrame(t *testing.T) {
	cases := []struct {
		name string
		send func(*rlpx.Conn)
		want string
	}{
		{
			name: "ping first",
			send: func(peer *rlpx.Conn) { _, _ = peer.Write(pingMsg, []byte{}) },
			want: "expected the peer hello as first frame, got msg code 2",
		},
		{
			name: "undecodable hello",
			send: func(peer *rlpx.Conn) { _, _ = peer.Write(handshakeMsg, []byte{0xff}) },
			want: "expected a decodable peer hello as first frame",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			client, peer, _, _, clientID := newScriptedPeer(t)

			// Send one non-Hello frame and stay silent.
			go func() {
				time.Sleep(100 * time.Millisecond)
				test.send(peer)
			}()

			hello := &protoHandshake{
				Version: 4,
				Caps:    []p2p.Cap{{Name: "eth", Version: ethProtoVersionXDpos2}},
				ID:      clientID,
			}
			suite := new(Suite)
			results := utesting.RunTests([]utesting.Test{{
				Name: "nonHelloFirstFrame",
				Fn:   func(t *utesting.T) { suite.expectStayConnectedAfterHello(t, client, hello) },
			}}, io.Discard)

			if !results[0].Failed {
				t.Fatalf("helper accepted a peer whose first frame was %q", test.name)
			}
			if !strings.Contains(results[0].Output, test.want) {
				t.Fatalf("helper failed for the wrong reason, want %q in output:\n%s", test.want, results[0].Output)
			}
		})
	}
}

// TestStayConnectedSnappyFollowUp guards snappy handling in
// expectStayConnectedAfterMessage: a peer that negotiated compression sends
// snappy-encoded frames, so the helper must enable snappy and reject a frame
// that is not valid snappy.
func TestStayConnectedSnappyFollowUp(t *testing.T) {
	cases := []struct {
		name       string
		peerSnappy bool
		wantFail   bool
	}{
		{"compressed follow-up", true, false},
		{"uncompressed follow-up", false, true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			client, peer, _, peerHello, clientID := newScriptedPeer(t)

			// The hello is always uncompressed; only the follow-up frame
			// follows the peer's snappy setting.
			go func() {
				time.Sleep(100 * time.Millisecond)
				_, _ = peer.Write(handshakeMsg, peerHello)
				peer.SetSnappy(test.peerSnappy)
				_, _ = peer.Write(statusMsgCode, []byte{0xff, 0xff, 0xff})
			}()

			hello := &protoHandshake{
				Version: 5,
				Caps:    []p2p.Cap{{Name: "eth", Version: ethProtoVersionXDpos2}},
				ID:      clientID,
			}
			suite := new(Suite)
			results := utesting.RunTests([]utesting.Test{{
				Name: "snappyFollowUp",
				Fn:   func(t *utesting.T) { suite.expectStayConnectedAfterHello(t, client, hello) },
			}}, io.Discard)

			if results[0].Failed != test.wantFail {
				t.Fatalf("helper failed = %v, want %v:\n%s", results[0].Failed, test.wantFail, results[0].Output)
			}
			if test.wantFail && !strings.Contains(results[0].Output, "snappy") {
				t.Fatalf("helper failed for the wrong reason, want a snappy error:\n%s", results[0].Output)
			}
		})
	}
}

// TestIsPeerTeardown pins the close/reset vs frame-decode error classification.
func TestIsPeerTeardown(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"clean close", io.EOF, true},
		{"partial frame", io.ErrUnexpectedEOF, true},
		{"reset", syscall.ECONNRESET, true},
		{"wrapped reset", fmt.Errorf("read tcp: %w", syscall.ECONNRESET), true},
		{"bad header MAC", errors.New("bad header MAC"), false},
		{"invalid message code", errors.New("invalid message code: rlp: expected input list for uint64"), false},
		{"snappy failure", errors.New("snappy: corrupt input"), false},
	}
	for _, test := range tests {
		if got := isPeerTeardown(test.err); got != test.want {
			t.Errorf("isPeerTeardown(%v) = %v, want %v", test.err, got, test.want)
		}
	}
}

// TestDisconnectAfterMessageFailurePaths guards the failure paths of
// expectDisconnectAfterMessage: a peer that stays open after our message, and a
// peer that sends a frame with a bad header MAC. Both must fail the helper
// instead of being reported as a disconnect.
func TestDisconnectAfterMessageFailurePaths(t *testing.T) {
	cases := []struct {
		name string
		send func(*rlpx.Conn, net.Conn, []byte)
		want string
		min  time.Duration
		max  time.Duration
	}{
		{
			name: "stays open",
			send: func(peer *rlpx.Conn, _ net.Conn, hello []byte) { _, _ = peer.Write(handshakeMsg, hello) },
			want: "connection still open",
			min:  idleWindow,
			max:  handshakeTimeout,
		},
		{
			name: "bad header mac",
			send: func(peer *rlpx.Conn, raw net.Conn, hello []byte) {
				_, _ = peer.Write(handshakeMsg, hello)
				_, _ = raw.Write(make([]byte, 32))
			},
			want: "got read error",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			client, peer, raw, peerHello, _ := newScriptedPeer(t)

			go func() {
				time.Sleep(100 * time.Millisecond)
				test.send(peer, raw, peerHello)
			}()

			suite := new(Suite)
			results := utesting.RunTests([]utesting.Test{{
				Name: "disconnectFailure",
				Fn: func(t *utesting.T) {
					suite.expectDisconnectAfterMessage(t, client, handshakeMsg, []byte{0xff})
				},
			}}, io.Discard)

			if !results[0].Failed {
				t.Fatalf("helper accepted a peer that %s", test.name)
			}
			if !strings.Contains(results[0].Output, test.want) {
				t.Fatalf("helper failed for the wrong reason, want %q in output:\n%s", test.want, results[0].Output)
			}
			if results[0].Duration < test.min {
				t.Fatalf("helper failed after %v, before %v", results[0].Duration, test.min)
			}
			if test.max > 0 && results[0].Duration >= test.max {
				t.Fatalf("helper failed after %v, not within the idle window", results[0].Duration)
			}
		})
	}
}

// lateHello* are shortened windows for the late-Hello regressions: the boundary
// is exercised in about a second instead of the production 5s/1.2s, and a Hello
// at lateHelloAt leaves a full idle window under the hard deadline.
const (
	lateHelloFirstFrame = 800 * time.Millisecond
	lateHelloIdle       = 600 * time.Millisecond
	lateHelloAt         = 600 * time.Millisecond
)

// newScriptedPeer returns an rlpx client, a scripted peer sharing a net.Pipe,
// and the client's hello identity. The peer drains the client's frames so client
// writes never block; peerHello is an encoded Hello the test can send at any time
// through peer.Write.
func newScriptedPeer(t *testing.T) (client, peer *rlpx.Conn, raw net.Conn, peerHello, clientID []byte) {
	t.Helper()

	clientConn, peerConn := net.Pipe()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	peerKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate peer key: %v", err)
	}
	client = rlpx.NewConn(clientConn, &peerKey.PublicKey)
	peer = rlpx.NewConn(peerConn, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := peer.Handshake(peerKey); err != nil {
			t.Errorf("peer handshake failed: %v", err)
		}
	}()
	if _, err := client.Handshake(key); err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	<-done
	t.Cleanup(func() {
		client.Close()
		peer.Close()
	})

	go io.Copy(io.Discard, peerConn)
	peerHello, err = rlp.EncodeToBytes(&protoHandshake{
		Version: 5,
		Caps:    []p2p.Cap{{Name: "eth", Version: ethProtoVersionXDpos2}},
		ID:      crypto.FromECDSAPub(&peerKey.PublicKey)[1:],
	})
	if err != nil {
		t.Fatalf("failed to encode peer hello: %v", err)
	}
	return client, peer, peerConn, peerHello, crypto.FromECDSAPub(&key.PublicKey)[1:]
}

// TestStayConnectedLateHelloWindow guards the late-Hello boundary: a Hello that
// arrives inside the first-frame budget must still be watched for a full idle
// window, so a close just past that budget cannot slip through and an idle peer
// is only accepted once the window has elapsed.
func TestStayConnectedLateHelloWindow(t *testing.T) {
	tests := []struct {
		name     string
		closeAt  time.Duration // zero: the peer stays silent
		wantFail bool
	}{
		{"close after a late hello", lateHelloAt + 350*time.Millisecond, true},
		{"idle after a late hello", 0, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, peer, raw, peerHello, _ := newScriptedPeer(t)
			go func() {
				time.Sleep(lateHelloAt)
				_, _ = peer.Write(handshakeMsg, peerHello)
				if test.closeAt == 0 {
					return
				}
				time.Sleep(test.closeAt - lateHelloAt)
				_ = raw.Close()
			}()

			suite := new(Suite)
			results := utesting.RunTests([]utesting.Test{{
				Name: "lateHello",
				Fn: func(t *utesting.T) {
					suite.expectStayConnectedWithin(t, client, handshakeMsg, []byte{0xff}, false, lateHelloFirstFrame, lateHelloIdle)
				},
			}}, io.Discard)

			if results[0].Failed != test.wantFail {
				t.Fatalf("helper failed = %v, want %v:\n%s", results[0].Failed, test.wantFail, results[0].Output)
			}
			min := lateHelloAt + lateHelloIdle - 50*time.Millisecond
			if test.wantFail {
				min = lateHelloAt + 300*time.Millisecond
				if !strings.Contains(results[0].Output, "keep the connection open") {
					t.Fatalf("helper failed for the wrong reason:\n%s", results[0].Output)
				}
			}
			if results[0].Duration < min {
				t.Fatalf("helper returned after %v, want at least %v", results[0].Duration, min)
			}
		})
	}
}

// TestStayConnectedChattyPeerAccepted guards the hard-deadline cap: a peer that
// keeps sending frames past the first-frame budget and then goes quiet is still
// accepted, even though the cap cuts the last idle window short.
func TestStayConnectedChattyPeerAccepted(t *testing.T) {
	client, peer, _, peerHello, _ := newScriptedPeer(t)
	go func() {
		time.Sleep(100 * time.Millisecond)
		_, _ = peer.Write(handshakeMsg, peerHello)
		for i := 0; i < 4; i++ {
			time.Sleep(300 * time.Millisecond)
			_, _ = peer.Write(statusMsgCode, []byte{0xff})
		}
	}()

	suite := new(Suite)
	results := utesting.RunTests([]utesting.Test{{
		Name: "chatty",
		Fn: func(t *utesting.T) {
			suite.expectStayConnectedWithin(t, client, handshakeMsg, []byte{0xff}, false, lateHelloFirstFrame, lateHelloIdle)
		},
	}}, io.Discard)

	if results[0].Failed {
		t.Fatalf("helper rejected a peer that stayed open:\n%s", results[0].Output)
	}
	if results[0].Duration < lateHelloFirstFrame+lateHelloIdle {
		t.Fatalf("helper returned after %v, want it to reach the hard deadline", results[0].Duration)
	}
}

// TestDisconnectLateHelloClose guards the disconnect helper's hard deadline: a
// peer that sends its Hello late and closes just past the first-frame budget
// must be reported as disconnected instead of still open.
func TestDisconnectLateHelloClose(t *testing.T) {
	client, peer, raw, peerHello, _ := newScriptedPeer(t)
	go func() {
		time.Sleep(lateHelloAt)
		_, _ = peer.Write(handshakeMsg, peerHello)
		time.Sleep(350 * time.Millisecond)
		_ = raw.Close()
	}()

	suite := new(Suite)
	results := utesting.RunTests([]utesting.Test{{
		Name: "lateClose",
		Fn: func(t *utesting.T) {
			suite.expectDisconnectWithin(t, client, handshakeMsg, []byte{0xff}, false, lateHelloFirstFrame, lateHelloIdle)
		},
	}}, io.Discard)

	if results[0].Failed {
		t.Fatalf("helper rejected a peer that disconnected:\n%s", results[0].Output)
	}
	if min := lateHelloAt + 300*time.Millisecond; results[0].Duration < min {
		t.Fatalf("helper returned after %v, want at least %v", results[0].Duration, min)
	}
}

// TestDisconnectSnappyDiscMsg locks the drain's framing switch: a node that read
// our version-5 Hello compresses its disconnect frame, so the helper must decode
// it and must reject an uncompressed frame from such a peer.
func TestDisconnectSnappyDiscMsg(t *testing.T) {
	cases := []struct {
		name       string
		peerSnappy bool
		wantFail   bool
	}{
		{"compressed disconnect", true, false},
		{"uncompressed disconnect", false, true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			client, peer, _, peerHello, clientID := newScriptedPeer(t)
			reason, err := rlp.EncodeToBytes([1]p2p.DiscReason{p2p.DiscRequested})
			if err != nil {
				t.Fatalf("failed to encode disconnect reason: %v", err)
			}
			go func() {
				time.Sleep(100 * time.Millisecond)
				_, _ = peer.Write(handshakeMsg, peerHello) // the node hello is never compressed
				peer.SetSnappy(test.peerSnappy)
				_, _ = peer.Write(discMsg, reason)
			}()

			suite := new(Suite)
			results := utesting.RunTests([]utesting.Test{{
				Name: "snappyDisc",
				Fn: func(t *utesting.T) {
					hello := &protoHandshake{
						Version: 5,
						Caps:    []p2p.Cap{{Name: "eth", Version: ethProtoVersionXDpos2}},
						ID:      clientID,
					}
					suite.expectDisconnectAfterHello(t, client, hello)
				},
			}}, io.Discard)

			if results[0].Failed != test.wantFail {
				t.Fatalf("helper failed = %v, want %v:\n%s", results[0].Failed, test.wantFail, results[0].Output)
			}
			if test.wantFail && !strings.Contains(results[0].Output, "snappy") {
				t.Fatalf("helper failed for the wrong reason, want a snappy error:\n%s", results[0].Output)
			}
			if !test.wantFail && results[0].Duration >= handshakeTimeout {
				t.Fatalf("helper waited %v without decoding the disconnect", results[0].Duration)
			}
		})
	}
}
