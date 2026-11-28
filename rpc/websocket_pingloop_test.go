// Copyright 2025 The go-ethereum Authors
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

package rpc

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestWebsocketPingLoopResetAfterFired covers the pingReset path once the ping
// timer has fired: the reset must return and re-arm the timer instead of
// draining a timer channel that has already delivered its value.
//
// The test is serial on purpose: it mutates the package-level wsPingInterval,
// and parallel tests are held back until all serial tests have finished.
func TestWebsocketPingLoopResetAfterFired(t *testing.T) {
	oldInterval := wsPingInterval
	wsPingInterval = 20 * time.Millisecond
	// Cleanup order is LIFO: the codec cleanup registered below stops the
	// pingLoop first, so this restore never races with a live Reset reader.
	t.Cleanup(func() { wsPingInterval = oldInterval })

	var (
		pings    = make(chan struct{}, 4)
		connCh   = make(chan *websocket.Conn, 1)
		upgrader = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		httpsrv  = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				t.Errorf("server WS upgrade error: %v", err)
				return
			}
			connCh <- conn
		}))
	)
	defer httpsrv.Close()

	clientConn, _, err := websocket.DefaultDialer.Dial("ws://"+httpsrv.Listener.Addr().String(), nil)
	if err != nil {
		t.Fatalf("client dial error: %v", err)
	}

	// Collect ping frames on the client side; the reader goroutine drives the
	// control-frame processing that invokes the ping handler.
	clientConn.SetPingHandler(func(string) error {
		select {
		case pings <- struct{}{}:
		default:
		}
		return nil
	})
	go func() {
		for {
			if _, _, err := clientConn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	// Build the server-side codec. Creating it starts the pingLoop. The close
	// is bounded instead of deferred: a wedged pingLoop would hang the test
	// process rather than fail it. A wedged loop never reads the interval
	// again, so leaving it behind is safe and the restore still runs.
	serverConn := <-connCh
	codec := newWebsocketCodec(serverConn, httpsrv.Listener.Addr().String(), http.Header{}, wsDefaultReadLimit).(*websocketCodec)
	t.Cleanup(func() {
		clientConn.Close()
		done := make(chan struct{})
		go func() {
			codec.close()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	})

	// The first ping proves the timer fired and its value was taken by the
	// select in pingLoop.
	select {
	case <-pings:
	case <-time.After(2 * time.Second):
		t.Fatal("no ping within the idle interval")
	}

	// A reset that took effect re-arms the timer, so one more ping has to
	// follow. A reset path that drains the taken value would block here.
	codec.pingReset <- struct{}{}
	select {
	case <-pings:
	case <-time.After(2 * time.Second):
		t.Fatal("no ping after reset: the reset path is blocked")
	}
}
