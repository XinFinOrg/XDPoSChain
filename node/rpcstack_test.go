package node

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/internal/testlog"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/rpc"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
)

const testMethod = "rpc_modules"

// TestCorsHandler makes sure CORS are properly handled on the http server.
func TestCorsHandler(t *testing.T) {
	srv := createAndStartServer(t, &httpConfig{CorsAllowedOrigins: []string{"test", "test.com"}}, false, &wsConfig{}, nil)
	defer srv.stop()
	url := "http://" + srv.listenAddr()

	resp := rpcRequest(t, url, testMethod, "origin", "test.com")
	assert.Equal(t, "test.com", resp.Header.Get("Access-Control-Allow-Origin"))

	resp2 := rpcRequest(t, url, testMethod, "origin", "bad")
	assert.Equal(t, "", resp2.Header.Get("Access-Control-Allow-Origin"))
}

// TestVhosts makes sure vhosts are properly handled on the http server.
func TestVhosts(t *testing.T) {
	srv := createAndStartServer(t, &httpConfig{Vhosts: []string{"test"}}, false, &wsConfig{}, nil)
	defer srv.stop()
	url := "http://" + srv.listenAddr()

	resp := rpcRequest(t, url, testMethod, "host", "test")
	assert.Equal(t, resp.StatusCode, http.StatusOK)

	resp2 := rpcRequest(t, url, testMethod, "host", "bad")
	assert.Equal(t, resp2.StatusCode, http.StatusForbidden)
}

type originTest struct {
	spec    string
	expOk   []string
	expFail []string
}

// splitAndTrim splits input separated by a comma
// and trims excessive white space from the substrings.
// Copied over from flags.go
func splitAndTrim(input string) (ret []string) {
	l := strings.Split(input, ",")
	for _, r := range l {
		r = strings.TrimSpace(r)
		if len(r) > 0 {
			ret = append(ret, r)
		}
	}
	return ret
}

// TestWebsocketOrigins makes sure the websocket origins are properly handled on the websocket server.
func TestWebsocketOrigins(t *testing.T) {
	tests := []originTest{
		{
			spec: "*", // allow all
			expOk: []string{"", "http://test", "https://test", "http://test:8540", "https://test:8540",
				"http://test.com", "https://foo.test", "http://testa", "http://atestb:8540", "https://atestb:8540"},
		},
		{
			spec:    "test",
			expOk:   []string{"http://test", "https://test", "http://test:8540", "https://test:8540"},
			expFail: []string{"http://test.com", "https://foo.test", "http://testa", "http://atestb:8540", "https://atestb:8540"},
		},
		// scheme tests
		{
			spec:  "https://test",
			expOk: []string{"https://test", "https://test:9999"},
			expFail: []string{
				"test",                                // no scheme, required by spec
				"http://test",                         // wrong scheme
				"http://test.foo", "https://a.test.x", // subdomain variatoins
				"http://testx:8540", "https://xtest:8540"},
		},
		// ip tests
		{
			spec:  "https://12.34.56.78",
			expOk: []string{"https://12.34.56.78", "https://12.34.56.78:8540"},
			expFail: []string{
				"http://12.34.56.78",     // wrong scheme
				"http://12.34.56.78:443", // wrong scheme
				"http://1.12.34.56.78",   // wrong 'domain name'
				"http://12.34.56.78.a",   // wrong 'domain name'
				"https://87.65.43.21", "http://87.65.43.21:8540", "https://87.65.43.21:8540"},
		},
		// port tests
		{
			spec:  "test:8540",
			expOk: []string{"http://test:8540", "https://test:8540"},
			expFail: []string{
				"http://test", "https://test", // spec says port required
				"http://test:8541", "https://test:8541", // wrong port
				"http://bad", "https://bad", "http://bad:8540", "https://bad:8540"},
		},
		// scheme and port
		{
			spec:  "https://test:8540",
			expOk: []string{"https://test:8540"},
			expFail: []string{
				"https://test",                          // missing port
				"http://test",                           // missing port, + wrong scheme
				"http://test:8540",                      // wrong scheme
				"http://test:8541", "https://test:8541", // wrong port
				"http://bad", "https://bad", "http://bad:8540", "https://bad:8540"},
		},
		// several allowed origins
		{
			spec: "localhost,http://127.0.0.1",
			expOk: []string{"localhost", "http://localhost", "https://localhost:8443",
				"http://127.0.0.1", "http://127.0.0.1:8080"},
			expFail: []string{
				"https://127.0.0.1", // wrong scheme
				"http://bad", "https://bad", "http://bad:8540", "https://bad:8540"},
		},
	}
	for _, tc := range tests {
		srv := createAndStartServer(t, &httpConfig{}, true, &wsConfig{Origins: splitAndTrim(tc.spec)}, nil)
		url := fmt.Sprintf("ws://%v", srv.listenAddr())
		for _, origin := range tc.expOk {
			if err := wsRequest(t, url, origin); err != nil {
				t.Errorf("spec '%v', origin '%v': expected ok, got %v", tc.spec, origin, err)
			}
		}
		for _, origin := range tc.expFail {
			if err := wsRequest(t, url, origin); err == nil {
				t.Errorf("spec '%v', origin '%v': expected not to allow,  got ok", tc.spec, origin)
			}
		}
		srv.stop()
	}
}

func Test_checkPath(t *testing.T) {
	tests := []struct {
		req      *http.Request
		prefix   string
		expected bool
	}{
		{
			req:      &http.Request{URL: &url.URL{Path: "/test"}},
			prefix:   "/test",
			expected: true,
		},
		{
			req:      &http.Request{URL: &url.URL{Path: "/testing"}},
			prefix:   "/test",
			expected: true,
		},
		{
			req:      &http.Request{URL: &url.URL{Path: "/"}},
			prefix:   "/test",
			expected: false,
		},
		{
			req:      &http.Request{URL: &url.URL{Path: "/fail"}},
			prefix:   "/test",
			expected: false,
		},
		{
			req:      &http.Request{URL: &url.URL{Path: "/"}},
			prefix:   "",
			expected: true,
		},
		{
			req:      &http.Request{URL: &url.URL{Path: "/fail"}},
			prefix:   "",
			expected: false,
		},
		{
			req:      &http.Request{URL: &url.URL{Path: "/"}},
			prefix:   "/",
			expected: true,
		},
		{
			req:      &http.Request{URL: &url.URL{Path: "/testing"}},
			prefix:   "/",
			expected: true,
		},
	}

	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			assert.Equal(t, tt.expected, checkPath(tt.req, tt.prefix))
		})
	}
}

func createAndStartServer(t *testing.T, conf *httpConfig, ws bool, wsConf *wsConfig, timeouts *rpc.HTTPTimeouts) *httpServer {
	t.Helper()

	if timeouts == nil {
		timeouts = &rpc.DefaultHTTPTimeouts
	}
	srv := newHTTPServer(testlog.Logger(t, log.LvlDebug), *timeouts)
	assert.NoError(t, srv.enableRPC(apis(), *conf))
	if ws {
		assert.NoError(t, srv.enableWS(nil, *wsConf))
	}
	assert.NoError(t, srv.setListenAddr("localhost", 0))
	assert.NoError(t, srv.start())

	return srv
}

// wsRequest attempts to open a WebSocket connection to the given URL.
func wsRequest(t *testing.T, url, browserOrigin string) error {
	t.Helper()
	t.Logf("checking WebSocket on %s (origin %q)", url, browserOrigin)

	headers := make(http.Header)
	if browserOrigin != "" {
		headers.Set("Origin", browserOrigin)
	}
	conn, _, err := websocket.DefaultDialer.Dial(url, headers)
	if conn != nil {
		conn.Close()
	}
	return err
}

// rpcRequest performs a JSON-RPC request to the given URL.
func rpcRequest(t *testing.T, url, method string, extraHeaders ...string) *http.Response {
	t.Helper()

	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"%s","params":[]}`, method)
	return baseRpcRequest(t, url, body, extraHeaders...)
}

func batchRpcRequest(t *testing.T, url string, methods []string, extraHeaders ...string) *http.Response {
	reqs := make([]string, len(methods))
	for i, m := range methods {
		reqs[i] = fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"%s","params":[]}`, m)
	}
	body := fmt.Sprintf(`[%s]`, strings.Join(reqs, ","))
	return baseRpcRequest(t, url, body, extraHeaders...)
}

func baseRpcRequest(t *testing.T, url, bodyStr string, extraHeaders ...string) *http.Response {
	t.Helper()

	// Create the request.
	body := bytes.NewReader([]byte(bodyStr))
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		t.Fatal("could not create http request:", err)
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept-encoding", "identity")

	// Apply extra headers.
	if len(extraHeaders)%2 != 0 {
		panic("odd extraHeaders length")
	}
	for i := 0; i < len(extraHeaders); i += 2 {
		key, value := extraHeaders[i], extraHeaders[i+1]
		if strings.ToLower(key) == "host" {
			req.Host = value
		} else {
			req.Header.Set(key, value)
		}
	}

	// Perform the request.
	t.Logf("checking RPC/HTTP on %s %v", url, extraHeaders)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestIsWebsocket tests if an incoming websocket upgrade request is handled properly.
func TestIsWebsocket(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)

	assert.False(t, isWebsocket(r))
	r.Header.Set("upgrade", "websocket")
	assert.False(t, isWebsocket(r))
	r.Header.Set("connection", "upgrade")
	assert.True(t, isWebsocket(r))
	r.Header.Set("connection", "upgrade,keep-alive")
	assert.True(t, isWebsocket(r))
	r.Header.Set("connection", " UPGRADE,keep-alive")
	assert.True(t, isWebsocket(r))
}

func TestGzipHandler(t *testing.T) {
	type gzipTest struct {
		name    string
		handler http.HandlerFunc
		status  int
		isGzip  bool
		header  map[string]string
	}
	tests := []gzipTest{
		{
			name: "Write",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("response"))
			},
			isGzip: true,
			status: 200,
		},
		{
			name: "WriteHeader",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("x-foo", "bar")
				w.WriteHeader(205)
				w.Write([]byte("response"))
			},
			isGzip: true,
			status: 205,
			header: map[string]string{"x-foo": "bar"},
		},
		{
			name: "WriteContentLength",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("content-length", "8")
				w.Write([]byte("response"))
			},
			isGzip: true,
			status: 200,
		},
		{
			name: "Flush",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("res"))
				w.(http.Flusher).Flush()
				w.Write([]byte("ponse"))
			},
			isGzip: true,
			status: 200,
		},
		{
			name: "disable",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("transfer-encoding", "identity")
				w.Header().Set("x-foo", "bar")
				w.Write([]byte("response"))
			},
			isGzip: false,
			status: 200,
			header: map[string]string{"x-foo": "bar"},
		},
		{
			name: "disable-WriteHeader",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("transfer-encoding", "identity")
				w.Header().Set("x-foo", "bar")
				w.WriteHeader(205)
				w.Write([]byte("response"))
			},
			isGzip: false,
			status: 205,
			header: map[string]string{"x-foo": "bar"},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			srv := httptest.NewServer(newGzipHandler(test.handler))
			defer srv.Close()

			resp, err := http.Get(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			content, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			wasGzip := resp.Uncompressed

			if string(content) != "response" {
				t.Fatalf("wrong response content %q", content)
			}
			if wasGzip != test.isGzip {
				t.Fatalf("response gzipped == %t, want %t", wasGzip, test.isGzip)
			}
			if resp.StatusCode != test.status {
				t.Fatalf("response status == %d, want %d", resp.StatusCode, test.status)
			}
			for name, expectedValue := range test.header {
				if v := resp.Header.Get(name); v != expectedValue {
					t.Fatalf("response header %s == %s, want %s", name, v, expectedValue)
				}
			}
		})
	}
}

func TestHTTPWriteTimeout(t *testing.T) {
	const (
		timeoutRes = `{"jsonrpc":"2.0","id":1,"error":{"code":-32002,"message":"request timed out"}}`
		greetRes   = `{"jsonrpc":"2.0","id":1,"result":"Hello"}`
	)
	// Set-up server
	timeouts := rpc.DefaultHTTPTimeouts
	timeouts.WriteTimeout = time.Second
	srv := createAndStartServer(t, &httpConfig{Modules: []string{"test"}}, false, &wsConfig{}, &timeouts)
	url := fmt.Sprintf("http://%v", srv.listenAddr())

	// Send normal request
	t.Run("message", func(t *testing.T) {
		resp := rpcRequest(t, url, "test_sleep")
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != timeoutRes {
			t.Errorf("wrong response. have %s, want %s", string(body), timeoutRes)
		}
	})

	// Batch request
	t.Run("batch", func(t *testing.T) {
		want := fmt.Sprintf("[%s,%s,%s]", greetRes, timeoutRes, timeoutRes)
		resp := batchRpcRequest(t, url, []string{"test_greet", "test_sleep", "test_greet"})
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != want {
			t.Errorf("wrong response. have %s, want %s", string(body), want)
		}
	})
}

func apis() []rpc.API {
	return []rpc.API{
		{
			Namespace: "test",
			Service:   &testService{},
		},
	}
}

type testService struct{}

func (s *testService) Greet() string {
	return "Hello"
}

func (s *testService) Sleep() {
	time.Sleep(1500 * time.Millisecond)
}
