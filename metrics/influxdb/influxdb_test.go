// Copyright 2023 The go-ethereum Authors
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

package influxdb

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/metrics"
	"github.com/XinFinOrg/XDPoSChain/metrics/internal"
	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
)

func TestMain(m *testing.M) {
	metrics.Enable()
	os.Exit(m.Run())
}

func TestExampleV1(t *testing.T) {
	if runtime.GOARCH == "arm64" {
		t.Skip("test skipped on ARM64 due to floating point precision differences")
	}

	r := internal.ExampleMetrics()
	var have, want string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		haveB, _ := io.ReadAll(r.Body)
		have = string(haveB)
		r.Body.Close()
	}))
	defer ts.Close()
	u, _ := url.Parse(ts.URL)
	rep := &reporter{
		reg:       r,
		url:       *u,
		namespace: "goth.",
	}
	if err := rep.makeClient(); err != nil {
		t.Fatal(err)
	}
	if err := rep.send(978307200); err != nil {
		t.Fatal(err)
	}
	if wantB, err := os.ReadFile("./testdata/influxdbv1.want"); err != nil {
		t.Fatal(err)
	} else {
		want = string(wantB)
	}
	if have != want {
		t.Errorf("\nhave:\n%v\nwant:\n%v\n", have, want)
		t.Logf("have vs want:\n%v", findFirstDiffPos(have, want))
	}
}

func TestExampleV2(t *testing.T) {
	if runtime.GOARCH == "arm64" {
		t.Skip("test skipped on ARM64 due to floating point precision differences")
	}

	r := internal.ExampleMetrics()
	wantB, err := os.ReadFile("./testdata/influxdbv2.want")
	if err != nil {
		t.Fatal(err)
	}
	want := string(wantB)

	var have strings.Builder
	haveCh := make(chan string, 16)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		haveB, _ := io.ReadAll(r.Body)
		r.Body.Close()
		haveCh <- string(haveB)
	}))
	defer ts.Close()

	rep := &v2Reporter{
		reg:       r,
		endpoint:  ts.URL,
		namespace: "goth.",
	}
	rep.client = influxdb2.NewClientWithOptions(rep.endpoint, rep.token, influxdb2.DefaultOptions().SetFlushInterval(50))
	defer rep.client.Close()
	rep.write = rep.client.WriteAPI(rep.organization, rep.bucket)

	rep.send(978307200)

	// The client flushes on its own ticker, so one send may arrive as several
	// HTTP requests. Accumulate bodies until the complete fixture has arrived.
	deadline := time.After(5 * time.Second)
	for have.String() != want {
		select {
		case body := <-haveCh:
			have.WriteString(body)
		case <-deadline:
			t.Fatalf("timed out waiting for InfluxDB write\nhave:\n%v\nwant:\n%v", have.String(), want)
		}
	}
}

func findFirstDiffPos(a, b string) string {
	yy := strings.Split(b, "\n")
	for i, x := range strings.Split(a, "\n") {
		if i >= len(yy) {
			return fmt.Sprintf("have:%d: %s\nwant:%d: <EOF>", i, x, i)
		}
		if y := yy[i]; x != y {
			return fmt.Sprintf("have:%d: %s\nwant:%d: %s", i, x, i, y)
		}
	}
	return ""
}

func TestV2ReporterRetriesAfterWriteFailure(t *testing.T) {
	var reqs int32
	delivered := make(chan string, 8)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if atomic.AddInt32(&reqs, 1) <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		select {
		case delivered <- string(body):
		default:
		}
	}))
	defer ts.Close()

	reg := metrics.NewRegistry()
	gauge := metrics.GetOrRegisterGauge("probe/gauge", reg)
	gauge.Update(7)

	rep := &v2Reporter{
		reg:       reg,
		endpoint:  ts.URL,
		namespace: "goth.",
	}
	opts := influxdb2.DefaultOptions().SetFlushInterval(20).SetRetryInterval(50).SetMaxRetries(5).SetRetryBufferLimit(500000)
	rep.client = influxdb2.NewClientWithOptions(rep.endpoint, rep.token, opts)
	defer rep.client.Close()
	rep.write = rep.client.WriteAPI(rep.organization, rep.bucket)
	go func() {
		for range rep.write.Errors() {
		}
	}()

	rep.send(0)
	gauge.Update(8)
	for i := 0; i < 100; i++ {
		select {
		case body := <-delivered:
			if strings.Contains(body, "goth.probe/gauge.gauge value=7i ") {
				return
			}
		case <-time.After(50 * time.Millisecond):
		}
		rep.send(0)
	}
	t.Fatalf("timed out waiting for the retried batch (requests=%d)", atomic.LoadInt32(&reqs))
}
