// Copyright 2026 The XDPoSChain Authors
// This file is part of the XDPoSChain library.
//
// The XDPoSChain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The XDPoSChain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the XDPoSChain library. If not, see <http://www.gnu.org/licenses/>.

package download

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func serveBody(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDownloadWithRetrySucceedsAfterTransientFailures(t *testing.T) {
	body := []byte("archive payload")
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Write(body)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "archive.tar.gz")
	if err := downloadWithRetry(srv.URL, dst, sha256Hex(body), 3, 0, 0, time.Minute); err != nil {
		t.Fatalf("download failed: %v", err)
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("server saw %d requests, want 3", got)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("downloaded %q, want %q", got, body)
	}
}

func TestDownloadWithRetryExhaustsAttempts(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "archive.tar.gz")
	err := downloadWithRetry(srv.URL, dst, sha256Hex([]byte("x")), downloadAttempts, 0, 0, time.Minute)
	if err == nil || !strings.Contains(err.Error(), "status 502") {
		t.Fatalf("error = %v, want status 502", err)
	}
	if got := hits.Load(); got != downloadAttempts {
		t.Fatalf("server saw %d requests, want %d", got, downloadAttempts)
	}
}

func TestDownloadWithRetryStopsOnPermanentStatus(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "archive.tar.gz")
	err := downloadWithRetry(srv.URL, dst, sha256Hex([]byte("x")), 3, 0, 0, time.Minute)
	if err == nil || !strings.Contains(err.Error(), "status 404") {
		t.Fatalf("error = %v, want status 404", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("server saw %d requests, want 1", got)
	}
	if _, err := os.Stat(dst); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("downloaded file exists after failed download: %v", err)
	}
}

func TestDownloadWithRetryRejectsWrongChecksum(t *testing.T) {
	body := []byte("tampered payload")
	srv := serveBody(t, body)

	dst := filepath.Join(t.TempDir(), "archive.tar.gz")
	err := downloadWithRetry(srv.URL, dst, sha256Hex([]byte("expected payload")), 3, 0, 0, time.Minute)
	if err == nil || !strings.Contains(err.Error(), "invalid file hash") {
		t.Fatalf("error = %v, want invalid file hash", err)
	}
	for _, path := range []string{dst, dst + ".tmp"} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s exists after failed download: %v", path, err)
		}
	}
}

func TestDownloadFileSkipsUpToDateFile(t *testing.T) {
	body := []byte("cached payload")
	db, err := ParseChecksums([]byte(sha256Hex(body) + "  archive.tar.gz\n"))
	if err != nil {
		t.Fatalf("parse checksums: %v", err)
	}
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "archive.tar.gz")
	if err := os.WriteFile(dst, body, 0644); err != nil {
		t.Fatalf("write cached file: %v", err)
	}
	if err := db.DownloadFile(srv.URL+"/archive.tar.gz", dst); err != nil {
		t.Fatalf("download failed: %v", err)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("server saw %d requests, want 0", got)
	}
}

func TestDownloadWithRetryBoundsEachAttempt(t *testing.T) {
	body := []byte("archive payload")
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(time.Second)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Write(body)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "archive.tar.gz")
	err := downloadWithRetry(srv.URL, dst, sha256Hex(body), 2, 0, 100*time.Millisecond, time.Minute)
	if err == nil {
		t.Fatal("download succeeded, want each attempt to be bounded")
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("server saw %d requests, want 2", got)
	}
}

func TestDownloadWithRetryRetriesBodyReadErrors(t *testing.T) {
	body := []byte("archive payload")
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			conn, bufrw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			bufrw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial")
			bufrw.Flush()
			conn.(*net.TCPConn).SetLinger(0)
			conn.Close()
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Write(body)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "archive.tar.gz")
	if err := downloadWithRetry(srv.URL, dst, sha256Hex(body), 2, 0, 0, time.Minute); err != nil {
		t.Fatalf("download failed: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("server saw %d requests, want 2", got)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("downloaded %q, want %q", got, body)
	}
}

func TestDownloadWithRetryBoundsBodyRead(t *testing.T) {
	body := []byte("archive payload")
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		if hits.Add(1) == 1 {
			w.WriteHeader(http.StatusOK)
			w.Write(body[:7])
			w.(http.Flusher).Flush()
			time.Sleep(300 * time.Millisecond)
			w.Write(body[7:])
			return
		}
		w.Write(body)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "archive.tar.gz")
	if err := downloadWithRetry(srv.URL, dst, sha256Hex(body), 2, 0, 100*time.Millisecond, time.Minute); err != nil {
		t.Fatalf("download failed: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("server saw %d requests, want 2", got)
	}
}

func TestDownloadWithRetryStopsAtBudget(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		time.Sleep(300 * time.Millisecond)
		conn.(*net.TCPConn).SetLinger(0)
		conn.Close()
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "archive.tar.gz")
	start := time.Now()
	err := downloadWithRetry(srv.URL, dst, "hash", 5, 0, 5*time.Second, 50*time.Millisecond)
	if err == nil {
		t.Fatal("download succeeded, want the budget to stop the retries")
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("retries ran for %s, want them bounded by the 50ms budget", elapsed)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("server saw %d requests, want 1", got)
	}
}

func TestIsTransient(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"too many requests", &httpStatusError{code: http.StatusTooManyRequests}, true},
		{"server error", &httpStatusError{code: http.StatusServiceUnavailable}, true},
		{"not found", &httpStatusError{code: http.StatusNotFound}, false},
		{"connection reset", &net.OpError{Op: "read", Err: errors.New("connection reset by peer")}, true},
		{"truncated body", io.ErrUnexpectedEOF, true},
		{"checksum mismatch", errors.New("invalid file hash: aa bb"), false},
		{"disk error", &fs.PathError{Op: "write", Path: "archive.tar.gz", Err: errors.New("no space left on device")}, false},
		{"wrapped disk error", &writeError{err: &fs.PathError{Op: "write", Path: "archive.tar.gz", Err: errors.New("no space left on device")}}, false},
	}
	for _, tt := range tests {
		if got := isTransient(tt.err); got != tt.want {
			t.Errorf("%s: isTransient(%v) = %v, want %v", tt.name, tt.err, got, tt.want)
		}
	}
}

func TestDownloadWriterMarksWriteErrors(t *testing.T) {
	fd, err := os.Create(filepath.Join(t.TempDir(), "archive.tar.gz"))
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	w := newDownloadWriter(fd, 8192)
	fd.Close()

	_, err = w.Write(bytes.Repeat([]byte("x"), 8192))
	if err == nil {
		t.Fatal("write to a closed file succeeded")
	}
	var writeErr *writeError
	if !errors.As(err, &writeErr) {
		t.Fatalf("error type = %T, want *writeError", err)
	}
	if isTransient(err) {
		t.Fatal("write error classified as transient")
	}
}
