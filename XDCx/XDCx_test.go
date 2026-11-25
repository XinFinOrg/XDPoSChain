package XDCx

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/XDCxDAO"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/node"
)

// mustReopen verifies the trading database was closed by opening it again.
func mustReopen(t *testing.T, dir string) {
	t.Helper()
	db, err := rawdb.NewLevelDBDatabase(dir, 0, 0, "", false)
	if err != nil {
		t.Fatalf("the trading database is still open: %v", err)
	}
	db.Close()
}

func TestNewReportsDatabaseOpenFailure(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "XDCx")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("can't prepare the path: %v", err)
	}
	stack, err := node.New(&node.Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatalf("can't create the node: %v", err)
	}
	defer stack.Close()

	if _, err := New(stack, &Config{DataDir: blocked}); err == nil {
		t.Fatal("New accepted a data directory that cannot be opened")
	}
}

func TestNodeCloseClosesTradingDatabase(t *testing.T) {
	dir := t.TempDir()
	stack, err := node.New(&node.Config{DataDir: dir})
	if err != nil {
		t.Fatalf("can't create the node: %v", err)
	}
	if _, err := New(stack, &Config{DataDir: filepath.Join(dir, "XDCx")}); err != nil {
		t.Fatalf("can't create the XDCx service: %v", err)
	}
	if err := stack.Start(); err != nil {
		t.Fatalf("can't start the node: %v", err)
	}
	if err := stack.Close(); err != nil {
		t.Fatalf("can't stop the node: %v", err)
	}
	mustReopen(t, filepath.Join(dir, "XDCx"))
}

func TestNodeCloseWithoutStartClosesTradingDatabase(t *testing.T) {
	dir := t.TempDir()
	stack, err := node.New(&node.Config{DataDir: dir})
	if err != nil {
		t.Fatalf("can't create the node: %v", err)
	}
	xdcx, err := New(stack, &Config{DataDir: filepath.Join(dir, "XDCx")})
	if err != nil {
		t.Fatalf("can't create the XDCx service: %v", err)
	}
	if err := stack.Close(); err != nil {
		t.Fatalf("can't close the node: %v", err)
	}
	// The node closed the database without starting the service; closing the
	// service handle afterwards must not report the double close.
	if err := xdcx.GetLevelDB().Close(); err != nil {
		t.Fatalf("closing the trading database after the node closed it: %v", err)
	}
	mustReopen(t, filepath.Join(dir, "XDCx"))
}

func TestNewOnRunningNodeReportsError(t *testing.T) {
	dir := t.TempDir()
	stack, err := node.New(&node.Config{DataDir: dir})
	if err != nil {
		t.Fatalf("can't create the node: %v", err)
	}
	if err := stack.Start(); err != nil {
		t.Fatalf("can't start the node: %v", err)
	}
	defer stack.Close()

	xdcxDir := filepath.Join(dir, "XDCx")
	if _, err := New(stack, &Config{DataDir: xdcxDir}); !errors.Is(err, node.ErrNodeRunning) {
		t.Fatalf("New error = %v, want %v", err, node.ErrNodeRunning)
	}
	mustReopen(t, xdcxDir)
}

func TestNewOnClosedNodeReportsError(t *testing.T) {
	dir := t.TempDir()
	stack, err := node.New(&node.Config{DataDir: dir})
	if err != nil {
		t.Fatalf("can't create the node: %v", err)
	}
	if err := stack.Close(); err != nil {
		t.Fatalf("can't close the node: %v", err)
	}

	xdcxDir := filepath.Join(dir, "XDCx")
	if _, err := New(stack, &Config{DataDir: xdcxDir}); !errors.Is(err, node.ErrNodeStopped) {
		t.Fatalf("New error = %v, want %v", err, node.ErrNodeStopped)
	}
	mustReopen(t, xdcxDir)
}

func TestGetLevelDBCloseUnregistersFromNode(t *testing.T) {
	dir := t.TempDir()
	stack, err := node.New(&node.Config{DataDir: dir})
	if err != nil {
		t.Fatalf("can't create the node: %v", err)
	}
	xdcx, err := New(stack, &Config{DataDir: filepath.Join(dir, "XDCx")})
	if err != nil {
		t.Fatalf("can't create the XDCx service: %v", err)
	}
	if err := stack.Start(); err != nil {
		t.Fatalf("can't start the node: %v", err)
	}
	if err := xdcx.GetLevelDB().Close(); err != nil {
		t.Fatalf("can't close the trading database: %v", err)
	}
	if err := stack.Close(); err != nil {
		t.Fatalf("node shutdown after the caller closed the trading database: %v", err)
	}
}

// lifecycleProbe records whether the trading database is still usable when the
// node stops it.
type lifecycleProbe struct {
	t        *testing.T
	db       XDCxDAO.XDCXDAO
	wantOpen bool
}

func (p *lifecycleProbe) Start() error { return nil }

func (p *lifecycleProbe) Stop() error {
	_, err := p.db.Has([]byte("lifecycle-probe"))
	if open := err == nil; open != p.wantOpen {
		p.t.Errorf("trading database open=%v when the probe stopped, want %v (err: %v)", open, p.wantOpen, err)
	}
	return nil
}

func TestNodeStopOrderClosesTradingDatabase(t *testing.T) {
	dir := t.TempDir()
	stack, err := node.New(&node.Config{DataDir: dir})
	if err != nil {
		t.Fatalf("can't create the node: %v", err)
	}
	defer stack.Close()

	// Lifecycles stop in reverse registration order: this probe stops last, after
	// XDCx.Stop has closed the trading database.
	closed := &lifecycleProbe{t: t, wantOpen: false}
	stack.RegisterLifecycle(closed)

	xdcx, err := New(stack, &Config{DataDir: filepath.Join(dir, "XDCx")})
	if err != nil {
		t.Fatalf("can't create the XDCx service: %v", err)
	}
	closed.db = xdcx.GetLevelDB()

	// This probe stops first, while the database must still be open.
	open := &lifecycleProbe{t: t, wantOpen: true}
	open.db = xdcx.GetLevelDB()
	stack.RegisterLifecycle(open)

	if err := stack.Start(); err != nil {
		t.Fatalf("can't start the node: %v", err)
	}
	if err := stack.Close(); err != nil {
		t.Fatalf("can't stop the node: %v", err)
	}
}
