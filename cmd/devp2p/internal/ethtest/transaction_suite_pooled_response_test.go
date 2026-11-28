package ethtest

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/rlp"
)

func TestWaitPooledTransactionsSkipsBroadcastFrames(t *testing.T) {
	txs := frameTestTxs(2)
	reads := 0
	readMsg := func() (uint64, interface{}, error) {
		reads++
		// Block and BFT broadcasts decode as raw values on the same stream, and
		// a full transaction broadcast decodes as *types.Transactions with no
		// request id
		if reads <= 6 {
			return 0, new(rlp.RawValue), nil
		}
		if reads == 7 {
			return 0, &txs, nil
		}
		return 1234, (*pooledTransactionsResponse)(&txs), nil
	}
	got, err := waitPooledTransactionsXdc166(readMsg, 1234, time.Now().Add(time.Second))
	if err != nil {
		t.Fatalf("waitPooledTransactionsXdc166: %v", err)
	}
	if reads != 8 {
		t.Fatalf("read %d frames, want 8", reads)
	}
	if len(got) != len(txs) || got[0].Hash() != txs[0].Hash() {
		t.Fatalf("unexpected response: %v", got)
	}
}

// A full transaction broadcast may reach the query peer before the response;
// it carries no request id and must not be taken for a mismatched response
func TestWaitPooledTransactionsSkipsFullTxBroadcast(t *testing.T) {
	txs := frameTestTxs(1)
	reads := 0
	readMsg := func() (uint64, interface{}, error) {
		reads++
		if reads == 1 {
			return 0, &txs, nil
		}
		return 1234, (*pooledTransactionsResponse)(&txs), nil
	}
	got, err := waitPooledTransactionsXdc166(readMsg, 1234, time.Now().Add(time.Second))
	if err != nil {
		t.Fatalf("full tx broadcast failed the wait: %v", err)
	}
	if reads != 2 {
		t.Fatalf("read %d frames, want 2", reads)
	}
	if len(got) != len(txs) || got[0].Hash() != txs[0].Hash() {
		t.Fatalf("unexpected response: %v", got)
	}
}

func TestWaitPooledTransactionsRejectsWrongRequestID(t *testing.T) {
	txs := frameTestTxs(1)
	readMsg := func() (uint64, interface{}, error) { return 7, (*pooledTransactionsResponse)(&txs), nil }
	_, err := waitPooledTransactionsXdc166(readMsg, 1234, time.Now().Add(time.Second))
	if err == nil || !strings.Contains(err.Error(), "request id mismatch") {
		t.Fatalf("wrong request id accepted: %v", err)
	}
}

// The broadcast is skipped because of its type, not because its id is zero: a
// pooled response carrying the wrong id must still fail the wait
func TestWaitPooledTransactionsRejectsZeroRequestID(t *testing.T) {
	txs := frameTestTxs(1)
	readMsg := func() (uint64, interface{}, error) { return 0, (*pooledTransactionsResponse)(&txs), nil }
	_, err := waitPooledTransactionsXdc166(readMsg, 1234, time.Now().Add(time.Second))
	if err == nil || !strings.Contains(err.Error(), "request id mismatch") {
		t.Fatalf("zero request id accepted: %v", err)
	}
}

func TestWaitPooledTransactionsHonoursDeadline(t *testing.T) {
	reads := 0
	readMsg := func() (uint64, interface{}, error) {
		reads++
		return 0, new(rlp.RawValue), nil
	}
	_, err := waitPooledTransactionsXdc166(readMsg, 1234, time.Now().Add(-time.Second))
	if !errors.Is(err, errPooledTxDeadline) {
		t.Fatalf("expired deadline accepted: %v", err)
	}
	if reads != 0 {
		t.Fatalf("read %d frames past the deadline, want 0", reads)
	}
}

type timeoutReadError struct{}

func (timeoutReadError) Error() string   { return "i/o timeout" }
func (timeoutReadError) Timeout() bool   { return true }
func (timeoutReadError) Temporary() bool { return true }

// A read timeout means the deadline passed: the RLPx frame read is not
// resumable, so the wait must not read the same connection again
func TestWaitPooledTransactionsStopsOnReadTimeout(t *testing.T) {
	reads := 0
	readMsg := func() (uint64, interface{}, error) {
		reads++
		return 0, nil, timeoutReadError{}
	}
	_, err := waitPooledTransactionsXdc166(readMsg, 1234, time.Now().Add(time.Second))
	if !errors.Is(err, errPooledTxDeadline) {
		t.Fatalf("read timeout not reported as the deadline: %v", err)
	}
	if reads != 1 {
		t.Fatalf("read %d frames after the timeout, want 1", reads)
	}
}

func TestWaitPooledTransactionsRejectsLateResponse(t *testing.T) {
	txs := frameTestTxs(1)
	readMsg := func() (uint64, interface{}, error) {
		time.Sleep(20 * time.Millisecond)
		return 1234, (*pooledTransactionsResponse)(&txs), nil
	}
	_, err := waitPooledTransactionsXdc166(readMsg, 1234, time.Now().Add(10*time.Millisecond))
	if !errors.Is(err, errPooledTxDeadline) {
		t.Fatalf("late response accepted: %v", err)
	}
}
