package countdown

import (
	"testing"
	"time"
)

// TestResetAfterCallbackReturns covers the reset path a callback drives once
// the timer has fired: the reset must return and re-arm the timer instead of
// draining a timer channel that has already delivered its value.
func TestResetAfterCallbackReturns(t *testing.T) {
	t.Parallel()

	const timeout = 50 * time.Millisecond

	fired := make(chan time.Time, 1)
	countdown, err := NewExpCountDown(timeout, 0, 0)
	if err != nil {
		t.Fatalf("NewExpCountDown: %v", err)
	}
	countdown.OnTimeoutFn = func(now time.Time, _ interface{}) error {
		select {
		case fired <- now:
		default:
		}
		return nil
	}
	countdown.Reset(nil, 0, 0)

	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Fatal("callback did not fire")
	}

	// Reset from another goroutine: a reset path that blocks would hang the
	// test, so the bound turns it into a failure.
	done := make(chan struct{})
	go func() {
		countdown.Reset(nil, 0, 0)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Reset blocked after the timer fired")
	}

	// A reset that took effect re-arms the timer, so one more callback has to
	// follow. Drop whatever the automatic re-arm queued before the reset first.
	select {
	case <-fired:
	default:
	}
	select {
	case <-fired:
		// startTimer answered the reset and re-armed, so it is back in its
		// select and takes the quit. No defer: a wedged startTimer would block
		// StopTimer and hang the package instead of failing the test.
		countdown.StopTimer()
	case <-time.After(time.Second):
		t.Fatal("callback did not fire after the reset: the reset path is blocked")
	}
}
