package countdown

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// These tests drive real time.Timer values, so the durations are scheduling
// targets, not deadlines: resetAt is the wait before the mid-flight Reset,
// stopAt an at-least sleep before StopTimer, and callbackGrace (4x interval)
// bounds awaitCallback and stopCountdown, leaving three intervals of slack.
// The waits bound when a call is issued, not when it lands; the gates below
// handle a landing that reaches the previous deadline.
const (
	interval      = 500 * time.Millisecond
	resetAt       = 200 * time.Millisecond
	stopAt        = interval / 5
	callbackGrace = 4 * interval
)

// awaitCallback waits up to callbackGrace for one callback stamp
func awaitCallback(t *testing.T, called <-chan time.Time) time.Time {
	t.Helper()
	select {
	case at := <-called:
		return at
	case <-time.After(callbackGrace):
		t.Fatalf("countdown callback did not arrive within %v", callbackGrace)
		return time.Time{}
	}
}

// awaitCallbackAfter waits for a callback stamped after since. The stamp is
// taken inside the callback goroutine, so a stamp before since belongs to the
// previous schedule and shows up only when this test goroutine was starved.
// Callers gate on the reset landing rather than trusting this filter.
func awaitCallbackAfter(t *testing.T, called <-chan time.Time, since time.Time) time.Time {
	t.Helper()
	for {
		if at := awaitCallback(t, called); at.After(since) {
			return at
		}
	}
}

// stopCountdown stops the countdown unless the test already failed, and bounds
// the stop: a wedged timer loop makes StopTimer block forever instead of
// failing here, and the bound cannot tell that from a starved runner, so the
// message names both. It returns the instant StopTimer returned, or the zero
// time when the stop was skipped.
func stopCountdown(t *testing.T, c *CountdownTimer) time.Time {
	t.Helper()
	if t.Failed() {
		return time.Time{}
	}
	stopped := make(chan time.Time, 1)
	go func() {
		c.StopTimer()
		stopped <- time.Now()
	}()
	select {
	case at := <-stopped:
		return at
	case <-time.After(callbackGrace):
		t.Fatalf("StopTimer did not return within %v: the timer loop may be starved or wedged", callbackGrace)
		return time.Time{}
	}
}

func TestCountdownWillCallback(t *testing.T) {
	t.Parallel()

	var fakeI interface{}
	called := make(chan time.Time, 1)
	OnTimeoutFn := func(now time.Time, _ interface{}) error {
		called <- now
		return nil
	}

	countdown, err := NewExpCountDown(interval, 0, 0)
	require.NoError(t, err)
	countdown.OnTimeoutFn = OnTimeoutFn
	countdown.Reset(fakeI, 0, 0)
	defer stopCountdown(t, countdown)

	awaitCallback(t, called)
	t.Log("Times up, successfully called OnTimeoutFn")
}

func TestCountdownShouldReset(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		err  error
	}{
		{"callback returns nil", nil},
		{"callback returns error", errors.New("ERROR!")},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var fakeI interface{}
			called := make(chan time.Time, 1)
			OnTimeoutFn := func(now time.Time, _ interface{}) error {
				called <- now
				return test.err
			}

			countdown, err := NewExpCountDown(interval, 0, 0)
			require.NoError(t, err)
			countdown.OnTimeoutFn = OnTimeoutFn
			require.False(t, countdown.isInitilised())
			start := time.Now()
			countdown.Reset(fakeI, 0, 0)
			defer stopCountdown(t, countdown)
			require.True(t, countdown.isInitilised())

			// A callback here means the runner was starved past the first deadline, so
			// the stamp check below only catches an early fire within interval of start.
			select {
			case <-time.After(resetAt):
			case at := <-called:
				if at.Sub(start) < interval {
					t.Fatalf("countdown fired after %v, want at least %v", at.Sub(start), interval)
				}
			}
			firstResetAt := time.Now()
			countdown.Reset(fakeI, 0, 0)
			firstResetLandedAt := time.Now()

			// A landed reset arms a full interval, so a dropped or short rearm fails here;
			// callbacks stamped before firstResetAt are stale.
			first := awaitCallbackAfter(t, called, firstResetAt)
			// The first deadline is at least interval after start, so a landing before
			// that bound can only be followed by a callback from the schedule the reset
			// installed; a later landing may leave a stale stamp, so skip the floor.
			if firstResetLandedAt.Before(start.Add(interval)) {
				if first.Sub(firstResetAt) < interval {
					t.Fatalf("countdown fired %v after the mid-flight reset, want at least %v", first.Sub(firstResetAt), interval)
				}
			} else {
				t.Log("skipped the mid-flight reset floor: the reset landed at or past the lower bound of the first deadline")
			}
			require.True(t, countdown.isInitilised())
			t.Log("Correctly reset the countdown once")

			// The countdown auto-resets after the callback, so this explicit Reset must
			// not shorten the next wait: a landed reset arms a full interval, so a dropped
			// or short rearm fails here. A callback error is only logged, so both table
			// cases assert the same path.
			secondResetAt := time.Now()
			countdown.Reset(fakeI, 0, 0)
			secondResetLandedAt := time.Now()
			second := awaitCallbackAfter(t, called, secondResetAt)
			// first came from the schedule the mid-flight reset installed (timer.Stop in
			// the reset branch cancelled the original deadline), so that reset is at least
			// interval after start; the auto-rearm adds another interval, making the
			// pending deadline at least 2x interval after start. That is a lower bound, so
			// the gate may skip the floor while the real deadline is still ahead.
			if secondResetLandedAt.Before(start.Add(2 * interval)) {
				if second.Sub(secondResetAt) < interval {
					t.Fatalf("countdown fired %v after the second reset, want at least %v", second.Sub(secondResetAt), interval)
				}
			} else {
				t.Log("skipped the second reset floor: the reset landed at or past the lower bound of the deadline")
			}
			require.True(t, countdown.isInitilised())
			t.Log("Correctly reset the countdown second time")
		})
	}
}

func TestCountdownShouldBeAbleToStop(t *testing.T) {
	t.Parallel()

	var fakeI interface{}
	called := make(chan time.Time, 1)
	OnTimeoutFn := func(now time.Time, _ interface{}) error {
		called <- now
		return nil
	}

	countdown, err := NewExpCountDown(interval, 0, 0)
	require.NoError(t, err)
	countdown.OnTimeoutFn = OnTimeoutFn
	require.False(t, countdown.isInitilised())
	start := time.Now()
	countdown.Reset(fakeI, 0, 0)
	require.True(t, countdown.isInitilised())
	// Stop well before the callback fires. No defer: StopTimer runs once, and a
	// second call would block on quitc after startTimer returned. The call is
	// bounded, and StopTimer returns only after startTimer took the quit branch,
	// so the baseline below is the stop's completion, not its request: a callback
	// goroutine launched before the stop may stamp after the request and is
	// skipped, while one stamped after the completion fails. That holds only
	// while the stop completes before the lower bound of the first deadline, so a
	// later landing skips the check. The window is two and a half intervals: a
	// rearm that fires within two intervals lands inside it and fails, the extra
	// half interval is scheduler margin, and a rearm beyond the window fires
	// after the test returns.
	time.Sleep(stopAt)
	stopReturnedAt := stopCountdown(t, countdown)
	require.False(t, countdown.isInitilised())
	if !stopReturnedAt.Before(start.Add(interval)) {
		t.Log("skipped the after-stop check: the stop completed at or past the lower bound of the first deadline")
		return
	}
	deadline := time.After(2*interval + interval/2)
	for {
		select {
		case at := <-called:
			if at.After(stopReturnedAt) {
				t.Fatal("callback fired after the countdown was stopped")
			}
		case <-deadline:
			return
		}
	}
}

func TestCountdownShouldAvoidDeadlock(t *testing.T) {
	t.Parallel()

	var fakeI interface{}
	called := make(chan time.Time, 1)
	countdown, err := NewExpCountDown(interval, 0, 0)
	require.NoError(t, err)
	OnTimeoutFn := func(now time.Time, _ interface{}) error {
		countdown.Reset(fakeI, 0, 0)
		called <- now
		return nil
	}

	countdown.OnTimeoutFn = OnTimeoutFn
	countdown.Reset(fakeI, 0, 0)
	defer stopCountdown(t, countdown)
	awaitCallback(t, called)
}
