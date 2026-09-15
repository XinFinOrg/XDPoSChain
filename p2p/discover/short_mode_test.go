package discover

import "testing"

func skipLongInShortMode(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping long-running test in -short mode")
	}
}
