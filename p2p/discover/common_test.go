// Copyright 2019 The go-ethereum Authors
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

package discover

import (
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/p2p/enode"
)

// This test checks that a non-positive revalidation interval is replaced by the
// default. A negative value used to reach Table.nextRevalidateTime, where it
// panics in rand.Int63n on the Table.loop goroutine.
func TestConfigWithDefaultsPingInterval(t *testing.T) {
	tests := []struct {
		name     string
		interval time.Duration
		want     time.Duration
	}{
		{"zero", 0, revalidateInterval},
		{"negative", -time.Second, revalidateInterval},
		{"custom", 5 * time.Second, 5 * time.Second},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := Config{PingInterval: test.interval}
			if got := cfg.withDefaults().PingInterval; got != test.want {
				t.Fatalf("withDefaults PingInterval = %v, want %v", got, test.want)
			}
			db, err := enode.OpenDB("")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()

			tab, err := newTable(newPingRecorder(), db, Config{PingInterval: test.interval})
			if err != nil {
				t.Fatal(err)
			}
			if tab.pingInterval != test.want {
				t.Fatalf("table pingInterval = %v, want %v", tab.pingInterval, test.want)
			}
		})
	}
}
