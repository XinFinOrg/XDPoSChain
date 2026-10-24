// Copyright 2017 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"os"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/log"
)

// TestMain installs the handler the wizard tests read their refusals from. The
// tests that drive makeGenesis re-run this binary, and the text log.Crit and
// log.Warn write is the only report a refused run leaves behind; the root logger
// discards by default, so the test binary installs a handler itself instead of
// relying on a dependency's init to do it.
func TestMain(m *testing.M) {
	log.SetDefault(log.NewLogger(log.NewTerminalHandlerWithLevel(os.Stderr, log.LevelInfo, false)))
	os.Exit(m.Run())
}
