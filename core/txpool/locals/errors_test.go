// Copyright 2025 The go-ethereum Authors
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

package locals

import (
	"errors"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/core/txpool"
)

// TestIsTemporaryRejectExcludesMinGasPrice pins that a transaction priced below
// the gas schedule floor is not a temporary reject: the floor only rises as the
// chain advances, so retrying it cannot help and AddLocal must not track it.
func TestIsTemporaryRejectExcludesMinGasPrice(t *testing.T) {
	if IsTemporaryReject(txpool.ErrUnderMinGasPrice) {
		t.Error("ErrUnderMinGasPrice must not be a temporary reject")
	}
	// The pool's own price limit is a node local setting that can change, so it
	// stays retryable. The contrast is what the assertion above is about.
	if !IsTemporaryReject(txpool.ErrUnderpriced) {
		t.Error("ErrUnderpriced must remain a temporary reject")
	}
	if IsTemporaryReject(errors.New("unrelated failure")) {
		t.Error("an unrelated error must not be a temporary reject")
	}
}
