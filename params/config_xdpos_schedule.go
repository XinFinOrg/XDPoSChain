// Copyright 2016 The go-ethereum Authors
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

package params

import (
	"errors"
	"fmt"
	"math/big"
)

// ErrInvalidEpochGap reports an XDPoS chain config whose schedule cannot place
// a gap block inside an epoch.
var ErrInvalidEpochGap = errors.New("invalid XDPoS schedule")

// CheckSchedule enforces 0 < gap < epoch on an XDPoS schedule. A nil receiver
// is a chain config without an XDPoS section, which is not an XDPoS chain and
// is left alone. Outside the bound a schedule has no consistent meaning: the
// two gap predicates disagree on Gap == Epoch (isGapBlockNumber accepts it,
// isNextEpochGapBlock refuses it), and for Gap > Epoch the v1 engine's
// checkpoint-minus-Gap lookup addresses heights those predicates never report.
// A violating config is therefore rejected where it enters the chain rather
// than interpreted.
//
// ChainConfig.checkConfigForkOrder calls this just before the alignment check,
// so a config that declares no schedule is rejected here rather than left to
// the engines, which rewrite a missing epoch but never a missing gap.
//
// The refusal names the shape it found, because the four shapes need different
// answers: an unset epoch has to be supplied, an epoch of one cannot satisfy
// 1 <= gap < epoch at all, and Gap == Epoch is the one rejected shape whose
// trigger still matches a height - the epoch switch block, where the gap block
// would have to sample the candidate set the switch consumes.
func (c *XDPoSConfig) CheckSchedule() error {
	if c == nil {
		return nil
	}
	if c.Gap != 0 && c.Gap < c.Epoch {
		return nil
	}
	switch {
	case c.Epoch == 0:
		return fmt.Errorf("%w: XDPoS.Epoch is unset, so no gap block fits (want 1 <= Gap < Epoch)", ErrInvalidEpochGap)
	case c.Epoch == 1:
		return fmt.Errorf("%w: XDPoS.Epoch 1 leaves no gap block (want Epoch >= 2 so that 1 <= Gap < Epoch is satisfiable)", ErrInvalidEpochGap)
	case c.Gap == c.Epoch:
		return fmt.Errorf("%w: XDPoS.Gap %d puts the gap trigger on the epoch switch block, which would have to consume the candidate set it samples (want 1 <= Gap < Epoch)", ErrInvalidEpochGap, c.Gap)
	default:
		return fmt.Errorf("%w: XDPoS.Gap %d designates no gap block inside XDPoS.Epoch %d (want 1 <= Gap < Epoch)", ErrInvalidEpochGap, c.Gap, c.Epoch)
	}
}

// SwitchEpochFor returns the epoch number a switch block falls on under epoch,
// i.e. block/epoch, and whether that number fits in a uint64, i.e. whether
// XDPoS.V2.SwitchEpoch can equal it. It is the definition the puppeth wizard
// stores with the genesis, so the stored SwitchEpoch is the value a future
// validator re-derives instead of a second copy of the division.
//
// The judgement runs on the big.Int, so want is the epoch the block really falls
// on rather than the one its low 64 bits name; a want no uint64 can hold reports
// fits as false. A negative block keeps its sign (big.Int.Div is Euclidean) and
// reports false; judging the sign is not this rule's job.
func SwitchEpochFor(block *big.Int, epoch uint64) (*big.Int, bool) {
	if block == nil || epoch == 0 {
		return nil, false
	}
	want := new(big.Int).Div(block, new(big.Int).SetUint64(epoch))
	return want, want.IsUint64()
}

// CheckSwitchBlockAlignment enforces that block starts the v2 era on a whole
// epoch under epoch, i.e. block % epoch == 0. It is the one statement of the
// rule: ChainConfig.checkConfigForkOrder reaches it for every config it judges,
// and the puppeth wizard calls it at the prompt so an answer is refused where it
// is given rather than after the genesis contracts have been deployed.
//
// The remainder runs on the big.Int, so it is the block's real remainder rather
// than its low 64 bits. Euclidean Mod keeps the verdict sign-blind in the only
// sense this rule needs - a block and its absolute value are both multiples of
// the epoch or neither is - which is what lets a negative multiple of the epoch
// pass. That the sign is not judged here is deliberate: BlockConsensusVersion
// compares block > SwitchBlock, so a SwitchBlock of 0 still starts v1 at the
// genesis block and a negative block is the only spelling of "v2 from block 0" a
// config has, and the caller that needs a switch epoch judges it - the wizard
// refuses a typed negative block where it can still be corrected, and
// SwitchEpochFor reports the negative quotient as one no uint64 can hold.
//
// A positive block is judged by the epoch it names before the remainder runs: the
// quotient has to fit XDPoS.V2.SwitchEpoch, which is a uint64, so a block past
// 2^64 is refused unless its quotient still fits. The remainder is then taken on
// the same big.Int, so a block past 2^64 that passes the quotient check is
// aligned exactly when it really is a multiple of the epoch - the low 64 bits
// would accept or refuse it by a remainder it does not have.
//
// A nil block and a zero epoch are refused rather than dereferenced or divided
// by: both mean the config is missing the input the rule needs, so both carry
// ErrMissingForkSwitch like the other required-field refusals of
// CheckConfigForkOrder, and both are refused before this runs on a startup path.
func CheckSwitchBlockAlignment(block *big.Int, epoch uint64) error {
	if block == nil {
		return fmt.Errorf("%w: XDPoS.V2.SwitchBlock is unset", ErrMissingForkSwitch)
	}
	if epoch == 0 {
		return fmt.Errorf("%w: XDPoS.Epoch is unset, so no XDPoS.V2.SwitchBlock is aligned", ErrMissingForkSwitch)
	}
	if block.Sign() >= 0 {
		if _, fits := SwitchEpochFor(block, epoch); !fits {
			return fmt.Errorf("%w: XDPoS.V2.SwitchBlock %v names an epoch no uint64 can hold", ErrWrongForkSwitchOrder, block)
		}
	}
	if new(big.Int).Mod(block, new(big.Int).SetUint64(epoch)).Sign() != 0 {
		return fmt.Errorf("%w: XDPoS.V2.SwitchBlock %v not aligned to XDPoS.Epoch %d", ErrWrongForkSwitchOrder, block, epoch)
	}
	return nil
}
