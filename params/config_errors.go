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

import "errors"

// Chain config validation and resolution errors.
//
// The sentinels are declared here rather than next to the built-in network
// presets in config_networks.go: their consumers are the validation in this
// package and the engine packages that judge a config they are handed directly,
// so keeping them under the presets buried them among unrelated network data.
// Each rejection is documented at its declaration.

var (
	ErrMissingForkSwitch    = errors.New("missing fork switch")
	ErrWrongForkSwitchOrder = errors.New("wrong fork switch order")
	// ErrUnusableGapSchedule is returned when the XDPoS gap schedule designates
	// no gap block of its own, so the next-epoch masternode set can never be
	// prepared from one. Gap == Epoch is refused under this sentinel too: the
	// trigger then matches only the epoch switch block, which consumes that set
	// rather than carrying a gap block of its own.
	ErrUnusableGapSchedule = errors.New("unusable gap schedule")
	// ErrUnusableGapScheduleDefaultEpoch is returned next to
	// ErrUnusableGapSchedule when the unusable schedule was judged against the
	// default epoch CheckConfigForkOrderWithEpochDefault fills in, because the
	// config never wrote an epoch. The rejection quotes an epoch the genesis does
	// not contain, and this sentinel is what lets error formatting tell that case
	// apart from a config whose own epoch spells the epoch out.
	ErrUnusableGapScheduleDefaultEpoch = errors.New("unusable gap schedule against the default XDPoS epoch")
	// ErrUnsetXDPoSEpoch is returned when a chain is opened with an XDPoS config
	// that leaves Epoch unset. That state is not a schedule defect but the
	// caller's: chain config validation deliberately leaves an omitted epoch for
	// the XDPoS engine to fill, so a constructor that resolves its own config can
	// still carry the unset value into the divisions the gap trigger performs. It
	// stays apart from ErrUnusableGapSchedule so a caller can tell "the engine
	// never filled the epoch in" from "the schedule designates no gap block".
	ErrUnsetXDPoSEpoch = errors.New("unset XDPoS epoch")
	// ErrMissingXDPoSConfig is returned when a gap path is asked to resolve a height
	// with no XDPoS config at all. No schedule exists to repair, so it is not a
	// schedule defect but the caller's programming error: engine_v2.New refuses a
	// nil config before it can build an engine, so only a directly constructed one
	// reports this, and the hint that fits it names the constructor rather than a
	// genesis field. It stays apart from ErrUnusableGapSchedule so a caller can tell
	// "there is no schedule" from "the schedule designates no gap block".
	ErrMissingXDPoSConfig = errors.New("missing XDPoS config")
	// ErrSwitchBlockUnalignedToEpoch is returned next to ErrWrongForkSwitchOrder
	// when XDPoS.V2.SwitchBlock is not a multiple of the XDPoS.Epoch the config
	// writes out itself, i.e. the shape CheckSwitchBlockAlignment rejects for a
	// config that spells its epoch out. The rejection is both an ordering defect of
	// the field and the alignment rule's own defect, so it keeps matching the fork
	// order sentinel while error formatting can select the alignment recovery path
	// instead of falling through to the bare message: before this sentinel the same
	// defect carried a hint only when the genesis omitted the epoch and the
	// rejection was tagged as judged against the default, leaving the config that
	// spells the epoch out - the very shape the default-epoch hint asks the operator
	// to write - with no hint at all.
	ErrSwitchBlockUnalignedToEpoch = errors.New("switch block unaligned to the XDPoS epoch")
	// ErrSwitchBlockUnalignedToDefaultEpoch is returned next to
	// ErrWrongForkSwitchOrder when an epoch-less config's switch block is not a
	// multiple of the default epoch that CheckConfigForkOrderWithEpochDefault
	// fills in. The alignment message then quotes an epoch the config never wrote,
	// and this sentinel is what lets error formatting tell that case apart from an
	// alignment rejection of a config that spells its epoch out.
	ErrSwitchBlockUnalignedToDefaultEpoch = errors.New("switch block unaligned to the default XDPoS epoch")
	// ErrSwitchEpochMismatchAgainstDefaultEpoch is returned next to
	// ErrSwitchEpochMismatch when an epoch-less config's switch epoch was judged
	// against the default epoch CheckConfigForkOrderWithEpochDefault fills in. The
	// pairing is a defect of the schedule the engine will run either way, because
	// the engine fills that same default in - but the message divides by an epoch
	// the config never wrote, and this sentinel is what lets error formatting say
	// where that number came from instead of sending the operator after an
	// arithmetic error the file does not describe.
	ErrSwitchEpochMismatchAgainstDefaultEpoch = errors.New("switch epoch mismatch against the default XDPoS epoch")
	// ErrNegativeSwitchBlock is returned when XDPoS.V2.SwitchBlock is negative.
	// A negative height has no meaning on the chain, and the field's two readers
	// disagree about it: XDPoS.V2.SwitchBlock.Uint64() folds it to its absolute
	// value (so -900 would otherwise pass the epoch alignment rule), while the
	// comparisons against it (XDPoSConfig.BlockConsensusVersion, isEpochSwitchAtRound)
	// keep treating it as negative and can never match. Refusing it is what keeps the
	// field to a single meaning, and both entry points that judge the field do so:
	// CheckConfigForkOrder, so the defect stays a defect of the config rather than an
	// artifact of the default epoch, and CheckSwitchBlockAlignment, which is the only
	// judgement a directly constructed engine_v2 makes. It stays apart from
	// ErrWrongForkSwitchOrder the way ErrSwitchEpochMismatch does: a sign is not an
	// ordering defect, and the two sentinels select different recovery hints.
	ErrNegativeSwitchBlock = errors.New("negative XDPoS switch block")
	// ErrSwitchEpochMismatch is returned when XDPoS.V2.SwitchEpoch does not name
	// the epoch XDPoS.V2.SwitchBlock falls on, i.e. SwitchEpoch !=
	// SwitchBlock / Epoch. The two fields describe one schedule: SwitchBlock is
	// the height v2 activates at and SwitchEpoch is the epoch number the v2 round
	// arithmetic adds to round/Epoch (isEpochSwitchAtRound and the epoch-switch
	// lookups of the v2 engine), so keeping them apart renumbers every epoch the
	// chain reports while every other rule still passes. It stays apart from
	// ErrWrongForkSwitchOrder so error formatting can name the arithmetic the
	// operator has to fix instead of the fork order, which is fine as it stands.
	ErrSwitchEpochMismatch = errors.New("switch epoch does not match the switch block")
)
