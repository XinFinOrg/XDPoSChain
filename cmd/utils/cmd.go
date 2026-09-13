// Copyright 2014 The go-ethereum Authors
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

// Package utils contains internal helper functions for go-ethereum commands.
package utils

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/internal/debug"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/node"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

const (
	importBatchSize = 2500

	ChainConfigMismatchPolicyExitHint = "Hint: Use --chain-config-mismatch-policy to recover; Or restart with a matching XDC binary and the same network/genesis settings."

	// UnusableGapScheduleHint is the recovery path for a schedule that designates
	// no gap block. The schedule is persisted with the genesis, and a data
	// directory that already stored one keeps judging it as written, so fixing the
	// JSON is not enough on its own: re-running init on the data directory rewrites
	// the stored config, but only while the directory has produced no blocks. The
	// mismatch policy does not cover this check, because the schedule is judged
	// while the config is resolved, before a compatibility error exists.
	//
	// init takes the genesis as its only positional argument, so the hint names it:
	// "init --datadir <dir>" on its own only reports the missing argument. There is
	// no automatic backfill of a stored schedule, so that command is the whole
	// in-place recovery path and belongs in the release notes for the upgrade -
	// with the head == 0 boundary storedScheduleRecovery spells out.
	UnusableGapScheduleHint = "Hint: set XDPoS.Epoch >= 2 with 1 <= XDPoS.Gap < XDPoS.Epoch in the genesis, then " + storedScheduleRecovery + "."
)

// storedScheduleRecovery is the qualification every hint that sends an operator to
// re-run init has to carry. Re-running init rewrites the stored chain config only
// while the data directory has produced no blocks (head == 0): correcting a
// schedule changes XDPoS.Gap/XDPoS.Epoch (or the switch pair), which
// SetupGenesisBlock reports as a ConfigCompatError on a non-empty directory, so
// XDC init aborts with "Failed to write chain config" and writes nothing at all.
// The directory then has to be resynchronised from the corrected genesis. Kept in
// one place so the hints cannot drift back to the unconditional claim.
const storedScheduleRecovery = "re-run init on the data directory with that genesis file as its argument (XDC init --datadir <dir> <genesis.json>) rewrites it only while the directory has produced no blocks - once blocks have been imported the corrected schedule is a historical change, init refuses it with a compatibility error and writes nothing, so the directory has to be resynchronised from the corrected genesis"

// UnsetXDPoSEpochHint is the recovery path for a chain opened with a config whose
// XDPoS.Epoch was never filled in. Chain config validation deliberately leaves an
// omitted epoch for the engine, so the gap schedule can be perfectly usable and
// the config still carries the unset value into the constructor that refuses it:
// the missing value is a caller-side defect, not a schedule one, which is why it
// has its own sentinel and its own hint.
//
// The constructor-level message this hint is usually appended to already tells the
// caller to build the engine first and open through the resolved constructors, so
// the hint carries only what that message cannot say: which constructor resolves the
// default onto its own copy, why the unresolved constructors never see it, and the
// genesis-side alternative for a stored config that is the one missing the epoch. It
// is also attached to sentinel-carrying errors that are not that message, so it has
// to stand on its own. Built from params.DefaultXDPoSEpoch so the value it quotes
// cannot drift from the one the engine fills in.
var UnsetXDPoSEpochHint = fmt.Sprintf("Hint: the XDPoS config this chain is being opened with leaves XDPoS.Epoch unset, and the XDPoS engine fills %d in when it builds its own view of the config - XDPoS.New resolves the default onto its own copy and exposes it as XDPoS.ChainConfig(), so the config it was given is left untouched, while the unresolved constructors resolve their own config from the database or the supplied genesis and never see the fill. Alternatively, if the stored config is the one missing the epoch, write \"epoch\": %d into the genesis and "+storedScheduleRecovery+".", params.DefaultXDPoSEpoch, params.DefaultXDPoSEpoch)

// UnalignedSwitchBlockHint is the recovery path for a switch block that is not a
// multiple of the epoch the genesis writes out itself. It is the sibling of
// UnalignedSwitchBlockDefaultEpochHint: the same rule, judged against a number the
// file actually contains, so the hint can name the arithmetic to fix without
// explaining where the epoch came from. Correcting the block also moves the paired
// XDPoS.V2.SwitchEpoch - the two fields describe one schedule and the validation
// refuses a switch epoch that does not name the epoch its block falls on - which is
// why the hint names both fields.
var UnalignedSwitchBlockHint = "Hint: XDPoS.V2.SwitchBlock has to be a non-negative multiple of XDPoS.Epoch; set it accordingly, keep XDPoS.V2.SwitchEpoch equal to XDPoS.V2.SwitchBlock / XDPoS.Epoch, then " + storedScheduleRecovery + "."

// UnalignedSwitchBlockDefaultEpochHint is the recovery path for a switch block
// that is not a multiple of an epoch the genesis never wrote. The alignment
// message quotes params.DefaultXDPoSEpoch, the value
// CheckConfigForkOrderWithEpochDefault fills in because XDPoS.Epoch was omitted,
// and nothing else in the message says where that number came from. Built from
// that definition rather than spelled out so the hint cannot drift from the value
// the validator applies.
var UnalignedSwitchBlockDefaultEpochHint = fmt.Sprintf("Hint: XDPoS.Epoch %d in the message above is the engine default, not a value written in the genesis; either set XDPoS.V2.SwitchBlock to a multiple of %d, or write \"epoch\": %d to make the schedule self-describing.", params.DefaultXDPoSEpoch, params.DefaultXDPoSEpoch, params.DefaultXDPoSEpoch)

// UnusableGapScheduleDefaultEpochHint is the recovery path for a schedule that
// designates no gap block and was judged against the epoch the engine fills in
// because the genesis never wrote one. The message quotes
// params.DefaultXDPoSEpoch, a number that appears nowhere in the file, and the
// schedule is still the thing that has to change: the fix is the gap, not the
// epoch, so this hint names the usable range instead of only explaining the
// number. Built from that definition rather than spelled out so it cannot drift
// from the value the validator applies.
var UnusableGapScheduleDefaultEpochHint = fmt.Sprintf("Hint: XDPoS.Epoch %d in the message above is the engine default, not a value written in the genesis; the genesis designates no gap block, so set XDPoS.Gap to a value with 1 <= Gap < %d (writing \"epoch\": %d into the genesis spells the same epoch out explicitly), then "+storedScheduleRecovery+".", params.DefaultXDPoSEpoch, params.DefaultXDPoSEpoch, params.DefaultXDPoSEpoch)

// NegativeSwitchBlockHint is the recovery path for a switch block that carries a
// negative height. The field is read two ways and the readers disagree about the
// sign: XDPoS.V2.SwitchBlock.Uint64() folds -900 to 900, so the alignment rule
// accepted such a value while every comparison against the field kept treating it
// as a height that can never match. A data directory that already stored one keeps
// judging it as written, so the value has to be corrected in the genesis and
// re-applied with init - the same recovery path as an unusable gap schedule.
// Built from DefaultXDPoSEpoch so the multiple it names cannot drift from the
// epoch the built-in networks use.
var NegativeSwitchBlockHint = fmt.Sprintf("Hint: XDPoS.V2.SwitchBlock is a block height, so a negative value has no meaning on the chain; set it to a non-negative multiple of the effective XDPoS.Epoch in the genesis (%d on the built-in networks, and the engine default when the genesis omits the epoch), then "+storedScheduleRecovery+".", params.DefaultXDPoSEpoch)

// SwitchEpochMismatchHint is the recovery path for a switch epoch that does not
// name the epoch its switch block falls on. This defect is quieter than the ones
// above: the value is read by the v2 round arithmetic rather than by a guard, so
// the chain still starts and simply numbers its epochs differently from the
// schedule the genesis describes. The fix is the arithmetic, and the stored config
// is judged as written, so the hint names init the same way the schedule hints do.
//
// It is the hint for a config that spells its epoch out. The message names that
// epoch, so the arithmetic it asks for can be checked against the file; when the
// genesis omitted the epoch the validator judged the rule against the engine
// default instead and tags the rejection, which is what selects
// SwitchEpochMismatchAgainstDefaultEpochHint.
var SwitchEpochMismatchHint = "Hint: XDPoS.V2.SwitchEpoch has to equal XDPoS.V2.SwitchBlock / XDPoS.Epoch; correct it in the genesis, then " + storedScheduleRecovery + "."

// SwitchEpochMismatchAgainstDefaultEpochHint is the recovery path for a switch
// epoch that was judged against the epoch the engine fills in because the genesis
// never wrote one. The message quotes params.DefaultXDPoSEpoch, a number that
// appears nowhere in the file, and the pairing can look self-consistent against
// the epoch the file's author had in mind, so the hint names the number's origin
// and both ways out: spell the intended epoch out, or move the switch epoch onto
// the default's boundary. Built from that definition rather than spelled out so it
// cannot drift from the value the validator applies.
var SwitchEpochMismatchAgainstDefaultEpochHint = fmt.Sprintf("Hint: XDPoS.Epoch %d in the message above is the engine default, not a value written in the genesis, so XDPoS.V2.SwitchEpoch is being compared against a schedule the file does not describe; either write \"epoch\": <the epoch XDPoS.V2.SwitchEpoch names> into the genesis so the file spells that schedule out, or set XDPoS.V2.SwitchEpoch to XDPoS.V2.SwitchBlock / %d, then "+storedScheduleRecovery+".", params.DefaultXDPoSEpoch, params.DefaultXDPoSEpoch)

// MissingXDPoSConfigHint is the recovery path for a gap path reached with no XDPoS
// config at all. There is no schedule to repair and nothing in the genesis an
// operator could edit, so this hint names the constructor contract instead: the
// engine that runs the gap lookups has to be built with a config that carries the
// XDPoS section.
var MissingXDPoSConfigHint = "Hint: the XDPoS engine running this lookup was built without an XDPoS config, so it has no gap schedule to read; build it from a chain config that carries the XDPoS section (XDPoS.New, XDPoS.NewFaker or engine_v2.New) and open the chain with that same config."

// chainConfigErrorHints maps the XDPoS config sentinels to the operator-facing
// recovery path for each. The order is the priority: FormatChainConfigError returns
// the first row the error identifies.
//
// Two rules set that order. A *DefaultEpoch variant tags a rejection that was judged
// against the epoch the engine fills in, and its error identifies both the variant
// and the base sentinel it refines (Unwrap reports the pair), so a variant has to be
// listed before the sentinel it refines. An unset epoch and a missing config come
// before every schedule row because both are caller-side defects rather than schedule
// ones: the schedule itself may be perfectly usable, and no genesis field can fix
// either, so their hints name the constructor contract instead of sending an operator
// to edit a schedule that is not broken. An error carrying both families therefore
// resolves to the caller-side row, which is the defect the operator can act on.
//
// A new sentinel is a new row in this order rather than a new branch, which is what
// the ordering tests in cmd_test.go pin.
var chainConfigErrorHints = []struct {
	sentinel error
	hint     string
}{
	{params.ErrUnsetXDPoSEpoch, UnsetXDPoSEpochHint},
	{params.ErrMissingXDPoSConfig, MissingXDPoSConfigHint},
	{params.ErrUnusableGapScheduleDefaultEpoch, UnusableGapScheduleDefaultEpochHint},
	{params.ErrUnusableGapSchedule, UnusableGapScheduleHint},
	{params.ErrSwitchBlockUnalignedToDefaultEpoch, UnalignedSwitchBlockDefaultEpochHint},
	{params.ErrSwitchBlockUnalignedToEpoch, UnalignedSwitchBlockHint},
	{params.ErrNegativeSwitchBlock, NegativeSwitchBlockHint},
	{params.ErrSwitchEpochMismatchAgainstDefaultEpoch, SwitchEpochMismatchAgainstDefaultEpochHint},
	{params.ErrSwitchEpochMismatch, SwitchEpochMismatchHint},
}

// Fatalf formats a message to standard error and exits the program.
// The message is also printed to standard output if standard error
// is redirected to a different file.
func Fatalf(format string, args ...interface{}) {
	w := io.MultiWriter(os.Stdout, os.Stderr)
	if runtime.GOOS == "windows" {
		// The SameFile check below doesn't work on Windows.
		// stdout is unlikely to get redirected though, so just print there.
		w = os.Stdout
	} else {
		outf, _ := os.Stdout.Stat()
		errf, _ := os.Stderr.Stat()
		if outf != nil && errf != nil && os.SameFile(outf, errf) {
			w = os.Stderr
		}
	}
	fmt.Fprintf(w, "Fatal: "+format+"\n", args...)
	os.Exit(1)
}

// FormatChainConfigError appends an operator-facing migration hint when strict
// XDC fork-config validation rejects a legacy sparse config, and the recovery path
// when it refuses an unusable gap schedule, a gap schedule judged against the
// epoch the engine fills in, a switch block that is not aligned to its epoch -
// whether the config wrote that epoch out or the engine filled it in - a
// negative switch block, a switch epoch judged against the epoch the engine fills
// in, a switch epoch that does not name the epoch its block falls on, a gap lookup
// reached with no XDPoS config, or a chain opened with an unset epoch.
func FormatChainConfigError(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if errors.Is(err, core.ErrConfigMismatchPolicyExit) {
		exitText := core.ErrConfigMismatchPolicyExit.Error()
		guidance := ChainConfigMismatchPolicyExitHint
		prefix := exitText + ": "
		if after, ok := strings.CutPrefix(message, prefix); ok {
			details := strings.TrimSpace(after)
			if details == "" {
				return guidance
			}
			return details + ".\n" + guidance
		}
		if message == exitText {
			return guidance
		}
		return message + ". " + ChainConfigMismatchPolicyExitHint
	}
	for _, entry := range chainConfigErrorHints {
		if errors.Is(err, entry.sentinel) {
			return message + ". " + entry.hint
		}
	}
	if !errors.Is(err, params.ErrMissingForkSwitch) {
		return message
	}
	for _, field := range []string{
		"TIPTRC21FeeBlock",
		"Gas50xBlock",
		"TRC21IssuerSMC",
		"XDCXListingSMC",
		"RelayerRegistrationSMC",
		"LendingRegistrationSMC",
	} {
		if strings.Contains(message, field) {
			return message + ". Migration hint: ensure the persisted chain config or external genesis JSON includes TIPTRC21FeeBlock, Gas50xBlock, TRC21IssuerSMC, XDCXListingSMC, RelayerRegistrationSMC, and LendingRegistrationSMC. Older sparse custom XDPoS genesis files are auto-hydrated only when these keys are omitted."
		}
	}
	return message
}

func StartNode(stack *node.Node, isConsole bool) {
	if err := stack.Start(); err != nil {
		Fatalf("Error starting protocol stack: %v", err)
	}
	go func() {
		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sigc)

		shutdown := func() {
			log.Info("Got interrupt, shutting down...")
			go stack.Close()
			for i := 10; i > 0; i-- {
				<-sigc
				if i > 1 {
					log.Warn("Already shutting down, interrupt more to panic.", "times", i-1)
				}
			}
			debug.Exit() // ensure trace and CPU profile data is flushed.
			debug.LoudPanic("boom")
		}

		if isConsole {
			// In JS console mode, SIGINT is ignored because it's handled by the console.
			// However, SIGTERM still shuts down the node.
			for {
				sig := <-sigc
				if sig == syscall.SIGTERM {
					shutdown()
					return
				}
			}
		} else {
			<-sigc
			shutdown()
		}
	}()
}

func ImportChain(chain *core.BlockChain, fn string) error {
	// Watch for Ctrl-C while the import is running.
	// If a signal is received, the import will stop at the next batch.
	interrupt := make(chan os.Signal, 1)
	stop := make(chan struct{})
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(interrupt)
	defer close(interrupt)
	go func() {
		if _, ok := <-interrupt; ok {
			log.Info("Interrupted during import, stopping at next batch")
		}
		close(stop)
	}()
	checkInterrupt := func() bool {
		select {
		case <-stop:
			return true
		default:
			return false
		}
	}

	log.Info("Importing blockchain", "file", fn)

	// Open the file handle and potentially unwrap the gzip stream
	fh, err := os.Open(fn)
	if err != nil {
		return err
	}
	defer fh.Close()

	var reader io.Reader = fh
	if strings.HasSuffix(fn, ".gz") {
		if reader, err = gzip.NewReader(reader); err != nil {
			return err
		}
	}
	stream := rlp.NewStream(reader, 0)

	// Run actual the import.
	blocks := make(types.Blocks, importBatchSize)
	n := 0
	for batch := 0; ; batch++ {
		// Load a batch of RLP blocks.
		if checkInterrupt() {
			return errors.New("interrupted")
		}
		i := 0
		for ; i < importBatchSize; i++ {
			var b types.Block
			if err := stream.Decode(&b); err == io.EOF {
				break
			} else if err != nil {
				return fmt.Errorf("at block %d: %v", n, err)
			}
			// don't import first block
			if b.NumberU64() == 0 {
				i--
				continue
			}
			blocks[i] = &b
			n++
		}
		if i == 0 {
			break
		}
		// Import the batch.
		if checkInterrupt() {
			return errors.New("interrupted")
		}
		missing := missingBlocks(chain, blocks[:i])
		if len(missing) == 0 {
			log.Info("Skipping batch as all blocks present", "batch", batch, "first", blocks[0].Hash(), "last", blocks[i-1].Hash())
			continue
		}
		if _, err := chain.InsertChain(missing); err != nil {
			return fmt.Errorf("invalid block %d: %v", n, err)
		}
	}
	return nil
}

func missingBlocks(chain *core.BlockChain, blocks []*types.Block) []*types.Block {
	head := chain.CurrentBlock()
	for i, block := range blocks {
		// If we're behind the chain head, only check block, state is available at head
		if head.Number.Uint64() > block.NumberU64() {
			if !chain.HasBlock(block.Hash(), block.NumberU64()) {
				return blocks[i:]
			}
			continue
		}
		// If we're above the chain head, state availability is a must
		if !chain.HasBlockAndFullState(block.Hash(), block.NumberU64()) {
			return blocks[i:]
		}
	}
	return nil
}

// ExportChain exports a blockchain into the specified file, truncating any data
// already present in the file.
func ExportChain(blockchain *core.BlockChain, fn string) error {
	log.Info("Exporting blockchain", "file", fn)

	// Open the file handle and potentially wrap with a gzip stream
	fh, err := os.OpenFile(fn, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return err
	}
	defer fh.Close()

	var writer io.Writer = fh
	if strings.HasSuffix(fn, ".gz") {
		writer = gzip.NewWriter(writer)
		defer writer.(*gzip.Writer).Close()
	}
	// Iterate over the blocks and export them
	if err := blockchain.Export(writer); err != nil {
		return err
	}
	log.Info("Exported blockchain", "file", fn)

	return nil
}

// ExportAppendChain exports a blockchain into the specified file, appending to
// the file if data already exists in it.
func ExportAppendChain(blockchain *core.BlockChain, fn string, first uint64, last uint64) error {
	log.Info("Exporting blockchain", "file", fn)

	// Open the file handle and potentially wrap with a gzip stream
	fh, err := os.OpenFile(fn, os.O_CREATE|os.O_APPEND|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return err
	}
	defer fh.Close()

	var writer io.Writer = fh
	if strings.HasSuffix(fn, ".gz") {
		writer = gzip.NewWriter(writer)
		defer writer.(*gzip.Writer).Close()
	}
	// Iterate over the blocks and export them
	if err := blockchain.ExportN(writer, first, last); err != nil {
		return err
	}
	log.Info("Exported blockchain to", "file", fn)
	return nil
}

// ImportPreimages imports a batch of exported hash preimages into the database.
func ImportPreimages(db ethdb.Database, fn string) error {
	log.Info("Importing preimages", "file", fn)

	// Open the file handle and potentially unwrap the gzip stream
	fh, err := os.Open(fn)
	if err != nil {
		return err
	}
	defer fh.Close()

	var reader io.Reader = fh
	if strings.HasSuffix(fn, ".gz") {
		if reader, err = gzip.NewReader(reader); err != nil {
			return err
		}
	}
	stream := rlp.NewStream(reader, 0)

	// Import the preimages in batches to prevent disk trashing
	preimages := make(map[common.Hash][]byte)

	for {
		// Read the next entry and ensure it's not junk
		var blob []byte

		if err := stream.Decode(&blob); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		// Accumulate the preimages and flush when enough ws gathered
		preimages[crypto.Keccak256Hash(blob)] = common.CopyBytes(blob)
		if len(preimages) > 1024 {
			rawdb.WritePreimages(db, preimages)
			preimages = make(map[common.Hash][]byte)
		}
	}
	// Flush the last batch preimage data
	if len(preimages) > 0 {
		rawdb.WritePreimages(db, preimages)
	}
	return nil
}

// ExportPreimages exports all known hash preimages into the specified file,
// truncating any data already present in the file.
func ExportPreimages(db ethdb.Database, fn string) error {
	log.Info("Exporting preimages", "file", fn)

	// Open the file handle and potentially wrap with a gzip stream
	fh, err := os.OpenFile(fn, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return err
	}
	defer fh.Close()

	var writer io.Writer = fh
	if strings.HasSuffix(fn, ".gz") {
		writer = gzip.NewWriter(writer)
		defer writer.(*gzip.Writer).Close()
	}
	// Iterate over the preimages and export them
	it := db.NewIterator([]byte("secure-key-"), nil)
	defer it.Release()

	for it.Next() {
		if err := rlp.Encode(writer, it.Value()); err != nil {
			return err
		}
	}
	log.Info("Exported preimages", "file", fn)
	return nil
}
