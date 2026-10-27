// Copyright 2026 The go-ethereum Authors
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

package tracers

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/eth/tracers/logger"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// structLoggerLimit caps how much output the struct logger collects in the tests
// below. They trace a contract that only stops when its gas runs out, so with
// the default, unlimited logger every executed opcode is kept: over a hundred
// million entries, tens of gigabytes, which is enough to send the host into
// the OOM killer and take the desktop session with it. Nothing here inspects the
// collected logs, so bounding them leaves what the tests assert (the error and
// the elapsed time) untouched.
const structLoggerLimit = 1 << 20

// loopContractCode is a JUMP loop: JUMPDEST; PUSH1 0; JUMP. It only ever ends
// when the gas runs out or when the EVM is cancelled, so it stands in for a
// transaction whose trace would keep the node busy for a long time.
var loopContractCode = []byte{0x5b, 0x60, 0x00, 0x56}

// newTraceCancellationBackend returns a backend with an empty chain whose
// genesis holds a funded sender and a contract running loopContractCode.
func newTraceCancellationBackend(t *testing.T) (backend *testBackend, sender, contract common.Address) {
	t.Helper()

	accounts := newAccounts(1)
	sender, contract = accounts[0].addr, common.Address{0xcc}
	genesis := &core.Genesis{
		Config: params.TestChainConfig,
		Alloc: types.GenesisAlloc{
			sender:   {Balance: new(big.Int).Mul(big.NewInt(10000), big.NewInt(params.Ether))},
			contract: {Code: loopContractCode},
		},
	}
	return newTestBackend(t, 1, genesis, nil), sender, contract
}

// traceLoopContract runs a single trace of a call into the loop contract with
// the given gas limit and config, and returns what the tracer produced.
func traceLoopContract(ctx context.Context, t *testing.T, api *API, backend *testBackend, sender, contract common.Address, gas uint64, config *TraceConfig) (interface{}, error) {
	t.Helper()

	header := backend.chain.CurrentBlock()
	statedb, err := backend.chain.StateAt(header.Root)
	if err != nil {
		t.Fatalf("failed to open the state at #%d: %v", header.Number, err)
	}
	// The message is built by hand instead of through TransactionToMessage so
	// that the trace can be given more gas than the EIP-7825 per-transaction cap
	// allows. Without that the loop would end within a fraction of a second and
	// the difference between stopping a trace and letting it run could not be
	// observed. Everything else the message carries is what a plain call into
	// the contract would carry.
	message := &core.Message{
		From:      sender,
		To:        &contract,
		Nonce:     0,
		GasLimit:  gas,
		GasPrice:  header.BaseFee,
		GasFeeCap: header.BaseFee,
		GasTipCap: big.NewInt(0),
		Value:     big.NewInt(0),
		// The skipped checks are the EIP-7825 gas cap being bypassed on purpose
		// and the sender being an EOA, which the funded sender above is.
		SkipTransactionChecks: true,
	}
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    0,
		To:       &contract,
		Gas:      gas,
		GasPrice: header.BaseFee,
		Value:    big.NewInt(0),
	})
	txctx := &Context{
		BlockHash:   header.Hash(),
		BlockNumber: header.Number,
		TxHash:      tx.Hash(),
	}
	vmctx := core.NewEVMBlockContext(header, backend.chain, nil)
	return api.traceTx(ctx, tx, message, txctx, vmctx, statedb, config)
}

// TestTraceTxStopsWhenCallerCancels checks that a trace whose caller went away
// stops instead of running until the deadline it was given (#2640).
func TestTraceTxStopsWhenCallerCancels(t *testing.T) {
	backend, sender, contract := newTraceCancellationBackend(t)
	defer backend.teardown()
	api := NewAPI(backend)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	time.AfterFunc(20*time.Millisecond, cancel)

	start := time.Now()
	_, err := traceLoopContract(ctx, t, api, backend, sender, contract, 500_000_000, &TraceConfig{Config: &logger.Config{Limit: structLoggerLimit}})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("trace kept running after the caller went away")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("trace error does not wrap context.Canceled: %v", err)
	}
	// Running out of gas on its own takes the trace seconds; stopping it has to
	// happen orders of magnitude earlier than that.
	if elapsed > 500*time.Millisecond {
		t.Fatalf("trace kept running for %v after the caller went away", elapsed)
	}
}

// TestTraceTxStopsOnItsOwnTimeout checks that the per-transaction timeout still
// reports itself as such: the cancellation fix must not turn a timeout into a
// cancellation for the caller.
func TestTraceTxStopsOnItsOwnTimeout(t *testing.T) {
	backend, sender, contract := newTraceCancellationBackend(t)
	defer backend.teardown()
	api := NewAPI(backend)

	timeout := "50ms"
	start := time.Now()
	_, err := traceLoopContract(context.Background(), t, api, backend, sender, contract, 500_000_000, &TraceConfig{Timeout: &timeout, Config: &logger.Config{Limit: structLoggerLimit}})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("trace kept running past its timeout")
	}
	if err.Error() != "execution timeout" {
		t.Fatalf("trace timeout error is %q, want %q", err, "execution timeout")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("trace took %v to time out", elapsed)
	}
}

// TestTraceTxCompletesWhenCallerStays checks that a trace whose caller neither
// cancels nor lets the deadline pass still produces a result: the watcher must
// not stop an execution that is still wanted.
func TestTraceTxCompletesWhenCallerStays(t *testing.T) {
	backend, sender, contract := newTraceCancellationBackend(t)
	defer backend.teardown()
	api := NewAPI(backend)

	res, err := traceLoopContract(context.Background(), t, api, backend, sender, contract, 100_000, nil)
	if err != nil {
		t.Fatalf("uninterrupted trace failed: %v", err)
	}
	// The result sits behind an interface, so comparing it against nil cannot
	// catch a tracer that returned nothing: an interface holding a nil slice is
	// not nil. Check the concrete type and its length instead.
	raw, ok := res.(json.RawMessage)
	if !ok || len(raw) == 0 {
		t.Fatalf("uninterrupted trace produced no result (got %T, %d bytes)", res, len(raw))
	}
}

// resultPhaseTracerName is a tracer whose GetResult does not return until Stop
// releases it. It stands in for a JS tracer: GetResult runs the caller-supplied
// result() script, and Stop is the only way to interrupt that script, so a
// deadline that no longer reaches the result generation phase leaves it running
// as long as the script wants.
const resultPhaseTracerName = "resultPhaseTracer"

// resultPhaseStop receives the reason Stop was called with for the trace that is
// using resultPhaseTracerName. Tests using this tracer do not run in parallel.
var resultPhaseStop chan error

func init() {
	DefaultDirectory.Register(resultPhaseTracerName, func(*Context, json.RawMessage, *params.ChainConfig) (*Tracer, error) {
		return &Tracer{
			Hooks: &tracing.Hooks{},
			Stop: func(err error) {
				resultPhaseStop <- err
			},
			GetResult: func() (json.RawMessage, error) {
				select {
				case err := <-resultPhaseStop:
					return nil, err
				case <-time.After(2 * time.Second):
					// The deadline never reached this phase.
					return json.RawMessage("{}"), nil
				}
			},
		}, nil
	}, false)
}

// TestTraceTxInterruptsResultGeneration checks that the deadline still reaches
// GetResult after the EVM call returned. A JS tracer generates its result there
// by running caller-supplied code, so a watcher that stops watching as soon as
// the EVM execution is over lets that code run unbounded.
func TestTraceTxInterruptsResultGeneration(t *testing.T) {
	run := func(t *testing.T, ctx context.Context, config *TraceConfig, wantText string, want func(error) bool) {
		t.Helper()
		backend, sender, contract := newTraceCancellationBackend(t)
		defer backend.teardown()
		api := NewAPI(backend)
		resultPhaseStop = make(chan error, 1)

		start := time.Now()
		// A small gas limit: the EVM call is over long before the deadline, the
		// trace spends its time in GetResult, as it would with a slow JS script.
		_, err := traceLoopContract(ctx, t, api, backend, sender, contract, 30_000, config)
		elapsed := time.Since(start)

		if err == nil {
			t.Fatalf("result generation was not interrupted, trace took %v", elapsed)
		}
		if wantText != "" && err.Error() != wantText {
			t.Fatalf("trace error is %q, want %q", err, wantText)
		}
		if !want(err) {
			t.Fatalf("trace error %v does not match", err)
		}
		if elapsed > time.Second {
			t.Fatalf("trace took %v to stop", elapsed)
		}
	}
	t.Run("timeout", func(t *testing.T) {
		timeout := "200ms"
		name := resultPhaseTracerName
		run(t, context.Background(), &TraceConfig{Timeout: &timeout, Tracer: &name}, "execution timeout", func(error) bool { return true })
	})
	t.Run("caller-cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		time.AfterFunc(20*time.Millisecond, cancel)
		name := resultPhaseTracerName
		run(t, ctx, &TraceConfig{Tracer: &name}, "", func(err error) bool { return errors.Is(err, context.Canceled) })
	})
}
