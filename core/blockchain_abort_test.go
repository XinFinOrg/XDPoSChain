package core

import (
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/ethash"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// stopAwareVerifyEngine overrides VerifyHeaders to make the first batch block
// after its first result, so we can assert insertChain aborts before starting
// the second batch.
type stopAwareVerifyEngine struct {
	consensus.Engine

	mu                 sync.Mutex
	verifyCalls        int
	secondBatchStarted chan struct{}
	secondBatchOnce    sync.Once
	firstBatchStopped  chan struct{}
}

func (e *stopAwareVerifyEngine) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	e.mu.Lock()
	e.verifyCalls++
	call := e.verifyCalls
	e.mu.Unlock()

	abort := make(chan struct{})
	results := make(chan error, len(headers))

	switch call {
	case 1:
		go func() {
			if len(headers) > 0 {
				results <- errors.New("forced first-batch failure")
			}
			<-abort
			close(e.firstBatchStopped)
		}()
	default:
		e.secondBatchOnce.Do(func() { close(e.secondBatchStarted) })
		go func() {
			for range headers {
				select {
				case <-abort:
					return
				case results <- nil:
				}
			}
		}()
	}

	return abort, results
}

// firstBatchContinuationEngine tries to emit a second result from the same
// batch after a delay; if outer abort propagation works, that send must not
// happen.
type firstBatchContinuationEngine struct {
	consensus.Engine

	secondResultSent    chan struct{}
	allowSecondDecision chan struct{}
	secondDecisionDone  chan struct{}
	abortObserved       chan struct{}
}

func (e *firstBatchContinuationEngine) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))
	go func() {
		<-abort
		close(e.abortObserved)
	}()

	go func() {
		if len(headers) == 0 {
			close(e.secondDecisionDone)
			return
		}
		results <- errors.New("forced first-result failure")
		if len(headers) == 1 {
			close(e.secondDecisionDone)
			return
		}

		<-e.allowSecondDecision
		select {
		case <-abort:
		default:
			close(e.secondResultSent)
		}
		close(e.secondDecisionDone)
	}()

	return abort, results
}

func waitForSignal(t *testing.T, ch <-chan struct{}, name string) {
	t.Helper()
	timeout := 5 * time.Second
	if deadline, ok := t.Deadline(); ok {
		if remaining := time.Until(deadline) / 2; remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}
	select {
	case <-ch:
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func TestInsertChainAbortStopsBeforeSecondConsensusBatch(t *testing.T) {
	testdb := rawdb.NewMemoryDatabase()

	cfg := *params.TestXDPoSMockChainConfig
	xdposCfg := *cfg.XDPoS
	v2Src := xdposCfg.V2
	v2Cfg := &params.V2{
		SwitchEpoch:   v2Src.SwitchEpoch,
		SwitchBlock:   big.NewInt(2), // #1,#2 -> v1 batch; #3+ -> v2 batch
		CurrentConfig: v2Src.CurrentConfig,
		AllConfigs:    v2Src.AllConfigs,
	}
	v2Cfg.BuildConfigIndex()
	xdposCfg.V2 = v2Cfg
	cfg.XDPoS = &xdposCfg

	engine := &stopAwareVerifyEngine{
		Engine:             ethash.NewFaker(),
		secondBatchStarted: make(chan struct{}),
		firstBatchStopped:  make(chan struct{}),
	}

	gspec := &Genesis{Config: &cfg, ExtraData: make([]byte, 32+65)}
	genesis := gspec.MustCommit(testdb)
	blocks, _ := GenerateChain(&cfg, genesis, engine, testdb, 3, nil)

	bc, err := NewBlockChain(testdb, nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	defer bc.Stop()

	if _, err := bc.InsertChain(blocks); err == nil {
		t.Fatal("expected InsertChain to fail on forced first-batch error")
	}
	waitForSignal(t, engine.firstBatchStopped, "first batch stop after abort")

	select {
	case <-engine.secondBatchStarted:
		t.Fatal("second consensus batch started despite early abort")
	default:
	}
}

func TestInsertChainAbortStopsFirstBatchTrailingResults(t *testing.T) {
	testdb := rawdb.NewMemoryDatabase()

	cfg := *params.TestXDPoSMockChainConfig
	xdposCfg := *cfg.XDPoS
	v2Src := xdposCfg.V2
	v2Cfg := &params.V2{
		SwitchEpoch:   v2Src.SwitchEpoch,
		SwitchBlock:   big.NewInt(10), // all generated blocks stay in the first batch
		CurrentConfig: v2Src.CurrentConfig,
		AllConfigs:    v2Src.AllConfigs,
	}
	v2Cfg.BuildConfigIndex()
	xdposCfg.V2 = v2Cfg
	cfg.XDPoS = &xdposCfg

	engine := &firstBatchContinuationEngine{
		Engine:              ethash.NewFaker(),
		secondResultSent:    make(chan struct{}),
		allowSecondDecision: make(chan struct{}),
		secondDecisionDone:  make(chan struct{}),
		abortObserved:       make(chan struct{}),
	}

	gspec := &Genesis{Config: &cfg, ExtraData: make([]byte, 32+65)}
	genesis := gspec.MustCommit(testdb)
	blocks, _ := GenerateChain(&cfg, genesis, engine, testdb, 3, nil)

	bc, err := NewBlockChain(testdb, nil, gspec, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create blockchain: %v", err)
	}
	defer bc.Stop()

	if _, err := bc.InsertChain(blocks); err == nil {
		t.Fatal("expected InsertChain to fail on forced first-result failure")
	}
	waitForSignal(t, engine.abortObserved, "batch abort propagation")
	close(engine.allowSecondDecision)
	waitForSignal(t, engine.secondDecisionDone, "second-result decision")

	select {
	case <-engine.secondResultSent:
		t.Fatal("trailing result from first batch was emitted after abort")
	default:
	}
}
