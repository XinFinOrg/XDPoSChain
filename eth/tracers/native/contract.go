package native

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync/atomic"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/eth/tracers"
)

func init() {
	tracers.DefaultDirectory.Register("contractTracer", NewContractTracer, false)
}

type contractTracer struct {
	env       *vm.EVM
	Addrs     map[string]string
	config    contractTracerConfig
	interrupt uint32 // Atomic flag to signal execution interruption
	reason    error  // Textual reason for the interruption
}

type contractTracerConfig struct {
	OpCode string `json:"opCode"` // Target opcode to trace
}

// NewContractTracer returns a native go tracer which tracks the contracr was created
func NewContractTracer(ctx *tracers.Context, cfg json.RawMessage) (tracers.Tracer, error) {
	var config contractTracerConfig
	if cfg != nil {
		if err := json.Unmarshal(cfg, &config); err != nil {
			return nil, err
		}
	}
	t := &contractTracer{
		Addrs:  make(map[string]string, 1),
		config: config,
	}
	// handle invalid opcode case
	op := vm.StringToOp(t.config.OpCode)
	if op == 0 && t.config.OpCode != "STOP" && t.config.OpCode != "" {
		t.reason = fmt.Errorf("opcode %s not defined", t.config.OpCode)
		return nil, t.reason
	}
	return t, nil
}

func (t *contractTracer) CaptureStart(env *vm.EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	t.env = env
	// When not searching for opcodes, record the contract address.
	if create && t.config.OpCode == "" {
		t.Addrs[addrToHex(to)] = ""
	}
}

func (t *contractTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {
}

func (*contractTracer) CaptureTxStart(gasLimit uint64) {}

func (*contractTracer) CaptureTxEnd(restGas uint64) {}

func (t *contractTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	// Skip if tracing was interrupted
	if atomic.LoadUint32(&t.interrupt) > 0 {
		t.env.Cancel()
		return
	}
	// If the OpCode is empty , exit early.
	if t.config.OpCode == "" {
		return
	}
	targetOp := vm.StringToOp(t.config.OpCode)
	if op == targetOp {
		addr := scope.Contract.Address()
		t.Addrs[addrToHex(addr)] = ""
	}
}

func (t *contractTracer) CaptureFault(pc uint64, op vm.OpCode, gas, cost uint64, _ *vm.ScopeContext, depth int, err error) {
}

func (t *contractTracer) CaptureEnter(typ vm.OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
}

func (t *contractTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
}

func (t *contractTracer) GetResult() (json.RawMessage, error) {
	// return Address array without duplicate address
	AddrArray := make([]string, 0, len(t.Addrs))
	for addr := range t.Addrs {
		AddrArray = append(AddrArray, addr)
	}

	res, err := json.Marshal(AddrArray)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(res), t.reason
}

func (t *contractTracer) Stop(err error) {
	t.reason = err
	atomic.StoreUint32(&t.interrupt, 1)
}

func addrToHex(a common.Address) string {
	return strings.ToLower(a.String0x())
}
