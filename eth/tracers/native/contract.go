package native

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync/atomic"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/eth/tracers"
	"github.com/XinFinOrg/XDPoSChain/params"
)

func init() {
	tracers.DefaultDirectory.Register("contractTracer", NewContractTracer, false)
}

type contractTracer struct {
	Addrs     map[string]string
	config    contractTracerConfig
	interrupt uint32 // Atomic flag to signal execution interruption
	reason    error  // Textual reason for the interruption
}

type contractTracerConfig struct {
	OpCode string `json:"opCode"` // Target opcode to trace
}

// NewContractTracer returns a native go tracer which tracks the contractor was created
func NewContractTracer(ctx *tracers.Context, cfg json.RawMessage, _ *params.ChainConfig) (*tracers.Tracer, error) {
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
	return &tracers.Tracer{
		Hooks: &tracing.Hooks{
			OnTxStart: t.OnTxStart,
			OnTxEnd:   t.OnTxEnd,
			OnEnter:   t.OnEnter,
			OnExit:    t.OnExit,
			OnOpcode:  t.OnOpcode,
			OnFault:   t.OnFault,
		},
		GetResult: t.GetResult,
		Stop:      t.Stop,
	}, nil
}

func (*contractTracer) OnTxStart(env *tracing.VMContext, tx *types.Transaction, from common.Address) {
}

func (*contractTracer) OnTxEnd(receipt *types.Receipt, err error) {}

func (t *contractTracer) OnOpcode(pc uint64, opcode byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
	// Skip if tracing was interrupted
	if atomic.LoadUint32(&t.interrupt) > 0 {
		return
	}
	// If the OpCode is empty , exit early.
	if t.config.OpCode == "" {
		return
	}
	targetOp := vm.StringToOp(t.config.OpCode)
	op := vm.OpCode(opcode)
	if op == targetOp {
		addr := scope.Address()
		t.Addrs[addrToHex(addr)] = ""
	}
}

func (t *contractTracer) OnFault(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, depth int, err error) {
}

func (t *contractTracer) OnEnter(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	create := vm.OpCode(typ) == vm.CREATE
	if create && t.config.OpCode == "" {
		t.Addrs[addrToHex(to)] = ""
	}
}

func (t *contractTracer) OnExit(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
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
