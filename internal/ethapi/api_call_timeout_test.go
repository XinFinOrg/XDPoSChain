package ethapi

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/XDCx"
	"github.com/XinFinOrg/XDPoSChain/XDCx/tradingstate"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/stretchr/testify/require"
)

// callTimeoutBackend is a Backend that executes the message on a real EVM and serves a
// fixed EVM timeout and gas cap, so the eth_call deadline can be observed.
type callTimeoutBackend struct {
	*callBackendMock
	timeout time.Duration
	gasCap  uint64
}

func (b *callTimeoutBackend) RPCEVMTimeout() time.Duration { return b.timeout }

func (b *callTimeoutBackend) RPCGasCap() uint64 { return b.gasCap }

// XDCxService needs a state cache: applyMessage reads the trading state root of the
// block, which resolves to the empty root for a block without trading transactions.
func (b *callTimeoutBackend) XDCxService() *XDCx.XDCX {
	return &XDCx.XDCX{StateCache: tradingstate.NewDatabase(rawdb.NewMemoryDatabase())}
}

func (b *callTimeoutBackend) GetEVM(ctx context.Context, statedb *state.StateDB, tradingStateDB *tradingstate.TradingStateDB, header *types.Header, vmConfig *vm.Config, blockContext *vm.BlockContext) (*vm.EVM, func() error, error) {
	return vm.NewEVM(*blockContext, statedb, tradingStateDB, b.ChainConfig(), *vmConfig), func() error { return nil }, nil
}

// TestCallVotingContractEVMTimeout checks that eth_call applies RPCEVMTimeout to the
// voting contract as well. The address used to be exempt, which let a caller keep an
// execution thread busy until the gas cap ran out (#2918).
func TestCallVotingContractEVMTimeout(t *testing.T) {
	t.Parallel()

	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()))
	require.NoError(t, err)
	// PUSH1 1 PUSH1 0 SSTORE writes a marker once. The abort stops the loop at the
	// next JUMP as a normal halt, so the marker survives; a timeout reported without
	// the contract code having run, or one whose state write was rolled back, fails
	// on it.
	// JUMPDEST PUSH1 5 JUMP: a loop only the deadline or the gas cap can end.
	code := []byte{0x60, 0x01, 0x60, 0x00, 0x55, 0x5b, 0x60, 0x05, 0x56}
	const timeout = 10 * time.Millisecond
	control := common.HexToAddress("0x2222222222222222222222222222222222222222")
	statedb.SetCode(common.MasternodeVotingSMCBinary, code)
	statedb.SetCode(control, code)

	header := &types.Header{Number: big.NewInt(1), GasLimit: 50_000_000, Time: 1, Difficulty: big.NewInt(1)}
	block := types.NewBlockWithHeader(header)
	from := common.HexToAddress("0x1111111111111111111111111111111111111111")

	for _, to := range []common.Address{common.MasternodeVotingSMCBinary, control} {
		backend := &callTimeoutBackend{
			callBackendMock: &callBackendMock{backendMock: newBackendMock(), stateDB: statedb, header: header, block: block},
			timeout:         timeout,
			gasCap:          50_000_000,
		}
		api := NewBlockChainAPI(backend, nil)

		// The outer deadline only keeps a regression from hanging the suite; a call that
		// runs into it fails the elapsed check instead of passing as a timeout.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		start := time.Now()
		_, err := api.Call(ctx, TransactionArgs{From: &from, To: &to}, nil, nil, nil)
		elapsed := time.Since(start)
		cancel()

		// The full message pins the deadline to the configured one: with the exemption back
		// the call ends on the gas cap and this substring is absent.
		require.ErrorContains(t, err, "execution aborted (timeout = 10ms)", "eth_call to %s", to.Hex())
		require.Less(t, elapsed, 2*time.Second, "eth_call to %s did not stop at the deadline", to.Hex())
		require.Equal(t, common.BigToHash(big.NewInt(1)), statedb.GetState(to, common.Hash{}), "eth_call to %s stopped before execution started", to.Hex())
	}
}
