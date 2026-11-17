// Copyright 2026 The XDPoSChain Authors
// This file is part of the XDPoSChain library.
//
// The XDPoSChain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The XDPoSChain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the XDPoSChain library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"errors"
	"math/big"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/XDCx/tradingstate"
	"github.com/XinFinOrg/XDPoSChain/XDCxlending/lendingstate"
	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/prque"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
)

var errXDCXProbeTouched = errors.New("xdcx probe service touched")

// probeTradingService records whether the XDCx trading state is read at all.
type probeTradingService struct {
	stateCalls int
	hasCalls   int
	rootCalls  int
	cacheCalls int
	hasState   bool
}

func (p *probeTradingService) GetTradingStateRoot(*types.Block, common.Address) (common.Hash, error) {
	p.rootCalls++
	return tradingstate.EmptyRoot, nil
}

func (p *probeTradingService) GetTradingState(*types.Block, common.Address) (*tradingstate.TradingStateDB, error) {
	p.stateCalls++
	return nil, errXDCXProbeTouched
}

func (p *probeTradingService) GetEmptyTradingState() (*tradingstate.TradingStateDB, error) {
	return nil, nil
}

func (p *probeTradingService) HasTradingState(*types.Block, common.Address) bool {
	p.hasCalls++
	return p.hasState
}

func (p *probeTradingService) GetStateCache() tradingstate.Database {
	p.cacheCalls++
	return nil
}

func (p *probeTradingService) GetTriegc() *prque.Prque[int64, common.Hash] { return nil }

func (p *probeTradingService) ApplyOrder(*types.Header, common.Address, consensus.ChainContext, *state.StateDB, *tradingstate.TradingStateDB, common.Hash, *tradingstate.OrderItem) ([]*tradingstate.OrderItem, error) {
	return nil, nil
}

func (p *probeTradingService) UpdateMediumPriceBeforeEpoch(uint64, *tradingstate.TradingStateDB, *state.StateDB) error {
	return nil
}

func (p *probeTradingService) GetTokenDecimal(consensus.ChainContext, *state.StateDB, common.Address) (*big.Int, error) {
	return nil, nil
}

// probeLendingService records whether the lending state is read at all.
type probeLendingService struct {
	stateCalls int
}

func (p *probeLendingService) GetLendingStateRoot(*types.Block, common.Address) (common.Hash, error) {
	return lendingstate.EmptyRoot, nil
}

func (p *probeLendingService) GetLendingState(*types.Block, common.Address) (*lendingstate.LendingStateDB, error) {
	p.stateCalls++
	return nil, errXDCXProbeTouched
}

func (p *probeLendingService) HasLendingState(*types.Block, common.Address) bool { return true }

func (p *probeLendingService) GetStateCache() lendingstate.Database { return nil }

func (p *probeLendingService) GetTriegc() *prque.Prque[int64, common.Hash] { return nil }

func (p *probeLendingService) ApplyOrder(*types.Header, common.Address, consensus.ChainContext, *state.StateDB, *lendingstate.LendingStateDB, *tradingstate.TradingStateDB, common.Hash, *lendingstate.LendingItem) ([]*lendingstate.LendingItem, error) {
	return nil, nil
}

func (p *probeLendingService) GetCollateralPrices(*types.Header, consensus.ChainContext, *state.StateDB, *tradingstate.TradingStateDB, common.Address, common.Address) (*big.Int, *big.Int, error) {
	return nil, nil, nil
}

func (p *probeLendingService) GetMediumTradePriceBeforeEpoch(consensus.ChainContext, *state.StateDB, *tradingstate.TradingStateDB, common.Address, common.Address) (*big.Int, error) {
	return nil, nil
}

func (p *probeLendingService) ProcessLiquidationData(*types.Header, consensus.ChainContext, *state.StateDB, *tradingstate.TradingStateDB, *lendingstate.LendingStateDB) (map[common.Hash]*lendingstate.LendingTrade, []*lendingstate.LendingTrade, []*lendingstate.LendingTrade, []*lendingstate.LendingTrade, []*lendingstate.LendingTrade, error) {
	return nil, nil, nil, nil, nil, nil
}

type xdcxTestChain struct {
	chain  *BlockChain
	blocks []*types.Block
	engine *XDPoS.XDPoS
}

// newXDCXTestChain opens the fixture chain with both XDCx disable forks at the
// same block, or with neither set.
func newXDCXTestChain(t *testing.T, receiverDisabled bool) *xdcxTestChain {
	t.Helper()

	if receiverDisabled {
		return newXDCXTestChainWithDisables(t, big.NewInt(0), big.NewInt(0))
	}
	return newXDCXTestChainWithDisables(t, nil, nil)
}

// positiveFork reports whether block is a configured fork above genesis.
func positiveFork(block *big.Int) bool {
	return block != nil && block.Sign() > 0
}

// newXDCXTestChainWithDisables opens a short-epoch XDPoS chain whose XDCx forks
// are already configured, and builds five blocks from genesis, the last of which
// carries one transaction to the trading batch address.
func newXDCXTestChainWithDisables(t *testing.T, minerDisableBlock, receiverDisableBlock *big.Int) *xdcxTestChain {
	t.Helper()

	cfg := params.TestXDPoSMockChainConfig.Clone()
	cfg.XDPoS.Epoch = 3
	cfg.XDPoS.Gap = 1
	cfg.XDPoS.SkipV1Validation = true
	cfg.TIPXDCXBlock = big.NewInt(0)
	cfg.TIPXDCXMinerDisableBlock = minerDisableBlock
	cfg.TIPXDCXReceiverDisableBlock = receiverDisableBlock
	if positiveFork(minerDisableBlock) || positiveFork(receiverDisableBlock) {
		// The fork-order check keeps the XDCx disable forks at or before the fee
		// market forks, so a window above the state height gate needs those later.
		late := big.NewInt(100)
		cfg.EIP1559Block = late
		cfg.CancunBlock = late
		cfg.PragueBlock = late
		cfg.OsakaBlock = late
		cfg.AmsterdamBlock = late
	}

	senderKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate the sender key: %v", err)
	}
	sender := crypto.PubkeyToAddress(senderKey.PublicKey)

	extraData := make([]byte, 32)
	for _, signer := range shortEpochMasternodes {
		extraData = append(extraData, signer.Bytes()...)
	}
	genesis := &Genesis{
		Alloc: types.GenesisAlloc{
			common.MasternodeVotingSMCBinary: {Storage: masternodeVotingStorage(shortEpochMasternodes)},
			sender:                           {Balance: big.NewInt(1e18)},
		},
		BaseFee:   big.NewInt(params.InitialBaseFee),
		Config:    cfg,
		ExtraData: extraData,
	}
	engine := XDPoS.NewFaker(rawdb.NewMemoryDatabase(), cfg)
	if engine == nil {
		t.Fatal("failed to create the XDPoS faker engine")
	}
	db := rawdb.NewMemoryDatabase()
	chain, err := NewBlockChain(db, nil, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("failed to create chain: %v", err)
	}
	t.Cleanup(chain.Stop)

	signerKey, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	if err != nil {
		t.Fatalf("failed to parse the signer key: %v", err)
	}
	tx, err := types.SignTx(
		types.NewTransaction(0, common.XDCXAddrBinary, common.Big0, params.TxGas, big.NewInt(params.InitialBaseFee), nil),
		types.LatestSigner(cfg), senderKey,
	)
	if err != nil {
		t.Fatalf("failed to sign the system transaction: %v", err)
	}

	var (
		blocks []*types.Block
		parent = genesis.ToBlock()
	)
	for i := 1; i <= 5; i++ {
		// The XDPoS generator returns its sealing errors through the batch; the
		// fixture seals the headers below and only needs the assembled block.
		generated, _ := GenerateChain(cfg, parent, engine, db, 1, func(_ int, b *BlockGen) {
			b.SetCoinbase(common.Address{0: byte(i)})
			b.SetExtra(make([]byte, 32+65))
			if i == 5 {
				b.AddTx(tx)
			}
		})
		if len(generated) != 1 {
			t.Fatalf("failed to generate block %d", i)
		}
		header := types.CopyHeader(generated[0].Header())
		seal, sealErr := crypto.Sign(engine.EngineV1.SigHash(header).Bytes(), signerKey)
		if sealErr != nil {
			t.Fatalf("failed to sign block %d: %v", i, sealErr)
		}
		copy(header.Extra[len(header.Extra)-65:], seal)
		parent = generated[0].WithSeal(header)
		blocks = append(blocks, parent)
	}
	if have := len(blocks[4].Transactions()); have != 1 {
		t.Fatalf("block 5 carries %d transactions, want 1", have)
	}
	if _, err := chain.InsertChain(blocks[:4]); err != nil {
		t.Fatalf("failed to insert the prefix chain: %v", err)
	}
	return &xdcxTestChain{chain: chain, blocks: blocks, engine: engine}
}

func (c *xdcxTestChain) setProbeServices(trading *probeTradingService, lending *probeLendingService) {
	c.engine.GetXDCXService = func() utils.TradingService { return trading }
	c.engine.GetLendingService = func() utils.LendingService { return lending }
}

// TestGetResultBlockSkipsXDCXAfterReceiverDisable pins that the broadcast import
// path stops reading XDCx state once the receiver fork is off.
func TestGetResultBlockSkipsXDCXAfterReceiverDisable(t *testing.T) {
	tests := []struct {
		name             string
		receiverDisabled bool
		wantCalls        bool
	}{
		{name: "receiver active", receiverDisabled: false, wantCalls: true},
		{name: "receiver disabled", receiverDisabled: true, wantCalls: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := newXDCXTestChain(t, tt.receiverDisabled)
			trading := &probeTradingService{hasState: true}
			lending := &probeLendingService{}
			chain.setProbeServices(trading, lending)

			_, _, _, err := chain.chain.getResultBlock(chain.blocks[4], false)
			if tt.wantCalls {
				if !errors.Is(err, errXDCXProbeTouched) {
					t.Fatalf("have error %v, want the probe service error", err)
				}
				if trading.stateCalls == 0 {
					t.Fatal("the trading state was not read while the receiver fork is active")
				}
				return
			}
			if err != nil {
				t.Fatalf("block rejected after the receiver disable fork: %v", err)
			}
			if trading.stateCalls != 0 || lending.stateCalls != 0 {
				t.Fatalf("XDCx state read after the receiver disable fork: trading %d, lending %d", trading.stateCalls, lending.stateCalls)
			}
		})
	}
}

// TestHasFullStateSkipsXDCXAfterReceiverDisable pins the parent-state probe the
// import paths use: a block past the receiver fork no longer needs XDCx state.
func TestHasFullStateSkipsXDCXAfterReceiverDisable(t *testing.T) {
	tests := []struct {
		name             string
		receiverDisabled bool
		want             bool
		wantCalls        bool
	}{
		{name: "receiver active", receiverDisabled: false, want: false, wantCalls: true},
		{name: "receiver disabled", receiverDisabled: true, want: true, wantCalls: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := newXDCXTestChain(t, tt.receiverDisabled)
			trading := &probeTradingService{hasState: false}
			chain.setProbeServices(trading, &probeLendingService{})

			if got := chain.chain.HasFullState(chain.blocks[3]); got != tt.want {
				t.Fatalf("HasFullState() = %v, want %v", got, tt.want)
			}
			if gotCalls := trading.hasCalls > 0; gotCalls != tt.wantCalls {
				t.Fatalf("trading state probed = %v, want %v", gotCalls, tt.wantCalls)
			}
		})
	}
}

// TestOrderAndLendingStateAtSkipXDCXAfterReceiverDisable pins that the state
// accessors the pools reset with stop reading the author-declared roots once the
// receiver fork is off.
func TestOrderAndLendingStateAtSkipXDCXAfterReceiverDisable(t *testing.T) {
	t.Run("receiver active", func(t *testing.T) {
		chain := newXDCXTestChain(t, false)
		trading := &probeTradingService{}
		lending := &probeLendingService{}
		chain.setProbeServices(trading, lending)

		if _, err := chain.chain.OrderStateAt(chain.blocks[3]); !errors.Is(err, errXDCXProbeTouched) {
			t.Fatalf("OrderStateAt error = %v, want the probe service error", err)
		}
		if _, err := chain.chain.LendingStateAt(chain.blocks[3]); !errors.Is(err, errXDCXProbeTouched) {
			t.Fatalf("LendingStateAt error = %v, want the probe service error", err)
		}
	})
	t.Run("receiver disabled", func(t *testing.T) {
		chain := newXDCXTestChain(t, true)
		trading := &probeTradingService{}
		lending := &probeLendingService{}
		chain.setProbeServices(trading, lending)

		if _, err := chain.chain.OrderStateAt(chain.blocks[3]); err != nil {
			t.Fatalf("OrderStateAt error after the receiver disable fork: %v", err)
		}
		if _, err := chain.chain.LendingStateAt(chain.blocks[3]); err == nil {
			t.Fatal("LendingStateAt must report no lending state after the receiver disable fork")
		}
		if trading.stateCalls != 0 || lending.stateCalls != 0 || trading.rootCalls != 0 {
			t.Fatalf("XDCx state read after the receiver disable fork: trading %d, lending %d, roots %d", trading.stateCalls, lending.stateCalls, trading.rootCalls)
		}
	})
}

// TestLoadLastStateSkipsXDCXAfterReceiverDisable pins the restart probe: a head
// past the receiver fork no longer needs the XDCx state roots its author declared.
func TestLoadLastStateSkipsXDCXAfterReceiverDisable(t *testing.T) {
	t.Run("receiver active", func(t *testing.T) {
		chain := newXDCXTestChain(t, false)
		trading := &probeTradingService{}
		chain.setProbeServices(trading, &probeLendingService{})

		if err := chain.chain.loadLastState(); err != nil {
			t.Fatalf("loadLastState failed: %v", err)
		}
		if trading.rootCalls == 0 {
			t.Fatal("the trading state root was not read while the receiver fork is active")
		}
	})
	t.Run("receiver disabled", func(t *testing.T) {
		chain := newXDCXTestChain(t, true)
		trading := &probeTradingService{}
		chain.setProbeServices(trading, &probeLendingService{})

		if err := chain.chain.loadLastState(); err != nil {
			t.Fatalf("loadLastState failed: %v", err)
		}
		if trading.rootCalls != 0 {
			t.Fatalf("trading state root read after the receiver disable fork: %d", trading.rootCalls)
		}
		if got := chain.chain.CurrentBlock().Number.Uint64(); got != chain.blocks[3].NumberU64() {
			t.Fatalf("head = %d, want %d", got, chain.blocks[3].NumberU64())
		}
	})
}

// TestSaveDataSkipsXDCXAfterReceiverDisable pins the shutdown flush: a node that
// stops past the receiver fork no longer fetches the XDCx trie handles, nor reads
// the roots their authors declared.
func TestSaveDataSkipsXDCXAfterReceiverDisable(t *testing.T) {
	tests := []struct {
		name             string
		receiverDisabled bool
		wantXDCX         bool
	}{
		{name: "receiver active", receiverDisabled: false, wantXDCX: true},
		{name: "receiver disabled", receiverDisabled: true, wantXDCX: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := newXDCXTestChain(t, tt.receiverDisabled)
			trading := &probeTradingService{}
			chain.setProbeServices(trading, &probeLendingService{})

			chain.chain.saveData()
			if got := trading.cacheCalls > 0; got != tt.wantXDCX {
				t.Fatalf("XDCx trie handles fetched = %v, want %v", got, tt.wantXDCX)
			}
			if got := trading.rootCalls > 0; got != tt.wantXDCX {
				t.Fatalf("XDCx roots read = %v, want %v", got, tt.wantXDCX)
			}
		})
	}
}

// TestSaveDataFlushesPreDisableRetainedRoots pins the other half of the shutdown
// flush: with the head at the receiver disable fork, the retained height below it
// is still behind the fork, so the flush has to fetch the handles to read its root.
func TestSaveDataFlushesPreDisableRetainedRoots(t *testing.T) {
	chain := newXDCXTestChainWithDisables(t, nil, big.NewInt(5))
	if _, err := chain.chain.InsertChain(chain.blocks[4:]); err != nil {
		t.Fatalf("failed to insert the fifth block: %v", err)
	}
	trading := &probeTradingService{}
	chain.setProbeServices(trading, &probeLendingService{})

	chain.chain.saveData()
	if trading.cacheCalls != 1 {
		t.Fatalf("XDCx trie handles fetched %d times, want 1", trading.cacheCalls)
	}
	if trading.rootCalls != 1 {
		t.Fatalf("XDCx roots read %d times, want 1", trading.rootCalls)
	}
	if trading.stateCalls != 0 {
		t.Fatalf("XDCx state read %d times, want 0", trading.stateCalls)
	}
}

// TestXDCXWindowStillReadsState pins the receiver half-window the miner fork
// leaves open: with the miner off and the receiver still on, core keeps reading
// XDCx state, and only the receiver fork stops it.
func TestXDCXWindowStillReadsState(t *testing.T) {
	// The fixture epoch is 3, so only blocks 4 and 5 are past the XDCx state
	// height gate; the miner fork is off at 2, the receiver fork at 5.
	chain := newXDCXTestChainWithDisables(t, big.NewInt(2), big.NewInt(5))
	trading := &probeTradingService{hasState: true}
	lending := &probeLendingService{}
	chain.setProbeServices(trading, lending)

	// Block 4 sits in the window: the miner no longer writes XDCx roots, but
	// the receiver still reads and validates them.
	if !chain.chain.HasFullState(chain.blocks[3]) {
		t.Fatal("HasFullState must probe XDCx state inside the miner-off, receiver-on window")
	}
	if trading.hasCalls == 0 {
		t.Fatal("the trading state was not probed inside the window")
	}
	if _, err := chain.chain.OrderStateAt(chain.blocks[3]); !errors.Is(err, errXDCXProbeTouched) {
		t.Fatalf("OrderStateAt error = %v, want the probe service error inside the window", err)
	}
	if _, err := chain.chain.LendingStateAt(chain.blocks[3]); !errors.Is(err, errXDCXProbeTouched) {
		t.Fatalf("LendingStateAt error = %v, want the probe service error inside the window", err)
	}

	// Block 5 is past the receiver fork: the EVM state alone must satisfy the
	// probes, and no XDCx read may happen.
	hasCalls, stateCalls := trading.hasCalls, trading.stateCalls
	if !chain.chain.HasFullState(chain.blocks[4]) {
		t.Fatal("HasFullState must be satisfied by the EVM state alone after the receiver fork")
	}
	if trading.hasCalls != hasCalls {
		t.Fatal("the trading state was probed after the receiver fork")
	}
	if _, err := chain.chain.OrderStateAt(chain.blocks[4]); err != nil {
		t.Fatalf("OrderStateAt error after the receiver fork: %v", err)
	}
	if trading.stateCalls != stateCalls {
		t.Fatal("the trading state was read after the receiver fork")
	}
}

// TestOrderStateAtWithoutService pins the missing-service fallback: an XDPoS
// engine without an XDCx service has to report an error, not dereference the
// nil service while constructing the empty trading state.
func TestOrderStateAtWithoutService(t *testing.T) {
	chain := newXDCXTestChain(t, true)
	// No probe services are installed here, so the engine answers nil.
	if _, err := chain.chain.OrderStateAt(chain.blocks[3]); err == nil {
		t.Fatal("OrderStateAt must report an error when the XDCx service is missing")
	}
}
