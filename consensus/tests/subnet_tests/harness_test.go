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

package subnet_tests

import (
	"crypto/ecdsa"
	"encoding/json"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/engines/engine_v2"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/eth/hooks"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/params"
)

// The harness builds subnet blocks the way the subnet specification describes
// them, without going through the engine's Prepare: it signs the quorum
// certificates with the masternodes of the parent's epoch, seals with the
// leader of the round and fills the subnet header fields from the snapshots
// and penalties the chain stored. The tests then assert those values against
// independent expectations and feed the blocks to the real import path.

const (
	testEpoch    = 20
	testGap      = 10
	testPeriod   = 2
	testGasLimit = 420000000
)

var testFoundation = common.HexToAddress("0x00000000000000000000000000000000000000f0")

type testNode struct {
	key   *ecdsa.PrivateKey
	addr  common.Address
	stake *big.Int
}

type subnetHarness struct {
	t      *testing.T
	config *params.ChainConfig
	db     ethdb.Database
	bc     *core.BlockChain
	engine *XDPoS.XDPoS

	nodes      []*testNode // candidates of the validator contract
	byAddr     map[common.Address]*testNode
	genesisMNs []common.Address

	offline map[common.Address]bool // masternodes whose rounds are skipped
	round   map[common.Hash]types.Round
}

// subnetTestConfig returns a subnet chain config with the given masternode cap.
func subnetTestConfig(maxMasternodes int) *params.ChainConfig {
	cfg := params.LocalnetChainConfig.Clone()
	cfg.ChainID = big.NewInt(18448)
	// The subnet header has no base fee, and the forks from Cancun on build on
	// EIP-1559.
	cfg.EIP1559Block = nil
	cfg.Gas2500xBlock = nil
	cfg.CancunBlock = nil
	cfg.PragueBlock = nil
	cfg.OsakaBlock = nil
	cfg.AmsterdamBlock = nil
	cfg.TIPFixedRewardBlock = nil
	cfg.TIPProportionalRewardBlock = nil
	cfg.TIPEpochHalvingBlock = nil
	cfg.TIPUpgradePenaltyBlock = nil
	cfg.TIPNoHalvingMNRewardBlock = big.NewInt(0)

	v2cfg := params.LocalnetV2Configs[0].Clone()
	v2cfg.MaxMasternodes = maxMasternodes
	v2cfg.MinePeriod = testPeriod
	v2cfg.CertThreshold = 0.667
	cfg.XDPoS = &params.XDPoSConfig{
		Period:               testPeriod,
		Epoch:                testEpoch,
		Reward:               10,
		RewardCheckpoint:     testEpoch,
		Gap:                  testGap,
		FoundationWalletAddr: testFoundation,
		MaxMasternodesV2:     maxMasternodes,
		IsSubnet:             true,
		V2: &params.V2{
			SwitchBlock:   big.NewInt(0),
			CurrentConfig: v2cfg,
			AllConfigs:    map[uint64]*params.V2Config{0: v2cfg},
		},
	}
	cfg.XDPoS.V2.BuildConfigIndex()
	return cfg
}

// newSubnetHarness starts a subnet chain whose validator contract holds one
// candidate per stake, in decreasing stake order, and whose genesis lists the
// first genesisMNs candidates as masternodes.
func newSubnetHarness(t *testing.T, maxMasternodes int, stakes []int64, genesisMNs int) *subnetHarness {
	t.Helper()
	h := &subnetHarness{
		t:       t,
		config:  subnetTestConfig(maxMasternodes),
		db:      rawdb.NewMemoryDatabase(),
		byAddr:  make(map[common.Address]*testNode),
		offline: make(map[common.Address]bool),
		round:   make(map[common.Hash]types.Round),
	}
	for _, stake := range stakes {
		key, _ := crypto.GenerateKey()
		n := &testNode{key: key, addr: crypto.PubkeyToAddress(key.PublicKey), stake: new(big.Int).Mul(big.NewInt(stake), big.NewInt(1e18))}
		h.nodes = append(h.nodes, n)
		h.byAddr[n.addr] = n
	}
	for _, n := range h.nodes[:genesisMNs] {
		h.genesisMNs = append(h.genesisMNs, n.addr)
	}

	genesis := &core.Genesis{
		Config:     h.config,
		Timestamp:  uint64(time.Now().Unix()) - 1_000_000,
		ExtraData:  genesisExtra(h.genesisMNs),
		GasLimit:   testGasLimit,
		Difficulty: big.NewInt(1),
		Alloc:      types.GenesisAlloc{common.MasternodeVotingSMCBinary: {Balance: big.NewInt(0), Storage: subnetValidatorStorage(h.nodes)}},
	}
	for _, n := range h.nodes {
		genesis.Alloc[n.addr] = types.Account{Balance: new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))}
	}

	engine, err := XDPoS.New(h.config, h.db)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	bc, err := core.NewBlockChain(h.db, nil, genesis, engine, vm.Config{})
	if err != nil {
		t.Fatalf("blockchain: %v", err)
	}
	t.Cleanup(bc.Stop)
	hooks.AttachConsensusV2Hooks(engine, bc, h.config)
	h.bc, h.engine = bc, engine
	// A node initialises the engine from its head at startup.
	if err := engine.Initial(bc, bc.CurrentBlock()); err != nil {
		t.Fatalf("initial: %v", err)
	}
	// The engine broadcasts its own timeouts and votes; nobody listens here.
	go func() {
		for range engine.EngineV2.BroadcastCh {
		}
	}()
	go func() {
		for range engine.MinePeriodCh {
		}
	}()
	go func() {
		for range engine.NewRoundCh {
		}
	}()
	return h
}

// genesisExtra lays out the genesis masternodes the way the v1 extra data does:
// 32 bytes of vanity, the addresses, 65 bytes of seal.
func genesisExtra(masternodes []common.Address) []byte {
	extra := make([]byte, utils.ExtraVanity)
	for _, mn := range masternodes {
		extra = append(extra, mn[:]...)
	}
	return append(extra, make([]byte, utils.ExtraSeal)...)
}

// subnetValidatorStorage lays out the storage of the subnet validator contract
// for the given candidates: the candidates array at slot 7 and, per candidate,
// validatorsState (slot 1) with the owner (each candidate owns itself) and cap.
func subnetValidatorStorage(nodes []*testNode) map[common.Hash]common.Hash {
	storage := map[common.Hash]common.Hash{
		common.BigToHash(big.NewInt(7)): common.BigToHash(big.NewInt(int64(len(nodes)))),
	}
	arrayStart := new(big.Int).SetBytes(crypto.Keccak256(common.BigToHash(big.NewInt(7)).Bytes()))
	for i, n := range nodes {
		storage[common.BigToHash(new(big.Int).Add(arrayStart, big.NewInt(int64(i))))] = common.BytesToHash(n.addr.Bytes())
		stateSlot := new(big.Int).SetBytes(crypto.Keccak256(common.BytesToHash(n.addr.Bytes()).Bytes(), common.BigToHash(big.NewInt(1)).Bytes()))
		ownerAndFlag := new(big.Int).SetBytes(n.addr.Bytes())
		ownerAndFlag.SetBit(ownerAndFlag, 160, 1) // isCandidate, packed after the owner
		storage[common.BigToHash(stateSlot)] = common.BigToHash(ownerAndFlag)
		storage[common.BigToHash(new(big.Int).Add(stateSlot, big.NewInt(1)))] = common.BigToHash(n.stake)
	}
	return storage
}

func (h *subnetHarness) addrs(nodes []*testNode) []common.Address {
	out := make([]common.Address, len(nodes))
	for i, n := range nodes {
		out[i] = n.addr
	}
	return out
}

func (h *subnetHarness) head() *types.Block {
	return h.bc.GetBlockByHash(h.bc.CurrentBlock().Hash())
}

// storedSnapshot reads the snapshot the chain stored for a gap block.
func (h *subnetHarness) storedSnapshot(gapHash common.Hash) *engine_v2.SnapshotV2 {
	h.t.Helper()
	blob, err := rawdb.ReadXdposV2Snapshot(h.db, gapHash)
	if err != nil {
		h.t.Fatalf("no snapshot stored for gap block %s: %v", gapHash.Hex(), err)
	}
	snap := new(engine_v2.SnapshotV2)
	if err := json.Unmarshal(blob, snap); err != nil {
		h.t.Fatal(err)
	}
	return snap
}

// masternodesOf returns the masternodes of the epoch the block at number on
// the chain of parent belongs to, read from its epoch switch header.
func (h *subnetHarness) masternodesOf(header *types.Header) []common.Address {
	for header.Number.Uint64()%testEpoch != 0 {
		header = h.bc.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	}
	if header.Number.Sign() == 0 {
		return h.genesisMNs
	}
	return common.ExtractAddressFromBytes(header.Validators)
}

// expectedMasternodes computes, from the stored snapshot of its gap block, the
// masternodes of the epoch that starts at number on top of parent.
func (h *subnetHarness) expectedMasternodes(parent *types.Header, number uint64) []common.Address {
	gap := h.ancestor(parent, number-testGap)
	snap := h.storedSnapshot(gap.Hash())
	var mns []common.Address
	for _, c := range snap.NextEpochCandidates {
		if !slices.Contains(snap.NextEpochPenalties, c) && len(mns) < h.config.XDPoS.V2.Config(0).MaxMasternodes {
			mns = append(mns, c)
		}
	}
	return mns
}

func (h *subnetHarness) ancestor(header *types.Header, number uint64) *types.Header {
	for header.Number.Uint64() > number {
		header = h.bc.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	}
	return header
}

// blockOpts tweaks a block before it is sealed, so tests can build invalid ones.
type blockOpts struct {
	round  types.Round // 0: the first round after the parent's that has an online leader
	txs    func(header *types.Header) []*types.Transaction
	mutate func(header *types.Header)
}

// buildBlock builds and seals the child of parent.
func (h *subnetHarness) buildBlock(parent *types.Block, opts blockOpts) *types.Block {
	h.t.Helper()
	number := parent.NumberU64() + 1
	parentRound := h.round[parent.Hash()]

	var masternodes []common.Address
	if number%testEpoch == 0 {
		masternodes = h.expectedMasternodes(parent.Header(), number)
	} else {
		masternodes = h.masternodesOf(parent.Header())
	}
	round := opts.round
	if round == 0 {
		round = parentRound + 1
		for h.offline[masternodes[uint64(round)%testEpoch%uint64(len(masternodes))]] {
			round++
		}
	}
	leader := h.byAddr[masternodes[uint64(round)%testEpoch%uint64(len(masternodes))]]

	header := &types.Header{
		ParentHash: parent.Hash(),
		UncleHash:  types.EmptyUncleHash,
		Coinbase:   leader.addr,
		Difficulty: big.NewInt(1),
		Number:     new(big.Int).SetUint64(number),
		GasLimit:   testGasLimit,
		Time:       parent.Time() + testPeriod,
		Extra:      h.extra(parent, round),
		Subnet:     true,
	}
	if number%testEpoch == 0 {
		header.Validators = types.PackAddresses(masternodes)
	}
	if number == 1 {
		header.NextValidators = types.PackAddresses(h.genesisMNs)
	} else if number%testEpoch == testEpoch-testGap+1 {
		snap := h.storedSnapshot(parent.Hash())
		header.NextValidators = types.PackAddresses(snap.NextEpochCandidates)
		header.Penalties = types.PackAddresses(snap.NextEpochPenalties)
	}

	statedb, err := h.bc.StateAt(parent.Root())
	if err != nil {
		h.t.Fatal(err)
	}
	parentState := statedb.Copy()
	var (
		txs      []*types.Transaction
		receipts []*types.Receipt
		usedGas  = new(uint64)
	)
	if opts.txs != nil {
		txs = opts.txs(header)
		gp := new(core.GasPool).AddGas(header.GasLimit)
		for i, tx := range txs {
			statedb.SetTxContext(tx.Hash(), i)
			evm := vm.NewEVM(core.NewEVMBlockContext(header, h.bc, &header.Coinbase), statedb, nil, h.config, vm.Config{})
			receipt, _, _, err := core.ApplyTransaction(nil, evm, gp, statedb, header, tx, usedGas)
			if err != nil {
				h.t.Fatalf("apply tx: %v", err)
			}
			receipts = append(receipts, receipt)
		}
		header.GasUsed = *usedGas
	}
	if opts.mutate != nil {
		opts.mutate(header)
	}
	block, err := h.engine.Finalize(h.bc, header, statedb, parentState, txs, nil, receipts)
	if err != nil {
		h.t.Fatalf("finalize block %d: %v", number, err)
	}
	header = block.Header()
	h.seal(header, leader.key)
	block = block.WithSeal(header)
	h.round[block.Hash()] = round
	return block
}

// extra encodes the round and a quorum certificate for parent.
func (h *subnetHarness) extra(parent *types.Block, round types.Round) []byte {
	h.t.Helper()
	extra, err := (&types.ExtraFields_v2{Round: round, QuorumCert: h.quorumCert(parent)}).EncodeToBytes()
	if err != nil {
		h.t.Fatal(err)
	}
	return extra
}

// quorumCert returns a quorum certificate for block, signed by the online
// masternodes of its epoch.
func (h *subnetHarness) quorumCert(parent *types.Block) *types.QuorumCert {
	h.t.Helper()
	parentNumber := parent.NumberU64()
	gapNumber := uint64(0)
	if switchNumber := parentNumber - parentNumber%testEpoch; switchNumber > testGap {
		gapNumber = switchNumber - testGap
	}
	info := &types.BlockInfo{Hash: parent.Hash(), Round: h.round[parent.Hash()], Number: parent.Number()}
	signHash := types.VoteSigHash(&types.VoteForSign{ProposedBlockInfo: info, GapNumber: gapNumber})
	var signatures []types.Signature
	for _, mn := range h.masternodesOf(parent.Header()) {
		if h.offline[mn] {
			continue
		}
		sig, err := crypto.Sign(signHash.Bytes(), h.byAddr[mn].key)
		if err != nil {
			h.t.Fatal(err)
		}
		signatures = append(signatures, sig)
	}
	qc := &types.QuorumCert{ProposedBlockInfo: info, Signatures: signatures, GapNumber: gapNumber}
	if parentNumber == 0 {
		qc.Signatures = nil
	}
	return qc
}

func (h *subnetHarness) seal(header *types.Header, key *ecdsa.PrivateKey) {
	h.t.Helper()
	sealHash, err := header.SubnetSealHash()
	if err != nil {
		h.t.Fatal(err)
	}
	sig, err := crypto.Sign(sealHash.Bytes(), key)
	if err != nil {
		h.t.Fatal(err)
	}
	header.Validator = sig
}

// insert imports a block and fails the test on error.
func (h *subnetHarness) insert(block *types.Block) {
	h.t.Helper()
	if _, err := h.bc.InsertChain(types.Blocks{block}); err != nil {
		h.t.Fatalf("insert block %d: %v", block.NumberU64(), err)
	}
}

// extend builds and imports blocks on the head until it reaches number.
func (h *subnetHarness) extend(number uint64, opts func(n uint64) blockOpts) {
	h.t.Helper()
	for h.head().NumberU64() < number {
		var o blockOpts
		if opts != nil {
			o = opts(h.head().NumberU64() + 1)
		}
		h.insert(h.buildBlock(h.head(), o))
	}
}

// signingTx returns a signing transaction from node for the block with the
// given number and hash, as the masternodes send them every MergeSignRange
// blocks.
func (h *subnetHarness) signingTx(node *testNode, nonce uint64, number uint64, hash common.Hash) *types.Transaction {
	h.t.Helper()
	data := common.Hex2Bytes(common.HexSignMethod)
	data = append(data, common.LeftPadBytes(new(big.Int).SetUint64(number).Bytes(), 32)...)
	data = append(data, hash.Bytes()...)
	tx := types.NewTransaction(nonce, common.BlockSignersBinary, big.NewInt(0), 200000, big.NewInt(0), data)
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(h.config.ChainID), node.key)
	if err != nil {
		h.t.Fatal(err)
	}
	return signed
}

func (h *subnetHarness) stateAtHead() *state.StateDB {
	h.t.Helper()
	statedb, err := h.bc.StateAt(h.head().Root())
	if err != nil {
		h.t.Fatal(err)
	}
	return statedb
}
