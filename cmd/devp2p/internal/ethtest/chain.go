package ethtest

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/hexutil"
	"github.com/XinFinOrg/XDPoSChain/core"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

// Chain is a lightweight blockchain-like store backed by ethtest fixtures.
type Chain struct {
	genesis core.Genesis
	blocks  []*types.Block
	state   map[common.Address]state.DumpAccount
	senders map[common.Address]*senderInfo
	config  *params.ChainConfig

	txInfo txInfo
}

type txInfo struct {
	LargeReceiptBlock *uint64 `json:"tx-largereceipt"`
}

type senderInfo struct {
	Key   *ecdsa.PrivateKey `json:"key"`
	Nonce uint64            `json:"nonce"`
}

// NewChain loads ethtest fixtures from the given directory.
func NewChain(dir string) (*Chain, error) {
	if dir == "" {
		return nil, fmt.Errorf("chain directory is required")
	}
	gen, err := loadGenesis(filepath.Join(dir, "genesis.json"))
	if err != nil {
		return nil, err
	}
	gblock := gen.ToBlock()

	blocks, err := blocksFromFile(filepath.Join(dir, "chain.rlp"), gblock)
	if err != nil {
		if !isLegacyFixtureEncodingError(err) {
			return nil, err
		}
		// Some fork fixtures encode block payloads in a legacy shape that doesn't
		// decode into types.Block directly. Keep Phase 1 usable by loading genesis
		// and defer full chain payload decoding to the protocol-adapter phases.
		blocks = []*types.Block{gblock}
	}
	stateDump, err := readState(filepath.Join(dir, "headstate.json"))
	if err != nil {
		return nil, err
	}
	accounts, err := readAccounts(filepath.Join(dir, "accounts.json"))
	if err != nil {
		return nil, err
	}

	var info txInfo
	if err := common.LoadJSON(filepath.Join(dir, "txinfo.json"), &info); err != nil {
		return nil, err
	}

	return &Chain{
		genesis: gen,
		blocks:  blocks,
		state:   stateDump,
		senders: accounts,
		config:  gen.Config,
		txInfo:  info,
	}, nil
}

func isLegacyFixtureEncodingError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "too few elements for types.Header")
}

func (c *Chain) Head() *types.Block {
	return c.blocks[c.Len()-1]
}

func (c *Chain) Len() int {
	return len(c.blocks)
}

func (c *Chain) GetBlock(number int) *types.Block {
	return c.blocks[number]
}

func (c *Chain) TD() *big.Int {
	return new(big.Int)
}

// GetSender returns the address and tracked nonce for an account in the
// deterministic sender set loaded from accounts.json.
func (c *Chain) GetSender(idx int) (common.Address, uint64) {
	accounts := make([]common.Address, 0, len(c.senders))
	for addr := range c.senders {
		accounts = append(accounts, addr)
	}
	sort.Slice(accounts, func(i, j int) bool {
		return bytes.Compare(accounts[i][:], accounts[j][:]) < 0
	})
	addr := accounts[idx]
	return addr, c.senders[addr].Nonce
}

// IncNonce increases the tracked pending nonce for a known sender account.
func (c *Chain) IncNonce(addr common.Address, amt uint64) {
	if _, ok := c.senders[addr]; !ok {
		panic("nonce increment for non-signer")
	}
	c.senders[addr].Nonce += amt
}

// Balance returns the account balance from head-state dump.
func (c *Chain) Balance(addr common.Address) *big.Int {
	bal := new(big.Int)
	if acc, ok := c.state[addr]; ok {
		bal, _ = bal.SetString(acc.Balance, 10)
	}
	return bal
}

// SignTx signs tx with the private key associated with sender address.
func (c *Chain) SignTx(from common.Address, tx *types.Transaction) (*types.Transaction, error) {
	signer := types.LatestSigner(c.config)
	acc, ok := c.senders[from]
	if !ok {
		return nil, fmt.Errorf("account not available for signing: %s", from)
	}
	return types.SignTx(tx, signer, acc.Key)
}

// GetHeaders returns headers matching a GetBlockHeaders query payload.
func (c *Chain) GetHeaders(req *getBlockHeadersData) ([]*types.Header, error) {
	if req == nil {
		return nil, errors.New("nil header request")
	}
	if req.Amount < 1 {
		return nil, errors.New("no block headers requested")
	}

	var (
		headers     = make([]*types.Header, req.Amount)
		blockNumber uint64
	)
	matchByHash := req.Origin.Hash != (common.Hash{})
	for _, block := range c.blocks {
		if matchByHash {
			if block.Hash() != req.Origin.Hash {
				continue
			}
		} else if block.Number().Uint64() != req.Origin.Number {
			continue
		}
		headers[0] = block.Header()
		blockNumber = block.Number().Uint64()
		break
	}
	if headers[0] == nil {
		return nil, fmt.Errorf("no headers found for given origin number %v, hash %v", req.Origin.Number, req.Origin.Hash)
	}
	if req.Amount == 1 {
		return headers[:1], nil
	}
	if req.Reverse {
		for i := 1; i < int(req.Amount); i++ {
			step := 1 + req.Skip
			if blockNumber < step {
				return headers[:i], nil
			}
			next := blockNumber - step
			if next >= uint64(len(c.blocks)) {
				return headers[:i], nil
			}
			blockNumber = next
			headers[i] = c.blocks[blockNumber].Header()
		}
		return headers, nil
	}
	for i := 1; i < int(req.Amount); i++ {
		next := blockNumber + 1 + req.Skip
		if int(next) >= len(c.blocks) {
			return headers[:i], nil
		}
		blockNumber = next
		headers[i] = c.blocks[blockNumber].Header()
	}
	return headers, nil
}

// GetBlockBodies returns block body payloads for blocks known by hash.
func (c *Chain) GetBlockBodies(req *getBlockBodiesData) (blockBodiesData, error) {
	if req == nil {
		return nil, errors.New("nil block bodies request")
	}
	bodies := make(blockBodiesData, 0, len(*req))
	for _, hash := range *req {
		block := c.findBlockByHash(hash)
		if block == nil {
			continue
		}
		bodies = append(bodies, &blockBody{
			Transactions: block.Transactions(),
			Uncles:       block.Uncles(),
		})
	}
	return bodies, nil
}

// GetReceipts returns receipt lists for blocks known by hash.
//
// The current fixture set does not carry per-block receipt payloads, so this
// method returns empty receipt lists aligned to known block hashes.
func (c *Chain) GetReceipts(req *getReceiptsData) (receiptsData, error) {
	if req == nil {
		return nil, errors.New("nil receipts request")
	}
	receipts := make(receiptsData, 0, len(*req))
	for _, hash := range *req {
		if c.findBlockByHash(hash) == nil {
			continue
		}
		receipts = append(receipts, types.Receipts{})
	}
	return receipts, nil
}

func (c *Chain) findBlockByHash(hash common.Hash) *types.Block {
	for _, block := range c.blocks {
		if block.Hash() == hash {
			return block
		}
	}
	return nil
}

func loadGenesis(genesisFile string) (core.Genesis, error) {
	chainConfig, err := os.ReadFile(genesisFile)
	if err != nil {
		return core.Genesis{}, err
	}
	var gen core.Genesis
	if err := json.Unmarshal(chainConfig, &gen); err != nil {
		return core.Genesis{}, err
	}
	return gen, nil
}

func blocksFromFile(chainfile string, gblock *types.Block) ([]*types.Block, error) {
	fh, err := os.Open(chainfile)
	if err != nil {
		return nil, err
	}
	defer fh.Close()

	var reader io.Reader = fh
	if strings.HasSuffix(chainfile, ".gz") {
		if reader, err = gzip.NewReader(reader); err != nil {
			return nil, err
		}
	}

	stream := rlp.NewStream(reader, 0)
	blocks := make([]*types.Block, 1)
	blocks[0] = gblock
forLoop:
	for i := 0; ; i++ {
		var b types.Block
		switch err := stream.Decode(&b); err {
		case nil:
			if b.NumberU64() != uint64(i+1) {
				return nil, fmt.Errorf("block at index %d has wrong number %d", i, b.NumberU64())
			}
			blocks = append(blocks, &b)
		case io.EOF:
			break forLoop
		default:
			return nil, fmt.Errorf("at block index %d: %v", i, err)
		}
	}
	return blocks, nil
}

func readState(file string) (map[common.Address]state.DumpAccount, error) {
	f, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("unable to read state: %v", err)
	}
	var dump state.Dump
	if err := json.Unmarshal(f, &dump); err != nil {
		return nil, fmt.Errorf("unable to unmarshal state: %v", err)
	}
	return dump.Accounts, nil
}

func readAccounts(file string) (map[common.Address]*senderInfo, error) {
	f, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("unable to read state: %v", err)
	}
	type account struct {
		Key hexutil.Bytes `json:"key"`
	}
	keys := make(map[common.Address]account)
	if err := json.Unmarshal(f, &keys); err != nil {
		return nil, fmt.Errorf("unable to unmarshal accounts: %v", err)
	}
	accounts := make(map[common.Address]*senderInfo)
	for addr, acc := range keys {
		pk, err := crypto.HexToECDSA(common.Bytes2Hex(acc.Key))
		if err != nil {
			return nil, fmt.Errorf("unable to read private key for %s: %v", addr, err)
		}
		accounts[addr] = &senderInfo{Key: pk, Nonce: 0}
	}
	return accounts, nil
}
