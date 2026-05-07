// Copyright 2014 The go-ethereum Authors
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

package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/hexutil"
	"github.com/XinFinOrg/XDPoSChain/common/math"
	"github.com/XinFinOrg/XDPoSChain/core/rawdb"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/tracing"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/trie"
)

//go:generate go run github.com/fjl/gencodec -type Genesis -field-override genesisSpecMarshaling -out gen_genesis.go

var (
	errGenesisNoConfig = errors.New("genesis has no chain configuration")
	jsonMarshal        = json.Marshal
)

// Deprecated: use types.Account instead.
type GenesisAccount = types.Account

// Deprecated: use types.GenesisAlloc instead.
type GenesisAlloc = types.GenesisAlloc

// Genesis specifies the header fields, state of a genesis block. It also defines hard
// fork switch-over blocks through the chain configuration.
type Genesis struct {
	Config     *params.ChainConfig `json:"config"`
	Nonce      uint64              `json:"nonce"`
	Timestamp  uint64              `json:"timestamp"`
	ExtraData  []byte              `json:"extraData"`
	GasLimit   uint64              `json:"gasLimit"   gencodec:"required"`
	Difficulty *big.Int            `json:"difficulty" gencodec:"required"`
	Mixhash    common.Hash         `json:"mixHash"`
	Coinbase   common.Address      `json:"coinbase"`
	Alloc      types.GenesisAlloc  `json:"alloc"      gencodec:"required"`

	// These fields are used for consensus tests. Please don't use them
	// in actual genesis blocks.
	Number     uint64      `json:"number"`
	GasUsed    uint64      `json:"gasUsed"`
	ParentHash common.Hash `json:"parentHash"`
	BaseFee    *big.Int    `json:"baseFeePerGas"`
}

// copy copies the genesis.
func (g *Genesis) copy() *Genesis {
	if g != nil {
		cpy := *g
		if g.Config != nil {
			conf := *g.Config
			cpy.Config = &conf
		}
		return &cpy
	}
	return nil
}

func getGenesisState(db ethdb.Database, blockhash common.Hash) (alloc types.GenesisAlloc, err error) {
	blob := rawdb.ReadGenesisStateSpec(db, blockhash)
	if len(blob) != 0 {
		if err := alloc.UnmarshalJSON(blob); err != nil {
			return nil, err
		}

		return alloc, nil
	}

	// Genesis allocation is missing and there are several possibilities:
	// the node is legacy which doesn't persist the genesis allocation or
	// the persisted allocation is just lost.
	// - supported networks(mainnet, testnets), recover with defined allocations
	// - private network, can't recover
	var genesis *Genesis
	switch blockhash {
	case params.MainnetGenesisHash:
		genesis = DefaultGenesisBlock()
	case params.TestnetGenesisHash:
		genesis = DefaultTestnetGenesisBlock()
	case params.DevnetGenesisHash:
		genesis = DefaultDevnetGenesisBlock()
	}
	if genesis != nil {
		return genesis.Alloc, nil
	}

	return nil, nil
}

// hashAlloc computes the state root according to the genesis specification.
func hashAlloc(ga *types.GenesisAlloc) (common.Hash, error) {
	// Create an ephemeral in-memory database for computing hash,
	// all the derived states will be discarded to not pollute disk.
	db := state.NewDatabaseWithConfig(rawdb.NewMemoryDatabase(), nil)
	statedb, err := state.New(types.EmptyRootHash, db)
	if err != nil {
		return common.Hash{}, err
	}
	for addr, account := range *ga {
		if account.Balance != nil {
			statedb.AddBalance(addr, account.Balance, tracing.BalanceIncreaseGenesisBalance)
		}
		statedb.SetCode(addr, account.Code)
		statedb.SetNonce(addr, account.Nonce, tracing.NonceChangeGenesis)
		for key, value := range account.Storage {
			statedb.SetState(addr, key, value)
		}
	}
	return statedb.Commit(0, false)
}

// flushAlloc is very similar to hashAlloc, but the main difference is
// all the generated states will be persisted into the given database.
// Also, the genesis state specification will be flushed as well.
func flushAlloc(ga *types.GenesisAlloc, db ethdb.Database, blockhash common.Hash) error {
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(db))
	if err != nil {
		return err
	}
	for addr, account := range *ga {
		if account.Balance != nil {
			statedb.AddBalance(addr, account.Balance, tracing.BalanceIncreaseGenesisBalance)
		}
		statedb.SetCode(addr, account.Code)
		statedb.SetNonce(addr, account.Nonce, tracing.NonceChangeGenesis)
		for key, value := range account.Storage {
			statedb.SetState(addr, key, value)
		}
	}
	root, err := statedb.Commit(0, false)
	if err != nil {
		return err
	}
	err = statedb.Database().TrieDB().Commit(root, true)
	if err != nil {
		return err
	}
	// Marshal the genesis state specification and persist.
	blob, err := json.Marshal(ga)
	if err != nil {
		return err
	}
	rawdb.WriteGenesisStateSpec(db, blockhash, blob)
	return nil
}

// field type overrides for gencodec
type genesisSpecMarshaling struct {
	Nonce      math.HexOrDecimal64
	Timestamp  math.HexOrDecimal64
	ExtraData  hexutil.Bytes
	GasLimit   math.HexOrDecimal64
	GasUsed    math.HexOrDecimal64
	Number     math.HexOrDecimal64
	Difficulty *math.HexOrDecimal256
	BaseFee    *math.HexOrDecimal256
	Alloc      map[common.UnprefixedAddress]types.Account
}

// GenesisMismatchError is raised when trying to overwrite an existing
// genesis block with an incompatible one.
type GenesisMismatchError struct {
	Stored, New common.Hash
}

func (e *GenesisMismatchError) Error() string {
	return fmt.Sprintf("database contains incompatible genesis (have %x, new %x)", e.Stored, e.New)
}

// canonicalizeChainConfig resolves built-in hashes to their bundled configs.
// For non built-in networks it clones and backfills missing fields from
// LocalnetChainConfig.
func canonicalizeChainConfig(hash common.Hash, cfg *params.ChainConfig) *params.ChainConfig {
	builtin := params.GetBuiltInChainConfigByHash(hash)
	if builtin != nil {
		return builtin
	}
	return cfg.BackfillMissingFields()
}

// SetupGenesisBlock writes or updates the genesis block in db,
// returning the resolved chain config and genesis hash.
// The block that will be used is:
//
//	                     genesis == nil       genesis != nil
//	                  +------------------------------------------
//	db has no genesis |  main-net default  |  genesis
//	db has genesis    |  from DB           |  genesis (if compatible)
//
// Rules:
//   - For built-in networks: always returns the hardcoded in-memory config.
//   - For custom networks: the provided genesis config is backfilled from
//     LocalnetChainConfig before write and validation.
//   - For stored custom configs: read-time backfill is also applied to keep
//     compatibility when new ChainConfig fields are introduced.
//
// Returns:
// - chainConfig: the resolved config (never nil on success)
// - genesisHash: the canonical genesis block hash
// - compatErr: compatibility error if config upgrade/downgrade is needed
// - err: other errors (e.g. missing config, DB errors)
func SetupGenesisBlock(db ethdb.Database, genesis *Genesis) (chainConfig *params.ChainConfig, genesisHash common.Hash, compatErr *params.ConfigCompatError, err error) {
	defer func() {
		if chainConfig == nil {
			log.Info("Resolved chain config", "cfg", "nil", "hash", genesisHash.Hex(), "compatErr", compatErr, "err", err)
		} else {
			name := chainConfig.Name
			if name == "" {
				name = "unknown"
			}
			log.Info("Resolved chain config", "cfg", name, "hash", genesisHash.Hex(), "chainId", chainConfig.ChainID, "compatErr", compatErr, "err", err)
		}
	}()

	// Copy the genesis, so we can operate on a copy.
	genesis = genesis.copy()

	var originalGenesisHash common.Hash
	if genesis != nil {
		// Sanitize the supplied genesis, ensuring it has the associated chain
		// config attached.
		if genesis.Config == nil {
			return nil, common.Hash{}, nil, errGenesisNoConfig
		}

		// Normalize caller-provided config once at entry so all later comparisons,
		// compatibility checks and persistence operate on canonical form.
		originalGenesisHash = genesis.ToBlock().Hash()
		genesis.Config = canonicalizeChainConfig(originalGenesisHash, genesis.Config)
	}

	// Commit the genesis if the database is empty
	ghash := rawdb.ReadCanonicalHash(db, 0)
	if (ghash == common.Hash{}) {
		if genesis == nil {
			log.Info("Writing default main-net genesis block")
			genesis = DefaultGenesisBlock()
		} else {
			log.Info("Writing custom genesis block")
		}
		block, err := genesis.Commit(db)
		if err != nil {
			return nil, common.Hash{}, nil, err
		}
		return genesis.Config, block.Hash(), nil, nil
	}

	// Commit the genesis if the genesis block exists in the ancient database
	// but the key-value database is empty without initializing the genesis
	// fields. This scenario can occur when the node is created from scratch
	// with an existing ancient store.
	storedCfg, readErr := rawdb.ReadChainConfig(db, ghash)
	if readErr != nil && !errors.Is(readErr, rawdb.ErrChainConfigNotFound) {
		return nil, common.Hash{}, nil, readErr
	}
	if storedCfg == nil {
		if header := rawdb.ReadHeader(db, ghash, 0); header == nil {
			return nil, ghash, nil, fmt.Errorf("missing genesis header for hash: %s", ghash.Hex())
		}
		// Ensure the stored genesis block matches with the given genesis. Private
		// networks must explicitly specify the genesis in the config file, mainnet
		// genesis will be used as default and the initialization will always fail.
		if genesis == nil {
			log.Info("Writing default main-net genesis block")
			genesis = DefaultGenesisBlock()
		} else {
			log.Info("Writing custom genesis block")
		}
		if hash := genesis.ToBlock().Hash(); hash != ghash {
			return nil, common.Hash{}, nil, &GenesisMismatchError{ghash, hash}
		}
		block, err := genesis.Commit(db)
		if err != nil {
			return nil, common.Hash{}, nil, err
		}
		return genesis.Config, block.Hash(), nil, nil
	}
	originalStoredCfg := storedCfg
	storedCfg = canonicalizeChainConfig(ghash, storedCfg)

	// The genesis block has already been committed previously. Verify that the
	// provided genesis with chain overrides matches the existing one, and update
	// the stored chain config if necessary.
	if genesis != nil {
		if hash := genesis.ToBlock().Hash(); hash != ghash && originalGenesisHash != ghash {
			return nil, common.Hash{}, nil, &GenesisMismatchError{ghash, hash}
		}
	}

	// Check config compatibility and write the config. Compatibility errors
	// are returned to the caller unless we're already at block zero.
	headHeaderHash := rawdb.ReadHeadHeaderHash(db)
	if headHeaderHash != (common.Hash{}) && rawdb.ReadHeaderNumber(db, headHeaderHash) == nil {
		return storedCfg, ghash, nil, errors.New("missing block number for head header hash")
	}
	head := rawdb.ReadHeadHeader(db)
	if head == nil {
		return nil, common.Hash{}, nil, errors.New("missing head header")
	}
	newCfg := genesis.chainConfigOrDefault(ghash, storedCfg)

	// Sanity-check the new configuration.
	if err := newCfg.CheckConfigForkOrder(); err != nil {
		return nil, common.Hash{}, nil, err
	}

	// TODO(rjl493456442) better to define the comparator of chain config
	// and short circuit if the chain config is not changed.
	compatErr = storedCfg.CheckCompatible(newCfg, head.Number.Uint64())
	if compatErr != nil && (head.Number.Uint64() != 0 && compatErr.RewindTo != 0) {
		return newCfg, ghash, compatErr, nil
	}

	// Don't overwrite if the old is identical to the new. It's useful
	// for the scenarios that database is opened in the read-only mode.
	storedData, err := jsonMarshal(originalStoredCfg)
	if err != nil {
		return newCfg, ghash, nil, fmt.Errorf("failed to marshal stored chain config: %w", err)
	}
	newData, err := jsonMarshal(newCfg)
	if err != nil {
		return newCfg, ghash, nil, fmt.Errorf("failed to marshal new chain config: %w", err)
	}
	if !bytes.Equal(storedData, newData) {
		rawdb.WriteChainConfig(db, ghash, newCfg)
	}

	return newCfg, ghash, nil, nil
}

// LoadChainConfig loads the stored chain config from the database, or falls back to the provided genesis config.
//   - For built-in networks: always returns the hardcoded in-memory config.
//   - For custom networks: applies LocalnetChainConfig backfill to both
//     provided genesis configs and stored configs from DB.
//   - Read-time backfill is intentionally kept so newly added ChainConfig
//     fields stay compatible with historical persisted configs.
//
// Returns:
//   - cfg: the resolved config (never nil on success)
//   - ghash: the canonical genesis block hash
//   - err: error if config is missing or invalid
func LoadChainConfig(db ethdb.Database, genesis *Genesis) (cfg *params.ChainConfig, ghash common.Hash, err error) {
	// Load the stored chain config from the database. It can be nil
	// in case the database is empty. Notably, we only care about the
	// chain config corresponds to the canonical chain.
	stored := rawdb.ReadCanonicalHash(db, 0)
	if stored != (common.Hash{}) {
		storedcfg, err := rawdb.ReadChainConfig(db, stored)
		if err != nil && !errors.Is(err, rawdb.ErrChainConfigNotFound) {
			return nil, common.Hash{}, err
		}
		if storedcfg != nil {
			cfg := canonicalizeChainConfig(stored, storedcfg)
			err := cfg.CheckConfigForkOrder()
			if err != nil {
				return nil, stored, err
			}
			return cfg, stored, err
		}
	}

	// Load the config from the provided genesis specification
	if genesis != nil {
		// Reject invalid genesis spec without valid chain config
		if genesis.Config == nil {
			return nil, common.Hash{}, errGenesisNoConfig
		}
		originalHash := genesis.ToBlock().Hash()
		genesis.Config = canonicalizeChainConfig(originalHash, genesis.Config)
		err := genesis.Config.CheckConfigForkOrder()
		if err != nil {
			return nil, common.Hash{}, err
		}
		// If the canonical genesis header is present, but the chain
		// config is missing(initialize the empty leveldb with an
		// external ancient chain segment), ensure the provided genesis
		// is matched.
		ghash := genesis.ToBlock().Hash()
		if stored != (common.Hash{}) && ghash != stored && originalHash != stored {
			return nil, ghash, &GenesisMismatchError{stored, ghash}
		}
		return genesis.Config, ghash, nil
	}

	// There is no stored chain config and no new config provided,
	// In this case the default chain config(mainnet) will be used
	return params.XDCMainnetChainConfig, params.MainnetGenesisHash, nil
}

// chainConfigOrDefault retrieves the attached chain configuration. If the genesis
// object is null, it returns the default chain configuration based on the given
// genesis hash, or the locally stored config if it's not a pre-defined network.
func (g *Genesis) chainConfigOrDefault(ghash common.Hash, stored *params.ChainConfig) *params.ChainConfig {
	switch {
	case g != nil:
		return g.Config
	case ghash == params.MainnetGenesisHash:
		return params.XDCMainnetChainConfig
	case ghash == params.TestnetGenesisHash:
		return params.TestnetChainConfig
	case ghash == params.DevnetGenesisHash:
		return params.DevnetChainConfig
	default:
		return stored
	}
}

// ToBlock returns the genesis block according to genesis specification.
func (g *Genesis) ToBlock() *types.Block {
	root, err := hashAlloc(&g.Alloc)
	if err != nil {
		panic(err)
	}
	head := &types.Header{
		Number:     new(big.Int).SetUint64(g.Number),
		Nonce:      types.EncodeNonce(g.Nonce),
		Time:       g.Timestamp,
		ParentHash: g.ParentHash,
		Extra:      g.ExtraData,
		GasLimit:   g.GasLimit,
		GasUsed:    g.GasUsed,
		BaseFee:    g.BaseFee,
		Difficulty: g.Difficulty,
		MixDigest:  g.Mixhash,
		Coinbase:   g.Coinbase,
		Root:       root,
	}
	if g.GasLimit == 0 {
		head.GasLimit = params.GenesisGasLimit
	}
	if g.Difficulty == nil {
		head.Difficulty = params.GenesisDifficulty
	}
	// Notice: Eip1559Block affects the block hash, so g.Config.Eip1559Block
	// must be set in genesis chain config when EIP-1559 should be active.
	if g.Config != nil && g.Config.IsEIP1559(common.Big0) {
		if g.BaseFee != nil {
			head.BaseFee = g.BaseFee
		} else {
			head.BaseFee = new(big.Int).SetUint64(params.InitialBaseFee)
		}
	}
	return types.NewBlock(head, nil, nil, trie.NewStackTrie(nil))
}

// Commit writes the block and state of a genesis specification to the database.
// The block is committed as the canonical head block.
func (g *Genesis) Commit(db ethdb.Database) (*types.Block, error) {
	block := g.ToBlock()
	if block.Number().Sign() != 0 {
		return nil, errors.New("can't commit genesis block with number > 0")
	}
	config := g.Config
	if config == nil {
		return nil, errors.New("invalid genesis without chain config")
	}
	if err := config.CheckConfigForkOrder(); err != nil {
		return nil, err
	}
	if config.XDPoS != nil && len(g.ExtraData) < 32+crypto.SignatureLength {
		return nil, errors.New("can't start XDPoS chain without signers")
	}
	// All the checks have passed, flushAlloc the states derived from the genesis
	// specification as well as the specification itself into the provided
	// database.
	if err := flushAlloc(&g.Alloc, db, block.Hash()); err != nil {
		return nil, err
	}
	batch := db.NewBatch()
	rawdb.WriteTd(batch, block.Hash(), block.NumberU64(), g.Difficulty)
	rawdb.WriteBlock(batch, block)
	rawdb.WriteReceipts(batch, block.Hash(), block.NumberU64(), nil)
	rawdb.WriteCanonicalHash(batch, block.Hash(), block.NumberU64())
	rawdb.WriteHeadBlockHash(batch, block.Hash())
	rawdb.WriteHeadFastBlockHash(batch, block.Hash())
	rawdb.WriteHeadHeaderHash(batch, block.Hash())
	rawdb.WriteChainConfig(batch, block.Hash(), config)
	return block, batch.Write()
}

// MustCommit writes the genesis block and state to db, panicking on error.
// The block is committed as the canonical head block.
func (g *Genesis) MustCommit(db ethdb.Database) *types.Block {
	block, err := g.Commit(db)
	if err != nil {
		panic(err)
	}
	return block
}

// DefaultGenesisBlock returns the XDC mainnet genesis block.
func DefaultGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.XDCMainnetChainConfig,
		Nonce:      0,
		ExtraData:  hexutil.MustDecode("0x000000000000000000000000000000000000000000000000000000000000000025c65b4b379ac37cf78357c4915f73677022eaffc7d49d0a2cf198deebd6ce581af465944ec8b2bbcfccdea1006a5cfa7d9484b5b293b46964c265c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
		Alloc:      DecodeAllocJson(MainnetAllocData),
		Timestamp:  1559211559,
	}
}

// DefaultTestnetGenesisBlock returns the XDC testnet genesis block.
func DefaultTestnetGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.TestnetChainConfig,
		Nonce:      0,
		ExtraData:  hexutil.MustDecode("0x00000000000000000000000000000000000000000000000000000000000000003ea0a3555f9b1de983572bff6444aeb1899ec58c4f7900282f3d371d585ab1361205b0940ab1789c942a5885a8844ee5587c8ac5e371fc39ffe618960000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
		Alloc:      DecodeAllocJson(TestnetAllocData),
		Timestamp:  1560417871,
	}
}

// DefaultDevnetGenesisBlock returns the XDC devnet genesis block.
func DefaultDevnetGenesisBlock() *Genesis {
	return &Genesis{
		Config:     params.DevnetChainConfig,
		Nonce:      0,
		ExtraData:  hexutil.MustDecode("0x0000000000000000000000000000000000000000000000000000000000000000008661dde98c6106224ac8d5e0356d6fdbf3923101346a2d41542d859e03f461ca74a1ff2686884c02729a332e4e16e4f02ff8a416a2006f943e110a066711cbf42f9ead9fca8a27a12f5f11e10f3ed6081f1ab6bfe1e01900e15164a0fe34283d32671c0983ab0acc9c0107031e681d128811f056b4e4150aed5c578e40595111352111472ea1ba55b1aad90fe62f8436d88005e2d69f3caeba10a713cd02a811c8ee9b7383eee8cb7967c60c09f9f5b6aa499d12fe3a241c805a94fecf98e9f2eab7370fb1873715df6e75c7d1cb8af14049caca19ed207cfb98bf180a2d5371a78de6376fdd0b7113d4364976a98e1bfa7d6cc47cf4be7362a288a531d6c621c337602026f1a303c8931793ad4eb38c1f2d45a7076ec62280e7bd75984b8dd8314330fbedbaa48984b45122f69af9d2268dbd79536e12c7af4afb462eaedd258fedd147585f34c5b2897e21ff7f7551340303263f0892e3a8a70c7debc968f66f1f2caca535082686b03018b3b811ac1fb42dbc6b325255e0fad826d5f7bcc51afc06d4284969ab8757f3e689163c2c2884f6c107184a4b9721aa84e7a2e901c81c9e2cc7bd34266d54ccd6d89296f0b8bc99faefc3772d5271b9f4692c1e36a1a862bea311cb6705f5872e3f6d1c0598c2d54c69d4011effc480407230842e67af84716b566b177dcf22d5a1062871d832ec3058a76ce02c06d6ff370882fa96ff42b9aeb6ca32be73ad19e1003eb3ad225d9059522059e36f8932c6cfb950940906a0212ce200092841b7a96dd1334fe0c390ff84448b4be1eb797b22e7ea5162e83a71897dd5f257b8376e37612d41635e63c715543d1daacc23b64751c1114f985912ce2b292ee2753eadc9be2dbc465d3f435adc85c5768e7c973f493fa2e9cab94aa24d536f10c0341edec4b662d0c34968f17a784968f884e2e51057c6fbe992c19d044a76a959b27d1f8c2aaa9d448a92b93be32020204b042ef47e5b12e511d1097eb7cf2e2b21f433304b4cf8b8d730c8f1b90b260f030840e735fe143e4ed19e4e0b08ddc57368ba278be696ac92ed6ab74ed4aa631ef6d9c02ba707782c875d9c44f80a835180f7a3beba24f5f4d70ecaf238aeee127a056d527dbaef13ab0431463d84355b47c4b9e66b5af1565a8d0da480bbc7fee3ad5e17d4e6c5fec0b5b657267ea675c25d669b6529bbbec5cf7e9283a117587a573ddbd2729f60bd4ebc9fb855bcbfb5c9215ad2a5f826c5028d82466dbb9d2a8bb03f1d0a965b5e45373d2c8a7235e4d6c3835fc6a4d00ebd105e6c696185044ce4f35508c04a8c8b3d99857cca61ce0cbd9364ee68e5336286387f2070e6abf69c6356862749cf11ed9b900228937a0172100ddb6563f915e663857b8a9f6a7a0e50cfe148fe310cc565a01d5808f1b0050702c49f150ae55137f90a7d67655cc7b49f4a33330249b82172961275604ef4685008ff89f3b10a85fa57b2accbca976603e7026969067dc17d6a6e5ce5939ab823072961e3b2f06afb44e2268e9ec27e73ebe0c11f79aa83de76fc6b77d1702ae1395c62a4368f7e8af39c02e799c96e851e2a96d094827470d0cf75362028527f3a0b71141ee85dc573b1a8a6eeae8dcc75a8e9d632b0782ffa5fdfb86c95fb891cec0bcd76413a9f38c178cbe4bc26aca957c439e20dc93fb5a9b2def5807974725114d48b6df7a2eb8b9f320addd4a732087e34d797f211ed1343ff9b5a8ff42fa0f3360d018013f4f2ae62c66416e4e0c8e95f0c8f0d1ad2e6830fb3711887f1f3b248c75bacaffe4e5f7fcdb289f5398bc06a32b84df3a2b9168aa6baf44110e88d13512e552e2032662fc8e910992f82a4493863917c67a7670441c22a16f47e85fb217312d6ca7893727b60f3e372bbfd6fdd076cf26e2e739ac737989e2807357ed613456af5d0b0a4c1a95594ba639def92fc6c55f98d09143d067998754237168365a08cc01242805ff9bcff7e46c14f8b454efaf0b1a5824fbc2b2db519039bb6ef9d6ab94110499a88ab8218ace9a7ef792c7527c226edc2183b3644d9abafbb0dce2fe4045ca90c06688201b8d08dafb7acb6efd260247cc56dc5aec68be725279c628f92ace6f5e22342b6d8e2c3f84b4d849bc1462bb173ad579fe5042a3e8d24b32499e80ee2bf5ed151fcae07b743487735e11d3b23bfb92475e90666f10bb0103109820e4907a277bc5492b09f502653308db25d2672ef54675df6a3159502f773c499498655b4210783b2cdf2ea5c878804c1948e94a5b6168cb5805efb3644b56a83569aa233f1a7f61255e247bd268f078c918db93dbce96e3d903dcb0f5f6378be25fe68a64e205de647c9116fc52c53432aba32c0772e0de9829847800de5e88936570c09ce7263c1a9f8f77b0afc5eadc2dc78106879eb3126bc62c205f666038daba72abcd4d23d77e9c774fdebaac34a3cd97fb1bb894f525d1a1f3ea18c592a3b08c3cb578638427389b7c6402d0b1a8de3e89a9b7bc6379a39caf697b91b3e4ea9a227bb940f70d96dc74d1b890db7eddb783b2f7e5dd3f010739df8e1c7c93c8aeaffea97e868168b8c3d754463e6d737c825253cad4cbf989201d7bd369fef887309c1b2cb1269432a080dbcff8053d7759e0c4962bec94dcdff7f7ec050b7a413626289a35616c0bc67a1e9ce49f6ea69bb0237303f90cbeb28a9665415b7cfcfb43f059e39456b29facabded44684cac35b04fd02310501c429f631b3097a4a0da84054a46cfecd483d3c52ebf10d94bca3c97ecfcfca88db84123d881cd6291e5463cbf200f90b9027c303cd84ba1d9b1d9d839d2218a5d313f27344cb7d8a3f1d95ddb83be484441c73848667000e5ce4001aec09d9bdde8431deb1004fbc35c579fd4f51b4c89f571e6de080a32c22019427b55e0326245a4bbe98544bfdf5d49f8477df0a9dbc7e0c6b2dc87e65b87b88ee07ba33902c8678108bd1fb2c79eb5863971f9f3e0cf647a85205c87d1352e19b28c37cfc6de8c33e1c427f8bf873e0bf5195bf78fd7b38ba0c4ced8e3c3c3febd671dc0e0ad3371366d968de46c4024e53e0f04360b4313173a5f266866fd248f94fec0e71ac88ffaf8d4c7b4d63f56a8859fa6f9f8ab85e901cc3175a3749c2d27c6bc051ca7c978626c43e9315c6c526c6acb478c0921fd28bbaa0a64b4c3ea5be13349f0bef623a40a74c3dda20c2c574a5eeabe066c8a4ac6fa52d70e0048ee5cadaa950736ed9221649af1eddbb6210fbc9ed713a757d6b096ee083522d9aad8938dfa7c260c10c9a29d7805b4f0c3bff6dd2e5ef97242ffc54d38be859c3a71b5f843965289b35dc11ce2873636b467bb3fafb699fa80871e330ca3ddb306bd5e6adb972f3303d96cfc1c194f8716d41709fbfe3acfb634c4b25939ddfe3424efa8ed03eae9a2bf4d001692abc1807a6cfe56bae25b109e61e5026b5e4e62c865fc6470f9ff7bb7db2ceb6cc08f718bcba954915bf1774df1fff2331a010cba90682763172b19f57f27831ac70000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		GasLimit:   4700000,
		Difficulty: big.NewInt(1),
		Alloc:      DecodeAllocJson(DevnetAllocData),
		Timestamp:  1765137783,
	}
}

// DeveloperGenesisBlock returns the 'geth --dev' genesis block.
func DeveloperGenesisBlock(period uint64, faucet common.Address) *Genesis {
	// Override the default period to the user requested one
	config := *params.AllDevChainProtocolChanges
	config.XDPoS.Period = period

	// Assemble and return the genesis with the precompiles and faucet pre-funded
	return &Genesis{
		Config:     &config,
		ExtraData:  append(append(make([]byte, 32), faucet[:]...), make([]byte, crypto.SignatureLength)...),
		GasLimit:   6283185,
		BaseFee:    big.NewInt(params.InitialBaseFee),
		Difficulty: big.NewInt(1),
		Alloc: map[common.Address]types.Account{
			common.BytesToAddress([]byte{1}): {Balance: big.NewInt(1)}, // ECRecover
			common.BytesToAddress([]byte{2}): {Balance: big.NewInt(1)}, // SHA256
			common.BytesToAddress([]byte{3}): {Balance: big.NewInt(1)}, // RIPEMD
			common.BytesToAddress([]byte{4}): {Balance: big.NewInt(1)}, // Identity
			common.BytesToAddress([]byte{5}): {Balance: big.NewInt(1)}, // ModExp
			common.BytesToAddress([]byte{6}): {Balance: big.NewInt(1)}, // ECAdd
			common.BytesToAddress([]byte{7}): {Balance: big.NewInt(1)}, // ECScalarMul
			common.BytesToAddress([]byte{8}): {Balance: big.NewInt(1)}, // ECPairing
			faucet:                           {Balance: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(9))},
			// Pre-deploy system contracts
			params.HistoryStorageAddress: {Nonce: 1, Code: params.HistoryStorageCode, Balance: common.Big0},
		},
	}
}

func DecodeAllocJson(s string) types.GenesisAlloc {
	alloc := types.GenesisAlloc{}
	json.Unmarshal([]byte(s), &alloc)
	return alloc
}
