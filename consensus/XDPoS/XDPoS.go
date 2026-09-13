// Copyright (c) 2021 XDPoSChain
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

// Package XDPoS is the adaptor for different consensus engine.
package XDPoS

import (
	"errors"
	"math/big"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/lru"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/engines/engine_v1"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/engines/engine_v2"
	"github.com/XinFinOrg/XDPoSChain/consensus/XDPoS/utils"
	"github.com/XinFinOrg/XDPoSChain/consensus/clique"
	"github.com/XinFinOrg/XDPoSChain/core/state"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/core/vm"
	"github.com/XinFinOrg/XDPoSChain/ethdb"
	"github.com/XinFinOrg/XDPoSChain/event"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/params"
	"github.com/XinFinOrg/XDPoSChain/rpc"
)

const (
	ExtraFieldCheck     = true
	SkipExtraFieldCheck = false
	newRoundChanSize    = 1
)

func (x *XDPoS) SigHash(header *types.Header) (hash common.Hash) {
	switch x.config.BlockConsensusVersion(header.Number) {
	case params.ConsensusEngineVersion2:
		return x.EngineV2.SignHash(header)
	default: // Default "v1"
		return x.EngineV1.SigHash(header)
	}
}

// XDPoS is the delegated-proof-of-stake consensus engine proposed to support the
// Ethereum testnet following the Ropsten attacks.
type XDPoS struct {
	// chainConfig is the config this engine resolved and runs with: the copy that
	// carries the XDPoS.Epoch filled in when the caller's config left it unset.
	// ChainConfig exposes it to callers that have to open the chain with the
	// resolution rather than with their own object.
	chainConfig *params.ChainConfig

	config *params.XDPoSConfig // Consensus engine configuration parameters
	db     ethdb.Database      // Database to store and retrieve snapshot checkpoints

	// Transaction cache, only make sense for adaptor level
	signingTxsCache *lru.Cache[common.Hash, []*types.Transaction]

	// Share Channel
	MinePeriodCh chan int // Miner wait Period Channel

	NewRoundCh chan types.Round // Miner use this channel to trigger worker to commitNewWork

	// Trading and lending service
	GetXDCXService    func() utils.TradingService
	GetLendingService func() utils.LendingService

	// The exact consensus engine with different versions
	EngineV1 *engine_v1.XDPoS_v1
	EngineV2 *engine_v2.XDPoS_v2
}

// Subscribe to consensus engines forensics events. Currently only exist for engine v2
func (x *XDPoS) SubscribeForensicsEvent(ch chan<- types.ForensicsEvent) event.Subscription {
	return x.EngineV2.ForensicsProcessor.SubscribeForensicsEvent(ch)
}

// New creates a XDPoS delegated-proof-of-stake consensus engine with the initial
// signers set to the ones provided by the user.
//
// The config the engine runs with is ChainConfig.ResolveXDPoSEpoch's answer: an
// omitted XDPoS.Epoch is judged against params.DefaultXDPoSEpoch and filled into a
// copy, so the caller's config is never mutated and keeps the state its source
// wrote. Callers that open the chain through core.NewBlockChain(ReadOnly)Resolved
// pass ChainConfig() of this engine.
func New(chainConfig *params.ChainConfig, db ethdb.Database) (*XDPoS, error) {
	log.Info("[New] initialise consensus engines")
	if chainConfig == nil {
		return nil, errors.New("missing chain config")
	}
	// Report the missing section before judging the rest of the config: without it
	// no XDPoS engine can be built at all, and letting the fork-order validation run
	// first made the answer depend on the other fields the config happens to carry
	// (a config that also names Ethash or Clique passed it and only then failed
	// here, while a bare one failed as a missing fork switch instead).
	if chainConfig.XDPoS == nil {
		// params.ErrMissingXDPoSConfig carries exactly this text, so the rejection
		// keeps the message callers and tests already quote while becoming
		// recognisable with errors.Is: cmd/utils.FormatChainConfigError selects its
		// recovery hint by that sentinel, and a bare errors.New here would drop it.
		return nil, params.ErrMissingXDPoSConfig
	}
	// Resolve the schedule the engine runs with. An omitted epoch is judged against
	// params.DefaultXDPoSEpoch and filled into a copy, so the caller's config keeps
	// the state its source wrote while ChainConfig can hand the resolution to the
	// blockchain constructors that judge their config as given. A rejected schedule
	// is refused before any engine exists.
	resolved, err := chainConfig.ResolveXDPoSEpoch()
	if err != nil {
		return nil, err
	}

	minePeriodCh := make(chan int)
	newRoundCh := make(chan types.Round, newRoundChanSize)
	engineV2, err := engine_v2.New(resolved, db, minePeriodCh, newRoundCh)
	if err != nil {
		return nil, err
	}

	return &XDPoS{
		chainConfig:    resolved,
		config:         resolved.XDPoS,
		db:             db,
		MinePeriodCh:   minePeriodCh,
		NewRoundCh:     newRoundCh,
		GetXDCXService: func() utils.TradingService { return nil },
		GetLendingService: func() utils.LendingService {
			return nil
		},
		signingTxsCache: lru.NewCache[common.Hash, []*types.Transaction](utils.BlockSignersCacheLimit),
		EngineV1:        engine_v1.New(resolved, db),
		EngineV2:        engineV2,
	}, nil
}

// Stop stops the consensus engine:
//   - close chanel MinePeriodCh
//   - close chanel NewRoundCh
func (x *XDPoS) Stop() {
	close(x.MinePeriodCh)
	close(x.NewRoundCh)
}

// ChainConfig returns the config this engine resolved and runs with: the copy that
// carries the XDPoS.Epoch filled in when the caller's config left it unset.
//
// Callers that open a chain through core.NewBlockChain(ReadOnly)Resolved have to
// pass this object. Those constructors judge the config as given, so the caller's
// own config - which may still carry the unset epoch - is refused with
// params.ErrUnsetXDPoSEpoch.
//
// The answer is the schedule the engine runs with, not ownership of it. A config
// that already wrote its epoch out is returned by ChainConfig.ResolveXDPoSEpoch as
// it is, so this is the caller's own object and a write to it is visible on both
// sides; only a config whose epoch the resolution filled in is a copy the engine
// owns. XDPoS.V2 is shared in either case by design - BuildConfigIndex and
// UpdateParams keep it live so callers read the running index back through
// blockchain.Config(). A caller that needs to write should Clone() first, and must
// not rewrite the epoch of a config the resolution produced: core.chainConfigAsStored
// reads XDPoSConfig.EpochFilledByEngine to restore the epoch the source wrote before
// persisting it.
//
// A nil answer means the engine carries no resolved config - the zero-value engine
// and the nil receiver both report nil. Callers that fall back to their own config
// on nil, as the chain openers do, have to check for it.
func (x *XDPoS) ChainConfig() *params.ChainConfig {
	if x == nil {
		return nil
	}
	return x.chainConfig
}

// ValidateFakerConfig applies the judgement NewFakerWithError makes about a chain
// config before an engine is built, so a caller can check a config - or name why the
// faker constructor would refuse it - without opening an engine. Like that constructor
// it treats an unset XDPoS.Epoch as the engine default, which is the state the
// constructor resolves before it builds the engine; that judgement lives in
// CheckConfigForkOrderWithEpochDefault, so this function does not repeat which rules
// an unset epoch defers. It only judges: it neither resolves the epoch nor mutates
// the config.
//
// A config without an XDPoS section is reported as that missing section, the way New
// reports it: the schedule rules would otherwise pass an ethash or clique config and
// leave this function answering "no error" for a config NewFakerWithError refuses.
func ValidateFakerConfig(chainConfig *params.ChainConfig) error {
	// The judgement is a method on the config and dereferences it, so the nil
	// receiver keeps its own guard here.
	if chainConfig == nil {
		return nil
	}
	if chainConfig.XDPoS == nil {
		return params.ErrMissingXDPoSConfig
	}
	return chainConfig.CheckConfigForkOrderWithEpochDefault()
}

// NewFakerWithError creates an XDPoS consensus engine with a full fake scheme that
// accepts all blocks as valid without enforcing consensus rules, and reports a refused
// chain config as the reason it was refused rather than as a nil engine.
//
// A refused chain config and a failed engine construction are different
// operator-facing problems, so the error says which one happened instead of
// collapsing both into one nil return.
//
// Like New it never mutates the caller's config: an omitted XDPoS.Epoch is filled
// into the copy the engine runs with, which ChainConfig exposes. A caller that
// commits a genesis from the resolved schedule reads ChainConfig() once the engine
// exists, so the stored config is the one the chain is opened with instead of the
// epoch-less config the open guard refuses.
func NewFakerWithError(db ethdb.Database, chainConfig *params.ChainConfig) (*XDPoS, error) {
	// A caller that passes none gets a clone of the package-level test config rather
	// than that config itself, so neither this constructor nor its resolution can
	// leak into every other holder of the shared object. A config the caller passed
	// is used as it is: the resolution below copies it anyway, so there is nothing to
	// clone on this path.
	fakeChainConfig := chainConfig
	if fakeChainConfig == nil {
		fakeChainConfig = params.TestXDPoSMockChainConfig.Clone()
	}
	// Mirror New: a config without an XDPoS section has no engine to build, and
	// naming the missing section here keeps this constructor's answer the same as
	// New's and as ValidateFakerConfig's.
	if fakeChainConfig.XDPoS == nil {
		return nil, params.ErrMissingXDPoSConfig
	}
	// Resolve the schedule the engine runs with onto a copy, so a faker engine cannot
	// carry an unset epoch into the v2 round arithmetic - the one state engine_v2.New
	// refuses - and a rejected config is not left half-updated in the caller's hands.
	resolved, err := fakeChainConfig.ResolveXDPoSEpoch()
	if err != nil {
		return nil, err
	}

	minePeriodCh := make(chan int)
	newRoundCh := make(chan types.Round, newRoundChanSize)
	engineV2, err := engine_v2.New(resolved, db, minePeriodCh, newRoundCh)
	if err != nil {
		return nil, err
	}

	fakeEngine := &XDPoS{
		chainConfig:       resolved,
		config:            resolved.XDPoS,
		db:                db,
		MinePeriodCh:      minePeriodCh,
		NewRoundCh:        newRoundCh,
		GetXDCXService:    func() utils.TradingService { return nil },
		GetLendingService: func() utils.LendingService { return nil },
		signingTxsCache:   lru.NewCache[common.Hash, []*types.Transaction](utils.BlockSignersCacheLimit),
		EngineV1:          engine_v1.NewFaker(db, resolved),
		EngineV2:          engineV2,
	}
	return fakeEngine, nil
}

// Reset parameters after checkpoint due to config may change
func (x *XDPoS) UpdateParams(header *types.Header) {
	switch x.config.BlockConsensusVersion(header.Number) {
	case params.ConsensusEngineVersion2:
		x.EngineV2.UpdateParams(header)
		return
	default: // Default "v1"
		return
	}
}

func (x *XDPoS) Initial(chain consensus.ChainReader, header *types.Header) error {
	switch x.config.BlockConsensusVersion(header.Number) {
	case params.ConsensusEngineVersion2:
		return x.EngineV2.Initial(chain, header)
	default: // Default "v1"
		return nil
	}
}

/*
	Eth Consensus engine interface implementation
*/
// APIs implements consensus.Engine, returning the user facing RPC API to allow
// controlling the signer voting.
func (x *XDPoS) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{{
		Namespace: "XDPoS",
		Service:   &API{chain: chain, XDPoS: x},
	}}
}

// Author implements consensus.Engine, returning the Ethereum address recovered
// from the signature in the header's extra-data section.
func (x *XDPoS) Author(header *types.Header) (common.Address, error) {
	switch x.config.BlockConsensusVersion(header.Number) {
	case params.ConsensusEngineVersion2:
		return x.EngineV2.Author(header)
	default: // Default "v1"
		return x.EngineV1.Author(header)
	}
}

// VerifyHeader checks whether a header conforms to the consensus rules.
func (x *XDPoS) VerifyHeader(chain consensus.ChainReader, header *types.Header, fullVerify bool) error {
	switch x.config.BlockConsensusVersion(header.Number) {
	case params.ConsensusEngineVersion2:
		return x.EngineV2.VerifyHeader(chain, header, fullVerify)
	default: // Default "v1"
		return x.EngineV1.VerifyHeader(chain, header, fullVerify)
	}
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications. For mixed v1/v2 inputs, results are emitted
// in deterministic consensus order: all v1 results first, then all v2 results.
func (x *XDPoS) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, fullVerifies []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))
	verifyChain := NewVerifyHeadersChainReader(chain, headers, nil)

	// Split the headers list into v1 and v2 buckets
	var v1Headers []*types.Header
	var v2Headers []*types.Header
	v1FullVerifies := make([]bool, 0, len(headers))
	v2FullVerifies := make([]bool, 0, len(headers))

	for i, header := range headers {
		switch x.config.BlockConsensusVersion(header.Number) {
		case params.ConsensusEngineVersion2:
			v2Headers = append(v2Headers, header)
			v2FullVerifies = append(v2FullVerifies, fullVerifies[i])
		default: // Default "v1"
			v1Headers = append(v1Headers, header)
			v1FullVerifies = append(v1FullVerifies, fullVerifies[i])
		}
	}

	v1Count := len(v1Headers)
	v2Count := len(v2Headers)
	if v1Count != 0 && v2Count == 0 {
		x.EngineV1.VerifyHeaders(verifyChain, v1Headers, v1FullVerifies, abort, results)
	} else if v1Count == 0 && v2Count != 0 {
		x.EngineV2.VerifyHeaders(verifyChain, v2Headers, v2FullVerifies, abort, results)
	} else if v1Count != 0 && v2Count != 0 {
		v1Results := make(chan error, v1Count)
		v2Results := make(chan error, v2Count)
		x.EngineV1.VerifyHeaders(verifyChain, v1Headers, v1FullVerifies, abort, v1Results)
		x.EngineV2.VerifyHeaders(verifyChain, v2Headers, v2FullVerifies, abort, v2Results)

		go func() {
			for range v1Count {
				select {
				case <-abort:
					return
				case err := <-v1Results:
					select {
					case <-abort:
						return
					case results <- err:
					}
				}
			}
			for range v2Count {
				select {
				case <-abort:
					return
				case err := <-v2Results:
					select {
					case <-abort:
						return
					case results <- err:
					}
				}
			}
		}()
	}

	return abort, results
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (x *XDPoS) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	switch x.config.BlockConsensusVersion(block.Number()) {
	case params.ConsensusEngineVersion2:
		return x.EngineV2.VerifyUncles(chain, block)
	default: // Default "v1"
		return x.EngineV1.VerifyUncles(chain, block)
	}
}

// VerifySeal implements consensus.Engine, checking whether the signature contained
// in the header satisfies the consensus protocol requirements.
func (x *XDPoS) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	switch x.config.BlockConsensusVersion(header.Number) {
	case params.ConsensusEngineVersion2:
		return nil
	default: // Default "v1"
		return x.EngineV1.VerifySeal(chain, header)
	}
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (x *XDPoS) Prepare(chain consensus.ChainReader, header *types.Header) error {
	switch x.config.BlockConsensusVersion(header.Number) {
	case params.ConsensusEngineVersion2:
		return x.EngineV2.Prepare(chain, header)
	default: // Default "v1"
		return x.EngineV1.Prepare(chain, header)
	}
}

// Finalize implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given, and returns the final block.
func (x *XDPoS) Finalize(chain consensus.ChainReader, header *types.Header, state vm.StateDB, parentState *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	switch x.config.BlockConsensusVersion(header.Number) {
	case params.ConsensusEngineVersion2:
		return x.EngineV2.Finalize(chain, header, state, parentState, txs, uncles, receipts)
	default: // Default "v1"
		return x.EngineV1.Finalize(chain, header, state, parentState, txs, uncles, receipts)
	}
}

// Seal implements consensus.Engine, attempting to create a sealed block using
// the local signing credentials.
func (x *XDPoS) Seal(chain consensus.ChainReader, block *types.Block, stop <-chan struct{}) (*types.Block, error) {
	switch x.config.BlockConsensusVersion(block.Number()) {
	case params.ConsensusEngineVersion2:
		return x.EngineV2.Seal(chain, block, stop)
	default: // Default "v1"
		return x.EngineV1.Seal(chain, block, stop)
	}
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have based on the previous blocks in the chain and the
// current signer.
func (x *XDPoS) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	switch x.config.BlockConsensusVersion(parent.Number) {
	case params.ConsensusEngineVersion2:
		return x.EngineV2.CalcDifficulty(chain, time, parent)
	default: // Default "v1"
		return x.EngineV1.CalcDifficulty(chain, time, parent)
	}
}

func (x *XDPoS) HandleProposedBlock(chain consensus.ChainReader, header *types.Header) error {
	switch x.config.BlockConsensusVersion(header.Number) {
	case params.ConsensusEngineVersion2:
		return x.EngineV2.ProposedBlockHandler(chain, header)
	default: // Default "v1"
		return nil
	}
}

/*
	XDC specific methods
*/

// Authorize injects a private key into the consensus engine to mint new blocks
// with.
func (x *XDPoS) Authorize(signer common.Address, signFn clique.SignerFn) {
	// Authorize each consensus individually
	x.EngineV1.Authorize(signer, signFn)
	x.EngineV2.Authorize(signer, signFn)
}

func (x *XDPoS) GetPeriod() uint64 {
	return x.config.Period
}

func (x *XDPoS) IsAuthorisedAddress(chain consensus.ChainReader, header *types.Header, address common.Address) bool {
	switch x.config.BlockConsensusVersion(header.Number) {
	case params.ConsensusEngineVersion2:
		return x.EngineV2.IsAuthorisedAddress(chain, header, address)
	default: // Default "v1"
		return x.EngineV1.IsAuthorisedAddress(chain, header, address)
	}
}

func (x *XDPoS) GetMasternodes(chain consensus.ChainReader, header *types.Header) []common.Address {
	switch x.config.BlockConsensusVersion(header.Number) {
	case params.ConsensusEngineVersion2:
		return x.EngineV2.GetMasternodes(chain, header)
	default: // Default "v1"
		return x.EngineV1.GetMasternodes(chain, header)
	}
}

func (x *XDPoS) GetMasternodesByNumber(chain consensus.ChainReader, blockNumber uint64) []common.Address {
	blockHeader := chain.GetHeaderByNumber(blockNumber)
	if blockHeader == nil {
		log.Error("[GetMasternodesByNumber] Unable to find block", "Num", blockNumber)
		return []common.Address{}
	}
	switch x.config.BlockConsensusVersion(big.NewInt(int64(blockNumber))) {
	case params.ConsensusEngineVersion2:
		return x.EngineV2.GetMasternodes(chain, blockHeader)
	default: // Default "v1"
		return x.EngineV1.GetMasternodes(chain, blockHeader)
	}
}

func (x *XDPoS) YourTurn(chain consensus.ChainReader, parent *types.Header, signer common.Address) (bool, error) {
	switch x.config.BlockConsensusVersion(big.NewInt(parent.Number.Int64() + 1)) {
	case params.ConsensusEngineVersion2:
		return x.EngineV2.YourTurn(chain, parent, signer)
	default: // Default "v1"
		return x.EngineV1.YourTurn(chain, parent, signer)
	}
}

func (x *XDPoS) GetValidator(creator common.Address, chain consensus.ChainReader, header *types.Header) (common.Address, error) {
	switch x.config.BlockConsensusVersion(header.Number) {
	default: // Default "v1", v2 does not need this function
		return x.EngineV1.GetValidator(creator, chain, header)
	}
}

func (x *XDPoS) UpdateMasternodes(chain consensus.ChainReader, header *types.Header, ms []utils.Masternode) error {
	// fmt.Println("UpdateMasternodes")
	switch x.config.BlockConsensusVersion(header.Number) {
	case params.ConsensusEngineVersion2:
		return x.EngineV2.UpdateMasternodes(chain, header, ms)
	default: // Default "v1"
		return x.EngineV1.UpdateMasternodes(chain, header, ms)
	}
}

func (x *XDPoS) RecoverSigner(header *types.Header) (common.Address, error) {
	switch x.config.BlockConsensusVersion(header.Number) {
	case params.ConsensusEngineVersion2:
		return common.Address{}, nil
	default: // Default "v1"
		return x.EngineV1.RecoverSigner(header)
	}
}

func (x *XDPoS) RecoverValidator(header *types.Header) (common.Address, error) {
	switch x.config.BlockConsensusVersion(header.Number) {
	case params.ConsensusEngineVersion2:
		return common.Address{}, nil
	default: // Default "v1"
		return x.EngineV1.RecoverValidator(header)
	}
}

// Get master nodes over extra data of previous checkpoint block.
func (x *XDPoS) GetMasternodesFromCheckpointHeader(checkpointHeader *types.Header) []common.Address {
	switch x.config.BlockConsensusVersion(checkpointHeader.Number) {
	case params.ConsensusEngineVersion2:
		return x.EngineV2.GetMasternodesFromEpochSwitchHeader(checkpointHeader)
	default: // Default "v1"
		return x.EngineV1.GetMasternodesFromCheckpointHeader(checkpointHeader)
	}
}

// Check is epoch switch (checkpoint) block
func (x *XDPoS) IsEpochSwitch(header *types.Header) (bool, uint64, error) {
	switch x.config.BlockConsensusVersion(header.Number) {
	case params.ConsensusEngineVersion2:
		return x.EngineV2.IsEpochSwitch(header)
	default: // Default "v1"
		return x.EngineV1.IsEpochSwitch(header)
	}
}

func (x *XDPoS) GetCurrentEpochSwitchBlock(chain consensus.ChainReader, blockNumber *big.Int) (uint64, uint64, error) {
	switch x.config.BlockConsensusVersion(blockNumber) {
	case params.ConsensusEngineVersion2:
		return x.EngineV2.GetCurrentEpochSwitchBlock(chain, blockNumber)
	default: // Default "v1"
		return x.EngineV1.GetCurrentEpochSwitchBlock(blockNumber)
	}
}

func (x *XDPoS) CalculateMissingRounds(chain consensus.ChainReader, header *types.Header) (*utils.PublicApiMissedRoundsMetadata, error) {
	switch x.config.BlockConsensusVersion(header.Number) {
	case params.ConsensusEngineVersion2:
		return x.EngineV2.CalculateMissingRounds(chain, header)
	default: // Default "v1"
		return nil, errors.New("not supported in the v1 consensus")
	}
}

// Same DB across all consensus engines
func (x *XDPoS) GetDb() ethdb.Database {
	return x.db
}

func (x *XDPoS) GetSnapshot(chain consensus.ChainReader, header *types.Header) (*utils.PublicApiSnapshot, error) {
	switch x.config.BlockConsensusVersion(header.Number) {
	case params.ConsensusEngineVersion2:
		sp, err := x.EngineV2.GetSnapshot(chain, header)
		if err != nil {
			return nil, err
		}
		return &utils.PublicApiSnapshot{
			Number:  sp.Number,
			Hash:    sp.Hash,
			Signers: sp.GetMappedCandidates(),
		}, err
	default: // Default "v1"
		sp, err := x.EngineV1.GetSnapshot(chain, header)
		if err != nil {
			return nil, err
		}
		// Convert to a standard PublicApiSnapshot type, otherwise it's a breaking change to API
		return &utils.PublicApiSnapshot{
			Number:  sp.Number,
			Hash:    sp.Hash,
			Signers: sp.Signers,
			Recents: sp.Recents,
			Votes:   sp.Votes,
			Tally:   sp.Tally,
		}, err
	}
}

func (x *XDPoS) GetAuthorisedSignersFromSnapshot(chain consensus.ChainReader, header *types.Header) ([]common.Address, error) {
	switch x.config.BlockConsensusVersion(header.Number) {
	case params.ConsensusEngineVersion2:
		return x.EngineV2.GetSignersFromSnapshot(chain, header)
	default: // Default "v1"
		return x.EngineV1.GetAuthorisedSignersFromSnapshot(chain, header)
	}
}

func (x *XDPoS) FindParentBlockToAssign(chain consensus.ChainReader, currentBlock *types.Header) *types.Block {
	var parent *types.Block = nil
	if x.config.BlockConsensusVersion(currentBlock.Number) == params.ConsensusEngineVersion2 {
		parent = x.EngineV2.FindParentBlockToAssign(chain)
	}
	if parent == nil {
		parent = chain.GetBlock(currentBlock.Hash(), currentBlock.Number.Uint64())
	}
	return parent
}

/**
Caching
*/

// Cache signing transaction data into BlockSingers cache object
func (x *XDPoS) CacheNoneTIPSigningTxs(header *types.Header, txs []*types.Transaction, receipts []*types.Receipt) []*types.Transaction {
	signTxs := []*types.Transaction{}
	for txIndex, tx := range txs {
		if tx.IsSigningTransaction() {
			receipt := findTransactionReceipt(txIndex, tx.Hash(), receipts)
			if receipt == nil {
				continue
			}

			status := receipt.Status
			if len(receipt.PostState) > 0 {
				status = types.ReceiptStatusSuccessful
			}
			if status == types.ReceiptStatusFailed {
				continue
			}

			signTxs = append(signTxs, tx)
		}
	}

	log.Debug("Save tx signers to cache", "hash", header.Hash(), "number", header.Number, "len(txs)", len(signTxs))
	x.signingTxsCache.Add(header.Hash(), signTxs)

	return signTxs
}

func findTransactionReceipt(txIndex int, txHash common.Hash, receipts []*types.Receipt) *types.Receipt {
	if txIndex < len(receipts) {
		receipt := receipts[txIndex]
		if receipt != nil && (receipt.TxHash == (common.Hash{}) || receipt.TxHash == txHash) {
			return receipt
		}
	}
	for _, receipt := range receipts {
		if receipt != nil && receipt.TxHash == txHash {
			return receipt
		}
	}
	return nil
}

// Cache
func (x *XDPoS) CacheSigningTxs(hash common.Hash, txs []*types.Transaction) []*types.Transaction {
	signTxs := []*types.Transaction{}
	for _, tx := range txs {
		if tx.IsSigningTransaction() {
			signTxs = append(signTxs, tx)
		}
	}
	log.Debug("Save tx signers to cache", "hash", hash, "len(txs)", len(signTxs))
	x.signingTxsCache.Add(hash, signTxs)
	return signTxs
}

func (x *XDPoS) GetCachedSigningTxs(hash common.Hash) ([]*types.Transaction, bool) {
	return x.signingTxsCache.Get(hash)
}

func (x *XDPoS) GetEpochSwitchInfoBetween(chain consensus.ChainReader, begin, end *types.Header) ([]*types.EpochSwitchInfo, error) {
	beginBlockVersion := x.config.BlockConsensusVersion(begin.Number)
	endBlockVersion := x.config.BlockConsensusVersion(end.Number)
	if beginBlockVersion == params.ConsensusEngineVersion2 && endBlockVersion == params.ConsensusEngineVersion2 {
		return x.EngineV2.GetEpochSwitchInfoBetween(chain, begin, end)
	}
	// Default "v1"
	return nil, errors.New("not supported in the v1 consensus")
}
