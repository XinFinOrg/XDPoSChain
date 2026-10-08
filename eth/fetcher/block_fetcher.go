// Copyright 2015 The go-ethereum Authors
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

// Package fetcher contains the announcement based blocks or transaction synchronisation.
package fetcher

import (
	"errors"
	"math/rand"
	"sync"
	"time"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/common/lru"
	"github.com/XinFinOrg/XDPoSChain/common/prque"
	"github.com/XinFinOrg/XDPoSChain/consensus"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/log"
	"github.com/XinFinOrg/XDPoSChain/metrics"
	"github.com/XinFinOrg/XDPoSChain/trie"
)

const (
	arriveTimeout = 500 * time.Millisecond // Time allowance before an announced block/transaction is explicitly requested
	gatherSlack   = 100 * time.Millisecond // Interval used to collate almost-expired announces with fetches
	fetchTimeout  = 5 * time.Second        // Maximum allotted time to return an explicitly requested block/transaction
)

const (
	maxUncleDist = 7   // Maximum allowed backward distance from the chain head
	maxQueueDist = 32  // Maximum allowed distance from the chain head to queue
	hashLimit    = 256 // Maximum number of unique blocks a peer may have announced
	blockLimit   = 64  // Maximum number of unique blocks a peer may have delivered
)

const (
	// parkedImportTimeout is a generous upper bound on how long a block whose
	// delivery reported success without importing it may wait for another
	// importer to store it before its signature is dropped. The fetcher imports
	// single blocks, so the reachable case is a block the downloader is already
	// fetching; that can span several download requests (a single request is
	// capped by the downloader's ttlLimit), so this is an upper bound rather
	// than one request's allowance.
	parkedImportTimeout      = 90 * time.Second
	parkedImportPollInterval = 100 * time.Millisecond // same cadence as the future-block loop

	// maxParkedSignatures caps the blocks waiting for their signature, so a
	// master equivocating at a height cannot accumulate unbounded blocks or
	// DB reads.
	maxParkedSignatures = 64
)

// IsPlausibleAnnouncement reports whether a block announcement at the given
// number is within the fetcher's plausibility window of the current chain
// height. Untrusted announced numbers must be gated on this check before being
// recorded (e.g. as a peer's live tip), so a peer cannot inflate the recorded
// number beyond the window.
func IsPlausibleAnnouncement(number, height uint64) bool {
	if number == 0 {
		return true
	}
	if number <= height {
		return height <= number+maxUncleDist
	}
	return number <= height+maxQueueDist
}

var (
	blockAnnounceInMeter   = metrics.NewRegisteredMeter("eth/fetcher/block/announces/in", nil)
	blockAnnounceOutTimer  = metrics.NewRegisteredTimer("eth/fetcher/block/announces/out", nil)
	blockAnnounceDropMeter = metrics.NewRegisteredMeter("eth/fetcher/block/announces/drop", nil)
	blockAnnounceDOSMeter  = metrics.NewRegisteredMeter("eth/fetcher/block/announces/dos", nil)

	blockBroadcastInMeter   = metrics.NewRegisteredMeter("eth/fetcher/block/broadcasts/in", nil)
	blockBroadcastOutTimer  = metrics.NewRegisteredTimer("eth/fetcher/block/broadcasts/out", nil)
	blockBroadcastDropMeter = metrics.NewRegisteredMeter("eth/fetcher/block/broadcasts/drop", nil)
	blockBroadcastDOSMeter  = metrics.NewRegisteredMeter("eth/fetcher/block/broadcasts/dos", nil)

	headerFetchMeter = metrics.NewRegisteredMeter("eth/fetcher/block/headers", nil)
	bodyFetchMeter   = metrics.NewRegisteredMeter("eth/fetcher/block/bodies", nil)

	headerFilterInMeter  = metrics.NewRegisteredMeter("eth/fetcher/block/filter/headers/in", nil)
	headerFilterOutMeter = metrics.NewRegisteredMeter("eth/fetcher/block/filter/headers/out", nil)
	bodyFilterInMeter    = metrics.NewRegisteredMeter("eth/fetcher/block/filter/bodies/in", nil)
	bodyFilterOutMeter   = metrics.NewRegisteredMeter("eth/fetcher/block/filter/bodies/out", nil)
)

var (
	errTerminated = errors.New("terminated")
)

// blockRetrievalFn is a callback type for retrieving a block from the local chain.
type blockRetrievalFn func(common.Hash) *types.Block

// headerRequesterFn is a callback type for sending a header retrieval request.
type headerRequesterFn func(common.Hash) error

// bodyRequesterFn is a callback type for sending a body retrieval request.
type bodyRequesterFn func([]common.Hash) error

// headerVerifierFn is a callback type to verify a block's header for fast propagation.
type headerVerifierFn func(header *types.Header) error

// proposeBlockHandlerFn is a callback type to handle a block by the consensus
type proposeBlockHandlerFn func(header *types.Header) error

// blockBroadcasterFn is a callback type for broadcasting a block to connected peers.
type blockBroadcasterFn func(block *types.Block, propagate bool)

// chainHeightFn is a callback type to retrieve the current chain height.
type chainHeightFn func() uint64

// blockInsertFn is a callback type to insert a batch of blocks into the local chain.
type blockInsertFn func(block *types.Block) error

type blockPrepareFn func(block *types.Block) error

// peerDropFn is a callback type for dropping a peer detected as malicious.
type peerDropFn func(id string)

// blockAnnounce is the hash notification of the availability of a new block in the
// network.
type blockAnnounce struct {
	hash   common.Hash   // Hash of the block being announced
	number uint64        // Number of the block being announced (0 = unknown | old protocol)
	header *types.Header // Header of the block partially reassembled (new protocol)
	time   time.Time     // Timestamp of the announcement

	origin string // Identifier of the peer originating the notification

	fetchHeader headerRequesterFn // Fetcher function to retrieve the header of an announced block
	fetchBodies bodyRequesterFn   // Fetcher function to retrieve the body of an announced block
}

// headerFilterTask represents a batch of headers needing fetcher filtering.
type headerFilterTask struct {
	peer    string          // The source peer of block headers
	headers []*types.Header // Collection of headers to filter
	time    time.Time       // Arrival time of the headers
}

// headerFilterTask represents a batch of block bodies (transactions and uncles)
// needing fetcher filtering.
type bodyFilterTask struct {
	peer         string                 // The source peer of block bodies
	transactions [][]*types.Transaction // Collection of transactions per block bodies
	uncles       [][]*types.Header      // Collection of uncles per block bodies
	time         time.Time              // Arrival time of the blocks' contents
}

// blockInject represents a schedules import operation.
type blockInject struct {
	origin string
	block  *types.Block
}

// parkedSign is a block whose delivery reported success without importing it,
// waiting for another importer to store it so its signature can be created.
type parkedSign struct {
	block    *types.Block
	deadline time.Time
}

// BlockFetcher is responsible for accumulating block announcements from various peers
// and scheduling them for retrieval.
type BlockFetcher struct {
	// Various event channels
	notify chan *blockAnnounce
	inject chan *blockInject

	headerFilter chan chan *headerFilterTask
	bodyFilter   chan chan *bodyFilterTask

	done chan common.Hash
	quit chan struct{}

	// Announce states
	announces  map[string]int                   // Per peer blockAnnounce counts to prevent memory exhaustion
	announced  map[common.Hash][]*blockAnnounce // Announced blocks, scheduled for fetching
	fetching   map[common.Hash]*blockAnnounce   // Announced blocks, currently fetching
	fetched    map[common.Hash][]*blockAnnounce // Blocks with headers fetched, scheduled for body retrieval
	completing map[common.Hash]*blockAnnounce   // Blocks with headers, currently body-completing

	// Block cache
	queue  *prque.Prque[int64, *blockInject] // Queue containing the import operations (block number sorted)
	queues map[string]int                    // Per peer block counts to prevent memory exhaustion
	queued map[common.Hash]*blockInject      // Set of already queued blocks (to dedup imports)
	knowns *lru.Cache[common.Hash, struct{}]

	// Parked signatures (XDPoS): blocks delivered while another importer was
	// still going to store them, waiting for the signing hook. Guarded by
	// parkedMu; waitParkedSignatures runs only while the set is non-empty, so an
	// idle fetcher runs no waiter.
	parkedMu      sync.Mutex
	parked        map[common.Hash]*parkedSign
	parkedWaiter  bool          // waitParkedSignatures is running (guarded by parkedMu)
	parkedTimeout time.Duration // bound per parked block; a field so tests can shrink it

	// Callbacks
	getBlock            blockRetrievalFn      // Retrieves a block from the local chain
	verifyHeader        headerVerifierFn      // Checks if a block's headers have a valid proof of work
	handleProposedBlock proposeBlockHandlerFn // Consensus v2 specific: Hanle new proposed block
	broadcastBlock      blockBroadcasterFn    // Broadcasts a block to connected peers
	chainHeight         chainHeightFn         // Retrieves the current chain's height
	insertBlock         blockInsertFn         // Injects a batch of blocks into the chain
	prepareBlock        blockPrepareFn
	dropPeer            peerDropFn // Drops a peer for misbehaving

	canonicalHash func(number uint64) common.Hash // Returns the canonical hash at a height, or the zero hash
	syncing       func() bool                     // Reports whether the node is still snap syncing

	// Testing hooks
	announceChangeHook func(common.Hash, bool) // Method to call upon adding or deleting a hash from the blockAnnounce list
	queueChangeHook    func(common.Hash, bool) // Method to call upon adding or deleting a block from the import queue
	fetchingHook       func([]common.Hash)     // Method to call upon starting a block (eth/61) or header (eth/62) fetch
	completingHook     func([]common.Hash)     // Method to call upon starting a block body fetch (eth/62)
	signHook           func(*types.Block) error
	appendM2HeaderHook func(*types.Block) (*types.Block, bool, error)
}

// NewBlockFetcher creates a block fetcher to retrieve blocks based on hash announcements.
func NewBlockFetcher(getBlock blockRetrievalFn, verifyHeader headerVerifierFn, handleProposedBlock proposeBlockHandlerFn, broadcastBlock blockBroadcasterFn, chainHeight chainHeightFn, insertBlock blockInsertFn, prepareBlock blockPrepareFn, dropPeer peerDropFn) *BlockFetcher {
	return &BlockFetcher{
		notify:              make(chan *blockAnnounce),
		inject:              make(chan *blockInject),
		headerFilter:        make(chan chan *headerFilterTask),
		bodyFilter:          make(chan chan *bodyFilterTask),
		done:                make(chan common.Hash),
		quit:                make(chan struct{}),
		announces:           make(map[string]int),
		announced:           make(map[common.Hash][]*blockAnnounce),
		fetching:            make(map[common.Hash]*blockAnnounce),
		fetched:             make(map[common.Hash][]*blockAnnounce),
		completing:          make(map[common.Hash]*blockAnnounce),
		queue:               prque.New[int64, *blockInject](nil),
		queues:              make(map[string]int),
		queued:              make(map[common.Hash]*blockInject),
		knowns:              lru.NewCache[common.Hash, struct{}](blockLimit),
		parked:              make(map[common.Hash]*parkedSign),
		parkedTimeout:       parkedImportTimeout,
		getBlock:            getBlock,
		verifyHeader:        verifyHeader,
		handleProposedBlock: handleProposedBlock,
		broadcastBlock:      broadcastBlock,
		chainHeight:         chainHeight,
		insertBlock:         insertBlock,
		prepareBlock:        prepareBlock,
		dropPeer:            dropPeer,
	}
}

// Start boots up the announcement based synchroniser, accepting and processing
// hash notifications and block fetches until termination requested.
func (f *BlockFetcher) Start() {
	go f.loop()
}

// Stop terminates the announcement based synchroniser, canceling all pending
// operations.
func (f *BlockFetcher) Stop() {
	close(f.quit)
}

// Notify announces the fetcher of the potential availability of a new block in
// the network.
func (f *BlockFetcher) Notify(peer string, hash common.Hash, number uint64, time time.Time,
	headerFetcher headerRequesterFn, bodyFetcher bodyRequesterFn) error {
	block := &blockAnnounce{
		hash:        hash,
		number:      number,
		time:        time,
		origin:      peer,
		fetchHeader: headerFetcher,
		fetchBodies: bodyFetcher,
	}
	select {
	case f.notify <- block:
		return nil
	case <-f.quit:
		return errTerminated
	}
}

// Enqueue tries to fill gaps the fetcher's future import queue.
func (f *BlockFetcher) Enqueue(peer string, block *types.Block) error {
	op := &blockInject{
		origin: peer,
		block:  block,
	}
	select {
	case f.inject <- op:
		return nil
	case <-f.quit:
		return errTerminated
	}
}

// FilterHeaders extracts all the headers that were explicitly requested by the fetcher,
// returning those that should be handled differently.
func (f *BlockFetcher) FilterHeaders(peer string, headers []*types.Header, time time.Time) []*types.Header {
	log.Trace("Filtering headers", "peer", peer, "headers", len(headers))

	// Send the filter channel to the fetcher
	filter := make(chan *headerFilterTask)

	select {
	case f.headerFilter <- filter:
	case <-f.quit:
		return nil
	}
	// Request the filtering of the header list
	select {
	case filter <- &headerFilterTask{peer: peer, headers: headers, time: time}:
	case <-f.quit:
		return nil
	}
	// Retrieve the headers remaining after filtering
	select {
	case task := <-filter:
		return task.headers
	case <-f.quit:
		return nil
	}
}

// FilterBodies extracts all the block bodies that were explicitly requested by
// the fetcher, returning those that should be handled differently.
func (f *BlockFetcher) FilterBodies(peer string, transactions [][]*types.Transaction, uncles [][]*types.Header, time time.Time) ([][]*types.Transaction, [][]*types.Header) {
	log.Trace("Filtering bodies", "peer", peer, "txs", len(transactions), "uncles", len(uncles))

	// Send the filter channel to the fetcher
	filter := make(chan *bodyFilterTask)

	select {
	case f.bodyFilter <- filter:
	case <-f.quit:
		return nil, nil
	}
	// Request the filtering of the body list
	select {
	case filter <- &bodyFilterTask{peer: peer, transactions: transactions, uncles: uncles, time: time}:
	case <-f.quit:
		return nil, nil
	}
	// Retrieve the bodies remaining after filtering
	select {
	case task := <-filter:
		return task.transactions, task.uncles
	case <-f.quit:
		return nil, nil
	}
}

// Loop is the main fetcher loop, checking and processing various notification
// events.
func (f *BlockFetcher) loop() {
	// Iterate the block fetching until a quit is requested
	fetchTimer := time.NewTimer(0)
	completeTimer := time.NewTimer(0)

	for {
		// Clean up any expired block fetches
		for hash, announce := range f.fetching {
			if time.Since(announce.time) > fetchTimeout {
				f.forgetHash(hash)
			}
		}
		// Import any queued blocks that could potentially fit
		height := f.chainHeight()
		for !f.queue.Empty() {
			op := f.queue.PopItem()
			if f.queueChangeHook != nil {
				f.queueChangeHook(op.block.Hash(), false)
			}
			// If too high up the chain or phase, continue later
			number := op.block.NumberU64()
			if number > height+1 {
				f.queue.Push(op, -int64(op.block.NumberU64()))
				if f.queueChangeHook != nil {
					f.queueChangeHook(op.block.Hash(), true)
				}
				break
			}
			// Otherwise if fresh and still unknown, try and import
			hash := op.block.Hash()
			if number+maxUncleDist < height || f.getBlock(hash) != nil {
				f.forgetBlock(hash)
				continue
			}
			f.insert(op.origin, op.block)
		}
		// Wait for an outside event to occur
		select {
		case <-f.quit:
			// Fetcher terminating, abort all operations
			return

		case notification := <-f.notify:
			// A block was announced, make sure the peer isn't DOSing us
			blockAnnounceInMeter.Mark(1)

			count := f.announces[notification.origin] + 1
			if count > hashLimit {
				log.Debug("Peer exceeded outstanding announces", "peer", notification.origin, "limit", hashLimit)
				blockAnnounceDOSMeter.Mark(1)
				break
			}
			// If we have a valid block number, check that it's potentially useful
			height := f.chainHeight()
			if !IsPlausibleAnnouncement(notification.number, height) {
				log.Debug("Peer discarded announcement", "peer", notification.origin, "number", notification.number, "hash", notification.hash, "height", height)
				blockAnnounceDropMeter.Mark(1)
				break
			}
			// All is well, schedule the announce if block's not yet downloading
			if _, ok := f.fetching[notification.hash]; ok {
				break
			}
			if _, ok := f.completing[notification.hash]; ok {
				break
			}
			f.announces[notification.origin] = count
			f.announced[notification.hash] = append(f.announced[notification.hash], notification)
			if f.announceChangeHook != nil && len(f.announced[notification.hash]) == 1 {
				f.announceChangeHook(notification.hash, true)
			}
			if len(f.announced) == 1 {
				f.rescheduleFetch(fetchTimer)
			}

		case op := <-f.inject:
			// A direct block insertion was requested, try and fill any pending gaps
			blockBroadcastInMeter.Mark(1)
			f.enqueue(op.origin, op.block)

		case hash := <-f.done:
			// A pending import finished, remove all traces of the notification
			f.forgetHash(hash)
			f.forgetBlock(hash)

		case <-fetchTimer.C:
			// At least one block's timer ran out, check for needing retrieval
			request := make(map[string][]common.Hash)

			for hash, announces := range f.announced {
				if time.Since(announces[0].time) > arriveTimeout-gatherSlack {
					// Pick a random peer to retrieve from, reset all others
					announce := announces[rand.Intn(len(announces))]
					f.forgetHash(hash)

					// If the block still didn't arrive, queue for fetching
					if f.getBlock(hash) == nil {
						request[announce.origin] = append(request[announce.origin], hash)
						f.fetching[hash] = announce
					}
				}
			}
			// Send out all block header requests
			for peer, hashes := range request {
				log.Trace("Fetching scheduled headers", "peer", peer, "list", hashes)

				// Create a closure of the fetch and schedule in on a new thread
				fetchHeader := f.fetching[hashes[0]].fetchHeader
				go func() {
					if f.fetchingHook != nil {
						f.fetchingHook(hashes)
					}
					for _, hash := range hashes {
						headerFetchMeter.Mark(1)
						fetchHeader(hash) // Suboptimal, but protocol doesn't allow batch header retrievals
					}
				}()
			}
			// Schedule the next fetch if blocks are still pending
			f.rescheduleFetch(fetchTimer)

		case <-completeTimer.C:
			// At least one header's timer ran out, retrieve everything
			request := make(map[string][]common.Hash)

			for hash, announces := range f.fetched {
				// Pick a random peer to retrieve from, reset all others
				announce := announces[rand.Intn(len(announces))]
				f.forgetHash(hash)

				// If the block still didn't arrive, queue for completion
				if f.getBlock(hash) == nil {
					request[announce.origin] = append(request[announce.origin], hash)
					f.completing[hash] = announce
				}
			}
			// Send out all block body requests
			for peer, hashes := range request {
				log.Trace("Fetching scheduled bodies", "peer", peer, "list", hashes)

				// Create a closure of the fetch and schedule in on a new thread
				if f.completingHook != nil {
					f.completingHook(hashes)
				}
				bodyFetchMeter.Mark(int64(len(hashes)))
				go f.completing[hashes[0]].fetchBodies(hashes)
			}
			// Schedule the next fetch if blocks are still pending
			f.rescheduleComplete(completeTimer)

		case filter := <-f.headerFilter:
			// Headers arrived from a remote peer. Extract those that were explicitly
			// requested by the fetcher, and return everything else so it's delivered
			// to other parts of the system.
			var task *headerFilterTask
			select {
			case task = <-filter:
			case <-f.quit:
				return
			}
			headerFilterInMeter.Mark(int64(len(task.headers)))

			// Split the batch of headers into unknown ones (to return to the caller),
			// knowns incomplete ones (requiring body retrievals) and completed blocks.
			unknown, incomplete, complete := []*types.Header{}, []*blockAnnounce{}, []*types.Block{}
			for _, header := range task.headers {
				hash := header.Hash()

				// Filter fetcher-requested headers from other synchronisation algorithms
				if announce := f.fetching[hash]; announce != nil && announce.origin == task.peer && f.fetched[hash] == nil && f.completing[hash] == nil && f.queued[hash] == nil {
					// If the delivered header does not match the promised number, drop the announcer
					if header.Number.Uint64() != announce.number {
						log.Trace("Invalid block number fetched", "peer", announce.origin, "hash", header.Hash(), "announced", announce.number, "provided", header.Number)
						f.dropPeer(announce.origin)
						f.forgetHash(hash)
						continue
					}
					// Only keep if not imported by other means
					if f.getBlock(hash) == nil {
						announce.header = header
						announce.time = task.time

						// If the block is empty (header only), short circuit into the final import queue
						if header.TxHash == types.DeriveSha(types.Transactions{}, trie.NewStackTrie(nil)) && header.UncleHash == types.CalcUncleHash([]*types.Header{}) {
							log.Trace("Block empty, skipping body retrieval", "peer", announce.origin, "number", header.Number, "hash", header.Hash())

							block := types.NewBlockWithHeader(header)
							block.ReceivedAt = task.time

							complete = append(complete, block)
							f.completing[hash] = announce
							continue
						}
						// Otherwise add to the list of blocks needing completion
						incomplete = append(incomplete, announce)
					} else {
						log.Trace("Block already imported, discarding header", "peer", announce.origin, "number", header.Number, "hash", header.Hash())
						f.forgetHash(hash)
					}
				} else {
					// BlockFetcher doesn't know about it, add to the return list
					unknown = append(unknown, header)
				}
			}
			headerFilterOutMeter.Mark(int64(len(unknown)))
			select {
			case filter <- &headerFilterTask{headers: unknown, time: task.time}:
			case <-f.quit:
				return
			}
			// Schedule the retrieved headers for body completion
			for _, announce := range incomplete {
				hash := announce.header.Hash()
				if _, ok := f.completing[hash]; ok {
					continue
				}
				f.fetched[hash] = append(f.fetched[hash], announce)
				if len(f.fetched) == 1 {
					f.rescheduleComplete(completeTimer)
				}
			}
			// Schedule the header-only blocks for import
			for _, block := range complete {
				if announce := f.completing[block.Hash()]; announce != nil {
					f.enqueue(announce.origin, block)
				}
			}

		case filter := <-f.bodyFilter:
			// Block bodies arrived, extract any explicitly requested blocks, return the rest
			var task *bodyFilterTask
			select {
			case task = <-filter:
			case <-f.quit:
				return
			}
			bodyFilterInMeter.Mark(int64(len(task.transactions)))
			blocks := []*types.Block{}
			// abort early if there's nothing explicitly requested
			if len(f.completing) > 0 {
				for i := 0; i < len(task.transactions) && i < len(task.uncles); i++ {
					// Match up a body to any possible completion request
					var (
						matched   = false
						uncleHash common.Hash // calculated lazily and reused
						txnHash   common.Hash // calculated lazily and reused
					)
					for hash, announce := range f.completing {
						if f.queued[hash] != nil || announce.origin != task.peer {
							continue
						}
						if uncleHash == (common.Hash{}) {
							uncleHash = types.CalcUncleHash(task.uncles[i])
						}
						if uncleHash != announce.header.UncleHash {
							continue
						}
						if txnHash == (common.Hash{}) {
							txnHash = types.DeriveSha(types.Transactions(task.transactions[i]), trie.NewStackTrie(nil))
						}
						if txnHash != announce.header.TxHash {
							continue
						}
						// Mark the body matched, reassemble if still unknown
						matched = true
						if f.getBlock(hash) == nil {
							block := types.NewBlockWithHeader(announce.header).WithBody(types.Body{Transactions: task.transactions[i], Uncles: task.uncles[i]})
							block.ReceivedAt = task.time
							blocks = append(blocks, block)
						} else {
							f.forgetHash(hash)
						}
					}
					if matched {
						task.transactions = append(task.transactions[:i], task.transactions[i+1:]...)
						task.uncles = append(task.uncles[:i], task.uncles[i+1:]...)
						i--
						continue
					}
				}
			}
			bodyFilterOutMeter.Mark(int64(len(task.transactions)))
			select {
			case filter <- task:
			case <-f.quit:
				return
			}
			// Schedule the retrieved blocks for ordered import
			for _, block := range blocks {
				if announce := f.completing[block.Hash()]; announce != nil {
					f.enqueue(announce.origin, block)
				}
			}
		}
	}
}

// rescheduleFetch resets the specified fetch timer to the next blockAnnounce timeout.
func (f *BlockFetcher) rescheduleFetch(fetch *time.Timer) {
	// Short circuit if no blocks are announced
	if len(f.announced) == 0 {
		return
	}
	// Otherwise find the earliest expiring announcement
	earliest := time.Now()
	for _, announces := range f.announced {
		if earliest.After(announces[0].time) {
			earliest = announces[0].time
		}
	}
	fetch.Reset(arriveTimeout - time.Since(earliest))
}

// rescheduleComplete resets the specified completion timer to the next fetch timeout.
func (f *BlockFetcher) rescheduleComplete(complete *time.Timer) {
	// Short circuit if no headers are fetched
	if len(f.fetched) == 0 {
		return
	}
	// Otherwise find the earliest expiring announcement
	earliest := time.Now()
	for _, announces := range f.fetched {
		if earliest.After(announces[0].time) {
			earliest = announces[0].time
		}
	}
	complete.Reset(gatherSlack - time.Since(earliest))
}

// enqueue schedules a new future import operation, if the block to be imported
// has not yet been seen.
func (f *BlockFetcher) enqueue(peer string, block *types.Block) {
	hash := block.Hash()
	if f.knowns.Contains(hash) {
		log.Trace("Discarded propagated block, known block", "peer", peer, "number", block.Number(), "hash", hash, "limit", blockLimit)
		return
	}
	// Ensure the peer isn't DOSing us
	count := f.queues[peer] + 1
	if count > blockLimit {
		log.Debug("Discarded propagated block, exceeded allowance", "peer", peer, "number", block.Number(), "hash", hash, "limit", blockLimit)
		blockBroadcastDOSMeter.Mark(1)
		f.forgetHash(hash)
		return
	}
	// Discard any past or too distant blocks, using the same overflow-safe
	// plausibility window as block announcements so a far-future number (e.g.
	// MaxUint64) cannot wrap to a small distance and slip into the queue.
	if !IsPlausibleAnnouncement(block.NumberU64(), f.chainHeight()) {
		log.Debug("Discarded propagated block, too far away", "peer", peer, "number", block.Number(), "hash", hash)
		blockBroadcastDropMeter.Mark(1)
		f.forgetHash(hash)
		return
	}
	// Schedule the block for future importing
	if _, ok := f.queued[hash]; !ok {
		op := &blockInject{
			origin: peer,
			block:  block,
		}
		f.queues[peer] = count
		f.queued[hash] = op
		f.knowns.Add(hash, struct{}{})
		f.queue.Push(op, -int64(block.NumberU64()))
		if f.queueChangeHook != nil {
			f.queueChangeHook(op.block.Hash(), true)
		}
		log.Debug("Queued propagated block", "peer", peer, "number", block.Number(), "hash", hash, "queued", f.queue.Size())
	}
}

// insert spawns a new goroutine to run a block insertion into the chain. If the
// block's number is at the same height as the current import phase, it updates
// the phase states accordingly.
func (f *BlockFetcher) insert(peer string, block *types.Block) {
	hash := block.Hash()

	// Run the import on a new thread
	log.Debug("Importing propagated block", "peer", peer, "number", block.Number(), "hash", hash)
	go func() {
		defer func() { f.done <- hash }()

		// If the parent's unknown, abort insertion
		parent := f.getBlock(block.ParentHash())
		if parent == nil {
			log.Debug("Unknown parent of propagated block", "peer", peer, "number", block.Number(), "hash", hash, "parent", block.ParentHash())
			return
		}
		isM2 := false
	again:
		err := f.verifyHeader(block.Header())
		// Quickly validate the header and propagate the block if it passes
		switch err {
		case nil:
			// All ok, quickly propagate to our peers
			if !isM2 {
				blockBroadcastOutTimer.UpdateSince(block.ReceivedAt)
				go f.broadcastBlock(block, true)
			}
		case consensus.ErrFutureBlock:
			delay := time.Until(time.Unix(int64(block.Time()), 0))
			log.Info("Receive future block", "number", block.NumberU64(), "hash", block.Hash().Hex(), "delay", delay)
			time.Sleep(delay)
			goto again
		case consensus.ErrNoValidatorSignature:
			newBlock := block
			var errM2 error
			if f.appendM2HeaderHook != nil {
				if newBlock, isM2, errM2 = f.appendM2HeaderHook(block); errM2 != nil {
					log.Error("Append m2 to block header fail", "err", errM2)
					return
				}
			}
			if !isM2 {
				blockBroadcastOutTimer.UpdateSince(block.ReceivedAt)
				go f.broadcastBlock(block, true)
				if err := f.prepareBlock(block); err != nil {
					log.Debug("Propagated block prepare failed", "peer", peer, "number", block.Number(), "hash", hash, "err", err)
				}
				return
			}
			log.Debug("Append M2 to header block", "number", block.NumberU64(), "hash", block.Hash())
			if err := f.prepareBlock(block); err != nil {
				log.Debug("Propagated block prepare failed", "peer", peer, "number", block.Number(), "hash", hash, "err", err)
				return
			}
			block = newBlock
			goto again
		default:
			// Something went very wrong, drop the peer
			log.Warn("Propagated block verification failed", "peer", peer, "number", block.Number(), "hash", hash, "err", err)
			f.dropPeer(peer)
			return
		}
		// Run the actual import and log any issues
		if err := f.insertBlock(block); err != nil {
			log.Warn("Propagated block import failed", "peer", peer, "number", block.Number(), "hash", hash, "err", err)
			return
		}

		// Signing and consensus handling require the block to actually be in
		// the chain, which a nil import error does not guarantee: this
		// fetcher's inserter discards the block while fast sync is still
		// running, the single-block path returns without storing a block the
		// downloader is already fetching, and a batch import parks its future
		// tail in the future queue instead of writing it. Signing an
		// unimported block, or voting on it, would corrupt the consensus
		// state: processQC writes highestQuorumCert before it checks that the
		// block exists. Relaying is safe either way - a receiver that has the
		// block drops it again - so the broadcast below must not depend on
		// whether the block was stored.
		if f.getBlock(block.Hash()) == nil {
			log.Debug("Propagated block was not imported, deferring signing", "peer", peer, "number", block.Number(), "hash", hash)
			// Another importer stores the block once its timestamp arrives
			// (procFutureBlocks) or once the downloader reaches it; create
			// the signature transaction then. The vote is not compensated:
			// procFutureBlocks feeds the imported block to the consensus
			// engine itself. Only nodes with a signing hook (XDPoS) park;
			// without one there is nothing to wait for.
			f.parkForSignature(block)
			if isM2 {
				blockBroadcastOutTimer.UpdateSince(block.ReceivedAt)
				go f.broadcastBlock(block, true)
			} else {
				blockAnnounceOutTimer.UpdateSince(block.ReceivedAt)
				go f.broadcastBlock(block, false)
			}
			return
		}
		// Being in the chain is not enough for the signature, which spends a
		// transaction: the block must also be canonical and still fresh. A
		// stored side entry, or one this node declined to adopt, passes the
		// existence gate but is not worth signing right now. This gate covers
		// the signature only and must not return: the consensus handling below
		// keeps the existence gate alone, and procFutureBlocks remains the
		// owner of the vote.
		if f.signHook != nil {
			signable := f.canSign(block)
			if signable {
				if err := f.signHook(block); err != nil {
					log.Error("Can't sign the imported block", "err", err)
					return
				}
			}
			if !signable {
				log.Debug("Imported block is not canonical, parking the signature", "peer", peer, "number", block.Number(), "hash", hash)
				// The block is stored, so the parked set can revive the
				// signature if a later reorg adopts this branch; failing that
				// the uncle-distance and deadline bounds drop it. Voting is
				// not deferred: handleProposedBlock below still runs now.
				// Parking a refused block costs a parked-slot (capped by
				// maxParkedSignatures, drained by the deadline), so a master
				// equivocating at a height can fill the set, but the slots
				// clear within parkedImportTimeout.
				f.parkForSignature(block)
			}
		}
		err = f.handleProposedBlock(block.Header())
		if err != nil {
			log.Warn("[insert] Unable to handle new proposed block", "err", err, "number", block.Number(), "hash", block.Hash())
			return
		}
		// If import succeeded, broadcast the block
		if isM2 {
			blockBroadcastOutTimer.UpdateSince(block.ReceivedAt)
			go f.broadcastBlock(block, true)
		} else {
			blockAnnounceOutTimer.UpdateSince(block.ReceivedAt)
			go f.broadcastBlock(block, false)
		}
	}()
}

// parkForSignature records a block whose signature cannot be created yet, so
// it can be created once the block becomes signable. Two callers feed the set:
// a delivery that reported success without importing the block (another
// importer stores it later), and a stored block refused for not being
// canonical (a later reorg can adopt its branch). The first park starts
// waitParkedSignatures; it stops when the set drains.
// The wait is bounded by parkedImportTimeout and the number of parked blocks by
// maxParkedSignatures. During snap sync the inserter discards propagated blocks
// outright, so nothing can arrive to sign and the block is not parked at all.
// The sign hook must be wired before blocks are delivered - eth.New does this
// before the syncer starts the fetcher - since a block delivered without a hook
// is not parked.
func (f *BlockFetcher) parkForSignature(block *types.Block) {
	if f.signHook == nil {
		return
	}
	if f.syncing != nil && f.syncing() {
		return
	}
	select {
	case <-f.quit:
		return
	default:
	}
	hash := block.Hash()

	f.parkedMu.Lock()
	if _, ok := f.parked[hash]; ok {
		f.parkedMu.Unlock()
		return
	}
	if len(f.parked) >= maxParkedSignatures {
		f.parkedMu.Unlock()
		log.Debug("Too many blocks parked for signing, dropping signature", "number", block.Number(), "hash", hash)
		return
	}
	f.parked[hash] = &parkedSign{block: block, deadline: time.Now().Add(f.parkedTimeout)}
	start := !f.parkedWaiter
	f.parkedWaiter = true
	f.parkedMu.Unlock()

	if start {
		go f.waitParkedSignatures()
	}
}

// waitParkedSignatures drains the parked-signature set on a single ticker and
// returns once the set is empty, so an idle fetcher runs no waiter. One
// goroutine and one ticker serve every parked block while any remain; a park
// racing the exit either finds the waiter running or starts a new one.
func (f *BlockFetcher) waitParkedSignatures() {
	ticker := time.NewTicker(parkedImportPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-f.quit:
			f.parkedMu.Lock()
			f.parkedWaiter = false
			f.parkedMu.Unlock()
			return
		case <-ticker.C:
			f.scanParkedSignatures()

			f.parkedMu.Lock()
			empty := len(f.parked) == 0
			if empty {
				f.parkedWaiter = false
			}
			f.parkedMu.Unlock()
			if empty {
				return
			}
		}
	}
}

// scanParkedSignatures signs the parked blocks that have become signable and
// drops the rest once one of the two bounds is hit: the block has fallen below
// the uncle distance, or its deadline has passed. A stored block that is not
// signable *right now* is not a reason to drop it — the body is written
// (rawdb.WriteBlock) before the canonical head (adoptHead), so a block that
// reads as stored-but-not-canonical here can become canonical moments later;
// discarding it would lose its signature for good. Signing happens outside the
// lock so a slow signature cannot stall the scan.
func (f *BlockFetcher) scanParkedSignatures() {
	var ready []*types.Block

	// The chain reads below (getBlock, and canSign's canonicalHash and
	// chainHeight) run under parkedMu on purpose: parkedMu is a leaf lock -
	// nothing beneath it takes another lock - and the set holds at most
	// maxParkedSignatures entries with short reads, so the worst case stalls
	// a parkForSignature caller for one scan pass. Collecting hashes under
	// the lock and reading the chain outside it would trade that bounded
	// stall for an ABA window: a reorg landing between the snapshot and the
	// re-lock could act on a stale height and drop a signature for good,
	// which is the loss this scan exists to prevent. Signing still happens
	// outside the lock, below.
	f.parkedMu.Lock()
	for hash, parked := range f.parked {
		if block := f.getBlock(hash); block != nil && f.canSign(block) {
			ready = append(ready, block)
			delete(f.parked, hash)
			continue
		}
		if parked.block.NumberU64()+maxUncleDist < f.chainHeight() {
			log.Debug("Parked block fell below the uncle distance, dropping signature", "number", parked.block.Number(), "hash", hash)
			delete(f.parked, hash)
			continue
		}
		if time.Now().After(parked.deadline) {
			if f.getBlock(hash) != nil {
				log.Debug("Parked block was stored but never became signable, dropping its signature", "number", parked.block.Number(), "hash", hash)
			} else {
				log.Warn("Block was not imported in time, dropping its signature", "number", parked.block.Number(), "hash", hash)
			}
			delete(f.parked, hash)
		}
	}
	f.parkedMu.Unlock()

	for _, block := range ready {
		// A reorg can land between the scan and this call, so re-check before
		// signing: a block the chain has moved past must not be signed.
		if !f.canSign(block) {
			log.Debug("Parked block is no longer signable, skipping signature", "number", block.Number(), "hash", block.Hash())
			continue
		}
		if err := f.signHook(block); err != nil {
			log.Error("Can't sign the imported block", "err", err)
		}
	}
}

// canSign reports whether a block is worth a signature: it must be on the
// canonical chain and not already too far below the head to matter. A stored
// block that is not canonical (a side entry, or one this node declined to
// adopt) fails the first test and is never signed. An unset canonicalHash fails
// closed: without a canonicality source no block is signed.
func (f *BlockFetcher) canSign(block *types.Block) bool {
	if f.canonicalHash == nil || f.canonicalHash(block.NumberU64()) != block.Hash() {
		return false
	}
	return block.NumberU64()+maxUncleDist >= f.chainHeight()
}

// forgetHash removes all traces of a block announcement from the fetcher's
// internal state.
func (f *BlockFetcher) forgetHash(hash common.Hash) {
	// Remove all pending announces and decrement DOS counters
	if announceMap, ok := f.announced[hash]; ok {
		for _, announce := range announceMap {
			f.announces[announce.origin]--
			if f.announces[announce.origin] <= 0 {
				delete(f.announces, announce.origin)
			}
		}
		delete(f.announced, hash)
		if f.announceChangeHook != nil {
			f.announceChangeHook(hash, false)
		}
	}
	// Remove any pending fetches and decrement the DOS counters
	if announce := f.fetching[hash]; announce != nil {
		f.announces[announce.origin]--
		if f.announces[announce.origin] <= 0 {
			delete(f.announces, announce.origin)
		}
		delete(f.fetching, hash)
	}

	// Remove any pending completion requests and decrement the DOS counters
	for _, announce := range f.fetched[hash] {
		f.announces[announce.origin]--
		if f.announces[announce.origin] <= 0 {
			delete(f.announces, announce.origin)
		}
	}
	delete(f.fetched, hash)

	// Remove any pending completions and decrement the DOS counters
	if announce := f.completing[hash]; announce != nil {
		f.announces[announce.origin]--
		if f.announces[announce.origin] <= 0 {
			delete(f.announces, announce.origin)
		}
		delete(f.completing, hash)
	}
}

// forgetBlock removes all traces of a queued block from the fetcher's internal
// state.
func (f *BlockFetcher) forgetBlock(hash common.Hash) {
	if insert := f.queued[hash]; insert != nil {
		f.queues[insert.origin]--
		if f.queues[insert.origin] == 0 {
			delete(f.queues, insert.origin)
		}
		delete(f.queued, hash)
	}
}

// Bind double validate hook before block imported into chain.
func (f *BlockFetcher) SetSignHook(signHook func(*types.Block) error) {
	f.signHook = signHook
}

// SetCanonicalHashFn binds the source of canonical hashes used to refuse
// signing a block that is not on the canonical chain. Until it is set, no block
// is signed.
func (f *BlockFetcher) SetCanonicalHashFn(canonicalHash func(number uint64) common.Hash) {
	f.canonicalHash = canonicalHash
}

// SetSyncingHook binds the predicate that reports whether the node is still
// snap syncing. While it holds, the inserter discards propagated blocks, so the
// fetcher parks no signature for them.
func (f *BlockFetcher) SetSyncingHook(syncing func() bool) {
	f.syncing = syncing
}

// CanonicalHashFn returns the canonical-hash source the fetcher was wired with,
// or nil if none. Exported for cross-package wiring tests only: eth's tests
// assert NewProtocolManager installs it, since canSign fails closed and a
// missing setter would silently stop every signature. Not part of the supported
// API; production code must not call it.
func (f *BlockFetcher) CanonicalHashFn() func(number uint64) common.Hash {
	return f.canonicalHash
}

// SyncingHook returns the snap-sync predicate the fetcher was wired with, or
// nil if none. Exported for cross-package wiring tests only - see
// CanonicalHashFn. Not part of the supported API.
func (f *BlockFetcher) SyncingHook() func() bool {
	return f.syncing
}

// Bind append m2 to block header hook when imported into chain.
func (f *BlockFetcher) SetAppendM2HeaderHook(appendM2HeaderHook func(*types.Block) (*types.Block, bool, error)) {
	f.appendM2HeaderHook = appendM2HeaderHook
}
