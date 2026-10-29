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
	parkedImportTimeout      = 90 * time.Second
	parkedImportPollInterval = 100 * time.Millisecond // same cadence as futureBlocksLoop's ticker in core/blockchain.go

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

func belowUncleDist(number, height uint64) bool {
	return number+maxUncleDist < height
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

	blockParkedRefusedMeter  = metrics.NewRegisteredMeter("eth/fetcher/block/parked/refused", nil)
	blockParkedStaleMeter    = metrics.NewRegisteredMeter("eth/fetcher/block/parked/stale", nil)
	blockParkedDeadlineMeter = metrics.NewRegisteredMeter("eth/fetcher/block/parked/deadline", nil)
	blockParkedFullMeter     = metrics.NewRegisteredMeter("eth/fetcher/block/parked/full", nil)
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

// bodyFilterTask represents a batch of block bodies (transactions and uncles)
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

type parkedBlock struct {
	block    *types.Block
	deadline time.Time
	claimed  bool // a caller (scan or delivery) owns the entry and is creating its signature
}

type readySignature struct {
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

	parkedMu      sync.Mutex
	parked        map[common.Hash]*parkedBlock
	signing       map[common.Hash]struct{} // signature hooks currently running; a hash with no entry is recorded too, and the marker outlives a parked entry evicted at its deadline (guarded by parkedMu)
	signingBatch  bool                     // a waiter-dispatched signing batch is running (guarded by parkedMu)
	parkedWaiter  bool                     // waitParkedSignatures is running (guarded by parkedMu)
	parkedTimeout time.Duration            // bound per parked block; a field so tests can shrink it before anything is parked (read under parkedMu; tests write it before the first park, where no reader can race)

	// Callbacks
	getBlock            blockRetrievalFn      // Retrieves a block from the local chain
	verifyHeader        headerVerifierFn      // Checks if a block's headers have a valid proof of work
	handleProposedBlock proposeBlockHandlerFn // Consensus v2 specific: Handle new proposed block
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
func NewBlockFetcher(getBlock blockRetrievalFn, verifyHeader headerVerifierFn, handleProposedBlock proposeBlockHandlerFn, broadcastBlock blockBroadcasterFn, chainHeight chainHeightFn, insertBlock blockInsertFn, prepareBlock blockPrepareFn, dropPeer peerDropFn, canonicalHash func(number uint64) common.Hash, syncing func() bool) *BlockFetcher {
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
		parked:              make(map[common.Hash]*parkedBlock),
		signing:             make(map[common.Hash]struct{}),
		parkedTimeout:       parkedImportTimeout,
		canonicalHash:       canonicalHash,
		syncing:             syncing,
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
			// block is the M2 rewrite: block.Hash() is the on-chain identity, while hash
			// stays the delivery identity and must not be updated here.
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

		// A nil import error does not mean the block is in the chain: the inserter
		// discards it while fast syncing and parks a batch tail in the future queue.
		// Signing or voting on it corrupts consensus state; relaying is safe.
		if f.getBlock(block.Hash()) == nil {
			log.Debug("Propagated block was not imported, deferring signing", "peer", peer, "number", block.Number(), "hash", hash)
			f.parkForSignature(block)
			f.relayBlock(block, isM2)
			return
		}
		// The signature spends a transaction, so the block must be canonical, fresh
		// and not snap syncing. This gate must not return on a refusal.
		if f.signHook != nil && !f.syncing() {
			switch f.signatureVerdictOf(block) {
			case signNow:
				// The parked set may already own it; signing on both paths spends two transactions.
				ok, tookEntry := f.claimParkedSignature(block.Hash())
				if !ok {
					log.Debug("Imported block's signature is already in flight or its parked entry expired", "peer", peer, "number", block.Number(), "hash", hash)
					break
				}
				// Taking the claim can wait behind a scan, and a reorg or snap sync can land
				// in that window: re-check before signing. A refused block keeps its entry.
				if f.syncing() {
					log.Debug("Imported block's signature deferred: snap sync started while its claim was taken", "peer", peer, "number", block.Number(), "hash", hash)
					f.resolveParked(block.Hash(), false)
					break
				}
				switch f.signatureVerdictOf(block) {
				case signNow:
					err := f.signBlock(block)
					f.resolveParked(block.Hash(), true)
					if err != nil {
						return
					}
				case signNotCanonical:
					blockParkedRefusedMeter.Mark(1)
					log.Debug("Imported block stopped being canonical while its signature was claimed, parking it", "peer", peer, "number", block.Number(), "hash", hash)
					// Release and re-park in one critical section, or a scan in between would let
					// this park recreate the entry. An entry the claim took over keeps its deadline.
					f.settleRefusedClaim(block, tookEntry)
				case signBelowUncleDist:
					log.Debug("Imported block fell below the uncle distance while its signature was claimed, not signing", "peer", peer, "number", block.Number(), "hash", hash)
					f.resolveParked(block.Hash(), false)
				default:
					f.resolveParked(block.Hash(), false)
				}
			case signNotCanonical:
				blockParkedRefusedMeter.Mark(1)
				log.Debug("Imported block is not canonical, parking the signature", "peer", peer, "number", block.Number(), "hash", hash)
				f.parkForSignature(block)
			case signBelowUncleDist:
				blockParkedStaleMeter.Mark(1)
				log.Debug("Imported block fell below the uncle distance, not signing", "peer", peer, "number", block.Number(), "hash", hash)
				// The head only moves away below the uncle distance, so do not park it.
			}
		}
		err = f.handleProposedBlock(block.Header())
		if err != nil {
			log.Warn("[insert] Unable to handle new proposed block", "err", err, "number", block.Number(), "hash", block.Hash())
			return
		}
		// If import succeeded, broadcast the block
		f.relayBlock(block, isM2)
	}()
}

func (f *BlockFetcher) relayBlock(block *types.Block, isM2 bool) {
	if isM2 {
		blockBroadcastOutTimer.UpdateSince(block.ReceivedAt)
		go f.broadcastBlock(block, true)
	} else {
		blockAnnounceOutTimer.UpdateSince(block.ReceivedAt)
		go f.broadcastBlock(block, false)
	}
}

func (f *BlockFetcher) signBlock(block *types.Block) error {
	if err := f.signHook(block); err != nil {
		log.Error("Can't sign the imported block", "err", err)
		return err
	}
	return nil
}

// parkForSignature parks a block whose signature cannot be created yet; the
// wait is bounded by parkedImportTimeout and maxParkedSignatures.
func (f *BlockFetcher) parkForSignature(block *types.Block) {
	if f.signHook == nil || f.syncing() {
		return
	}
	select {
	case <-f.quit:
		return
	default:
	}
	f.parkedMu.Lock()
	start := f.parkLocked(block)
	f.parkedMu.Unlock()

	if start {
		go f.waitParkedSignatures()
	}
}

// parkLocked inserts an entry unless one or its in-flight marker is present or
// the set is full; start tells the caller to start waitParkedSignatures.
func (f *BlockFetcher) parkLocked(block *types.Block) (start bool) {
	hash := block.Hash()
	if _, ok := f.signing[hash]; ok {
		return false
	}
	if _, ok := f.parked[hash]; ok {
		return false
	}
	if len(f.parked) >= maxParkedSignatures {
		blockParkedFullMeter.Mark(1)
		// Debug on purpose: a peer can reach this gate repeatedly, so the meter is the signal.
		log.Debug("Too many blocks parked for signing, dropping signature", "number", block.Number(), "hash", hash)
		return false
	}
	f.parked[hash] = &parkedBlock{block: block, deadline: time.Now().Add(f.parkedTimeout)}
	start = !f.parkedWaiter
	f.parkedWaiter = true
	return start
}

// settleRefusedClaim settles a refused claim in one critical section: drop the
// marker and either unclaim or drop the entry, or park an entry-less claim.
func (f *BlockFetcher) settleRefusedClaim(block *types.Block, tookEntry bool) {
	hash := block.Hash()

	f.parkedMu.Lock()
	delete(f.signing, hash)
	if tookEntry {
		if parked, ok := f.parked[hash]; ok {
			if time.Now().After(parked.deadline) {
				blockParkedDeadlineMeter.Mark(1)
				log.Debug("Parked block's signature expired while its claim was held, dropping the entry", "number", block.Number(), "hash", hash)
				delete(f.parked, hash)
			} else {
				parked.claimed = false
			}
		}
		f.parkedMu.Unlock()
		return
	}
	if f.signHook == nil || f.syncing() {
		f.parkedMu.Unlock()
		return
	}
	select {
	case <-f.quit:
		f.parkedMu.Unlock()
		return
	default:
	}
	start := f.parkLocked(block)
	f.parkedMu.Unlock()

	if start {
		go f.waitParkedSignatures()
	}
}

func (f *BlockFetcher) stopWaiter() {
	f.parkedMu.Lock()
	f.parkedWaiter = false
	f.parkedMu.Unlock()
}

// waitParkedSignatures drains the parked set on one ticker. It evicts every tick
// but signs in its own goroutine, so a blocked hook stalls neither eviction nor the set.
func (f *BlockFetcher) waitParkedSignatures() {
	ticker := time.NewTicker(parkedImportPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-f.quit:
			// The parked entries are left for the GC: clearing them would break tests that drive the scan.
			f.stopWaiter()
			return
		case <-ticker.C:
			// A tick that wins the race against a stop must still check quit before scanning.
			select {
			case <-f.quit:
				f.stopWaiter()
				return
			default:
			}
			// One batch at a time, so a blocked hook cannot accumulate goroutines and claims.
			if ready := f.collectSignableParked(!f.signingBatchRunning()); len(ready) > 0 {
				f.markSigningBatch(true)
				go f.runSigningBatch(ready)
			}

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

func (f *BlockFetcher) signingBatchRunning() bool {
	f.parkedMu.Lock()
	defer f.parkedMu.Unlock()
	return f.signingBatch
}

func (f *BlockFetcher) markSigningBatch(running bool) {
	f.parkedMu.Lock()
	defer f.parkedMu.Unlock()
	f.signingBatch = running
}

func (f *BlockFetcher) runSigningBatch(ready []readySignature) {
	f.signReadyParked(ready, f.quit)
	f.markSigningBatch(false)
}

// scanParkedSignatures signs the parked blocks that became signable and drops the
// rest at the uncle-distance or deadline bound; a block merely not canonical yet
// stays parked. The scan claims each entry before signing, so the delivery path
// cannot sign it too.
func (f *BlockFetcher) scanParkedSignatures() {
	f.signReadyParked(f.collectSignableParked(true), nil)
}

// collectSignableParked evicts at the two bounds and, when claim is true, claims
// the signable entries.
func (f *BlockFetcher) collectSignableParked(claim bool) []readySignature {
	// Signing during snap sync would spend a transaction on a block the inserter
	// discards. The scan returns before reading the set, so the bounds wait.
	if f.syncing() {
		return nil
	}
	var ready []readySignature

	// The chain reads below run under parkedMu on purpose: they call only read-only
	// caches that never call back into the fetcher, so there is no lock inversion.
	// Reading outside the lock would open an ABA window; the set is capped.
	f.parkedMu.Lock()
	for hash, parked := range f.parked {
		// A previous pass claimed the entry and is about to sign it. An entry past its
		// deadline is dropped here so a blocked hook cannot pin the slot forever.
		if parked.claimed {
			if time.Now().After(parked.deadline) {
				blockParkedDeadlineMeter.Mark(1)
				log.Warn("Parked block's signature did not finish before its deadline, dropping the entry", "number", parked.block.Number(), "hash", hash)
				// Keep the signing marker until the owner settles, so a re-delivery cannot sign.
				delete(f.parked, hash)
			}
			continue
		}
		// Bounds are checked before readiness: an entry past its deadline is dropped even
		// if the block just became signable.
		if belowUncleDist(parked.block.NumberU64(), f.chainHeight()) {
			blockParkedStaleMeter.Mark(1)
			log.Debug("Parked block fell below the uncle distance, dropping signature", "number", parked.block.Number(), "hash", hash)
			delete(f.parked, hash)
			continue
		}
		if time.Now().After(parked.deadline) {
			blockParkedDeadlineMeter.Mark(1)
			if f.getBlock(hash) != nil {
				log.Debug("Parked block was stored but never became signable, dropping its signature", "number", parked.block.Number(), "hash", hash)
			} else {
				log.Warn("Block was not imported in time, dropping its signature", "number", parked.block.Number(), "hash", hash)
			}
			delete(f.parked, hash)
			continue
		}
		if block := f.getBlock(hash); block != nil && f.canSign(block) {
			// Not reachable today, kept as a guard: a second signature would cost a transaction.
			if _, ok := f.signing[hash]; ok {
				continue
			}
			if !claim {
				continue
			}
			parked.claimed = true
			f.signing[hash] = struct{}{}
			ready = append(ready, readySignature{block: block, deadline: parked.deadline})
		}
	}
	f.parkedMu.Unlock()

	return ready
}

// signReadyParked signs every collected block and settles its claim. Each block is
// re-checked against its parked deadline, so a slow hook does not sign the ones behind it.
func (f *BlockFetcher) signReadyParked(ready []readySignature, stop <-chan struct{}) {
	for i, sig := range ready {
		select {
		case <-stop:
			for _, rest := range ready[i:] {
				f.resolveParked(rest.block.Hash(), false)
			}
			return
		default:
		}
		// The deadline is an upper bound on the wait: an earlier hook can outlive this
		// block's, so only release the claim and let the waiter count the eviction.
		if time.Now().After(sig.deadline) {
			log.Debug("Parked block's deadline passed before its signature started, dropping it", "number", sig.block.Number(), "hash", sig.block.Hash())
			f.resolveParked(sig.block.Hash(), false)
			continue
		}
		// Re-check both gates: a reorg or a snap sync can land after the collect.
		if f.syncing() || !f.canSign(sig.block) {
			log.Debug("Parked block is no longer signable, releasing it", "number", sig.block.Number(), "hash", sig.block.Hash())
			f.resolveParked(sig.block.Hash(), false)
			continue
		}
		// A signing failure is logged by signBlock and deliberately not retried here.
		_ = f.signBlock(sig.block)
		f.resolveParked(sig.block.Hash(), true)
	}
}

// resolveParked settles a claimed signature: an attempt removes the entry, a
// failed re-check only releases the claim. The in-flight marker always goes.
func (f *BlockFetcher) resolveParked(hash common.Hash, signed bool) {
	f.parkedMu.Lock()
	defer f.parkedMu.Unlock()

	delete(f.signing, hash)
	parked, ok := f.parked[hash]
	if !ok {
		return
	}
	if !signed {
		parked.claimed = false
		return
	}
	delete(f.parked, hash)
}

// claimParkedSignature takes the parked entry so the scan cannot sign the block
// too, and reports whether the caller may sign now and whether the claim took an
// entry over. The claim marks the entry instead of removing it.
func (f *BlockFetcher) claimParkedSignature(hash common.Hash) (ok bool, tookEntry bool) {
	f.parkedMu.Lock()
	defer f.parkedMu.Unlock()

	if _, ok := f.signing[hash]; ok {
		return false, false
	}
	parked, ok := f.parked[hash]
	if !ok {
		f.signing[hash] = struct{}{}
		return true, false
	}
	if parked.claimed {
		return false, false
	}
	if time.Now().After(parked.deadline) {
		blockParkedDeadlineMeter.Mark(1)
		log.Debug("Parked block's signature expired before delivery claimed it, dropping it", "number", parked.block.Number(), "hash", hash)
		delete(f.parked, hash)
		return false, false
	}
	parked.claimed = true
	f.signing[hash] = struct{}{}
	return true, true
}

type signatureVerdict int

const (
	signNow            signatureVerdict = iota // canonical and still fresh
	signNotCanonical                           // another chain is canonical at this height
	signBelowUncleDist                         // too far below the head: only a rewind can change it
)

func (f *BlockFetcher) canSign(block *types.Block) bool {
	return f.signatureVerdictOf(block) == signNow
}

// signatureVerdictOf reports whether a stored block is worth a signature, and if
// not, why. The irreversible bound is tested first, so no reorg can revive a stale block.
func (f *BlockFetcher) signatureVerdictOf(block *types.Block) signatureVerdict {
	if belowUncleDist(block.NumberU64(), f.chainHeight()) {
		return signBelowUncleDist
	}
	if f.canonicalHash(block.NumberU64()) != block.Hash() {
		return signNotCanonical
	}
	return signNow
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

// SetSignHook wires the XDPoS signature hook. Install it before Start: a block
// delivered without a hook is not parked, so its signature is never created.
// nil is valid (non-XDPoS), and the setter is not synchronized.
func (f *BlockFetcher) SetSignHook(signHook func(*types.Block) error) {
	f.signHook = signHook
}

// SetAppendM2HeaderHook wires the M2 rewrite hook, with SetSignHook's wiring rules.
func (f *BlockFetcher) SetAppendM2HeaderHook(appendM2HeaderHook func(*types.Block) (*types.Block, bool, error)) {
	f.appendM2HeaderHook = appendM2HeaderHook
}
