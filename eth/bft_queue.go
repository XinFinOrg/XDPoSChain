package eth

import (
	"sync"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/log"
)

const (
	// maxQueuedBFTMsgs and maxQueuedBFTBytes bound the number and total wire
	// size of BFT messages (votes, timeouts and syncInfos) buffered while the
	// downloader is synchronising. When either is exceeded, the oldest messages
	// are dropped, since newer messages are more likely to belong to the
	// current round.
	maxQueuedBFTMsgs  = 4096
	maxQueuedBFTBytes = 16 * 1024 * 1024

	// maxQueuedBFTMsgSize is the largest BFT message that is queued. Real BFT
	// messages are a few KB at most, but a peer can send up to
	// protocolMaxMsgSize, so larger messages are dropped instead of retained.
	maxQueuedBFTMsgSize = 1024 * 1024
)

// queuedBFTMsg is a BFT message received while synchronising, kept until the
// sync finishes.
type queuedBFTMsg struct {
	peer string
	hash common.Hash
	size uint32 // Wire size of the message
	msg  any    // *types.Vote, *types.Timeout or *types.SyncInfo
}

// bftQueue buffers BFT messages that arrive while the downloader is
// synchronising, so they can be processed once the sync is over instead of
// being dropped. Senders mark a message as known to a peer and never send it
// again, so dropping it here would lose it for good.
type bftQueue struct {
	mu     sync.Mutex
	msgs   []queuedBFTMsg
	hashes map[common.Hash]struct{}
	bytes  uint64 // Total wire size of the queued messages
}

func newBFTQueue() *bftQueue {
	return &bftQueue{hashes: make(map[common.Hash]struct{})}
}

// enqueueIf adds the message to the queue if syncing reports true. The check
// runs under the queue lock, so a message is either queued before a drain
// takes the queue, or reported as not queued and must be handled directly.
// A message larger than maxQueuedBFTMsgSize is dropped while syncing.
func (q *bftQueue) enqueueIf(syncing func() bool, peer string, hash common.Hash, size uint32, msg any) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	if !syncing() {
		return false
	}
	if _, ok := q.hashes[hash]; ok {
		return true
	}
	if size > maxQueuedBFTMsgSize {
		log.Debug("BFT message too large to queue, dropping", "hash", hash, "size", size)
		return true
	}
	for len(q.msgs) >= maxQueuedBFTMsgs || q.bytes+uint64(size) > maxQueuedBFTBytes {
		oldest := q.msgs[0]
		delete(q.hashes, oldest.hash)
		q.bytes -= uint64(oldest.size)
		q.msgs[0] = queuedBFTMsg{}
		q.msgs = q.msgs[1:]
		log.Debug("BFT message queue full, dropping oldest", "hash", oldest.hash)
	}
	q.msgs = append(q.msgs, queuedBFTMsg{peer: peer, hash: hash, size: size, msg: msg})
	q.hashes[hash] = struct{}{}
	q.bytes += uint64(size)
	return true
}

// takeUnless removes and returns all queued messages, unless syncing reports
// true, in which case the queue is kept for the next drain.
func (q *bftQueue) takeUnless(syncing func() bool) []queuedBFTMsg {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.msgs) == 0 || syncing() {
		return nil
	}
	msgs := q.msgs
	q.msgs = nil
	q.hashes = make(map[common.Hash]struct{})
	q.bytes = 0
	return msgs
}

// len returns the number of queued messages.
func (q *bftQueue) len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.msgs)
}
