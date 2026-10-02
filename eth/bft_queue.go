package eth

import (
	"sync"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/log"
)

// maxQueuedBFTMsgs is the maximum number of BFT messages (votes, timeouts and
// syncInfos) buffered while the downloader is synchronising. When full, the
// oldest message is dropped, since newer messages are more likely to belong to
// the current round.
const maxQueuedBFTMsgs = 4096

// queuedBFTMsg is a BFT message received while synchronising, kept until the
// sync finishes.
type queuedBFTMsg struct {
	peer string
	hash common.Hash
	msg  any // *types.Vote, *types.Timeout or *types.SyncInfo
}

// bftQueue buffers BFT messages that arrive while the downloader is
// synchronising, so they can be processed once the sync is over instead of
// being dropped. Senders mark a message as known to a peer and never send it
// again, so dropping it here would lose it for good.
type bftQueue struct {
	mu     sync.Mutex
	msgs   []queuedBFTMsg
	hashes map[common.Hash]struct{}
}

func newBFTQueue() *bftQueue {
	return &bftQueue{hashes: make(map[common.Hash]struct{})}
}

// enqueueIf adds the message to the queue if syncing reports true. The check
// runs under the queue lock, so a message is either queued before a drain
// takes the queue, or reported as not queued and must be handled directly.
func (q *bftQueue) enqueueIf(syncing func() bool, peer string, hash common.Hash, msg any) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	if !syncing() {
		return false
	}
	if _, ok := q.hashes[hash]; ok {
		return true
	}
	if len(q.msgs) >= maxQueuedBFTMsgs {
		oldest := q.msgs[0]
		delete(q.hashes, oldest.hash)
		q.msgs[0] = queuedBFTMsg{}
		q.msgs = q.msgs[1:]
		log.Debug("BFT message queue full, dropping oldest", "hash", oldest.hash)
	}
	q.msgs = append(q.msgs, queuedBFTMsg{peer: peer, hash: hash, msg: msg})
	q.hashes[hash] = struct{}{}
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
	return msgs
}

// len returns the number of queued messages.
func (q *bftQueue) len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.msgs)
}
