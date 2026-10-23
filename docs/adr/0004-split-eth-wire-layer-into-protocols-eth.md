---
status: accepted
---

# Split the eth wire layer into `eth/protocols/eth`, matching geth #21482 without snap

## Context

The `eth` package holds two different jobs: the wire protocol (message types and encoding, the peer transport, the broadcast loops, the handshake, and the message dispatch in `handleMsg`) and node orchestration (`handler`, sync, fetcher, and the XDPoS BFT wiring). Upstream go-ethereum separated these in `017831dd` (PR #21482, v1.9.25-11) by moving the wire layer into `eth/protocols/eth/`. That commit also introduced the snap protocol and snap sync.

XDPoSChain's wire layer is heavily diverged from geth's: the capability is still named `eth`, but the versions are `xdc165`/`xdc164`/`xdc100`, `protocolLengths` is 230/227/227 rather than 17, and the message set adds `OrderTxMsg` (0x08), `LendingTxMsg` (0x09) and the BFT messages `VoteMsg` (0xe0), `TimeoutMsg` (0xe1), `SyncInfoMsg` (0xe2), plus the pooled-transaction trio at 0xe3–0xe5.

## Decision

Split along geth #21482's boundary and keep the shape it produced:

- `eth/protocols/eth/` holds the wire layer — `protocol.go`, `peer.go`, `broadcast.go`, `handshake.go`, `handler.go` (message dispatch behind a `Backend` interface), `discovery.go`, `metrics.go` (the metered read/writer, whose wrapping point moves to `NewPeer`) — including the encoding of the XDC-specific messages.
- `eth/` keeps node orchestration — a slim `handler.go`, a new `handler_eth.go` implementing the wire layer's reactions, a new `peerset.go`, and the BFT machinery (`eth/bft`, `bft_queue.go`), which is where vote/timeout/sync-info messages are acted on.
- Snap stays out. Upstream go-ethereum's snap protocol, snap sync and everything they pull in (`eth/protocols/snap/`, `eth/handler_snap.go`, the downloader's snap mode, `core/state/snapshot`, `trie/notary.go`) are a separate effort, not part of this boundary. This repository has neither a snap protocol nor snap sync today — the `snapSync` flag in `eth/handler.go` only gates fast sync (`downloader.FastSync`) — so the exclusion means "do not port that upstream set along with this split".
- Moved symbols are imported from the new package directly; `eth` keeps no compatibility aliases.
- Wire encoding is frozen: capability name, version numbers, message codes, message lengths and the status handshake payload are byte-identical before and after.[^wire-encoding]

## Considered options

- **A minimal move** — only the message types and `peer` into the new package. Cheaper now, but the handler monolith stays, the next upstream port hits the same wall, and the split has to be redone properly later.
- **Taking snap along** — porting `017831dd` in full. Snap sync is an order of magnitude more work, is disabled by default upstream, and would make this change impossible to review as a pure refactor.
- **Keeping re-export aliases in `eth`** — zero churn for callers, but every moved symbol then has two names in the tree, and the alias layer is exactly the drift later ports would trip over.

## Consequences

- Future geth ports that assume the `eth/protocols/eth` layout land without another restructuring pass.
- The path says `eth` and the versions say `xdc*`; that mismatch is deliberate — the capability name is `eth`, the versions are XDC's own — and it survives this decision (see the glossary: eth capability, xdc version).
- Upstream follow-ups after `017831dd` that touch `eth/protocols/eth` are ported one by one on their own merits; the five between `017831dd` and v1.10.0 are dispositioned under "Known follow-ups".
- The wire invariants are pinned by tests in the package rather than by a checklist: `TestProtocolRegistration` (capability name, version order, lengths, ENR attribute), `TestMessageCodes` (every message code, including the XDC and pooled codes) and `TestPacketRoundTrips` (every packet type, including the xdc/100 status form).

## Porting notes

Copying upstream `017831dd` verbatim does not compile here. The differences that bite:

| Upstream | This tree |
| --- | --- |
| `mapset "github.com/deckarep/golang-set"` | `github.com/deckarep/golang-set/v2`; generics, `mapset.Set[common.Hash]` / `NewSet[common.Hash]()` |
| `Backend.StateBloom() *trie.SyncBloom` | no state bloom here, the `trie.SyncBloom` type is gone; the `Backend` method set is decided against this tree |
| `types.Header.NumberU64` | removed; use `Number.Uint64()` |
| `forkid.NewID(config, genesisHash, head)` | `forkid.NewID(config, *types.Block, head uint64)` (`core/forkid/forkid.go:66`) |
| `tx.Size()` returns `common.StorageSize` | returns `uint64`; accumulate with `common.StorageSize(tx.Size())` |

Three traps in the upstream skeleton: its version table carries `ETH63` and an `ETH63` length, which is not one of this tree's versions and would advertise one capability too many; its `peer.version >= ETH65` / `ETH64` branches have to be mapped onto `xdc165` / `xdc164` or deleted; and the symbol names do not all carry over: upstream's `protocolVersions` / `maxMessageSize` are `ProtocolVersions` / `protocolMaxMsgSize` here, while the same-named `StatusPacket` / `blockBody` do not have the same shape.

Exports: packet types are exported and named after upstream — `StatusPacket`, `StatusPacket100` (the xdc/100 form, which upstream has no counterpart for), `NewBlockHashesPacket`, `TransactionsPacket`, `GetBlockHeadersPacket` / `BlockHeadersPacket`, `HashOrNumber`, `NewBlockPacket`, `GetBlockBodiesPacket` / `BlockBodiesPacket` / `BlockBody`, `GetNodeDataPacket` / `NodeDataPacket`, `GetReceiptsPacket` / `ReceiptsPacket`, `NewPooledTransactionHashesPacket` / `GetPooledTransactionsPacket` / `PooledTransactionsPacket` — plus XDC's `OrderTransactionsPacket`, `LendingTransactionsPacket`, `VotePacket`, `TimeoutPacket` and `SyncInfoPacket` in the same style. The error model stays this tree's: `errCode` with the `Err*` constants, `errorToString` and `errResp`; upstream's `err*` variables are not adopted.

`ProtocolName`, `ProtocolVersions` and `ProtocolLengths` stay exported where upstream makes them private. `ProtocolVersions` is read outside the wire package by the node layer (`eth/backend.go`), `ethstats/ethstats.go` and `cmd/XDC/misccmd.go`; `ProtocolName` and `ProtocolLengths` have none and stay exported as the seam the alignment pass below left open. That seam is not an invitation for `cmd/devp2p/internal/ethtest` to take `ProtocolLengths`: its `ethProtoLen = 18` counts messages, while 230/227/227 bounds the code space (see "Known risks"). `discovery.go` does keep the upstream shape — `enrEntry` and `currentENREntry` stay unexported and the ENR attribute is set inside `MakeProtocols`.

## Deviations taken while landing

- **Resolved by the alignment pass: the wire layer no longer borrows the downloader's serve caps.** It defines its own `maxHeadersServe` / `maxBodiesServe` / `maxNodeDataServe` / `maxReceiptsServe` (plus a `maxPooledTransactionsServe` backstop the pre-split loop did not have) and imports nothing from `eth/downloader`, so the dependency direction the split wanted holds again. The numbers are this tree's (192 / 128 / 384 / 256), not upstream's 1024 — see the alignment pass for why.
- The nil-transaction check moved into `Packet.sanityCheck()`, a batch pre-scan in the wire layer: a batch containing a nil transaction no longer marks the preceding transactions as known before the disconnect. Error text and disconnect behaviour are unchanged.
- **Resolved by the alignment pass: the two stamps live together.** `ReceivedFrom` and `ReceivedAt` are both assigned in the wire layer's `NewBlockMsg` case, next to that message's block mark and the payload self-checks; the `eth` side keeps the fetcher enqueue, the tip/total-difficulty update and the sync kick-off. The announce handler's block mark and the transaction, order and lending marks stay in the node layer next to the known-set dedup and the pool enqueue — the side upstream's `handleTransactions` marks on. `ReceivedFrom` now holds the wire peer rather than the node-layer `*peer`: the field is `interface{}` and nothing in the tree reads it.
- `Backend.Handle` takes an extra `size uint32`: `bftQueue`'s byte ceiling is charged against the on-wire message length, which the wire layer decodes and the node layer used to read off `p2p.Msg`.
- `Backend` has an extra `AcceptTxs()`: the transaction gate (silently drop transaction traffic while not synced) stays on the wire layer's dispatch path, before decoding, with its order and semantics unchanged.
- `NewPeer` seeds `td` with zero: the old constructor never initialised it while `Head()` does `new(big.Int).Set(p.td)`, so asking a pre-handshake peer for its head nil-panicked.
- `eth/helper_test.go` was kept and grown rather than deleted — it carries the node-layer fixtures (`newTestPeer`, `testHandler`, `newTestRawPeer`) — and `eth/protocol_test.go` / `eth/handler_test.go` keep their node-level tests.
- The external callers move first, while `eth/` still states the same wire facts, so the two copies coexist for one commit; the node layer then switches over and drops its copies in a single step. That step cannot be subdivided: `eth/protocol.go` carries the error codes and the pool interfaces the node layer's own `handler.go` uses, so deleting it, slimming `peer.go` / `handler.go` and adding `handler_eth.go` have to land together, and no compatibility alias is allowed to bridge them (upstream completes the switch in one commit for the same reason).
- **The DAO fork-check and the syncer hand-off resolve the peer through the peer set.** The wire peer carries no `forkDrop`, so `eth/handler_eth.go` looks the node-layer peer up by id and, when it is missing, skips that branch instead of failing the message loop: the fork-drop timer is not stopped, the DAO header is not verified (it is handed to the fetcher and the downloader like any other header) and the sync kick-off is dropped. A miss means the peer is already being removed — it is disconnected anyway, and `syncer()`'s BestPeer loop retries the kick-off.
- **The broadcast loops start in `NewPeer`, not in the peer set's registration** (upstream's shape since #21482). The peer set therefore assumes every peer it is handed wraps a `*ethproto.Peer`; a bare `&peer{}` has no broadcasters to stop. `eth/peerset_test.go` pins that assumption.

## Alignment pass

The "later alignment pass" this ADR promised twice landed as #2856, one commit per item except #2862, which landed as two (the unsigned xdc version, then the short-id helper). Every item either moves the wire layer towards `017831dd`'s shape or records why it stays as it is.

| item | disposition |
| --- | --- |
| `GetAncestor` on the header chain (#2857) | taken: the bounded ancestor lookup the reverse hash walk spends its non-canonical budget on |
| bound the `GetBlockHeaders` hash walk (#2858) | taken; ships first as its own pull request, because the defect predates the split and is exploitable on the branch every node runs |
| upstream's serve loop in the wire package (#2859) | taken: the `first` flag, `maxNonCanonical`, and `lookups < 2*maxHeadersServe` |
| the other four reply loops (#2860) | taken: each decodes into its packet type and carries a `2x cap` lookup budget, so "every hash is one I do not have" is no longer free. The pooled loop's `2x` sits on top of a 4096-reply backstop, where upstream bounds the same loop at 4096 *lookups* and no reply count — see the serve-cap row |
| peer marks and payload checks in the wire loop (#2861) | taken: the `NewBlockMsg` block mark, the payload checks and both stamps sit in the wire loop; the announce mark and the transaction marks stay in the node layer next to the known-set dedup, as upstream's `handleTransactions` does |
| downloader xdc version and peer ids (#2862) | taken: the version parameter is unsigned, and a short peer id comes from one shared helper rather than upstream's duplicated inline block |
| the eth/63–65 cleanup commits of #21482 (`0e94a23`, `f769329`, `5f0932a`) | **not applicable.** This tree dropped eth/63 in #2499 (the capability, the version-gated branches, and `errTooOld` / the `syncWithPeer` guard now derived from `minProtocolVer` instead of a hardcoded number), renumbered the survivors to xdc/164 (#2470) and xdc/165 (#2490), and carries no `les` (geth #28586); the downloader tests already run over 100/164/165, so there is no eth/63 test to delete and no 63–65 constant to raise. The short-id half of `0e94a23` is the `shortPeerID` helper above. Two pieces of the same cleanup stay unported on purpose: `errTooOld` still omits the peer's own version (`eth/downloader/downloader.go:520`), and three `[eth/62]` tags survived #2499 at `eth/downloader/downloader.go:65` and `eth/downloader/queue.go:57-58` — both are diagnostic and comment polish, not the wire boundary this ADR draws |
| `handler` / `newHandler(*handlerConfig)` (#2863) | taken: upstream's type, constructor and field names, with this tree's four extra dependencies as config fields |
| parallel api debug tests (#2864) | taken; test-only |
| peerset event subscriptions | **not taken.** Upstream's peer set grew four feeds because it serves two protocols that must each observe joins and drops. This tree has one protocol on that peer set, so the subscriber count would be permanently zero; the synchronous peer set stays as it is |
| request ids (`GetBlockHeadersPacket66`, `peer.ReplyBlockHeaders`) | **not applicable.** This tree has no request-id plumbing: the loop shape was adopted, the ids were not |
| upstream's `1024` serve caps | **not taken.** The caps stay 192 / 128 / 384 / 256, the values the borrowed downloader constants had, so a peer sees the reply sizes it saw before the split. Pooled transactions are the one addition: the old loop had no count cap at all, and the wire package gives it a `maxPooledTransactionsServe` reply backstop (4096) plus the same `2x` lookup budget as the other three loops (8192), both recorded above. Upstream's 4096 is a *lookup* cap on that loop, not a reply count, so its work bound per message is half of this tree's — kept for consistency with the other three loops, and both bounds stay constant |
| the snap-adjacent follow-up `e3430ac7df` | **deferred**, as recorded under "Known follow-ups" |

Four places deliberately do not follow upstream, each for one reason:

- the numeric caps stay local and unchanged, so the answered batch sizes are identical to the pre-split node layer — save the pooled-transaction serve backstop the old loop never had, recorded under "Deviations taken while landing";
- the receiver identifier stays `pm`, because upstream's naming would touch hundreds of lines for no benefit;
- the short-id log field goes through one shared helper instead of upstream's duplicated inline block, and it keeps this tree's 16-character truncation (upstream slices to 8), so the logged id length does not move;
- `ethHandler` keeps its embedded-struct shape, because the embedding is what supplies the node metadata the wire layer asks for.

One gap is recorded rather than closed: the non-canonical header budget is covered only against an in-process peer on a fixture side chain. `TestGetBlockHeadersNonCanonicalBudget` spends the budget — 120 side headers, a `Skip` covering the branch, `maxNonCanonical = 100` — and pins the truncated reply to `[origin]`; no test drives it from a peer on a live network.

## Known follow-ups (`017831dd..v1.10.0`, 5 commits touching `eth/protocols/eth`)

| commit | title | disposition |
| --- | --- | --- |
| `c76573a97b` | fix slice resize flaw (#22181) | not applicable: it resizes against `maxQueuedTxs` instead of `maxQueuedTxAnns`, and this tree's `broadcast.go` already uses `maxQueuedTxAnns` |
| `0fe66f8ae4` | remove magic numbers in test (#21999) | optional: pure test tidying |
| `e01096f531` | optimize tx broadcast mechanism (#22176) | as needed: the XDC broadcast path differs a lot, assess before porting |
| `e3430ac7df` | check snap satelliteness, delegate drop to `eth` (#22235) | as needed: mostly a snap satellite check, but it also touches `protocols/eth/handler.go`, `protocols/eth/protocol.go`, `eth/peerset.go` and `p2p/peer.go`; assess the non-snap part first |
| `6ec1561044` | implement eth66 (#22241) | not applicable: XDC's version scheme is not eth6x |

## Known risks

- `cmd/devp2p/internal/ethtest` keeps a second copy of the wire facts: `baseProtoLen = 16`, `ethProtoLen = 18` and `snapProtoLen = 10` in `cmd/devp2p/internal/ethtest/protocol.go`, plus `ethProtoVersionXDpos2 = 100` in `conn.go`. `getProto()` panics on any code past `baseProtoLen+ethProtoLen+snapProtoLen` (44), while the BFT codes 0xe0–0xe2 and the pooled trio 0xe3–0xe5 frame to 240–245, and `Conn.ReadEth` calls `getProto()` on every inbound frame: a live xdc/100+ node sending a single `VoteMsg` would panic the client. It has not fired because the live-node suites run outside CI and the decode tests call `decodeEthPayload` directly, bypassing `getProto`. The values stay as they are — changing them is a behaviour change for the suite — and the divergence is commented where it lives.

## Prior attempt (reference only)

Branch `split-eth-protocol` (commit `46163c0c`, message `temp`, same base `baf6d167e9`) adds only `eth/protocols/eth/` and leaves `eth/` untouched. It does not compile: it imports `golang-set` v1, which this module no longer has, and after that it is missing six symbols that live on the node side it cannot import (`protocolVersions`, `protocolName`, `protocolLengths`, `currentENREntry`, `blockBody`, `txsyncPackSize`). It also lacks the XDC message layer — no `Send*` for order/lending/BFT, no dispatch branches, no `readStatus100` — and its four tests are upstream-shaped with no XDC cases. Reference only: no merge, no `cherry-pick`.

## Out of scope

- Upstream go-ethereum's snap protocol, snap sync and everything they pull in (`eth/protocols/snap/`, `eth/handler_snap.go`, the downloader's snap mode, `core/state/snapshot`, `trie/notary.go`) — a separate effort, not this boundary. This repository has neither a snap protocol nor snap sync today, so what is excluded here is the upstream set, not existing local code.
- Wire encoding: the capability name, version numbers, message codes, message lengths and the status handshake payload stay byte-identical. Reply contents are not covered by that promise, and the alignment pass narrows the header reply to a non-canonical origin.
- Upstream protocol evolution past the current versions (`eth66` and later).
- Refactoring the `eth` package's business logic (BFT reactions, OrderTx and LendingTx handling) — this split moves code, it does not rewrite it.

[^wire-encoding]: Encoding, not reply contents. Every packet the wire layer emits is byte-identical to what it emitted before the split. What the alignment pass changes is which replies are produced: a `GetBlockHeaders` request whose origin is not canonical now stops after the non-canonical budget instead of walking arbitrarily far, the four data loops (#2860) now stop at their lookup budgets, and the pooled-transaction loop additionally at its serve backstop, where the pre-split loop knew only `softResponseLimit`. Reply contents may therefore converge on canonicality while their encoding does not move. One difference outside that promise sits in the decode path rather than in the replies: the four query loops decode the whole hash list up front, where the pre-split loops streamed it hash by hash and stopped at their budget, so a malformed hash beyond the point the old loop would have stopped is now a decode error that disconnects the peer. Upstream shapes the loops the same way (#2860).
