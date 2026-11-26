// D2 fixture pair (protocol decision D2, approved 2026-11-11): delegation-
// target metering vs plain control, mirroring the f6/f6b runtime-meter pair
// shape. Offline tooling (untracked); emits under /tmp/t8n-day4.
package main

import (
	"github.com/XinFinOrg/XDPoSChain/common"
)

// genD2 writes:
//   f13-delegation — tx DIRECTLY to a 7702 delegation holder (designator →
//     STOP target), 1,000 data bytes. Runtime bytes: 20 (delegation
//     target, resolveCode) → floor 15,000+64×1,020 = 80,280 binds (A1).
//   f13b-control — identical tx to a plain no-code account: 0 runtime
//     bytes → floor 79,000. Delta f13−f13b = 1,280 = 20×64.
//
// Nethermind equivalence (source: ~/nethermind-src, EvmInstructions.Call.cs
// :183 — TryMeterBalAddress on the resolved delegation, +20 B per-tx dedup;
// Eip8279Tests.cs delegation vector): NM charges the same 20 B×64 = 1,280
// floor delta on the equivalent CALL. NM-side execution of this pair is out
// of scope for the geth repo (and the NM tree must not be modified).
func genD2() {
	sk := "0x" + senderHex
	delegHolder := common.HexToAddress("0x00000000000000000000000000000000de1e602")

	alloc := baseAlloc(false)
	alloc[delegHolder.Hex()] = allocEntry{Balance: "0x0", Code: "0xef0100" + delegTarget.Hex()[2:]}
	alloc[delegTarget.Hex()] = allocEntry{Balance: "0x0", Code: "0x00"}

	writeFixture("f13-delegation",
		[]txjson{{"nonce": "0x0", "gasPrice": "0x7", "gas": hx(100000), "to": delegHolder.Hex(), "value": "0x0", "input": repeats(0x01, 1000), "r": "0x0", "s": "0x0", "v": "0x0", "yParity": "0x0", "secretKey": sk}},
		alloc,
		"gasUsed=80280 (floor 15000+64*(1000+20 delegation target)=80280 binds; f13b delta 1280=20*64)")

	writeFixture("f13b-control",
		[]txjson{{"nonce": "0x0", "gasPrice": "0x7", "gas": hx(100000), "to": recipient.Hex(), "value": "0x0", "input": repeats(0x01, 1000), "r": "0x0", "s": "0x0", "v": "0x0", "yParity": "0x0", "secretKey": sk}},
		baseAlloc(false),
		"gasUsed=79000 (floor 15000+64*1000=79000 binds; no runtime bytes)")
}
