// M-RETEST cross-client fixture extensions (Phase 4): PAY execution,
// 3298 refund accounting, and the live 3298 full-counter vs 3529 cap
// divergence on the standard path. Emits under /tmp/t8n-mretest.
// Untracked working-copy tooling — not production code.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/XinFinOrg/XDPoSChain/common"
)

var (
	payRecipient = common.HexToAddress("0x00000000000000000000000000000000beef002")
	payContract  = common.HexToAddress("0x00000000000000000000000000000000c0ffee03")
	clearContract = common.HexToAddress("0x00000000000000000000000000000000c0ffee04")
)

type allocEntry2 struct {
	Balance string            `json:"balance"`
	Nonce   string            `json:"nonce,omitempty"`
	Code    string            `json:"code,omitempty"`
	Storage map[string]string `json:"storage,omitempty"`
}

func mustWrite2(path string, v interface{}) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		panic(err)
	}
}

func writeFixture2(name string, txs []txjson, alloc map[string]allocEntry2, expect string) {
	dir := filepath.Join("/tmp/t8n-mretest", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		panic(err)
	}
	mustWrite2(filepath.Join(dir, "alloc.json"), alloc)
	mustWrite2(filepath.Join(dir, "env.json"), env())
	mustWrite2(filepath.Join(dir, "txs.json"), txs)
	if err := os.WriteFile(filepath.Join(dir, "expected.txt"), []byte(expect+"\n"), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("%-20s %s\n", name, expect)
}

// payContractCode: PUSH1 1, PUSH20 payRecipient, PAY, STOP.
func payContractCode() string {
	return "0x6001" + "73" + fmt.Sprintf("%040x", payRecipient) + "fc00"
}

func genMretest() {
	sk := "0x" + senderHex

	// f7-pay-cold: cold PAY of 1 wei to a fresh (EIP-161 empty) recipient.
	// exec = 15000 (A1 intrinsic) + 6 (pushes) + PAY(100 warm + 2500 cold + 9000 value + 25000 new) = 51,606.
	a := map[string]allocEntry2{
		senderAddr.Hex(): {Balance: "0xde0b6b3a7640000"},
		payContract.Hex(): {Balance: "0x2", Code: payContractCode()},
	}
	writeFixture2("f7-pay-cold",
		[]txjson{{"nonce": "0x0", "gasPrice": "0x7", "gas": "0x186a0", "to": payContract.Hex(), "value": "0x0", "input": "0x", "r": "0x0", "s": "0x0", "v": "0x0", "yParity": "0x0", "secretKey": sk}},
		a,
		"fork=Bogota gasUsed=51606; post-state payRecipient balance=1, payContract balance=1")

	// f8-pay-warm: PAY to a pre-funded, access-list-warmed recipient.
	// exec = 15000 + 6 + PAY(100 warm + 9000 value) = 24,106; floor = 15000+64*20.
	a2 := map[string]allocEntry2{
		senderAddr.Hex(): {Balance: "0xde0b6b3a7640000"},
		payContract.Hex(): {Balance: "0x2", Code: payContractCode()},
		payRecipient.Hex(): {Balance: "0x1"},
	}
	writeFixture2("f8-pay-warm",
		[]txjson{{
			"type": hx(1), "chainId": hx(chainID.Uint64()), "nonce": "0x0", "gasPrice": "0x7", "gas": "0x186a0",
			"to": payContract.Hex(), "value": "0x0", "input": "0x",
			"accessList": []interface{}{map[string]interface{}{"address": payRecipient.Hex(), "storageKeys": []string{}}},
			"r": "0x0", "s": "0x0", "v": "0x0", "yParity": "0x0", "secretKey": sk,
		}},
		a2,
		"fork=Bogota gasUsed=26506 (15000+2400 AL-intrinsic+6 pushes+100 warm+9000 value); post-state payRecipient balance=2")

	// f9/f10: SSTORE clear-refund accounting, same fixture both forks.
	// Contract slot0=1 (alloc storage = committed), code PUSH0 PUSH0 SSTORE STOP.
	clearAlloc := func() map[string]allocEntry2 {
		return map[string]allocEntry2{
			senderAddr.Hex(): {Balance: "0xde0b6b3a7640000"},
			clearContract.Hex(): {Balance: "0x0", Nonce: "0x1", Code: "0x5f5f5500",
				Storage: map[string]string{"0x0000000000000000000000000000000000000000000000000000000000000000": "0x0000000000000000000000000000000000000000000000000000000000000001"}},
		}
	}
	clearTx := []txjson{{"nonce": "0x0", "gasPrice": "0x7", "gas": "0x186a0", "to": clearContract.Hex(), "value": "0x0", "input": "0x", "r": "0x0", "s": "0x0", "v": "0x0", "yParity": "0x0", "secretKey": sk}}
	writeFixture2("f9-clear-bogota", clearTx, clearAlloc(),
		"fork=Bogota gasUsed=28004 (clear-refund struck: 15000+4 PUSH0x2@2gas+3000 access+10000 write; NO refund)")
	writeFixture2("f10-clear-prague", clearTx, clearAlloc(),
		"fork=Prague gasUsed=21204 (Berlin/3529: 21000+4+2100+2900-4800 clear refund; delta vs Bogota 12800)")

	// f11/f12: EIP-7702 existing-authority refund (12,500) under Bogotá
	// (3298 FULL counter) vs Prague (3529 1/5 cap) — the live standard-path
	// divergence, via t8n. authority = authAddr EXISTS (alloc, nonce 0).
	authAlloc := func() map[string]allocEntry2 {
		return map[string]allocEntry2{
			senderAddr.Hex(): {Balance: "0xde0b6b3a7640000"},
			authAddr.Hex():   {Balance: "0x0", Nonce: "0x0"},
		}
	}
	authTx := []txjson{{
		"type": hx(4), "chainId": hx(chainID.Uint64()), "nonce": "0x0",
		"gas": "0x30d40", "maxFeePerGas": "0x7", "maxPriorityFeePerGas": "0x7",
		"to": recipient.Hex(), "value": "0x0", "input": "0x",
		"authorizationList": []interface{}{signedAuth()}, "r": "0x0", "s": "0x0", "v": "0x0", "yParity": "0x0", "secretKey": sk,
	}}
	writeFixture2("f11-authrefund-bogota", authTx, authAlloc(),
		"fork=Bogota gasUsed=27500 (15000 intrinsic + 25000 auth cost - 12500 FULL 3298 refund); 12,500 fully refunded")
	writeFixture2("f12-authrefund-prague", authTx, authAlloc(),
		"fork=Prague gasUsed=36800 (3529 cap: refund = min(preRefund/5, 12500))")
}
