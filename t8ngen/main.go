// Day-4 offline t8ntool fixture generator for the combined EIP-8131 + EIP-8279 floor.
// Working-copy-only tooling (untracked). Emits alloc/env/txs JSON per fixture under /tmp/t8n-day4.
package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/core/types"
	"github.com/XinFinOrg/XDPoSChain/crypto"
	"github.com/holiman/uint256"
)

var chainID = big.NewInt(1) // matches tests/init.go "Bogota"/"Prague" fork entries in this tree

var (
	senderKey    = mustKey("0000000000000000000000000000000000000000000000000000000000000001")
	authorityKey = mustKey("0000000000000000000000000000000000000000000000000000000000000002")
	senderAddr   = crypto.PubkeyToAddress(senderKey.PublicKey)
	authAddr     = crypto.PubkeyToAddress(authorityKey.PublicKey)
	recipient    = common.HexToAddress("0x00000000000000000000000000000000000beef1")
	contract     = common.HexToAddress("0x00000000000000000000000000000000c0ffee01") // SLOAD slot0, POP, STOP
	contractNoop = common.HexToAddress("0x00000000000000000000000000000000c0ffee02") // STOP only
	delegTarget  = common.HexToAddress("0x00000000000000000000000000000000de1e601")
	senderHex    = "0000000000000000000000000000000000000000000000000000000000000001"
)

func mustKey(hex string) *ecdsa.PrivateKey {
	k, err := crypto.HexToECDSA(hex)
	if err != nil {
		panic(err)
	}
	return k
}

// hx renders n as a minimal 0x-prefixed hex quantity (hexutil: no leading zeros,
// odd length allowed).
func hx(n uint64) string {
	return "0x" + fmt.Sprintf("%x", n)
}

// hxb renders big-endian bytes as a minimal 0x-prefixed hex quantity.
func hxb(b []byte) string {
	v := new(big.Int).SetBytes(b)
	if v.Sign() == 0 {
		return "0x0"
	}
	return "0x" + v.Text(16)
}

type allocEntry struct {
	Balance string `json:"balance"`
	Nonce   string `json:"nonce,omitempty"`
	Code    string `json:"code,omitempty"`
}

type environment struct {
	Coinbase    string `json:"currentCoinbase"`
	Difficulty  string `json:"currentDifficulty"`
	GasLimit    string `json:"currentGasLimit"`
	Number      string `json:"currentNumber"`
	Timestamp   string `json:"currentTimestamp"`
	BaseFee     string `json:"currentBaseFee"`
	Random      string `json:"currentRandom"`
	Withdrawals []string `json:"withdrawals"`
	ParentBeaconBlockRoot string `json:"parentBeaconBlockRoot"`
	ExcessBlobGas         string `json:"currentExcessBlobGas"`
}

type txjson map[string]interface{}

func floorGas(dataBytes, alAddr, alKeys, auths int) uint64 {
	// A1: Bogotá includes EIP-2780 — the floor anchor is the 2780 intrinsic
	// base (15,000 for these value-free to≠from fixtures), not 21,000.
	return 15000 + 64*uint64(dataBytes+20*alAddr+32*alKeys+108*auths) + 51*64*uint64(auths)
}

func repeats(b byte, n int) string {
	return "0x" + strings.Repeat(fmt.Sprintf("%02x", b), n)
}

func signedAuth() map[string]interface{} {
	auth, err := types.SignSetCode(authorityKey, types.SetCodeAuthorization{
		ChainID: *uint256.MustFromBig(chainID),
		Address: delegTarget,
		Nonce:   0,
	})
	if err != nil {
		panic(err)
	}
	return map[string]interface{}{
		"chainId": hx(chainID.Uint64()),
		"address": auth.Address.Hex(),
		"nonce":   hx(auth.Nonce),
		"yParity": hx(uint64(auth.V)),
		"r":       hxb(auth.R.Bytes()),
		"s":       hxb(auth.S.Bytes()),
	}
}

func baseAlloc(withContract bool) map[string]allocEntry {
	a := map[string]allocEntry{
		senderAddr.Hex(): {Balance: "0xde0b6b3a7640000"}, // 1e18
		authAddr.Hex():   {Balance: "0x0", Nonce: "0x0"},
		recipient.Hex():  {Balance: "0x0"},
	}
	if withContract {
		a[contract.Hex()] = allocEntry{Balance: "0x0", Code: "0x60006000545000"} // PUSH1 0, PUSH1 0, SLOAD, POP, STOP
		a[contractNoop.Hex()] = allocEntry{Balance: "0x0", Code: "0x00"}         // STOP
	}
	return a
}

func env() environment {
	return environment{
		Coinbase:   strings.Repeat("0", 34) + "c0ffee", // unprefixed 40-hex per t8ntool stEnv
		Difficulty: "0x00",
		GasLimit:   "0x01c9c380",
		Number:     "0x01",
		Timestamp:  "0x03e8",
		BaseFee:    "0x07",
		Random:      "0x4242424242424242424242424242424242424242424242424242424242424242",
		Withdrawals: []string{},
		ParentBeaconBlockRoot: "0x4242424242424242424242424242424242424242424242424242424242424242",
		ExcessBlobGas: "0x0",
	}
}

func writeFixture(name string, txs []txjson, alloc map[string]allocEntry, expect string) {
	dir := filepath.Join("/tmp/t8n-day4", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		panic(err)
	}
	mustWrite(filepath.Join(dir, "alloc.json"), alloc)
	mustWrite(filepath.Join(dir, "env.json"), env())
	mustWrite(filepath.Join(dir, "txs.json"), txs)
	if err := os.WriteFile(filepath.Join(dir, "expected.txt"), []byte(expect+"\n"), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("%-14s %s\n", name, expect)
}

func mustWrite(path string, v interface{}) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		panic(err)
	}
}

func main() {
	fmt.Printf("sender=%s authority=%s chainID=%d\n", senderAddr.Hex(), authAddr.Hex(), chainID)
	sk := "0x" + senderHex
	f2floor := floorGas(1000, 0, 0, 1)

	// f1: plain transfer (value=1); A1 floor = 2780 base incl value cost =
	// 12000+3000+4244+1756 = 21,000; exec = intrinsic 21,000 (+ any runtime
	// account-creation charge for the empty recipient — measured by t8n).
	writeFixture("f1-plain",
		[]txjson{{"nonce": "0x0", "gasPrice": "0x7", "gas": "0x5208", "to": recipient.Hex(), "value": "0x1", "input": "0x", "r": "0x0", "s": "0x0", "v": "0x0", "yParity": "0x0", "secretKey": sk}},
		baseAlloc(false),
		"gasUsed=21000 (A1 floor 21000 = 12000+3000 cold+6000 value; exec 21000)")

	// f2: 1 authorization + 1000 nonzero data bytes; combined floor = 85,912 + 3,264 = 89,176 binds
	writeFixture("f2-auth",
		[]txjson{{
			"type": hx(4), "chainId": hx(chainID.Uint64()), "nonce": "0x0",
			"gas": hx(200000), "maxFeePerGas": "0x7", "maxPriorityFeePerGas": "0x7",
			"to": recipient.Hex(), "value": "0x0", "input": repeats(0x01, 1000),
			"authorizationList": []interface{}{signedAuth()}, "r": "0x0", "s": "0x0", "v": "0x0", "yParity": "0x0", "secretKey": sk,
		}},
		baseAlloc(false),
		fmt.Sprintf("gasUsed=%d (combined floor 85912+3264=89176 binds; exec=15000+16000+12500=43500)", f2floor))

	// f3: access list (1 addr, 1 key) + 500 nonzero data bytes; floor = 15,000+64*552 = 50,328 binds
	writeFixture("f3-accesslist",
		[]txjson{{
			"type": hx(1), "chainId": hx(chainID.Uint64()), "nonce": "0x0",
			"gasPrice": "0x7", "gas": hx(100000), "to": recipient.Hex(), "value": "0x0",
			"input": repeats(0x01, 500),
			"accessList": []interface{}{map[string]interface{}{
				"address":     recipient.Hex(),
				"storageKeys": []string{"0x0000000000000000000000000000000000000000000000000000000000000001"},
			}},
			"r": "0x0", "s": "0x0", "v": "0x0", "yParity": "0x0", "secretKey": sk,
		}},
		baseAlloc(false),
		fmt.Sprintf("gasUsed=%d (floor 15000+64*552=50328 binds; exec=15000+8000+4300=27300)", floorGas(500, 1, 1, 0)))

	// f4: authorization + access list + 500 data; floor = 15,000+64*711 = 60,504 binds
	writeFixture("f4-auth-al",
		[]txjson{{
			"type": hx(4), "chainId": hx(chainID.Uint64()), "nonce": "0x0",
			"gas": hx(120000), "maxFeePerGas": "0x7", "maxPriorityFeePerGas": "0x7",
			"to": recipient.Hex(), "value": "0x0", "input": repeats(0x01, 500),
			"accessList": []interface{}{map[string]interface{}{
				"address":     recipient.Hex(),
				"storageKeys": []string{"0x0000000000000000000000000000000000000000000000000000000000000001"},
			}},
			"authorizationList": []interface{}{signedAuth()}, "r": "0x0", "s": "0x0", "v": "0x0", "yParity": "0x0", "secretKey": sk,
		}},
		baseAlloc(false),
		fmt.Sprintf("gasUsed=%d (floor 15000+64*(500+108+51+20+32)=60504 binds; exec=15000+8000+4300+12500=39800)", floorGas(500, 1, 1, 1)))

	// f5: boundary — gasLimit one below the f2 floor: tx must be rejected
	writeFixture("f5-boundary",
		[]txjson{{
			"type": hx(4), "chainId": hx(chainID.Uint64()), "nonce": "0x0",
			"gas": hx(f2floor - 1), "maxFeePerGas": "0x7", "maxPriorityFeePerGas": "0x7",
			"to": recipient.Hex(), "value": "0x0", "input": repeats(0x01, 1000),
			"authorizationList": []interface{}{signedAuth()}, "r": "0x0", "s": "0x0", "v": "0x0", "yParity": "0x0", "secretKey": sk,
		}},
		baseAlloc(false),
		fmt.Sprintf("REJECTED: gasLimit %d < combined floor %d", f2floor-1, f2floor))

	// f6: runtime metered byte extends settled floor — one cold SLOAD (32 B) + 300 data
	writeFixture("f6-runtime",
		[]txjson{{"nonce": "0x0", "gasPrice": "0x7", "gas": hx(100000), "to": contract.Hex(), "value": "0x0", "input": repeats(0x01, 300), "r": "0x0", "s": "0x0", "v": "0x0", "yParity": "0x0", "secretKey": sk}},
		baseAlloc(true),
		fmt.Sprintf("gasUsed=%d (floor 15000+64*(300+32 runtime SLOAD)=36248 binds)", floorGas(300, 0, 0, 0)+32*64))

	// f6b: control — same tx against STOP-only contract: no runtime bytes
	writeFixture("f6b-control",
		[]txjson{{"nonce": "0x0", "gasPrice": "0x7", "gas": hx(100000), "to": contractNoop.Hex(), "value": "0x0", "input": repeats(0x01, 300), "r": "0x0", "s": "0x0", "v": "0x0", "yParity": "0x0", "secretKey": sk}},
		baseAlloc(true),
		fmt.Sprintf("gasUsed=%d (floor 15000+64*300=34200 binds; f6-f6b delta 2048=32*64 runtime)", floorGas(300, 0, 0, 0)))

	// D2 delegation-target metering pair (f13/f13b) + M-RETEST fixtures.
	genD2()
	genMretest()
}
