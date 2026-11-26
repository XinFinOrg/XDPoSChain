// Copyright 2026 The go-ethereum Authors
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

package types

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/XinFinOrg/XDPoSChain/common"
	"github.com/XinFinOrg/XDPoSChain/rlp"
)

// frameReceiptFixture builds a frame receipt for tests.
func frameReceiptFixture(status uint8, exec, state uint64, nLogs int) *FrameReceipt {
	fr := &FrameReceipt{Status: status, GasUsedExecution: exec, GasUsedState: state}
	for i := 0; i < nLogs; i++ {
		fr.Logs = append(fr.Logs, &Log{
			Address: common.BytesToAddress([]byte{0xaa, byte(i)}),
			Topics:  []common.Hash{common.BytesToHash([]byte{byte(i), 0x01})},
			Data:    []byte{0xde, 0xad},
		})
	}
	return fr
}

// TestFrameReceiptExactEncoding pins the EIP-8141 ReceiptPayload encoding to
// independently computed bytes:
//
//	payload = [5, 0x000..01, [[1, [2, 3], []]]]
//	typed   = 0x06 || rlp(payload)
//	EncodeRLP wraps the typed bytes as an RLP string.
func TestFrameReceiptExactEncoding(t *testing.T) {
	payer := common.BytesToAddress([]byte{0x01})
	r := &Receipt{
		Type:              FrameTxType,
		CumulativeGasUsed: 5,
		Payer:             &payer,
		FrameReceipts:     []*FrameReceipt{frameReceiptFixture(1, 2, 3, 0)},
	}
	// payload: [0x05, 0x94<addr>, 0xc6 0xc5 0x01 0xc2 0x02 0x03 0xc0]
	//   frames list content = 6 bytes (c5-list of frame), frame list content =
	//   5 bytes (status 01, gas pair c20203, empty logs c0); payload content =
	//   1 + 21 + 7 = 29 bytes (0xdd).
	var payload bytes.Buffer
	payload.WriteByte(0xdd)
	payload.WriteByte(0x05)
	payload.WriteByte(0x94)
	payload.Write(payer.Bytes())
	payload.Write([]byte{0xc6, 0xc5, 0x01, 0xc2, 0x02, 0x03, 0xc0})

	var typed bytes.Buffer
	typed.WriteByte(FrameTxType)
	typed.Write(payload.Bytes())

	var want bytes.Buffer
	want.WriteByte(0x80 + byte(typed.Len())) // short string, 31 bytes
	want.Write(typed.Bytes())

	// MarshalBinary must equal the raw typed bytes.
	bin, err := r.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(bin, typed.Bytes()) {
		t.Fatalf("MarshalBinary mismatch\n got %x\nwant %x", bin, typed.Bytes())
	}
	// EncodeRLP must produce the string-wrapped form.
	var enc bytes.Buffer
	if err := r.EncodeRLP(&enc); err != nil {
		t.Fatalf("EncodeRLP: %v", err)
	}
	if !bytes.Equal(enc.Bytes(), want.Bytes()) {
		t.Fatalf("EncodeRLP mismatch\n got %x\nwant %x", enc.Bytes(), want.Bytes())
	}
	// Encoding must be deterministic.
	bin2, err := r.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary (2nd): %v", err)
	}
	if !bytes.Equal(bin, bin2) {
		t.Fatalf("non-deterministic encoding: %x vs %x", bin, bin2)
	}
}

// TestFrameReceiptRoundTrip exercises decode of every status value, multiple
// frames, empty logs and a zero payer.
func TestFrameReceiptRoundTrip(t *testing.T) {
	payer := common.HexToAddress("0xdeadbeef00000000000000000000000000000001")
	r := &Receipt{
		Type:              FrameTxType,
		CumulativeGasUsed: 123456,
		Payer:             &payer,
		FrameReceipts: []*FrameReceipt{
			frameReceiptFixture(1, 100, 50, 2), // success, logs
			frameReceiptFixture(0, 200, 0, 0),  // failure, no logs
			frameReceiptFixture(0x2, 0, 0, 0),  // skipped
			frameReceiptFixture(1, 0, 0, 0),    // zero gas, zero logs
		},
	}
	bin, err := r.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	var dec Receipt
	if err := dec.UnmarshalBinary(bin); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if dec.Type != FrameTxType {
		t.Fatalf("type mismatch: %d", dec.Type)
	}
	if dec.CumulativeGasUsed != r.CumulativeGasUsed {
		t.Fatalf("cumgas mismatch: %d != %d", dec.CumulativeGasUsed, r.CumulativeGasUsed)
	}
	if dec.Payer == nil || *dec.Payer != payer {
		t.Fatalf("payer mismatch: %v", dec.Payer)
	}
	if len(dec.FrameReceipts) != 4 {
		t.Fatalf("frame count mismatch: %d", len(dec.FrameReceipts))
	}
	// Decoded status must be derived: one failed frame -> failed.
	if dec.Status != ReceiptStatusFailed {
		t.Fatalf("derived status mismatch: %d", dec.Status)
	}
	// The transaction logs are the concatenation of the frame logs.
	if len(dec.Logs) != 2 {
		t.Fatalf("decoded tx logs mismatch: %d", len(dec.Logs))
	}
	if dec.Bloom != CreateBloom(&dec) {
		t.Fatalf("decoded bloom mismatch")
	}
	for i, fr := range dec.FrameReceipts {
		src := r.FrameReceipts[i]
		if fr.Status != src.Status || fr.GasUsedExecution != src.GasUsedExecution ||
			fr.GasUsedState != src.GasUsedState || len(fr.Logs) != len(src.Logs) {
			t.Fatalf("frame %d mismatch: %+v vs %+v", i, fr, src)
		}
	}

	// A receipt with only successful frames derives a successful status.
	r.FrameReceipts[1].Status = 1
	bin, err = r.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	var dec2 Receipt
	if err := dec2.UnmarshalBinary(bin); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if dec2.Status != ReceiptStatusSuccessful {
		t.Fatalf("derived status mismatch: %d", dec2.Status)
	}
}

// TestFrameReceiptStorageRoundTrip checks the ReceiptForStorage encoding,
// including backward compatibility with the classic 3-field stored form.
func TestFrameReceiptStorageRoundTrip(t *testing.T) {
	payer := common.HexToAddress("0xbeef")
	r := &Receipt{
		Type:              FrameTxType,
		Status:            ReceiptStatusSuccessful,
		CumulativeGasUsed: 77,
		Logs:              []*Log{frameReceiptFixture(1, 1, 1, 1).Logs[0]},
		Payer:             &payer,
		FrameReceipts:     []*FrameReceipt{frameReceiptFixture(1, 10, 20, 1)},
	}
	stored := ReceiptForStorage(*r)
	blob, err := rlp.EncodeToBytes(&stored)
	if err != nil {
		t.Fatalf("encode stored: %v", err)
	}
	var back ReceiptForStorage
	if err := rlp.DecodeBytes(blob, &back); err != nil {
		t.Fatalf("decode stored: %v", err)
	}
	br := (*Receipt)(&back)
	if br.CumulativeGasUsed != 77 || len(br.Logs) != 1 {
		t.Fatalf("stored roundtrip mismatch: %+v", br)
	}
	if br.Payer == nil || *br.Payer != payer {
		t.Fatalf("stored payer mismatch: %v", br.Payer)
	}
	if len(br.FrameReceipts) != 1 || br.FrameReceipts[0].GasUsedExecution != 10 ||
		br.FrameReceipts[0].GasUsedState != 20 || len(br.FrameReceipts[0].Logs) != 1 {
		t.Fatalf("stored frame receipts mismatch: %+v", br.FrameReceipts)
	}

	// Classic receipts (no payer, no frames) must keep the 3-field encoding
	// and decode identically with the new code.
	classic := &ReceiptForStorage{
		Type:              DynamicFeeTxType,
		Status:            ReceiptStatusFailed,
		CumulativeGasUsed: 9,
		Logs:              []*Log{{Address: common.BytesToAddress([]byte{0x42}), Topics: []common.Hash{{0x01}}, Data: []byte{0x02}}},
	}
	cblob, err := rlp.EncodeToBytes(classic)
	if err != nil {
		t.Fatalf("encode classic stored: %v", err)
	}
	// The classic encoding must have exactly 3 list elements.
	content, _, err := rlp.SplitList(cblob)
	if err != nil {
		t.Fatalf("split classic stored: %v", err)
	}
	elems, err := rlp.CountValues(content)
	if err != nil {
		t.Fatalf("count classic elems: %v", err)
	}
	if elems != 3 {
		t.Fatalf("classic stored encoding has %d elements, want 3", elems)
	}
	var cback ReceiptForStorage
	if err := rlp.DecodeBytes(cblob, &cback); err != nil {
		t.Fatalf("decode classic stored: %v", err)
	}
	cr := (*Receipt)(&cback)
	if cr.CumulativeGasUsed != 9 || cr.Status != ReceiptStatusFailed || len(cr.Logs) != 1 {
		t.Fatalf("classic stored roundtrip mismatch: %+v", cr)
	}
	if cr.Payer != nil || cr.FrameReceipts != nil {
		t.Fatalf("classic receipt gained frame fields: %+v", cr)
	}
}

// TestFrameReceiptEncodeIndex checks the receipt-root (DeriveSha) encoding
// path matches the canonical typed encoding.
func TestFrameReceiptEncodeIndex(t *testing.T) {
	payer := common.HexToAddress("0x01")
	r := &Receipt{
		Type:              FrameTxType,
		CumulativeGasUsed: 42,
		Payer:             &payer,
		FrameReceipts:     []*FrameReceipt{frameReceiptFixture(1, 3, 4, 1)},
	}
	rs := Receipts{r}
	var buf bytes.Buffer
	rs.EncodeIndex(0, &buf)
	bin, err := r.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), bin) {
		t.Fatalf("EncodeIndex mismatch\n got %x\nwant %x", buf.Bytes(), bin)
	}
	if buf.Bytes()[0] != FrameTxType {
		t.Fatalf("missing type prefix: %x", buf.Bytes()[0])
	}
}

// TestFrameReceiptJSONRoundTrip checks the RPC JSON representation.
func TestFrameReceiptJSONRoundTrip(t *testing.T) {
	payer := common.HexToAddress("0x01")
	r := &Receipt{
		Type:              FrameTxType,
		Status:            ReceiptStatusFailed,
		CumulativeGasUsed: 100,
		Logs:              []*Log{},
		TxHash:            common.HexToHash("0x99"),
		GasUsed:           50,
		FrameReceipts: []*FrameReceipt{
			{Status: 1, GasUsedExecution: 10, GasUsedState: 5},
			{Status: 0, GasUsedExecution: 20, GasUsedState: 0},
		},
		Payer: &payer,
	}
	blob, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(blob, &m); err != nil {
		t.Fatalf("unmarshal map: %v", err)
	}
	if m["payer"] != "0x0000000000000000000000000000000000000001" {
		t.Fatalf("payer json mismatch: %v", m["payer"])
	}
	frames, ok := m["frameReceipts"].([]interface{})
	if !ok || len(frames) != 2 {
		t.Fatalf("frameReceipts json mismatch: %v", m["frameReceipts"])
	}
	f0 := frames[0].(map[string]interface{})
	if f0["status"] != "0x1" || f0["execution"] != "0xa" || f0["state"] != "0x5" {
		t.Fatalf("frame 0 json mismatch: %v", f0)
	}
	var back Receipt
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatalf("unmarshal receipt: %v", err)
	}
	if back.Payer == nil || *back.Payer != payer || len(back.FrameReceipts) != 2 ||
		back.FrameReceipts[1].Status != 0 || back.FrameReceipts[0].GasUsedExecution != 10 {
		t.Fatalf("json roundtrip mismatch: %+v", back)
	}
}

// TestFrameReceiptInvalidData checks malformed inputs are rejected.
func TestFrameReceiptInvalidData(t *testing.T) {
	var r Receipt
	if err := r.UnmarshalBinary([]byte{FrameTxType}); err == nil {
		t.Fatal("expected error for empty frame payload")
	}
	if err := r.UnmarshalBinary([]byte{0x7f, 0x01}); err == nil {
		t.Fatal("expected error for unknown receipt type")
	}
	// A legacy-style RLP list must not be interpreted as a frame receipt.
	var dec Receipt
	if err := dec.DecodeRLP(rlp.NewStream(bytes.NewReader(mustRlpLegacy(t)), 0)); err != nil {
		t.Fatalf("legacy decode: %v", err)
	}
	if dec.Type != LegacyTxType || dec.Payer != nil || dec.FrameReceipts != nil {
		t.Fatalf("legacy receipt polluted: %+v", dec)
	}
	// DeriveFrameTxStatus on an empty frame list is successful.
	if status := DeriveFrameTxStatus(nil); status != ReceiptStatusSuccessful {
		t.Fatalf("empty frame status: %d", status)
	}
}

func mustRlpLegacy(t *testing.T) []byte {
	t.Helper()
	blob, err := rlp.EncodeToBytes(&receiptRLP{receiptStatusSuccessfulRLP, 1, Bloom{}, nil})
	if err != nil {
		t.Fatalf("encode legacy: %v", err)
	}
	return blob
}

// TestFrameReceiptNilFrameEntry ensures malformed frame-receipt lists return
// errors instead of panicking or silently dropping entries.
func TestFrameReceiptNilFrameEntry(t *testing.T) {
	// Programmatic construction: every error-returning encoder must reject.
	r := &Receipt{
		Type:              FrameTxType,
		CumulativeGasUsed: 5,
		FrameReceipts:     []*FrameReceipt{nil},
	}
	if _, err := r.MarshalBinary(); err == nil {
		t.Fatal("MarshalBinary must reject a nil frame receipt")
	}
	var buf bytes.Buffer
	if err := r.EncodeRLP(&buf); err == nil {
		t.Fatal("EncodeRLP must reject a nil frame receipt")
	}
	stored := ReceiptForStorage(*r)
	if _, err := rlp.EncodeToBytes(&stored); err == nil {
		t.Fatal("storage EncodeRLP must reject a nil frame receipt")
	}
	// EncodeIndex cannot return an error; it must write nothing (beyond the
	// type prefix) rather than silently emit a receipt with the nil frame
	// omitted.
	rs := Receipts{r}
	buf.Reset()
	rs.EncodeIndex(0, &buf)
	if !bytes.Equal(buf.Bytes(), []byte{FrameTxType}) {
		t.Fatalf("EncodeIndex wrote %x for a malformed receipt", buf.Bytes())
	}

	// JSON is the entry point for external data: a null frame entry must be
	// rejected at unmarshal time.
	bad := `{
		"status": "0x1",
		"cumulativeGasUsed": "0x5",
		"logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"logs": [],
		"transactionHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
		"gasUsed": "0x1",
		"frameReceipts": [null]
	}`
	var dec Receipt
	if err := json.Unmarshal([]byte(bad), &dec); err == nil {
		t.Fatal("JSON unmarshal must reject a null frame receipt")
	}
}

// TestFrameReceiptEmptyFrameList covers the empty-frame-list payload: wire
// encoding, decoding, derived status, storage round trip, and nil-vs-empty
// slice behavior.
func TestFrameReceiptEmptyFrameList(t *testing.T) {
	payer := common.BytesToAddress([]byte{0x01})
	r := &Receipt{
		Type:              FrameTxType,
		CumulativeGasUsed: 5,
		Payer:             &payer,
		Logs:              []*Log{},
		FrameReceipts:     []*FrameReceipt{},
	}
	// Exact wire bytes: payload [5, 0x00..01, []] -> content 1+21+1 = 23
	// bytes (0xd7); the empty frame list encodes as 0xc0. Typed form is 24
	// bytes, string-wrapped as 0x98.
	var typed bytes.Buffer
	typed.WriteByte(FrameTxType)
	typed.WriteByte(0xd7)
	typed.WriteByte(0x05)
	typed.WriteByte(0x94)
	typed.Write(payer.Bytes())
	typed.WriteByte(0xc0)

	bin, err := r.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(bin, typed.Bytes()) {
		t.Fatalf("MarshalBinary mismatch\n got %x\nwant %x", bin, typed.Bytes())
	}
	var dec Receipt
	if err := dec.UnmarshalBinary(bin); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if dec.CumulativeGasUsed != 5 || dec.Payer == nil || *dec.Payer != payer {
		t.Fatalf("roundtrip header fields: %+v", dec)
	}
	if dec.FrameReceipts == nil || len(dec.FrameReceipts) != 0 {
		t.Fatalf("frame receipts must decode to an empty non-nil slice: %v", dec.FrameReceipts)
	}
	// Documented derivation rule: no failed frames -> successful.
	if dec.Status != ReceiptStatusSuccessful {
		t.Fatalf("derived status: %d", dec.Status)
	}
	if len(dec.Logs) != 0 || dec.Bloom != (Bloom{}) {
		t.Fatalf("empty frame list must yield no logs and an empty bloom")
	}

	// Storage round trip keeps the empty list distinct from "absent".
	stored := ReceiptForStorage(*r)
	blob, err := rlp.EncodeToBytes(&stored)
	if err != nil {
		t.Fatalf("encode stored: %v", err)
	}
	var back ReceiptForStorage
	if err := rlp.DecodeBytes(blob, &back); err != nil {
		t.Fatalf("decode stored: %v", err)
	}
	br := (*Receipt)(&back)
	if br.FrameReceipts == nil || len(br.FrameReceipts) != 0 {
		t.Fatalf("stored roundtrip frame receipts: %v", br.FrameReceipts)
	}
	if br.Payer == nil || *br.Payer != payer || br.CumulativeGasUsed != 5 {
		t.Fatalf("stored roundtrip header: %+v", br)
	}
	if len(br.Logs) != 0 {
		t.Fatalf("stored roundtrip logs: %d", len(br.Logs))
	}

	// JSON round trip: an empty (non-nil) slice carries no information the
	// wire encoding needs, and omitempty drops the field, so decoding yields
	// a nil slice. Document that nil-vs-empty distinction here.
	jblob, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	if bytes.Contains(jblob, []byte("frameReceipts")) {
		t.Fatalf("omitempty must drop the empty frame list: %s", jblob)
	}
	var jdec Receipt
	if err := json.Unmarshal(jblob, &jdec); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}
	if jdec.FrameReceipts != nil {
		t.Fatalf("json roundtrip frame receipts: %v", jdec.FrameReceipts)
	}
}

// TestFrameReceiptLegacyStoredFormat verifies that stored FrameTx receipts
// written by the initial Milestone 6 encoding — which duplicated the log list
// at the top level and inside the frame receipts — decode to the same result
// as the deduplicated encoding.
func TestFrameReceiptLegacyStoredFormat(t *testing.T) {
	payer := common.HexToAddress("0xbeef")
	log := &Log{Address: payer, Topics: []common.Hash{{0x01}}, Data: []byte{0x02}}
	// Hand-craft the M6-era stored form: top-level logs duplicated alongside
	// the frame receipts.
	stored := &storedReceiptRLP{
		PostStateOrStatus: receiptStatusSuccessfulRLP,
		CumulativeGasUsed: 7,
		Logs:              []*Log{log},
		Payer:             &payer,
		FrameReceipts: []*frameReceiptRLP{{
			Status:  1,
			GasUsed: frameGasUsedRLP{Execution: 3, State: 4},
			Logs:    []*Log{log},
		}},
	}
	blob, err := rlp.EncodeToBytes(stored)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var back ReceiptForStorage
	if err := rlp.DecodeBytes(blob, &back); err != nil {
		t.Fatalf("decode: %v", err)
	}
	br := (*Receipt)(&back)
	if br.CumulativeGasUsed != 7 || br.Payer == nil || *br.Payer != payer {
		t.Fatalf("header mismatch: %+v", br)
	}
	if len(br.FrameReceipts) != 1 || br.FrameReceipts[0].GasUsedExecution != 3 || br.FrameReceipts[0].GasUsedState != 4 {
		t.Fatalf("frame mismatch: %+v", br.FrameReceipts)
	}
	// The top-level logs are rebuilt from the frame receipts.
	if len(br.Logs) != 1 || br.Logs[0].Address != payer {
		t.Fatalf("logs mismatch: %+v", br.Logs)
	}
}
