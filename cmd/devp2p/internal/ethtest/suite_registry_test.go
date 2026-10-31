package ethtest

import "testing"

func assertEthTestsInclude(t *testing.T, testName string) {
	t.Helper()
	for _, test := range loadTestSuite(t).EthTests() {
		if test.Name == testName {
			return
		}
	}
	t.Fatalf("expected EthTests to include %s", testName)
}

func TestEthTestsIncludesNonexistentHeadersCase(t *testing.T) {
	assertEthTestsInclude(t, "GetNonexistentBlockHeaders")
}

func TestEthTestsIncludesNonexistentHeadersByHashCase(t *testing.T) {
	assertEthTestsInclude(t, "GetNonexistentBlockHeadersByHash")
}

func TestEthTestsIncludesNonexistentHeadersThenBlockBodiesCase(t *testing.T) {
	assertEthTestsInclude(t, "GetNonexistentHeadersThenBlockBodies")
}

func TestEthTestsIncludesNonexistentHeadersThenReceiptsCase(t *testing.T) {
	assertEthTestsInclude(t, "GetNonexistentHeadersThenReceipts")
}

func TestEthTestsIncludesHeadersByHashCase(t *testing.T) {
	assertEthTestsInclude(t, "GetBlockHeadersByHash")
}

func TestEthTestsIncludesNonexistentHeadersRepeatedCase(t *testing.T) {
	assertEthTestsInclude(t, "GetNonexistentBlockHeadersRepeated")
}

func TestEthTestsIncludesHeadersReverseFromGenesisCase(t *testing.T) {
	assertEthTestsInclude(t, "GetBlockHeadersReverseFromGenesis")
}

func TestEthTestsIncludesHeadersSequentialRequestsCase(t *testing.T) {
	assertEthTestsInclude(t, "GetBlockHeadersSequentialRequests")
}

func TestEthTestsIncludesSequentialMixedRequestsCase(t *testing.T) {
	assertEthTestsInclude(t, "GetSequentialMixedRequests")
}

func TestEthTestsIncludesBlockBodiesMixedHashesCase(t *testing.T) {
	assertEthTestsInclude(t, "GetBlockBodiesMixedHashes")
}

func TestEthTestsIncludesBlockBodiesSequentialRequestsCase(t *testing.T) {
	assertEthTestsInclude(t, "GetBlockBodiesSequentialRequests")
}

func TestEthTestsIncludesReceiptsMixedHashesCase(t *testing.T) {
	assertEthTestsInclude(t, "GetReceiptsMixedHashes")
}

func TestEthTestsIncludesReceiptsSequentialRequestsCase(t *testing.T) {
	assertEthTestsInclude(t, "GetReceiptsSequentialRequests")
}

func TestEthTestsIncludesBlockBodiesUnknownOnlyCase(t *testing.T) {
	assertEthTestsInclude(t, "GetBlockBodiesUnknownOnly")
}

func TestEthTestsIncludesReceiptsUnknownOnlyCase(t *testing.T) {
	assertEthTestsInclude(t, "GetReceiptsUnknownOnly")
}

func TestEthTestsIncludesBlockBodiesUnknownThenKnownCase(t *testing.T) {
	assertEthTestsInclude(t, "GetBlockBodiesUnknownThenKnown")
}

func TestEthTestsIncludesReceiptsUnknownThenKnownCase(t *testing.T) {
	assertEthTestsInclude(t, "GetReceiptsUnknownThenKnown")
}

func TestEthTestsIncludesTransactionBatchSmokeCase(t *testing.T) {
	assertEthTestsInclude(t, "TransactionBatchSmoke")
}

func TestEthTestsIncludesTransactionEmptyListSmokeCase(t *testing.T) {
	assertEthTestsInclude(t, "TransactionEmptyListSmoke")
}

func TestEthTestsIncludesTransactionEmptyListThenBlockBodiesSmokeCase(t *testing.T) {
	assertEthTestsInclude(t, "TransactionEmptyListThenBlockBodiesSmoke")
}

func TestEthTestsIncludesTransactionEmptyListThenReceiptsSmokeCase(t *testing.T) {
	assertEthTestsInclude(t, "TransactionEmptyListThenReceiptsSmoke")
}

func TestEthTestsIncludesTransactionThenBlockBodiesSmokeCase(t *testing.T) {
	assertEthTestsInclude(t, "TransactionThenBlockBodiesSmoke")
}

func TestEthTestsIncludesTransactionThenReceiptsSmokeCase(t *testing.T) {
	assertEthTestsInclude(t, "TransactionThenReceiptsSmoke")
}

func TestEthTestsIncludesTransactionBatchThenBlockBodiesSmokeCase(t *testing.T) {
	assertEthTestsInclude(t, "TransactionBatchThenBlockBodiesSmoke")
}

func TestEthTestsIncludesTransactionBatchThenReceiptsSmokeCase(t *testing.T) {
	assertEthTestsInclude(t, "TransactionBatchThenReceiptsSmoke")
}

func TestEthTestsIncludesStatus66Case(t *testing.T) {
	assertEthTestsInclude(t, "Status_66")
}

func TestEthTestsIncludesGetBlockHeaders66Case(t *testing.T) {
	assertEthTestsInclude(t, "GetBlockHeaders_66")
}

func TestEthTestsIncludesGetBlockBodies66Case(t *testing.T) {
	assertEthTestsInclude(t, "GetBlockBodies_66")
}

func TestEthTestsIncludesGetNodeData66Case(t *testing.T) {
	assertEthTestsInclude(t, "GetNodeData_66")
}

func TestEthTestsIncludesGetReceipts66Case(t *testing.T) {
	assertEthTestsInclude(t, "GetReceipts_66")
}

func TestEthTestsIncludesGetPooledTransactions66Case(t *testing.T) {
	assertEthTestsInclude(t, "GetPooledTransactions_66")
}

func TestEthTestsIncludesSameRequestID66Case(t *testing.T) {
	assertEthTestsInclude(t, "SameRequestID_66")
}

func TestEthTestsIncludesLargeAnnounceCase(t *testing.T) {
	assertEthTestsInclude(t, "LargeAnnounce")
}

func TestEthTestsIncludesOldAnnounceCase(t *testing.T) {
	assertEthTestsInclude(t, "OldAnnounce")
}

func TestEthTestsIncludesBlockHashAnnounceCase(t *testing.T) {
	assertEthTestsInclude(t, "BlockHashAnnounce")
}

func TestEthTestsIncludesBlockHashAnnounce66Case(t *testing.T) {
	assertEthTestsInclude(t, "BlockHashAnnounce_66")
}

func TestEthTestsIncludesMaliciousTxCase(t *testing.T) {
	assertEthTestsInclude(t, "MaliciousTx")
}

func TestEthTestsIncludesNewPooledTxs66Case(t *testing.T) {
	assertEthTestsInclude(t, "NewPooledTxs_66")
}

func TestEthTestsIncludesLargeTxRequest66Case(t *testing.T) {
	assertEthTestsInclude(t, "LargeTxRequest_66")
}
