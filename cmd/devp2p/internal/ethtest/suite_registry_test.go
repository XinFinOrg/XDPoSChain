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

func TestEthTestsIncludesStatusXdc166Case(t *testing.T) {
	assertEthTestsInclude(t, "Status_Xdc166")
}

func TestEthTestsIncludesGetBlockHeadersXdc166Case(t *testing.T) {
	assertEthTestsInclude(t, "GetBlockHeaders_Xdc166")
}

func TestEthTestsIncludesGetBlockBodiesXdc166Case(t *testing.T) {
	assertEthTestsInclude(t, "GetBlockBodies_Xdc166")
}

func TestEthTestsIncludesGetNodeDataXdc166Case(t *testing.T) {
	assertEthTestsInclude(t, "GetNodeData_Xdc166")
}

func TestEthTestsIncludesGetReceiptsXdc166Case(t *testing.T) {
	assertEthTestsInclude(t, "GetReceipts_Xdc166")
}

func TestEthTestsIncludesGetPooledTransactionsXdc166Case(t *testing.T) {
	assertEthTestsInclude(t, "GetPooledTransactions_Xdc166")
}

func TestEthTestsIncludesSameRequestIDXdc166Case(t *testing.T) {
	assertEthTestsInclude(t, "SameRequestID_Xdc166")
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

func TestEthTestsIncludesBlockHashAnnounceXdc166Case(t *testing.T) {
	assertEthTestsInclude(t, "BlockHashAnnounce_Xdc166")
}

func TestEthTestsIncludesMaliciousTxCase(t *testing.T) {
	assertEthTestsInclude(t, "MaliciousTx")
}

func TestEthTestsIncludesNewPooledTxsXdc166Case(t *testing.T) {
	assertEthTestsInclude(t, "NewPooledTxs_Xdc166")
}

func TestEthTestsIncludesLargeTxRequestXdc166Case(t *testing.T) {
	assertEthTestsInclude(t, "LargeTxRequest_Xdc166")
}
