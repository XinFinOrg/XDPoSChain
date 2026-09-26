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
