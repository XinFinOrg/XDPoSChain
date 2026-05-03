package common

import "testing"

func TestIsIgnoreSignerCheckBlock(t *testing.T) {
	t.Parallel()

	if !IsIgnoreSignerCheckBlock(1032300) {
		t.Fatal("expected block 1032300 to be in ignore signer check list")
	}

	if IsIgnoreSignerCheckBlock(1) {
		t.Fatal("expected block 1 to not be in ignore signer check list")
	}
}

func TestIsInDenylist(t *testing.T) {
	t.Parallel()

	inList := HexToAddress("0x5248bfb72fd4f234e062d3e9bb76f08643004fcd")
	if !IsInDenylist(&inList) {
		t.Fatal("expected known address to be in denylist")
	}

	notInList := HexToAddress("0x0000000000000000000000000000000000000001")
	if IsInDenylist(&notInList) {
		t.Fatal("expected unknown address to not be in denylist")
	}

	if IsInDenylist(nil) {
		t.Fatal("expected nil address to not be in denylist")
	}
}
