package common

import (
	"math/big"
	"testing"
)

func TestCloneBigInt(t *testing.T) {
	if clone := CloneBigInt(nil); clone != nil {
		t.Fatalf("expected nil clone for nil input, got %v", clone)
	}

	original := big.NewInt(42)
	clone := CloneBigInt(original)
	if clone == nil {
		t.Fatal("expected clone for non-nil input")
	}
	if clone == original {
		t.Fatal("expected deep copy, got same pointer")
	}
	if clone.Cmp(original) != 0 {
		t.Fatalf("expected clone value %v, got %v", original, clone)
	}

	clone.SetInt64(7)
	if original.Int64() != 42 {
		t.Fatalf("expected original to remain unchanged, got %v", original)
	}
	if clone.Int64() != 7 {
		t.Fatalf("expected updated clone value, got %v", clone)
	}
}
