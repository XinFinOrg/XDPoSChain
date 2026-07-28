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

func TestDenylistVersion(t *testing.T) {
	t.Parallel()

	version1 := HexToAddress("0x5248bfb72fd4f234e062d3e9bb76f08643004fcd")
	if version, ok := DenylistVersion(&version1); !ok || version != 1 {
		t.Fatalf("expected known address in version 1, have version=%d listed=%v", version, ok)
	}

	version2 := HexToAddress("0xdb6552adc538e39b4f2a58aea3cd365def1be89b")
	if version, ok := DenylistVersion(&version2); !ok || version != 2 {
		t.Fatalf("expected known address in version 2, have version=%d listed=%v", version, ok)
	}

	notInList := HexToAddress("0x0000000000000000000000000000000000000001")
	if _, ok := DenylistVersion(&notInList); ok {
		t.Fatal("expected unknown address to not be in denylist")
	}

	if _, ok := DenylistVersion(nil); ok {
		t.Fatal("expected nil address to not be in denylist")
	}
}

// TestValidateDenylistVersionsRejectsBadInput covers the checks init makes on the
// literal. Each rejected case would otherwise deny the wrong addresses from the
// wrong height, so the node refuses to start rather than running with it.
func TestValidateDenylistVersionsRejectsBadInput(t *testing.T) {
	t.Parallel()

	first := HexToAddress("0x0000000000000000000000000000000000000001")
	second := HexToAddress("0x0000000000000000000000000000000000000002")

	tests := []struct {
		name     string
		versions map[uint8][]Address
		// why the input is rejected, for the failure message
		reason string
	}{
		{
			name: "address listed in two versions",
			// Silently collapses in an address-keyed literal, rescheduling the
			// address to whichever version is written last.
			versions: map[uint8][]Address{1: {first}, 2: {first}},
			reason:   "an address may only belong to one version",
		},
		{
			name:     "address listed twice in one version",
			versions: map[uint8][]Address{1: {first, first}},
			reason:   "a repeated address is a copy-paste error",
		},
		{
			name: "version gap",
			// Version 3's addresses would sit under a version nothing schedules,
			// leaving them never denied.
			versions: map[uint8][]Address{1: {first}, 3: {second}},
			reason:   "versions must be contiguous from 1",
		},
		{
			name:     "versions do not start at 1",
			versions: map[uint8][]Address{2: {first}},
			reason:   "version 1 must exist",
		},
		{
			name:     "version with no addresses",
			versions: map[uint8][]Address{1: {first}, 2: {}},
			reason:   "an empty version is meaningless",
		},
		{
			name:     "no versions at all",
			versions: map[uint8][]Address{},
			reason:   "the denylist must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("expected validateDenylistVersions to panic: %s", tt.reason)
				}
			}()
			validateDenylistVersions(tt.versions)
		})
	}
}

// TestDenylistVersionsResolveAsDeclared checks the real literal: every declared
// address resolves to the version it is declared under. There is no derived index
// to drift from the literal, so this is the whole correctness surface.
func TestDenylistVersionsResolveAsDeclared(t *testing.T) {
	t.Parallel()

	declared := 0
	for version, addresses := range denylistVersions {
		for _, address := range addresses {
			declared++
			got, listed := DenylistVersion(&address)
			if !listed {
				t.Errorf("declared address %s does not resolve", address.Hex())
				continue
			}
			if got != version {
				t.Errorf("address %s resolves to version %d, declared under version %d", address.Hex(), got, version)
			}
		}
	}
	if declared == 0 {
		t.Fatal("no addresses declared in denylistVersions")
	}
}
