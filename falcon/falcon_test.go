package falcon

import (
	"bytes"
	"fmt"
	"testing"
)

func TestFalconSignatureLifecycle(t *testing.T) {
	// Generate a key pair using Falcon-512 (logN = 9)
	keyPair, err := GenerateKeyPair(9)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Print debug info about key sizes
	t.Logf("Private key size: %d", len(keyPair.PrivateKey))
	t.Logf("Public key size: %d", len(keyPair.PublicKey))

	// Verify key sizes
	if len(keyPair.PublicKey) == 0 || len(keyPair.PrivateKey) == 0 {
		t.Fatal("Generated keys are empty")
	}

	// Test message
	message := []byte("Hello, Falcon!")
	t.Logf("Message size: %d", len(message))

	// Sign the message with different signature types
	sigTypes := []struct {
		name string
		typ  int
	}{
		{"Compressed", SigCompressed},
		{"Padded", SigPadded},
		{"CT", SigCT},
	}

	for _, st := range sigTypes {
		t.Run(st.name, func(t *testing.T) {
			t.Logf("Testing signature type: %s", st.name)

			// Generate signature
			signature, err := Sign(message, keyPair.PrivateKey, st.typ)
			if err != nil {
				t.Fatalf("Failed to sign message: %v", err)
			}
			t.Logf("Generated signature size: %d", len(signature))

			// Verify signature
			err = Verify(signature, message, keyPair.PublicKey, st.typ)
			if err != nil {
				t.Fatalf("Signature verification failed: %v", err)
			}
		})
	}
}
func TestPRNG(t *testing.T) {
	// Test PRNG functionality
	ctx := &PRNGContext{}

	// Test system RNG initialization
	err := ctx.InitFromSystem()
	if err != nil {
		t.Fatalf("Failed to initialize PRNG from system: %v", err)
	}

	// Test seed-based initialization
	seed := []byte("test seed for PRNG")
	ctx.InitFromSeed(seed)

	// Test injection and extraction
	input := []byte("test input data")
	output1 := make([]byte, 32)
	output2 := make([]byte, 32)

	ctx.Init()
	ctx.Inject(input)
	ctx.Flip()
	ctx.Extract(output1)

	// Verify deterministic output with same input
	ctx.Init()
	ctx.Inject(input)
	ctx.Flip()
	ctx.Extract(output2)

	if !bytes.Equal(output1, output2) {
		t.Fatal("PRNG output not deterministic")
	}

	// Log which PRNG is being used
	t.Logf("Using %s PRNG", getPRNGName())
}

func TestGetLogN(t *testing.T) {
	// Generate keys with different logN values
	testLogNs := []uint{9, 10} // Test Falcon-512 and Falcon-1024

	for _, logN := range testLogNs {
		t.Run(fmt.Sprintf("logN=%d", logN), func(t *testing.T) {
			keyPair, err := GenerateKeyPair(logN)
			if err != nil {
				t.Fatalf("Failed to generate key pair: %v", err)
			}

			// Test GetLogN with private key
			detectedLogN, err := GetLogN(keyPair.PrivateKey)
			if err != nil {
				t.Fatalf("Failed to get logN from private key: %v", err)
			}
			if uint(detectedLogN) != logN {
				t.Errorf("Wrong logN from private key: got %d, want %d", detectedLogN, logN)
			}

			// Test GetLogN with public key
			detectedLogN, err = GetLogN(keyPair.PublicKey)
			if err != nil {
				t.Fatalf("Failed to get logN from public key: %v", err)
			}
			if uint(detectedLogN) != logN {
				t.Errorf("Wrong logN from public key: got %d, want %d", detectedLogN, logN)
			}
		})
	}
}
