// internal/falcon/bench_test.go

package falcon

import (
	"fmt"
	"testing"
)

// BenchContext holds context for benchmarks, similar to bench_context in C
type BenchContext struct {
	logN      uint
	rng       *PRNGContext
	publicKey []byte
	privKey   []byte
	sig       []byte
	sigCT     []byte
}

// setupBenchContext creates and initializes a benchmark context
func setupBenchContext(b *testing.B, logN uint) *BenchContext {
	bc := &BenchContext{
		logN: logN,
		rng:  &PRNGContext{},
	}

	if err := bc.rng.InitFromSystem(); err != nil {
		b.Fatalf("Failed to initialize RNG: %v", err)
	}

	// Generate initial keypair
	kp, err := GenerateKeyPair(logN)
	if err != nil {
		b.Fatalf("Failed to generate initial keypair: %v", err)
	}

	bc.publicKey = kp.PublicKey
	bc.privKey = kp.PrivateKey

	// Pre-allocate signature buffers
	bc.sig = make([]byte, sigCompressedMaxSize(logN))
	bc.sigCT = make([]byte, sigCTSize(logN))

	return bc
}

func BenchmarkFalcon(b *testing.B) {
	// Log which PRNG implementation is being used
	b.Logf("Using %s PRNG", getPRNGName())

	// Test for Falcon-512 (logN=9) and Falcon-1024 (logN=10)
	for _, logN := range []uint{9, 10} {
		degree := 1 << logN
		b.Run(fmt.Sprintf("Degree-%d", degree), func(b *testing.B) {
			bc := setupBenchContext(b, logN)

			// Benchmark key generation
			b.Run("KeyGen", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_, err := GenerateKeyPair(logN)
					if err != nil {
						b.Fatalf("KeyGen failed: %v", err)
					}
				}
			})

			// Benchmark signing (compressed)
			b.Run("Sign-Compressed", func(b *testing.B) {
				msg := []byte("data")
				for i := 0; i < b.N; i++ {
					_, err := Sign(msg, bc.privKey, SigCompressed)
					if err != nil {
						b.Fatalf("Sign compressed failed: %v", err)
					}
				}
			})

			// Benchmark signing (CT)
			b.Run("Sign-CT", func(b *testing.B) {
				msg := []byte("data")
				for i := 0; i < b.N; i++ {
					_, err := Sign(msg, bc.privKey, SigCT)
					if err != nil {
						b.Fatalf("Sign CT failed: %v", err)
					}
				}
			})

			// Benchmark verification (compressed)
			b.Run("Verify-Compressed", func(b *testing.B) {
				msg := []byte("data")
				sig, err := Sign(msg, bc.privKey, SigCompressed)
				if err != nil {
					b.Fatalf("Initial signature failed: %v", err)
				}
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					err := Verify(sig, msg, bc.publicKey, SigCompressed)
					if err != nil {
						b.Fatalf("Verify compressed failed: %v", err)
					}
				}
			})

			// Benchmark verification (CT)
			b.Run("Verify-CT", func(b *testing.B) {
				msg := []byte("data")
				sig, err := Sign(msg, bc.privKey, SigCT)
				if err != nil {
					b.Fatalf("Initial signature failed: %v", err)
				}
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					err := Verify(sig, msg, bc.publicKey, SigCT)
					if err != nil {
						b.Fatalf("Verify CT failed: %v", err)
					}
				}
			})
		})
	}
}

// Helper function to print results similar to C implementation
func PrintBenchmarkResults(result testing.BenchmarkResult, name string) {
	nsPerOp := result.NsPerOp()
	var output string
	if name == "KeyGen" {
		// Convert to milliseconds for keygen
		output = fmt.Sprintf("%8.2f", float64(nsPerOp)/1000000.0)
	} else {
		// Convert to microseconds for others
		output = fmt.Sprintf("%8.2f", float64(nsPerOp)/1000.0)
	}
	fmt.Printf("%s: %s", name, output)
}

// To run the benchmark with custom settings, create a main_test.go file
func Example_benchmarkOutput() {
	fmt.Println("degree  kg(ms)   sd(us)  sdc(us)   vv(us)  vvc(us)")
	// The actual benchmarks will be run using 'go test -bench=.'
}
