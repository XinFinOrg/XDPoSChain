// internal/falcon/falcon.go

package falcon

/*
#cgo CFLAGS: -I${SRCDIR}/../c
#cgo LDFLAGS: ${SRCDIR}/../c/codec.o ${SRCDIR}/../c/common.o ${SRCDIR}/../c/falcon.o ${SRCDIR}/../c/fft.o ${SRCDIR}/../c/fpr.o ${SRCDIR}/../c/keygen.o ${SRCDIR}/../c/rng.o ${SRCDIR}/../c/shake.o ${SRCDIR}/../c/sign.o ${SRCDIR}/../c/vrfy.o

#include "falcon.h"
#include <stdlib.h>

// Wrapper functions for macros
size_t falcon_privkey_size(unsigned logn) {
    return FALCON_PRIVKEY_SIZE(logn);
}

size_t falcon_pubkey_size(unsigned logn) {
    return FALCON_PUBKEY_SIZE(logn);
}

size_t falcon_sig_compressed_maxsize(unsigned logn) {
    return FALCON_SIG_COMPRESSED_MAXSIZE(logn);
}

size_t falcon_sig_padded_size(unsigned logn) {
    return FALCON_SIG_PADDED_SIZE(logn);
}

size_t falcon_sig_ct_size(unsigned logn) {
    return FALCON_SIG_CT_SIZE(logn);
}

size_t falcon_tmpsize_keygen(unsigned logn) {
    return FALCON_TMPSIZE_KEYGEN(logn);
}

size_t falcon_tmpsize_signdyn(unsigned logn) {
    return FALCON_TMPSIZE_SIGNDYN(logn);
}

size_t falcon_tmpsize_verify(unsigned logn) {
    return FALCON_TMPSIZE_VERIFY(logn);
}
*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

// Error codes from Falcon
const (
	ErrRandom   = C.FALCON_ERR_RANDOM   // OS RNG failure
	ErrSize     = C.FALCON_ERR_SIZE     // Buffer too small
	ErrFormat   = C.FALCON_ERR_FORMAT   // Invalid format
	ErrBadSig   = C.FALCON_ERR_BADSIG   // Invalid signature
	ErrBadArg   = C.FALCON_ERR_BADARG   // Invalid argument
	ErrInternal = C.FALCON_ERR_INTERNAL // Internal error
)

// Signature types
const (
	SigCompressed = C.FALCON_SIG_COMPRESSED
	SigPadded     = C.FALCON_SIG_PADDED
	SigCT         = C.FALCON_SIG_CT
)

// Wrapper functions for size calculations
func privateKeySize(logN uint) int {
	return int(C.falcon_privkey_size(C.uint(logN)))
}

func publicKeySize(logN uint) int {
	return int(C.falcon_pubkey_size(C.uint(logN)))
}

func sigCompressedMaxSize(logN uint) int {
	return int(C.falcon_sig_compressed_maxsize(C.uint(logN)))
}

func sigPaddedSize(logN uint) int {
	return int(C.falcon_sig_padded_size(C.uint(logN)))
}

func sigCTSize(logN uint) int {
	return int(C.falcon_sig_ct_size(C.uint(logN)))
}

func tmpSizeKeygen(logN uint) int {
	return int(C.falcon_tmpsize_keygen(C.uint(logN)))
}

func tmpSizeSignDyn(logN uint) int {
	return int(C.falcon_tmpsize_signdyn(C.uint(logN)))
}

func tmpSizeVerify(logN uint) int {
	return int(C.falcon_tmpsize_verify(C.uint(logN)))
}

// KeyPair represents a Falcon key pair
type KeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
}

// GetLogN returns the Falcon degree from an encoded object (private key, public key, or signature)
func GetLogN(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, errors.New("empty input data")
	}

	result := C.falcon_get_logn(unsafe.Pointer(&data[0]), C.size_t(len(data)))
	if result < 0 {
		return 0, falconError(result)
	}
	return int(result), nil
}

// GenerateKeyPair generates a new Falcon key pair for the given degree (logN)
func GenerateKeyPair(logN uint) (*KeyPair, error) {
	if logN < 1 || logN > 10 {
		return nil, errors.New("logN must be between 1 and 10")
	}

	privKeySize := privateKeySize(logN)
	pubKeySize := publicKeySize(logN)
	tmpSize := tmpSizeKeygen(logN)

	privKey := make([]byte, privKeySize)
	pubKey := make([]byte, pubKeySize)
	tmp := make([]byte, tmpSize)

	// Initialize PRNG
	rng := &PRNGContext{}
	if err := rng.InitFromSystem(); err != nil {
		return nil, fmt.Errorf("failed to initialize RNG: %w", err)
	}

	result := C.falcon_keygen_make(
		&rng.ctx,
		C.uint(logN),
		unsafe.Pointer(&privKey[0]), C.size_t(len(privKey)),
		unsafe.Pointer(&pubKey[0]), C.size_t(len(pubKey)),
		unsafe.Pointer(&tmp[0]), C.size_t(len(tmp)),
	)

	if result != 0 {
		return nil, falconError(result)
	}

	return &KeyPair{
		PublicKey:  pubKey,
		PrivateKey: privKey,
	}, nil
}

// Sign generates a signature for the given message using the private key
func Sign(message, privateKey []byte, sigType int) ([]byte, error) {
	logN, err := GetLogN(privateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	var sigLen C.size_t
	var sigSize int

	// Calculate maximum buffer size based on signature type
	switch sigType {
	case SigCompressed:
		sigSize = sigCompressedMaxSize(uint(logN))
	case SigPadded:
		sigSize = sigPaddedSize(uint(logN))
	case SigCT:
		sigSize = sigCTSize(uint(logN))
	default:
		return nil, errors.New("invalid signature type")
	}

	// Create buffers
	signature := make([]byte, sigSize)
	sigLen = C.size_t(sigSize)
	tmpSize := tmpSizeSignDyn(uint(logN))
	tmp := make([]byte, tmpSize)

	// Initialize PRNG
	rng := &PRNGContext{}
	if err := rng.InitFromSystem(); err != nil {
		return nil, fmt.Errorf("failed to initialize RNG: %w", err)
	}

	result := C.falcon_sign_dyn(
		&rng.ctx,
		unsafe.Pointer(&signature[0]), &sigLen, C.int(sigType),
		unsafe.Pointer(&privateKey[0]), C.size_t(len(privateKey)),
		unsafe.Pointer(&message[0]), C.size_t(len(message)),
		unsafe.Pointer(&tmp[0]), C.size_t(len(tmp)),
	)

	if result != 0 {
		return nil, falconError(result)
	}

	return signature[:sigLen], nil
}

// Verify verifies a signature using the public key
func Verify(signature, message, publicKey []byte, sigType int) error {
	logN, err := GetLogN(publicKey)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	tmpSize := tmpSizeVerify(uint(logN))
	tmp := make([]byte, tmpSize)

	result := C.falcon_verify(
		unsafe.Pointer(&signature[0]), C.size_t(len(signature)), C.int(sigType),
		unsafe.Pointer(&publicKey[0]), C.size_t(len(publicKey)),
		unsafe.Pointer(&message[0]), C.size_t(len(message)),
		unsafe.Pointer(&tmp[0]), C.size_t(len(tmp)),
	)

	if result != 0 {
		return falconError(result)
	}

	return nil
}

// PRNGContext wraps the C prng_context struct
type PRNGContext struct {
	ctx C.prng_context
}

// PRNGContext methods
func (p *PRNGContext) Init() {
	C.prng_init(&p.ctx)
}

func (p *PRNGContext) InitFromSystem() error {
	result := C.prng_init_prng_from_system(&p.ctx)
	if result != 0 {
		return falconError(result)
	}
	return nil
}

func (p *PRNGContext) InitFromSeed(seed []byte) {
	C.prng_init_prng_from_seed(&p.ctx, unsafe.Pointer(&seed[0]), C.size_t(len(seed)))
}

func (p *PRNGContext) Inject(data []byte) {
	C.prng_inject(&p.ctx, unsafe.Pointer(&data[0]), C.size_t(len(data)))
}

func (p *PRNGContext) Flip() {
	C.prng_flip(&p.ctx)
}

func (p *PRNGContext) Extract(out []byte) {
	C.prng_extract(&p.ctx, unsafe.Pointer(&out[0]), C.size_t(len(out)))
}

// Helper function to convert Falcon error codes to Go errors
func falconError(code C.int) error {
	switch code {
	case ErrRandom:
		return errors.New("random number generation failed")
	case ErrSize:
		return errors.New("buffer too small")
	case ErrFormat:
		return errors.New("invalid format")
	case ErrBadSig:
		return errors.New("invalid signature")
	case ErrBadArg:
		return errors.New("invalid argument")
	case ErrInternal:
		return errors.New("internal error")
	default:
		return fmt.Errorf("unknown error: %d", code)
	}
}

// Helper function to get PRNG implementation name
func getPRNGName() string {
	if C.prng_type() == 1 {
		return "Keccak256"
	}
	return "SHAKE256"
}
