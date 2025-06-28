#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

// we use shake256 based prng
#ifndef FALCON_PRNG_KECCAK256
#define FALCON_PRNG_KECCAK256   0
#endif
#include "inner.h"

void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void test_unified_basic_functionality() {
    printf("Test: Unified Basic Functionality\n");
    
#if FALCON_PRNG_KECCAK256
    printf("Using: Keccak256 PRNG\n");
#else
    printf("Using: SHAKE256 PRNG\n");
#endif
    
    inner_prng_context ctx;
    uint8_t input[] = "test input";
    uint8_t output1[32];
    uint8_t output2[32];
    
    // Test 1: Same input should generate same output
    inner_prng_init(&ctx);
    inner_prng_inject(&ctx, input, strlen((char*)input));
    inner_prng_flip(&ctx);
    inner_prng_extract(&ctx, output1, 32);
    
    inner_prng_context ctx2;
    inner_prng_init(&ctx2);
    inner_prng_inject(&ctx2, input, strlen((char*)input));
    inner_prng_flip(&ctx2);
    inner_prng_extract(&ctx2, output2, 32);
    
    printf("Output 1: ");
    print_hex(output1, 32);
    printf("Output 2: ");
    print_hex(output2, 32);
    
    assert(memcmp(output1, output2, 32) == 0);
    printf("PASSED: Same input generates same output\n");
}

void test_unified_different_lengths() {
    printf("\nTest: Different Output Lengths\n");
    
    inner_prng_context ctx;
    uint8_t input[] = "test input";
    uint8_t output32[32];
    uint8_t output64[64];
    
    inner_prng_init(&ctx);
    inner_prng_inject(&ctx, input, strlen((char*)input));
    inner_prng_flip(&ctx);
    inner_prng_extract(&ctx, output32, 32);
    inner_prng_extract(&ctx,  output64, 64);
    
    printf("32-byte output: ");
    print_hex(output32, 32);
    printf("First 32 bytes of 64-byte output: ");
    print_hex(output64, 32);
    
    assert(memcmp(output32, output64, 32) != 0);
    printf("PASSED: Different length outputs are unique\n");
}

void test_unified_incremental_injection() {
    printf("\nTest: Incremental Injection\n");
    
    inner_prng_context ctx1, ctx2;
    uint8_t input1[] = "test";
    uint8_t input2[] = "input";
    uint8_t output1[32];
    uint8_t output2[32];
    
    // Inject in one go
    inner_prng_init(&ctx1);
    inner_prng_inject(&ctx1, (uint8_t*)"testinput", 9);
    inner_prng_flip(&ctx1);
    inner_prng_extract(&ctx1, output1, 32);
    
    // Inject incrementally
    inner_prng_init(&ctx2);
    inner_prng_inject(&ctx2, input1, 4);
    inner_prng_inject(&ctx2, input2, 5);
    inner_prng_flip(&ctx2);
    inner_prng_extract(&ctx2, output2, 32);
    
    printf("Single injection output: ");
    print_hex(output1, 32);
    printf("Incremental injection output: ");
    print_hex(output2, 32);
    
    assert(memcmp(output1, output2, 32) == 0);
    printf("PASSED: Incremental injection matches single injection\n");
}

void test_unified_sequence() {
    printf("\nTest: Output Sequence\n");
    
    inner_prng_context ctx;
    uint8_t input[] = "test sequence";
    uint8_t output1[16];
    uint8_t output2[16];
    uint8_t output3[16];
    
    inner_prng_init(&ctx);
    inner_prng_inject(&ctx, input, strlen((char*)input));
    inner_prng_flip(&ctx);
    
    inner_prng_extract(&ctx, output1, 16);
    inner_prng_extract(&ctx, output2, 16);
    inner_prng_extract(&ctx, output3, 16);
    
    printf("Sequence 1: ");
    print_hex(output1, 16);
    printf("Sequence 2: ");
    print_hex(output2, 16);
    printf("Sequence 3: ");
    print_hex(output3, 16);
    
    // Outputs should all be different
    assert(memcmp(output1, output2, 16) != 0);
    assert(memcmp(output2, output3, 16) != 0);
    assert(memcmp(output1, output3, 16) != 0);
    printf("PASSED: Sequential outputs are unique\n");
}

int main() {
    printf("Running Unified PRNG Tests\n");
    printf("==========================\n\n");
    
    test_unified_basic_functionality();
    test_unified_different_lengths();
    test_unified_incremental_injection();
    test_unified_sequence();
    
    printf("\nAll unified PRNG tests passed successfully!\n");
    return 0;
}