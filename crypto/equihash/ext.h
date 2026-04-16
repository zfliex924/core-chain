// Copyright 2024 The core-chain Authors
// This file is part of the core-chain library.
//
// Equihash C wrapper - provides C-linkage functions for CGO interop.

#ifndef EQUIHASH_EXT_H
#define EQUIHASH_EXT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// equihash_result_t holds the result of an equihash solve operation.
typedef struct {
    uint32_t nonce;
    uint32_t num_inputs;
    uint32_t* inputs;   // caller must free via equihash_free_inputs()
    int      success;   // 1 = found, 0 = failed
} equihash_result_t;

// equihash_solve finds an equihash proof for the given parameters.
//
// Returns: result struct with success=1 if proof found
// Args:    n:        width parameter
//          k:        length parameter
//          seed:     pointer to seed array (SEED_LENGTH uint32_t values)
//          seed_len: number of uint32_t values in seed (should be 4)
equihash_result_t equihash_solve(
    uint32_t n,
    uint32_t k,
    const uint32_t* seed,
    uint32_t seed_len
);

// equihash_verify checks whether the given proof is valid.
//
// Returns: 1 if valid, 0 if invalid
// Args:    n:          width parameter
//          k:          length parameter
//          seed:       pointer to seed array
//          seed_len:   number of uint32_t values in seed
//          nonce:      the nonce from the proof
//          inputs:     pointer to input indices array
//          num_inputs: number of input indices
int equihash_verify(
    uint32_t n,
    uint32_t k,
    const uint32_t* seed,
    uint32_t seed_len,
    uint32_t nonce,
    const uint32_t* inputs,
    uint32_t num_inputs
);

// equihash_free_inputs frees the inputs array allocated by equihash_solve.
void equihash_free_inputs(uint32_t* inputs);

// equihash_verify_zcash verifies an Equihash proof using Zcash's personalized-
// Blake2b variant (person = "ZcashPoW" + LE32(n) + LE32(k)).
//
// Returns: 1 if valid, 0 if invalid
// Args:    n:          width parameter (e.g. 200 for Zcash mainnet)
//          k:          length parameter (e.g. 9 for Zcash mainnet)
//          header:     block header bytes (all fields up to and including
//                      nNonce, i.e. the 140 bytes before nSolution)
//          header_len: length of header in bytes
//          inputs:     expanded solution indices (2^k uint32 values)
//          num_inputs: must equal 2^k
int equihash_verify_zcash(
    uint32_t n,
    uint32_t k,
    const uint8_t* header,
    uint32_t header_len,
    const uint32_t* inputs,
    uint32_t num_inputs
);

#ifdef __cplusplus
}
#endif

#endif // EQUIHASH_EXT_H
