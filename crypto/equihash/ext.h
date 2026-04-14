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

#ifdef __cplusplus
}
#endif

#endif // EQUIHASH_EXT_H
