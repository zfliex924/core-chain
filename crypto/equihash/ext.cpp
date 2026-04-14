// Copyright 2024 The core-chain Authors
// This file is part of the core-chain library.
//
// Equihash C++ to C bridge - includes vendored source and provides extern "C" wrappers.

// Include vendored C++ source directly. These files are in a subdirectory
// so CGO won't auto-compile them; they are pulled in via #include here.
#include "libequihash/blake/blake2b.cpp"
#include "libequihash/pow.cc"

#include "ext.h"
#include <cstring>
#include <cstdlib>

extern "C" {

equihash_result_t equihash_solve(
    uint32_t n, uint32_t k,
    const uint32_t* seed, uint32_t seed_len
) {
    equihash_result_t result;
    memset(&result, 0, sizeof(result));

    try {
        _POW::Seed s(seed, seed_len);
        _POW::Equihash eq(n, k, s);
        _POW::Proof proof = eq.FindProof();

        if (proof.inputs.empty()) {
            result.success = 0;
            return result;
        }

        result.nonce = proof.nonce;
        result.num_inputs = (uint32_t)proof.inputs.size();
        result.inputs = (uint32_t*)malloc(result.num_inputs * sizeof(uint32_t));
        if (result.inputs) {
            memcpy(result.inputs, proof.inputs.data(),
                   result.num_inputs * sizeof(uint32_t));
            result.success = 1;
        }
    } catch (...) {
        result.success = 0;
    }
    return result;
}

int equihash_verify(
    uint32_t n, uint32_t k,
    const uint32_t* seed, uint32_t seed_len,
    uint32_t nonce,
    const uint32_t* inputs, uint32_t num_inputs
) {
    try {
        _POW::Seed s(seed, seed_len);
        std::vector<_POW::Input> inp(inputs, inputs + num_inputs);
        _POW::Proof proof(n, k, s, nonce, inp);
        return proof.Test() ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

void equihash_free_inputs(uint32_t* inputs) {
    free(inputs);
}

} // extern "C"
