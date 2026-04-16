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

// ---------------------------------------------------------------------------
// Zcash-compatible Equihash verification
// ---------------------------------------------------------------------------

// Initialise a personalized Blake2b state and feed the block header into it.
// Personalization = "ZcashPoW" (8 bytes) + LE32(n) + LE32(k) = 16 bytes.
// digest_length = 2*(n/8) so that one call produces hashes for two indices.
static void zcash_init_state(
    blake2b_state*  state,
    uint32_t        n,
    uint32_t        k,
    const uint8_t*  header,
    uint32_t        header_len)
{
    blake2b_param P;
    memset(&P, 0, sizeof(P));
    P.digest_length = (uint8_t)(2u * (n / 8u));   // e.g. 50 for n=200
    P.fanout        = 1;
    P.depth         = 1;
    // "ZcashPoW" + LE32(n) + LE32(k)  — memcpy copies native-endian (LE on x86/ARM)
    memcpy(P.personal,      "ZcashPoW", 8);
    memcpy(P.personal +  8, &n,         4);
    memcpy(P.personal + 12, &k,         4);
    blake2b_init_param(state, &P);
    blake2b_update(state, header, header_len);
}

// Compute the n/8-byte Zcash hash for solution index i.
// Indices come in pairs that share the same Blake2b call (group g = i/2).
static void zcash_hash_index(
    const blake2b_state* base,
    uint32_t             i,
    uint32_t             n,
    uint8_t*             out)          // receives n/8 bytes
{
    blake2b_state s = *base;           // copy so base_state stays reusable
    uint32_t g = i / 2u;
    blake2b_update(&s, (const uint8_t*)&g, sizeof(g));

    uint8_t  buf[BLAKE2B_OUTBYTES];
    uint8_t  digest_len = (uint8_t)(2u * (n / 8u));
    blake2b_final(&s, buf, digest_len);

    uint32_t half = n / 8u;
    memcpy(out, buf + (i & 1u) * half, half);   // first or second half
}

// Extract bit_count bits starting at bit position bit_start from a byte array,
// MSB-first (bit 0 = MSB of byte 0).
static uint32_t extract_bits_msb(
    const uint8_t* data,
    uint32_t       data_len,
    uint32_t       bit_start,
    uint32_t       bit_count)
{
    uint32_t result = 0;
    for (uint32_t i = 0; i < bit_count; i++) {
        uint32_t bit      = bit_start + i;
        uint32_t byte_idx = bit >> 3u;
        uint32_t bit_pos  = 7u - (bit & 7u);    // 0 = LSB within byte
        uint32_t b        = (byte_idx < data_len)
                            ? (uint32_t)(data[byte_idx] >> bit_pos) & 1u
                            : 0u;
        result = (result << 1u) | b;
    }
    return result;
}

int equihash_verify_zcash(
    uint32_t       n,
    uint32_t       k,
    const uint8_t* header,
    uint32_t       header_len,
    const uint32_t* inputs,
    uint32_t       num_inputs)
{
    if (n == 0 || k == 0)                        return 0;
    if ((k + 1u) == 0 || n % (k + 1u) != 0)     return 0;
    if (num_inputs != (1u << k))                 return 0;
    if (2u * (n / 8u) > BLAKE2B_OUTBYTES)        return 0;

    const uint32_t hash_len       = n / 8u;
    const uint32_t bits_per_block = n / (k + 1u);

    blake2b_state base_state;
    zcash_init_state(&base_state, n, k, header, header_len);

    std::vector<uint8_t>  hash(hash_len);
    std::vector<uint32_t> blocks(k + 1u, 0u);

    for (uint32_t i = 0; i < num_inputs; i++) {
        zcash_hash_index(&base_state, inputs[i], n, hash.data());
        for (uint32_t j = 0; j < k + 1u; j++) {
            blocks[j] ^= extract_bits_msb(
                hash.data(), hash_len,
                j * bits_per_block, bits_per_block);
        }
    }

    for (uint32_t j = 0; j < k + 1u; j++) {
        if (blocks[j] != 0u) return 0;
    }
    return 1;
}

} // extern "C"
