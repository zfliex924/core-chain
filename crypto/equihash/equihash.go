//go:build !gofuzz && cgo
// +build !gofuzz,cgo

// Package equihash wraps the equihash C++ proof-of-work library.
// Equihash is a memory-hard proof-of-work algorithm based on the
// generalized birthday problem, using Blake2b as the underlying hash function.
package equihash

/*
#cgo CXXFLAGS: -std=c++11 -O3 -DNDEBUG -I./libequihash -I./libequihash/blake
#cgo CFLAGS: -I./libequihash -I./libequihash/blake
#cgo amd64 CXXFLAGS: -maes
#include "ext.h"
*/
import "C"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"
)

const SeedLength = 4 // Seed length in uint32 words (16 bytes)

var (
	ErrInvalidSeedLen = errors.New("equihash: seed must be 16 bytes (4 x uint32)")
	ErrInvalidParams  = errors.New("equihash: invalid parameters")
	ErrSolveFailed    = errors.New("equihash: failed to find proof")
)

// Proof represents an equihash proof-of-work solution.
type Proof struct {
	N      uint32   // Width parameter
	K      uint32   // Length parameter
	Seed   []byte   // 16 bytes (4 x uint32)
	Nonce  uint32   // Nonce that produces the solution
	Inputs []uint32 // Solution indices (2^k elements)
}

// Solve finds an equihash proof for the given parameters and seed.
// seed must be exactly 16 bytes (4 x uint32, little-endian).
func Solve(n, k uint32, seed []byte) (*Proof, error) {
	if len(seed) != SeedLength*4 {
		return nil, ErrInvalidSeedLen
	}
	if n == 0 || k == 0 {
		return nil, ErrInvalidParams
	}

	seedWords := bytesToUint32s(seed)

	result := C.equihash_solve(
		C.uint32_t(n),
		C.uint32_t(k),
		(*C.uint32_t)(unsafe.Pointer(&seedWords[0])),
		C.uint32_t(SeedLength),
	)

	if result.success == 0 || result.inputs == nil {
		return nil, ErrSolveFailed
	}
	defer C.equihash_free_inputs(result.inputs)

	numInputs := uint32(result.num_inputs)
	inputs := make([]uint32, numInputs)
	cInputs := unsafe.Slice((*uint32)(unsafe.Pointer(result.inputs)), numInputs)
	copy(inputs, cInputs)

	return &Proof{
		N:      n,
		K:      k,
		Seed:   append([]byte(nil), seed...),
		Nonce:  uint32(result.nonce),
		Inputs: inputs,
	}, nil
}

// Verify checks whether the given equihash proof is valid.
func Verify(n, k uint32, seed []byte, nonce uint32, inputs []uint32) bool {
	if len(seed) != SeedLength*4 || len(inputs) == 0 || n == 0 || k == 0 {
		return false
	}

	seedWords := bytesToUint32s(seed)

	result := C.equihash_verify(
		C.uint32_t(n),
		C.uint32_t(k),
		(*C.uint32_t)(unsafe.Pointer(&seedWords[0])),
		C.uint32_t(SeedLength),
		C.uint32_t(nonce),
		(*C.uint32_t)(unsafe.Pointer(&inputs[0])),
		C.uint32_t(len(inputs)),
	)
	return result != 0
}

// VerifyProof is a convenience method that verifies a Proof struct directly.
func VerifyProof(p *Proof) bool {
	if p == nil {
		return false
	}
	return Verify(p.N, p.K, p.Seed, p.Nonce, p.Inputs)
}

// ExpandZcashSolution unpacks a Zcash bit-packed equihash solution into a
// slice of uint32 indices. Zcash stores indices MSB-first with
// bitLen = n/(k+1)+1 bits each (e.g. 21 bits for n=200, k=9).
func ExpandZcashSolution(n, k uint32, packed []byte) ([]uint32, error) {
	bitLen := n/(k+1) + 1
	numIndices := uint32(1) << k
	expectedBytes := (bitLen*numIndices + 7) / 8
	if uint32(len(packed)) != expectedBytes {
		return nil, fmt.Errorf("equihash: expected %d solution bytes, got %d",
			expectedBytes, len(packed))
	}

	mask := uint64((1 << bitLen) - 1)
	var acc uint64
	accBits := uint32(0)
	indices := make([]uint32, 0, numIndices)

	for _, b := range packed {
		acc = (acc << 8) | uint64(b)
		accBits += 8
		if accBits >= bitLen {
			accBits -= bitLen
			indices = append(indices, uint32((acc>>accBits)&mask))
		}
	}
	if uint32(len(indices)) != numIndices {
		return nil, fmt.Errorf("equihash: expected %d indices, got %d",
			numIndices, len(indices))
	}
	return indices, nil
}

// VerifyZcash verifies an Equihash proof using Zcash's personalized-Blake2b
// variant (person = "ZcashPoW" + LE32(n) + LE32(k)).
//
// header must be the raw block-header bytes up to and including nNonce
// (140 bytes for Zcash mainnet/testnet), and inputs must already be expanded
// via ExpandZcashSolution.
func VerifyZcash(n, k uint32, header []byte, inputs []uint32) bool {
	if len(header) == 0 || len(inputs) == 0 || n == 0 || k == 0 {
		return false
	}

	result := C.equihash_verify_zcash(
		C.uint32_t(n),
		C.uint32_t(k),
		(*C.uint8_t)(unsafe.Pointer(&header[0])),
		C.uint32_t(len(header)),
		(*C.uint32_t)(unsafe.Pointer(&inputs[0])),
		C.uint32_t(len(inputs)),
	)
	return result != 0
}

func bytesToUint32s(b []byte) []uint32 {
	words := make([]uint32, len(b)/4)
	for i := range words {
		words[i] = binary.LittleEndian.Uint32(b[i*4:])
	}
	return words
}
