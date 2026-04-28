package vm

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/params"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

// poseidonT3 implements the Poseidon hash function with 2 inputs (t=3, BN254 scalar field)
// as a native precompiled contract. The output matches circomlibjs / circomlib's Poseidon
// implementation byte-for-byte, so MASP commitments and nullifiers remain compatible with
// the existing snarkjs proofs.
//
// Input layout : 64 bytes — two 32-byte big-endian BN254 scalar field elements.
// Output       : 32 bytes — Poseidon([a, b]) as a big-endian field element.
type poseidonT3 struct{}

// poseidonT4 implements Poseidon with 3 inputs (t=4, BN254 scalar field).
//
// Input layout : 96 bytes — three 32-byte big-endian BN254 scalar field elements.
// Output       : 32 bytes — Poseidon([a, b, c]) as a big-endian field element.
type poseidonT4 struct{}

const (
	poseidonScalarSize = 32
)

var (
	errPoseidonInvalidInputLen = errors.New("poseidon: invalid input length")
	errPoseidonInvalidScalar   = errors.New("poseidon: input not in BN254 scalar field")
)

// RequiredGas returns the constant gas cost for a Poseidon T3 hash.
func (c *poseidonT3) RequiredGas(input []byte) uint64 {
	return params.PoseidonT3Gas
}

// Run executes the Poseidon T3 hash on two BN254 scalar field elements.
func (c *poseidonT3) Run(input []byte) ([]byte, error) {
	if len(input) != 2*poseidonScalarSize {
		return nil, errPoseidonInvalidInputLen
	}
	return runPoseidon(input, 2)
}

// RequiredGas returns the constant gas cost for a Poseidon T4 hash.
func (c *poseidonT4) RequiredGas(input []byte) uint64 {
	return params.PoseidonT4Gas
}

// Run executes the Poseidon T4 hash on three BN254 scalar field elements.
func (c *poseidonT4) Run(input []byte) ([]byte, error) {
	if len(input) != 3*poseidonScalarSize {
		return nil, errPoseidonInvalidInputLen
	}
	return runPoseidon(input, 3)
}

// runPoseidon parses n big-endian field elements from input, runs Poseidon, and returns
// the 32-byte big-endian result. It rejects any input that does not lie in the BN254
// scalar field, matching the circomlib contract behaviour.
func runPoseidon(input []byte, n int) ([]byte, error) {
	inputs := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		offset := i * poseidonScalarSize
		v := new(big.Int).SetBytes(input[offset : offset+poseidonScalarSize])
		if v.Cmp(bn254ScalarField) >= 0 {
			return nil, errPoseidonInvalidScalar
		}
		inputs[i] = v
	}

	h, err := poseidon.Hash(inputs)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 32)
	hBytes := h.Bytes()
	copy(out[32-len(hBytes):], hBytes)
	return out, nil
}

// bn254ScalarField is the order of the BN254 scalar field used by circomlib's Poseidon.
// 21888242871839275222246405745257275088548364400416034343698204186575808495617
var bn254ScalarField, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088548364400416034343698204186575808495617",
	10,
)
