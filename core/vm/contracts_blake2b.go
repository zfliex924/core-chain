package vm

import (
	"github.com/ethereum/go-ethereum/crypto/blake2b"
	"github.com/ethereum/go-ethereum/params"
)

// blake2bHash implements BLAKE2b-256 hash as a native precompiled contract.
type blake2bHash struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *blake2bHash) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+31)/32*params.Blake2bPerWordGas + params.Blake2bBaseGas
}

// Run executes the BLAKE2b-256 hash on the input data and returns the 32-byte result.
func (c *blake2bHash) Run(input []byte) ([]byte, error) {
	h := blake2b.Sum256(input)
	return h[:], nil
}
