package vm

import (
	"encoding/binary"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto/equihash"
	"github.com/ethereum/go-ethereum/params"
)

// equihashVerify implements Equihash proof verification as a native precompiled contract.
type equihashVerify struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *equihashVerify) RequiredGas(input []byte) uint64 {
	if len(input) <= 28 {
		return params.EquihashVerifyBaseGas
	}
	numInputs := (uint64(len(input)) - 28) / 4
	return params.EquihashVerifyBaseGas + numInputs*params.EquihashVerifyPerInputGas
}

// Run executes the Equihash verification on the input data.
//
// Input format (big-endian, tightly packed):
//
//	| n (4B) | k (4B) | seed (16B) | nonce (4B) | inputs (2^k * 4B) |
//
// Returns 0x01 if the proof is valid, empty bytes if invalid.
func (c *equihashVerify) Run(input []byte) ([]byte, error) {
	const headerSize = 28 // 4 + 4 + 16 + 4

	if len(input) < headerSize {
		return nil, ErrExecutionReverted
	}

	n := binary.BigEndian.Uint32(input[0:4])
	k := binary.BigEndian.Uint32(input[4:8])
	seed := make([]byte, 16)
	copy(seed, input[8:24])
	nonce := binary.BigEndian.Uint32(input[24:28])

	if n == 0 || k == 0 || k > 20 {
		return nil, ErrExecutionReverted
	}

	inputsBytes := input[headerSize:]
	if len(inputsBytes)%4 != 0 {
		return nil, ErrExecutionReverted
	}
	numInputs := len(inputsBytes) / 4
	if numInputs != 1<<k {
		return nil, ErrExecutionReverted
	}

	inputs := make([]uint32, numInputs)
	for i := 0; i < numInputs; i++ {
		inputs[i] = binary.BigEndian.Uint32(inputsBytes[i*4 : (i+1)*4])
	}

	if equihash.Verify(n, k, seed, nonce, inputs) {
		return big1.Bytes(), nil
	}
	return common.Big0.Bytes(), nil
}
