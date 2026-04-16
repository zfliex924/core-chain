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
	// Zcash mode: magic byte 0x5A followed by n(4B) k(4B) …
	if len(input) > 0 && input[0] == 0x5A {
		if len(input) < 9 {
			return params.EquihashVerifyBaseGas
		}
		k := binary.BigEndian.Uint32(input[5:9])
		if k == 0 || k > 20 {
			return params.EquihashVerifyBaseGas
		}
		numInputs := uint64(1) << k
		return params.EquihashVerifyBaseGas + numInputs*params.EquihashVerifyPerInputGas
	}
	// Standard mode
	if len(input) <= 28 {
		return params.EquihashVerifyBaseGas
	}
	numInputs := (uint64(len(input)) - 28) / 4
	return params.EquihashVerifyBaseGas + numInputs*params.EquihashVerifyPerInputGas
}

// Run executes Equihash verification on the input data.
//
// Two input modes are supported, selected by the first byte:
//
// Standard mode (first byte != 0x5A):
//
//	| n (4B BE) | k (4B BE) | seed (16B) | nonce (4B BE) | inputs (2^k × 4B BE) |
//
// Zcash mode (first byte == 0x5A):
//
//	| 0x5A (1B) | n (4B BE) | k (4B BE) | header (140B) | solution (packed, (n/(k+1)+1)×2^k bits) |
//
// Returns 0x01 if the proof is valid, 0x00 if invalid.
func (c *equihashVerify) Run(input []byte) ([]byte, error) {
	if len(input) > 0 && input[0] == 0x5A {
		return c.runZcash(input[1:])
	}
	return c.runStandard(input)
}

// runStandard handles the original big-endian packed input format.
func (c *equihashVerify) runStandard(input []byte) ([]byte, error) {
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

// runZcash handles Zcash-format block headers.
// input is the payload after stripping the 0x5A magic byte:
//
//	| n (4B BE) | k (4B BE) | header (140B) | solution (packed bits) |
func (c *equihashVerify) runZcash(input []byte) ([]byte, error) {
	const zcashHeaderLen = 140
	const minLen = 4 + 4 + zcashHeaderLen

	if len(input) < minLen {
		return nil, ErrExecutionReverted
	}

	n := binary.BigEndian.Uint32(input[0:4])
	k := binary.BigEndian.Uint32(input[4:8])

	if n == 0 || k == 0 || k > 20 {
		return nil, ErrExecutionReverted
	}
	if n%(k+1) != 0 {
		return nil, ErrExecutionReverted
	}

	header := input[8 : 8+zcashHeaderLen]
	solutionPacked := input[8+zcashHeaderLen:]

	inputs, err := equihash.ExpandZcashSolution(n, k, solutionPacked)
	if err != nil {
		return nil, ErrExecutionReverted
	}

	if equihash.VerifyZcash(n, k, header, inputs) {
		return big1.Bytes(), nil
	}
	return common.Big0.Bytes(), nil
}
