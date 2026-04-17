package vm

import (
	"github.com/ethereum/go-ethereum/crypto/equihash"
	"github.com/ethereum/go-ethereum/params"
)

// equihashVerify implements Equihash proof verification as a native precompiled contract.
//
// Input format (raw Zcash block, as sent by ZcashLightClient.sol):
//
//	| header (140B) | VarInt fd4005 (3B) | solution (1344B) |
//
// Equihash parameters n=200, k=9 are implied (Zcash mainnet / testnet).
// Total input length must be exactly 1487 bytes.
// Returns 0x01 if the proof is valid, 0x00 if invalid.
type equihashVerify struct{}

const (
	zcashN           = uint32(200)
	zcashK           = uint32(9)
	zcashNumInputs   = uint64(1) << zcashK // 512
	zcashHeaderLen   = 140
	zcashVarIntLen   = 3    // fd 40 05
	zcashSolutionLen = 1344 // 512 indices × 21 bits
	zcashInputLen    = zcashHeaderLen + zcashVarIntLen + zcashSolutionLen // 1487
)

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *equihashVerify) RequiredGas(input []byte) uint64 {
	return params.EquihashVerifyBaseGas + zcashNumInputs*params.EquihashVerifyPerInputGas
}

// Run verifies an Equihash 200/9 proof embedded in a raw Zcash block header.
func (c *equihashVerify) Run(input []byte) ([]byte, error) {
	if len(input) != zcashInputLen {
		return nil, ErrExecutionReverted
	}

	// validate VarInt sentinel
	if input[zcashHeaderLen] != 0xfd || input[zcashHeaderLen+1] != 0x40 || input[zcashHeaderLen+2] != 0x05 {
		return nil, ErrExecutionReverted
	}

	header := input[:zcashHeaderLen]
	solutionPacked := input[zcashHeaderLen+zcashVarIntLen:]

	inputs, err := equihash.ExpandZcashSolution(zcashN, zcashK, solutionPacked)
	if err != nil {
		return nil, ErrExecutionReverted
	}

	if equihash.VerifyZcash(zcashN, zcashK, header, inputs) {
		return big1.Bytes(), nil
	}
	return []byte{0x00}, nil
}
