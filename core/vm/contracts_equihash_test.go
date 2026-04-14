//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package vm

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/ethereum/go-ethereum/crypto/equihash"
)

// encodeEquihashInput packs equihash verify parameters into the precompiled contract input format.
func encodeEquihashInput(n, k uint32, seed []byte, nonce uint32, inputs []uint32) []byte {
	buf := make([]byte, 28+len(inputs)*4)
	binary.BigEndian.PutUint32(buf[0:4], n)
	binary.BigEndian.PutUint32(buf[4:8], k)
	copy(buf[8:24], seed)
	binary.BigEndian.PutUint32(buf[24:28], nonce)
	for i, v := range inputs {
		binary.BigEndian.PutUint32(buf[28+i*4:28+(i+1)*4], v)
	}
	return buf
}

func TestEquihashVerify(t *testing.T) {
	n, k := uint32(60), uint32(4)
	seed := make([]byte, 16)

	proof, err := equihash.Solve(n, k, seed)
	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	c := &equihashVerify{}
	input := encodeEquihashInput(n, k, seed, proof.Nonce, proof.Inputs)

	result, err := c.Run(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(result, big1.Bytes()) {
		t.Fatalf("expected valid proof to return 0x01, got %x", result)
	}
}

func TestEquihashVerifyTampered(t *testing.T) {
	n, k := uint32(60), uint32(4)
	seed := make([]byte, 16)

	proof, err := equihash.Solve(n, k, seed)
	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	// Tamper with inputs
	badInputs := make([]uint32, len(proof.Inputs))
	copy(badInputs, proof.Inputs)
	badInputs[0] ^= 1

	c := &equihashVerify{}
	input := encodeEquihashInput(n, k, seed, proof.Nonce, badInputs)

	result, err := c.Run(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected tampered proof to return empty, got %x", result)
	}
}

func TestEquihashVerifyInvalidInput(t *testing.T) {
	c := &equihashVerify{}

	tests := []struct {
		name  string
		input []byte
	}{
		{"too short", make([]byte, 10)},
		{"empty", []byte{}},
		{"header only, n=0", encodeEquihashInput(0, 4, make([]byte, 16), 0, make([]uint32, 16))},
		{"header only, k=0", encodeEquihashInput(60, 0, make([]byte, 16), 0, nil)},
		{"k too large", encodeEquihashInput(60, 21, make([]byte, 16), 0, nil)},
		{"wrong input count", encodeEquihashInput(60, 4, make([]byte, 16), 0, make([]uint32, 8))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := c.Run(tt.input)
			if err != ErrExecutionReverted {
				t.Fatalf("expected ErrExecutionReverted, got %v", err)
			}
		})
	}
}

func TestEquihashVerifyRequiredGas(t *testing.T) {
	c := &equihashVerify{}

	tests := []struct {
		name        string
		inputLen    int
		expectedGas uint64
	}{
		{"empty", 0, 25},
		{"header only", 28, 25},
		{"with 16 inputs", 28 + 16*4, 25 + 16*9},
		{"with 512 inputs", 28 + 512*4, 25 + 512*9},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := make([]byte, tt.inputLen)
			gas := c.RequiredGas(input)
			if gas != tt.expectedGas {
				t.Fatalf("gas mismatch: got %d, expected %d", gas, tt.expectedGas)
			}
		})
	}
}

func BenchmarkEquihashVerify(b *testing.B) {
	n, k := uint32(60), uint32(4)
	seed := make([]byte, 16)

	proof, err := equihash.Solve(n, k, seed)
	if err != nil {
		b.Fatalf("Solve failed: %v", err)
	}

	c := &equihashVerify{}
	input := encodeEquihashInput(n, k, seed, proof.Nonce, proof.Inputs)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Run(input)
	}
}
