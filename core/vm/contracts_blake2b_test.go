package vm

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/crypto/blake2b"
)

func TestBlake2bHash(t *testing.T) {
	c := &blake2bHash{}

	tests := []struct {
		name  string
		input []byte
	}{
		{"empty input", []byte{}},
		{"hello", []byte("hello")},
		{"short data", []byte{0x01, 0x02, 0x03}},
		{"32 bytes", make([]byte, 32)},
		{"long data", make([]byte, 1024)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := c.Run(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(result) != 32 {
				t.Fatalf("expected 32 bytes, got %d", len(result))
			}

			// Verify against direct blake2b.Sum256 call
			expected := blake2b.Sum256(tt.input)
			if !bytes.Equal(result, expected[:]) {
				t.Fatalf("result mismatch:\n  got:    %x\n  expect: %x", result, expected)
			}
		})
	}
}

func TestBlake2bHashRequiredGas(t *testing.T) {
	c := &blake2bHash{}

	tests := []struct {
		name        string
		inputLen    int
		expectedGas uint64
	}{
		// gas = ceil(len/32) * Blake2bPerWordGas + Blake2bBaseGas
		// Blake2bBaseGas=12, Blake2bPerWordGas=3
		{"empty", 0, 12},          // (0+31)/32*3 + 12 = 0 + 12
		{"1 byte", 1, 15},         // (1+31)/32*3 + 12 = 3 + 12
		{"32 bytes", 32, 15},      // (32+31)/32*3 + 12 = 3 + 12 (63/32=1)
		{"33 bytes", 33, 18},      // (33+31)/32*3 + 12 = 6 + 12
		{"64 bytes", 64, 18},      // (64+31)/32*3 + 12 = 6 + 12 (95/32=2)
		{"128 bytes", 128, 24},    // (128+31)/32*3 + 12 = 12 + 12 (159/32=4)
		{"1024 bytes", 1024, 108}, // (1024+31)/32*3 + 12 = 96 + 12
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

func TestBlake2bHashDeterministic(t *testing.T) {
	c := &blake2bHash{}
	input := []byte("deterministic test")

	result1, _ := c.Run(input)
	result2, _ := c.Run(input)

	if !bytes.Equal(result1, result2) {
		t.Fatal("blake2b hash is not deterministic")
	}
}

func BenchmarkBlake2bHash(b *testing.B) {
	c := &blake2bHash{}
	input := make([]byte, 128)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Run(input)
	}
}
