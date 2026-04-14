package vm

import (
	"bytes"
	"testing"
)

func TestPedersenHash(t *testing.T) {
	c := &pedersenHash{}

	tests := []struct {
		name  string
		input []byte
	}{
		{"empty input", []byte{}},
		{"hello", []byte("hello")},
		{"short data", []byte{0x01, 0x02, 0x03}},
		{"31 bytes", make([]byte, 31)},
		{"32 bytes", make([]byte, 32)},
		{"62 bytes", make([]byte, 62)},
		{"long data", make([]byte, 256)},
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
		})
	}
}

func TestPedersenHashDeterministic(t *testing.T) {
	c := &pedersenHash{}
	input := []byte("deterministic test")

	result1, _ := c.Run(input)
	result2, _ := c.Run(input)

	if !bytes.Equal(result1, result2) {
		t.Fatal("pedersen hash is not deterministic")
	}
}

func TestPedersenHashDifferentInputs(t *testing.T) {
	c := &pedersenHash{}

	result1, _ := c.Run([]byte("input1"))
	result2, _ := c.Run([]byte("input2"))

	if bytes.Equal(result1, result2) {
		t.Fatal("different inputs should produce different hashes")
	}
}

func TestPedersenHashInputTooLarge(t *testing.T) {
	c := &pedersenHash{}
	// maxGenerators=256, each handles 31 bytes, so max = 256*31 = 7936 bytes
	input := make([]byte, 256*31+1)
	_, err := c.Run(input)
	if err == nil {
		t.Fatal("expected error for oversized input")
	}
}

func TestPedersenHashRequiredGas(t *testing.T) {
	c := &pedersenHash{}

	tests := []struct {
		name        string
		inputLen    int
		expectedGas uint64
	}{
		// gas = ceil(len/31) * PedersenPerChunkGas + PedersenBaseGas
		// PedersenBaseGas=100, PedersenPerChunkGas=120
		{"empty", 0, 220},       // nChunks=1 (min), 1*120 + 100
		{"1 byte", 1, 220},      // (1+30)/31=1, 1*120 + 100
		{"31 bytes", 31, 220},   // (31+30)/31=1, 1*120 + 100 (61/31=1)
		{"32 bytes", 32, 340},   // (32+30)/31=2, 2*120 + 100
		{"62 bytes", 62, 340},   // (62+30)/31=2, 2*120 + 100 (92/31=2)
		{"63 bytes", 63, 460},   // (63+30)/31=3, 3*120 + 100
		{"256 bytes", 256, 1180}, // ceil(256/31)=9, 9*120 + 100 = 1180
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

func BenchmarkPedersenHash(b *testing.B) {
	c := &pedersenHash{}
	input := make([]byte, 128)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Run(input)
	}
}
