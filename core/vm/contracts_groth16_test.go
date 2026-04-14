package vm

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// buildGroth16Input constructs a well-formed input blob for the groth16Verify precompile.
func buildGroth16Input(
	n int,
	proofA, proofC *bn254.G1Affine,
	proofB *bn254.G2Affine,
	vkAlpha *bn254.G1Affine,
	vkBeta, vkGamma, vkDelta *bn254.G2Affine,
	ic []bn254.G1Affine,
	publicInputs []*big.Int,
) []byte {
	size := groth16FixedInputSize + (n+1)*g1Size + n*scalarSize
	buf := make([]byte, size)
	binary.BigEndian.PutUint32(buf[0:4], uint32(n))

	offset := 4
	offset += marshalG1Into(buf[offset:], proofA)
	offset += marshalG1Into(buf[offset:], proofC)
	offset += marshalG2Into(buf[offset:], proofB)
	offset += marshalG1Into(buf[offset:], vkAlpha)
	offset += marshalG2Into(buf[offset:], vkBeta)
	offset += marshalG2Into(buf[offset:], vkGamma)
	offset += marshalG2Into(buf[offset:], vkDelta)

	for i := 0; i <= n; i++ {
		offset += marshalG1Into(buf[offset:], &ic[i])
	}
	for i := 0; i < n; i++ {
		b := publicInputs[i].Bytes()
		copy(buf[offset+32-len(b):offset+32], b)
		offset += 32
	}
	return buf
}

func marshalG1Into(dst []byte, p *bn254.G1Affine) int {
	xBytes := p.X.Bytes()
	yBytes := p.Y.Bytes()
	copy(dst[0:32], xBytes[:])
	copy(dst[32:64], yBytes[:])
	return 64
}

func marshalG2Into(dst []byte, p *bn254.G2Affine) int {
	// EIP-197 format: x_im[32] || x_re[32] || y_im[32] || y_re[32]
	xA1 := p.X.A1.Bytes()
	xA0 := p.X.A0.Bytes()
	yA1 := p.Y.A1.Bytes()
	yA0 := p.Y.A0.Bytes()
	copy(dst[0:32], xA1[:])
	copy(dst[32:64], xA0[:])
	copy(dst[64:96], yA1[:])
	copy(dst[96:128], yA0[:])
	return 128
}

func TestGroth16VerifyInvalidInputLength(t *testing.T) {
	c := &groth16Verify{}

	tests := []struct {
		name  string
		input []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte{0, 0, 0, 0}},
		{"wrong length for 0 inputs", make([]byte, 100)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := c.Run(tt.input)
			if err == nil {
				t.Fatal("expected error for invalid input length")
			}
		})
	}
}

func TestGroth16VerifyTooManyInputs(t *testing.T) {
	c := &groth16Verify{}
	input := make([]byte, 4)
	binary.BigEndian.PutUint32(input, 257) // > 256
	_, err := c.Run(input)
	if err != errGroth16TooManyInputs {
		t.Fatalf("expected errGroth16TooManyInputs, got %v", err)
	}
}

func TestGroth16VerifyRequiredGas(t *testing.T) {
	c := &groth16Verify{}

	tests := []struct {
		name     string
		nInputs  uint32
		expected uint64
	}{
		{"0 inputs", 0, 45000},
		{"1 input", 1, 46000},
		{"10 inputs", 10, 55000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := make([]byte, 4)
			binary.BigEndian.PutUint32(input, tt.nInputs)
			gas := c.RequiredGas(input)
			if gas != tt.expected {
				t.Fatalf("gas mismatch: got %d, expected %d", gas, tt.expected)
			}
		})
	}
}

func TestGroth16VerifyRequiredGasShortInput(t *testing.T) {
	c := &groth16Verify{}
	gas := c.RequiredGas([]byte{})
	if gas != 45000 {
		t.Fatalf("expected base gas 45000 for empty input, got %d", gas)
	}
}

func TestGroth16VerifyInvalidG1Point(t *testing.T) {
	c := &groth16Verify{}

	// Build input with 0 public inputs but with an invalid G1 point for proof.A
	size := groth16FixedInputSize + 1*g1Size // n=0, IC has 1 point
	input := make([]byte, size)
	binary.BigEndian.PutUint32(input[0:4], 0)

	// Set proof.A x-coordinate to 1, y to 1 — not a valid BN254 point
	input[35] = 1 // x = 1
	input[67] = 1 // y = 1

	_, err := c.Run(input)
	if err == nil {
		t.Fatal("expected error for invalid G1 point")
	}
}

// TestGroth16VerifyValidProof tests with a real Groth16 proof constructed
// by setting up a trivial verification equation.
// We construct points such that e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) = 1.
func TestGroth16VerifyValidProof(t *testing.T) {
	// Use generator points G1 and G2
	_, _, g1Gen, g2Gen := bn254.Generators()

	// For a trivial verification with 0 public inputs:
	// vk_x = IC[0]
	// We need: e(-A, B) · e(α, β) · e(IC[0], γ) · e(C, δ) = 1
	//
	// Strategy: set A=G1, B=G2, α=G1, β=G2, IC[0]=G1, γ=G2, C=G1, δ=G2
	// Then: e(-G1, G2) · e(G1, G2) · e(G1, G2) · e(G1, G2) = 1
	// => e(G1,G2)^(-1) · e(G1,G2)^1 · e(G1,G2)^1 · e(G1,G2)^1 = e(G1,G2)^2 ≠ 1
	//
	// Instead, use: A=G1, B=G2, and set everything else to identity (0).
	// e(-G1, G2) · e(0, β) · e(0, γ) · e(0, δ) = e(-G1, G2)
	// That doesn't work either because e(-G1,G2) ≠ 1.
	//
	// Correct approach: set α=A, β=B, and C=0, IC[0]=0
	// e(-A, B) · e(A, B) · e(0, γ) · e(0, δ) = e(-A,B) · e(A,B) = 1 ✓

	proofA := g1Gen
	proofB := g2Gen
	vkAlpha := g1Gen
	vkBeta := g2Gen
	vkGamma := g2Gen
	vkDelta := g2Gen

	var zeroG1 bn254.G1Affine // point at infinity
	proofC := zeroG1
	ic := []bn254.G1Affine{zeroG1} // IC[0] = 0

	input := buildGroth16Input(
		0, // no public inputs
		&proofA, &proofC, &proofB,
		&vkAlpha, &vkBeta, &vkGamma, &vkDelta,
		ic, nil,
	)

	c := &groth16Verify{}
	result, err := c.Run(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(result, true32Byte) {
		t.Fatal("expected valid proof (true), got false")
	}
}

// TestGroth16VerifyInvalidProof tests that an incorrect proof returns false.
func TestGroth16VerifyInvalidProof(t *testing.T) {
	_, _, g1Gen, g2Gen := bn254.Generators()

	// All non-zero generators — the pairing equation won't hold
	proofA := g1Gen
	proofB := g2Gen
	proofC := g1Gen

	// Use a different point for alpha so α ≠ A
	var vkAlpha bn254.G1Affine
	vkAlpha.ScalarMultiplication(&g1Gen, big.NewInt(2))

	vkBeta := g2Gen
	vkGamma := g2Gen
	vkDelta := g2Gen
	ic := []bn254.G1Affine{g1Gen}

	input := buildGroth16Input(
		0,
		&proofA, &proofC, &proofB,
		&vkAlpha, &vkBeta, &vkGamma, &vkDelta,
		ic, nil,
	)

	c := &groth16Verify{}
	result, err := c.Run(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(result, false32Byte) {
		t.Fatal("expected invalid proof (false), got true")
	}
}

// TestGroth16VerifyWithPublicInputs tests verification with public inputs.
func TestGroth16VerifyWithPublicInputs(t *testing.T) {
	_, _, g1Gen, g2Gen := bn254.Generators()

	// For 1 public input with value s:
	// vk_x = IC[0] + s * IC[1]
	// We need: e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) = 1
	//
	// Set C=0, IC[0]=0, IC[1]=0 → vk_x=0
	// Then: e(-A, B) · e(α, β) = 1 → α=A, β=B

	proofA := g1Gen
	proofB := g2Gen
	vkAlpha := g1Gen
	vkBeta := g2Gen
	vkGamma := g2Gen
	vkDelta := g2Gen

	var zeroG1 bn254.G1Affine
	proofC := zeroG1
	ic := []bn254.G1Affine{zeroG1, zeroG1} // IC[0]=0, IC[1]=0

	s := big.NewInt(42)
	input := buildGroth16Input(
		1,
		&proofA, &proofC, &proofB,
		&vkAlpha, &vkBeta, &vkGamma, &vkDelta,
		ic, []*big.Int{s},
	)

	c := &groth16Verify{}
	result, err := c.Run(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(result, true32Byte) {
		t.Fatal("expected valid proof (true), got false")
	}
}

func TestGroth16VerifyScalarOutOfRange(t *testing.T) {
	c := &groth16Verify{}

	_, _, g1Gen, g2Gen := bn254.Generators()
	var zeroG1 bn254.G1Affine

	// Build valid structure with 1 public input
	ic := []bn254.G1Affine{zeroG1, zeroG1}
	input := buildGroth16Input(
		1,
		&g1Gen, &zeroG1, &g2Gen,
		&g1Gen, &g2Gen, &g2Gen, &g2Gen,
		ic, []*big.Int{big.NewInt(0)},
	)

	// Overwrite the public input with a value >= fr.Modulus
	modulus := fr.Modulus()
	mBytes := modulus.Bytes()
	// Public input starts after fixed header + IC points
	// groth16FixedInputSize already includes the 4-byte numInputs header
	inputOffset := groth16FixedInputSize + 2*g1Size // IC has 2 points (n+1=2)
	copy(input[inputOffset:inputOffset+32], mBytes)

	_, err := c.Run(input)
	if err != errGroth16InvalidScalar {
		t.Fatalf("expected errGroth16InvalidScalar, got %v", err)
	}
}

func BenchmarkGroth16Verify(b *testing.B) {
	_, _, g1Gen, g2Gen := bn254.Generators()

	var zeroG1 bn254.G1Affine
	input := buildGroth16Input(
		0,
		&g1Gen, &zeroG1, &g2Gen,
		&g1Gen, &g2Gen, &g2Gen, &g2Gen,
		[]bn254.G1Affine{zeroG1}, nil,
	)

	c := &groth16Verify{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Run(input)
	}
}

func BenchmarkGroth16VerifyWithInputs(b *testing.B) {
	_, _, g1Gen, g2Gen := bn254.Generators()

	for _, n := range []int{1, 5, 10, 20} {
		b.Run(
			func() string { return "inputs_" + string(rune('0'+n/10)) + string(rune('0'+n%10)) }(),
			func(b *testing.B) {
				var zeroG1 bn254.G1Affine
				ic := make([]bn254.G1Affine, n+1)
				publicInputs := make([]*big.Int, n)
				for i := range publicInputs {
					publicInputs[i] = big.NewInt(int64(i + 1))
				}
				input := buildGroth16Input(
					n,
					&g1Gen, &zeroG1, &g2Gen,
					&g1Gen, &g2Gen, &g2Gen, &g2Gen,
					ic, publicInputs,
				)
				c := &groth16Verify{}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					c.Run(input)
				}
			},
		)
	}
}
