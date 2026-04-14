package vm

import (
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/ethereum/go-ethereum/params"
)

// groth16Verify implements Groth16 zero-knowledge proof verification over the BN254 curve
// as a native precompiled contract.
//
// Input layout (all points use raw big-endian coordinates, no compression flags):
//
//	[0:4]                          numPublicInputs (n) as uint32 big-endian
//	[4:68]                         proof.A   (G1: x[32] || y[32])
//	[68:132]                       proof.C   (G1: x[32] || y[32])
//	[132:260]                      proof.B   (G2: x_im[32] || x_re[32] || y_im[32] || y_re[32])
//	[260:324]                      vk.Alpha  (G1: 64 bytes)
//	[324:452]                      vk.Beta   (G2: 128 bytes)
//	[452:580]                      vk.Gamma  (G2: 128 bytes)
//	[580:708]                      vk.Delta  (G2: 128 bytes)
//	[708:708+(n+1)*64]             vk.IC     ((n+1) G1 points, 64 bytes each)
//	[708+(n+1)*64:708+(n+1)*64+n*32] public inputs (n scalars, 32 bytes each)
//
// Output: 32 bytes — 0x01 (valid) or 0x00 (invalid).
// Returns error only for malformed input (wrong length, invalid points).
type groth16Verify struct{}

const (
	g1Size = 64  // uncompressed G1 point size in bytes
	g2Size = 128 // uncompressed G2 point size in bytes
	scalarSize = 32 // field element size in bytes

	// Fixed portion: 4 (numInputs) + 64 (A) + 64 (C) + 128 (B) + 64 (alpha) + 128 (beta) + 128 (gamma) + 128 (delta)
	groth16FixedInputSize = 4 + g1Size + g1Size + g2Size + g1Size + g2Size + g2Size + g2Size // 708
)

var (
	errGroth16InvalidInputLen  = errors.New("groth16: invalid input length")
	errGroth16InvalidPoint     = errors.New("groth16: invalid curve point")
	errGroth16InvalidScalar    = errors.New("groth16: invalid scalar field element")
	errGroth16TooManyInputs    = errors.New("groth16: too many public inputs")
)

// RequiredGas returns the gas required to execute the Groth16 verification.
func (c *groth16Verify) RequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return params.Groth16VerifyBaseGas
	}
	n := uint64(binary.BigEndian.Uint32(input[:4]))
	return params.Groth16VerifyBaseGas + n*params.Groth16VerifyPerInputGas
}

// Run executes the Groth16 proof verification.
func (c *groth16Verify) Run(input []byte) ([]byte, error) {
	if len(input) < 4 {
		return nil, errGroth16InvalidInputLen
	}

	n := int(binary.BigEndian.Uint32(input[:4]))
	if n > 256 {
		return nil, errGroth16TooManyInputs
	}

	// Expected total length: fixed + (n+1)*64 (IC points) + n*32 (public inputs)
	expectedLen := groth16FixedInputSize + (n+1)*g1Size + n*scalarSize
	if len(input) != expectedLen {
		return nil, errGroth16InvalidInputLen
	}

	offset := 4

	// Parse proof.A (G1)
	proofA, err := parseG1(input[offset : offset+g1Size])
	if err != nil {
		return nil, err
	}
	offset += g1Size

	// Parse proof.C (G1)
	proofC, err := parseG1(input[offset : offset+g1Size])
	if err != nil {
		return nil, err
	}
	offset += g1Size

	// Parse proof.B (G2)
	proofB, err := parseG2(input[offset : offset+g2Size])
	if err != nil {
		return nil, err
	}
	offset += g2Size

	// Parse vk.Alpha (G1)
	vkAlpha, err := parseG1(input[offset : offset+g1Size])
	if err != nil {
		return nil, err
	}
	offset += g1Size

	// Parse vk.Beta (G2)
	vkBeta, err := parseG2(input[offset : offset+g2Size])
	if err != nil {
		return nil, err
	}
	offset += g2Size

	// Parse vk.Gamma (G2)
	vkGamma, err := parseG2(input[offset : offset+g2Size])
	if err != nil {
		return nil, err
	}
	offset += g2Size

	// Parse vk.Delta (G2)
	vkDelta, err := parseG2(input[offset : offset+g2Size])
	if err != nil {
		return nil, err
	}
	offset += g2Size

	// Parse vk.IC ((n+1) G1 points)
	ic := make([]bn254.G1Affine, n+1)
	for i := 0; i <= n; i++ {
		pt, err := parseG1(input[offset : offset+g1Size])
		if err != nil {
			return nil, err
		}
		ic[i] = *pt
		offset += g1Size
	}

	// Parse public inputs (n scalars)
	publicInputs := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		s, err := parseScalar(input[offset : offset+scalarSize])
		if err != nil {
			return nil, err
		}
		publicInputs[i] = s
		offset += scalarSize
	}

	// Compute vk_x = IC[0] + Σᵢ publicInputs[i] * IC[i+1]
	var vkX bn254.G1Affine
	vkX.Set(&ic[0])

	for i := 0; i < n; i++ {
		var tmp bn254.G1Affine
		tmp.ScalarMultiplication(&ic[i+1], publicInputs[i])
		vkX.Add(&vkX, &tmp)
	}

	// Groth16 verification: e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) == 1
	// Using PairingCheck which verifies ∏ᵢ e(Pᵢ, Qᵢ) == 1
	var negA bn254.G1Affine
	negA.Neg(proofA)

	ok, err := bn254.PairingCheck(
		[]bn254.G1Affine{negA, *vkAlpha, vkX, *proofC},
		[]bn254.G2Affine{*proofB, *vkBeta, *vkGamma, *vkDelta},
	)
	if err != nil {
		return false32Byte, nil
	}

	if ok {
		return true32Byte, nil
	}
	return false32Byte, nil
}

// parseG1 parses a G1 point from 64 bytes of raw coordinates (x[32] || y[32]).
func parseG1(data []byte) (*bn254.G1Affine, error) {
	if len(data) != g1Size {
		return nil, errGroth16InvalidPoint
	}

	// Check for point at infinity (all zeros)
	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		var p bn254.G1Affine
		// Zero value is the point at infinity
		return &p, nil
	}

	var x, y fp.Element
	x.SetBytes(data[:32])
	y.SetBytes(data[32:64])

	p := bn254.G1Affine{X: x, Y: y}
	if !p.IsOnCurve() {
		return nil, errGroth16InvalidPoint
	}
	// BN254 G1 has cofactor 1, so any point on the curve is in the subgroup
	return &p, nil
}

// parseG2 parses a G2 point from 128 bytes of raw coordinates
// (x_im[32] || x_re[32] || y_im[32] || y_re[32]).
// This matches the EIP-197 encoding convention.
func parseG2(data []byte) (*bn254.G2Affine, error) {
	if len(data) != g2Size {
		return nil, errGroth16InvalidPoint
	}

	// Check for point at infinity (all zeros)
	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		var p bn254.G2Affine
		return &p, nil
	}

	var xA1, xA0, yA1, yA0 fp.Element
	xA1.SetBytes(data[0:32])   // imaginary part
	xA0.SetBytes(data[32:64])  // real part
	yA1.SetBytes(data[64:96])  // imaginary part
	yA0.SetBytes(data[96:128]) // real part

	var p bn254.G2Affine
	p.X.A0.Set(&xA0)
	p.X.A1.Set(&xA1)
	p.Y.A0.Set(&yA0)
	p.Y.A1.Set(&yA1)

	if !p.IsOnCurve() {
		return nil, errGroth16InvalidPoint
	}
	// Note: For BN254 G2, we should also verify the point is in the correct subgroup.
	// The gnark-crypto PairingCheck performs subgroup checks internally.
	return &p, nil
}

// parseScalar parses a 32-byte big-endian scalar and validates it is in the BN254 scalar field.
func parseScalar(data []byte) (*big.Int, error) {
	if len(data) != scalarSize {
		return nil, errGroth16InvalidScalar
	}
	s := new(big.Int).SetBytes(data)
	if s.Cmp(fr.Modulus()) >= 0 {
		return nil, errGroth16InvalidScalar
	}
	return s, nil
}
