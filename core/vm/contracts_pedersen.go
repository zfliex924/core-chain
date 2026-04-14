package vm

import (
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/ethereum/go-ethereum/params"
)

// pedersenHash implements Pedersen hash over bn254's twisted Edwards curve as a native precompiled contract.
// Input is split into 31-byte chunks, each mapped to a scalar multiplication on a unique generator point,
// and the results are summed. The output is the 32-byte x-coordinate of the resulting curve point.
type pedersenHash struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *pedersenHash) RequiredGas(input []byte) uint64 {
	nChunks := uint64(len(input)+30) / 31
	if nChunks == 0 {
		nChunks = 1
	}
	return nChunks*params.PedersenPerChunkGas + params.PedersenBaseGas
}

// generators are deterministically derived base points for the Pedersen hash.
// Each generator is created by hashing an index with SHA-256 and mapping the
// result to a valid twisted Edwards curve point.
var generators []twistededwards.PointAffine

const maxGenerators = 256

func init() {
	curve := twistededwards.GetEdwardsCurve()
	generators = make([]twistededwards.PointAffine, maxGenerators)
	for i := 0; i < maxGenerators; i++ {
		generators[i] = deriveGenerator(curve, i)
	}
}

// deriveGenerator deterministically derives a curve point from an index
// by repeatedly hashing until a valid point is found.
func deriveGenerator(curve twistededwards.CurveParams, index int) twistededwards.PointAffine {
	// Hash "pedersen_generator_<index>" to get a seed
	prefix := []byte("pedersen_generator")
	buf := make([]byte, len(prefix)+4)
	copy(buf, prefix)
	buf[len(prefix)] = byte(index >> 24)
	buf[len(prefix)+1] = byte(index >> 16)
	buf[len(prefix)+2] = byte(index >> 8)
	buf[len(prefix)+3] = byte(index)

	for nonce := uint32(0); ; nonce++ {
		h := sha256.New()
		h.Write(buf)
		h.Write([]byte{byte(nonce >> 24), byte(nonce >> 16), byte(nonce >> 8), byte(nonce)})
		hash := h.Sum(nil)

		// Try to use hash as the y-coordinate and solve for x
		var y fr.Element
		y.SetBytes(hash)

		// For twisted Edwards curve: a*x^2 + y^2 = 1 + d*x^2*y^2
		// x^2 = (1 - y^2) / (a - d*y^2)
		var y2, num, den, x2 fr.Element
		y2.Mul(&y, &y)

		// num = 1 - y^2
		num.SetOne()
		num.Sub(&num, &y2)

		// den = a - d*y^2
		den.Mul(&curve.D, &y2)
		den.Sub(&curve.A, &den)

		if den.IsZero() {
			continue
		}

		den.Inverse(&den)
		x2.Mul(&num, &den)

		// Check if x^2 is a quadratic residue using Euler's criterion
		x := sqrt(&x2)
		if x == nil {
			continue
		}

		p := twistededwards.NewPointAffine(*x, y)
		if !p.IsOnCurve() || p.IsZero() {
			continue
		}

		// Multiply by cofactor to ensure the point is in the prime-order subgroup
		cofactorBig := new(big.Int)
		curve.Cofactor.BigInt(regular(cofactorBig))
		p.ScalarMultiplication(&p, cofactorBig)

		if p.IsZero() {
			continue
		}

		return p
	}
}

// regular returns a pointer to a regular (non-Montgomery) big.Int.
func regular(z *big.Int) *big.Int {
	return z
}

// sqrt computes the square root of a field element, returning nil if none exists.
func sqrt(a *fr.Element) *fr.Element {
	// For bn254's scalar field, q ≡ 1 (mod 4), use Tonelli-Shanks via big.Int
	var aBig big.Int
	a.BigInt(&aBig)

	q := fr.Modulus()
	result := new(big.Int).ModSqrt(&aBig, q)
	if result == nil {
		return nil
	}

	var x fr.Element
	x.SetBigInt(result)

	// Verify
	var check fr.Element
	check.Mul(&x, &x)
	if check.Equal(a) {
		return &x
	}
	return nil
}

var errPedersenInputTooLarge = errors.New("pedersen hash: input exceeds maximum size")

// Run executes the Pedersen hash on the input data and returns the 32-byte x-coordinate result.
func (c *pedersenHash) Run(input []byte) ([]byte, error) {
	if len(input) == 0 {
		// Hash of empty input: return the identity point's x-coordinate (0)
		return make([]byte, 32), nil
	}

	nChunks := (len(input) + 30) / 31
	if nChunks > maxGenerators {
		return nil, errPedersenInputTooLarge
	}

	var result twistededwards.PointAffine
	// Start with the identity point (0, 1) on twisted Edwards
	var one fr.Element
	one.SetOne()
	result = twistededwards.NewPointAffine(*new(fr.Element), one)

	for i := 0; i < nChunks; i++ {
		start := i * 31
		end := start + 31
		if end > len(input) {
			end = len(input)
		}

		chunk := input[start:end]
		scalar := new(big.Int).SetBytes(chunk)

		var p twistededwards.PointAffine
		p.ScalarMultiplication(&generators[i], scalar)
		result.Add(&result, &p)
	}

	// Return the x-coordinate as 32 bytes
	var xBig big.Int
	result.X.BigInt(&xBig)
	out := make([]byte, 32)
	xBytes := xBig.Bytes()
	copy(out[32-len(xBytes):], xBytes)
	return out, nil
}
