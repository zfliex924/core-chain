//go:build gofuzz || !cgo
// +build gofuzz !cgo

package equihash

import "errors"

const SeedLength = 4

var (
	ErrInvalidSeedLen = errors.New("equihash: seed must be 16 bytes (4 x uint32)")
	ErrInvalidParams  = errors.New("equihash: invalid parameters")
	ErrSolveFailed    = errors.New("equihash: not available without cgo")
)

type Proof struct {
	N      uint32
	K      uint32
	Seed   []byte
	Nonce  uint32
	Inputs []uint32
}

func Solve(n, k uint32, seed []byte) (*Proof, error) {
	return nil, ErrSolveFailed
}

func Verify(n, k uint32, seed []byte, nonce uint32, inputs []uint32) bool {
	return false
}

func VerifyProof(p *Proof) bool {
	return false
}
