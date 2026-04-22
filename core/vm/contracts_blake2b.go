package vm

import (
	"encoding/binary"
	"errors"

	"github.com/ethereum/go-ethereum/crypto/blake2b"
	"github.com/ethereum/go-ethereum/params"
)

// blake2bPersonalHash implements a personalized BLAKE2b-256 hash as a native
// precompiled contract, matching the variant used by Zcash's Equihash
// (parameter block personalization = "ZcashPoW" || LE32(n) || LE32(k)).
//
// Input layout:
//
//	[16 bytes] personalization
//	[rest]     message
//
// Output: 32 bytes.
type blake2bPersonalHash struct{}

// blake2bIV is the BLAKE2b initialization vector.
var blake2bIV = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

const (
	blake2bBlockSize   = 128
	blake2bOutLen      = 32
	blake2bPersonalLen = 16
)

var errBlake2bInputTooShort = errors.New("blake2b: input must be at least 16 bytes for personalization")

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *blake2bPersonalHash) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+31)/32*params.Blake2bPerWordGas + params.Blake2bBaseGas
}

// Run executes the personalized BLAKE2b-256 hash.
func (c *blake2bPersonalHash) Run(input []byte) ([]byte, error) {
	if len(input) < blake2bPersonalLen {
		return nil, errBlake2bInputTooShort
	}
	personal := input[:blake2bPersonalLen]
	data := input[blake2bPersonalLen:]

	// Initial state: h[i] = IV[i] XOR param_block[i].
	// Parameter block (sequential mode, no key, no salt):
	//   byte 0: digest_length (32), byte 1: key_length (0),
	//   byte 2: fanout (1),          byte 3: depth (1), bytes 4..7: leaf_length (0)
	//   bytes 8..31: node_offset/node_depth/inner_length/reserved (all 0)
	//   bytes 32..47: salt (0)
	//   bytes 48..63: personal
	h := blake2bIV
	h[0] ^= uint64(blake2bOutLen) | (1 << 16) | (1 << 24)
	h[6] ^= binary.LittleEndian.Uint64(personal[0:8])
	h[7] ^= binary.LittleEndian.Uint64(personal[8:16])

	var (
		block [16]uint64
		t     uint64
	)

	// Absorb every full block except the final one (which must be flagged as last).
	for len(data) > blake2bBlockSize {
		for i := 0; i < 16; i++ {
			block[i] = binary.LittleEndian.Uint64(data[i*8:])
		}
		t += blake2bBlockSize
		blake2b.F(&h, block, [2]uint64{t, 0}, false, 12)
		data = data[blake2bBlockSize:]
	}

	// Final block: zero-pad to blockSize, counter counts only real input bytes.
	// buf is fresh-zero on each call, so copy is sufficient — no explicit clear needed.
	var buf [blake2bBlockSize]byte
	copy(buf[:], data)
	for i := 0; i < 16; i++ {
		block[i] = binary.LittleEndian.Uint64(buf[i*8:])
	}
	t += uint64(len(data))
	blake2b.F(&h, block, [2]uint64{t, 0}, true, 12)

	out := make([]byte, blake2bOutLen)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(out[i*8:], h[i])
	}
	return out, nil
}
