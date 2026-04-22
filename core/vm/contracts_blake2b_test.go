package vm

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/ethereum/go-ethereum/crypto/blake2b"
)

// buildInput builds the precompile input: [personal(16)][data].
func buildInput(personal []byte, data []byte) []byte {
	p := make([]byte, 16)
	copy(p, personal)
	in := make([]byte, 0, 16+len(data))
	in = append(in, p...)
	in = append(in, data...)
	return in
}

// TestBlake2bHashEmptyPersonalMatchesStandard verifies that with a zero
// personalization the precompile produces the same output as plain BLAKE2b-256.
func TestBlake2bHashEmptyPersonalMatchesStandard(t *testing.T) {
	c := &blake2bPersonalHash{}

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"hello", []byte("hello")},
		{"short", []byte{0x01, 0x02, 0x03}},
		{"32 bytes", make([]byte, 32)},
		{"block size", make([]byte, 128)},
		{"long", make([]byte, 1024)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.Run(buildInput(nil, tt.data))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != 32 {
				t.Fatalf("expected 32 bytes, got %d", len(got))
			}
			expected := blake2b.Sum256(tt.data)
			if !bytes.Equal(got, expected[:]) {
				t.Fatalf("mismatch:\n  got:    %x\n  expect: %x", got, expected)
			}
		})
	}
}

// TestBlake2bHashPersonalizationChangesOutput ensures personalization is
// actually mixed into the state.
func TestBlake2bHashPersonalizationChangesOutput(t *testing.T) {
	c := &blake2bPersonalHash{}
	data := []byte("zcash equihash test")

	p1 := make([]byte, 16)
	copy(p1, "ZcashPoW")
	binary.LittleEndian.PutUint32(p1[8:], 200)
	binary.LittleEndian.PutUint32(p1[12:], 9)

	p2 := make([]byte, 16)
	copy(p2, "ZcashPoW")
	binary.LittleEndian.PutUint32(p2[8:], 96)
	binary.LittleEndian.PutUint32(p2[12:], 5)

	out1, err := c.Run(buildInput(p1, data))
	if err != nil {
		t.Fatalf("run p1: %v", err)
	}
	out2, err := c.Run(buildInput(p2, data))
	if err != nil {
		t.Fatalf("run p2: %v", err)
	}
	if bytes.Equal(out1, out2) {
		t.Fatal("different personalizations produced identical digests")
	}
}

// TestBlake2bHashZcashVector checks against a known Zcash personalization
// vector: personal = "ZTxIdSaplingHash" (16 bytes), data = empty.
//
// Reference digest can be regenerated with any standard BLAKE2b implementation
// configured with digest_length=32 and personal="ZTxIdSaplingHash", e.g.:
//
//	b2sum -l 256 --personal=5a54784964536170 6c696e67486173 68 /dev/null
//
// (used by Zcash for ZIP-244 transaction-id hashing).
func TestBlake2bHashZcashVector(t *testing.T) {
	c := &blake2bPersonalHash{}
	in := buildInput([]byte("ZTxIdSaplingHash"), nil)

	got, err := c.Run(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []byte{
		0x6f, 0x2f, 0xc8, 0xf9, 0x8f, 0xea, 0xfd, 0x94,
		0xe7, 0x4a, 0x0d, 0xf4, 0xbe, 0xd7, 0x43, 0x91,
		0xee, 0x0b, 0x5a, 0x69, 0x94, 0x5e, 0x4c, 0xed,
		0x8c, 0xa8, 0xa0, 0x95, 0x20, 0x6f, 0x00, 0xae,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("mismatch:\n  got:    %x\n  expect: %x", got, want)
	}
}

func TestBlake2bHashInvalidInput(t *testing.T) {
	c := &blake2bPersonalHash{}

	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{"nil", nil, true},
		{"zero length", []byte{}, true},
		{"one short of personal", make([]byte, 15), true},
		{"personal only, empty data", make([]byte, 16), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := c.Run(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestBlake2bHashRequiredGas(t *testing.T) {
	c := &blake2bPersonalHash{}

	tests := []struct {
		name        string
		inputLen    int
		expectedGas uint64
	}{
		{"empty", 0, 12},
		{"1 byte", 1, 15},
		{"32 bytes", 32, 15},
		{"33 bytes", 33, 18},
		{"64 bytes", 64, 18},
		{"128 bytes", 128, 24},
		{"1024 bytes", 1024, 108},
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
	c := &blake2bPersonalHash{}
	in := buildInput([]byte("ZcashPoW"), []byte("deterministic test"))

	a, _ := c.Run(in)
	b, _ := c.Run(in)
	if !bytes.Equal(a, b) {
		t.Fatal("blake2b hash is not deterministic")
	}
}

func BenchmarkBlake2bHash(b *testing.B) {
	c := &blake2bPersonalHash{}
	input := buildInput([]byte("ZcashPoW"), make([]byte, 128))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Run(input)
	}
}
