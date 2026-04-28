package vm

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"
)

// TestPoseidonT3KnownVectors checks the Poseidon T3 precompile against the canonical
// circomlib test vectors used by MASP. These match poseidon-lite, circomlibjs and
// the iden3 reference implementation.
func TestPoseidonT3KnownVectors(t *testing.T) {
	cases := []struct {
		name     string
		inputs   [2]string // decimal strings
		expected string    // decimal string
	}{
		{
			name:     "poseidon([1, 2])",
			inputs:   [2]string{"1", "2"},
			expected: "7853200120776062878684798364095072458815029376092732009249414926327459813530",
		},
		{
			name:     "poseidon([0, 0])",
			inputs:   [2]string{"0", "0"},
			expected: "14744269619966411208579211824598458697587494354926760081771325075741142829156",
		},
	}

	p := &poseidonT3{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := encodeFieldElements(tc.inputs[:])
			out, err := p.Run(input)
			if err != nil {
				t.Fatalf("poseidonT3 failed: %v", err)
			}
			if len(out) != 32 {
				t.Fatalf("expected 32-byte output, got %d", len(out))
			}
			expected, _ := new(big.Int).SetString(tc.expected, 10)
			got := new(big.Int).SetBytes(out)
			if got.Cmp(expected) != 0 {
				t.Fatalf("poseidon mismatch\n  got:      %s\n  expected: %s",
					got.String(), expected.String())
			}
		})
	}
}

// TestPoseidonT4KnownVectors checks the Poseidon T4 precompile.
func TestPoseidonT4KnownVectors(t *testing.T) {
	cases := []struct {
		name     string
		inputs   [3]string
		expected string
	}{
		{
			name:     "poseidon([1, 2, 3])",
			inputs:   [3]string{"1", "2", "3"},
			expected: "6542985608222806190361240322586112750744169038454362455181422643027100751666",
		},
		{
			name:     "poseidon([0, 0, 0])",
			inputs:   [3]string{"0", "0", "0"},
			expected: "5317387130258456662214331362918410991734007599705406860481038345552731150762",
		},
	}

	p := &poseidonT4{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := encodeFieldElements(tc.inputs[:])
			out, err := p.Run(input)
			if err != nil {
				t.Fatalf("poseidonT4 failed: %v", err)
			}
			expected, _ := new(big.Int).SetString(tc.expected, 10)
			got := new(big.Int).SetBytes(out)
			if got.Cmp(expected) != 0 {
				t.Fatalf("poseidon mismatch\n  got:      %s\n  expected: %s",
					got.String(), expected.String())
			}
		})
	}
}

func TestPoseidonInputValidation(t *testing.T) {
	if _, err := (&poseidonT3{}).Run(make([]byte, 63)); err == nil {
		t.Fatal("poseidonT3 accepted 63-byte input")
	}
	if _, err := (&poseidonT3{}).Run(make([]byte, 65)); err == nil {
		t.Fatal("poseidonT3 accepted 65-byte input")
	}
	if _, err := (&poseidonT4{}).Run(make([]byte, 95)); err == nil {
		t.Fatal("poseidonT4 accepted 95-byte input")
	}

	// Out-of-field scalar must be rejected.
	overField, _ := hex.DecodeString(
		"30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
	)
	if len(overField) == 31 {
		overField = append([]byte{0x00}, overField...)
	}
	input := append(overField, make([]byte, 32)...)
	if _, err := (&poseidonT3{}).Run(input); err == nil {
		t.Fatal("poseidonT3 accepted out-of-field scalar")
	}
}

func TestPoseidonGasCost(t *testing.T) {
	if g := (&poseidonT3{}).RequiredGas(make([]byte, 64)); g != 1500 {
		t.Errorf("poseidonT3 gas: want 1500, got %d", g)
	}
	if g := (&poseidonT4{}).RequiredGas(make([]byte, 96)); g != 2000 {
		t.Errorf("poseidonT4 gas: want 2000, got %d", g)
	}
}

func encodeFieldElements(decStrs []string) []byte {
	buf := bytes.Buffer{}
	for _, s := range decStrs {
		v, _ := new(big.Int).SetString(s, 10)
		b := v.Bytes()
		pad := make([]byte, 32-len(b))
		buf.Write(pad)
		buf.Write(b)
	}
	return buf.Bytes()
}
