//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package equihash

import "testing"

func TestSolveAndVerify(t *testing.T) {
	n, k := uint32(60), uint32(4)
	seed := make([]byte, 16) // zero seed

	proof, err := Solve(n, k, seed)
	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}
	if proof.N != n || proof.K != k {
		t.Errorf("proof params mismatch: got N=%d K=%d, want N=%d K=%d", proof.N, proof.K, n, k)
	}
	expectedInputs := 1 << k
	if len(proof.Inputs) != expectedInputs {
		t.Errorf("expected %d inputs, got %d", expectedInputs, len(proof.Inputs))
	}

	if !Verify(n, k, seed, proof.Nonce, proof.Inputs) {
		t.Error("valid proof failed verification")
	}

	if !VerifyProof(proof) {
		t.Error("VerifyProof failed for valid proof")
	}
}

func TestVerifyTamperedInputs(t *testing.T) {
	n, k := uint32(60), uint32(4)
	seed := make([]byte, 16)

	proof, err := Solve(n, k, seed)
	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	// Tamper with inputs
	badInputs := make([]uint32, len(proof.Inputs))
	copy(badInputs, proof.Inputs)
	badInputs[0] ^= 1

	if Verify(n, k, seed, proof.Nonce, badInputs) {
		t.Error("tampered proof should fail verification")
	}
}

func TestVerifyInvalidSeed(t *testing.T) {
	if Verify(60, 4, []byte{1, 2, 3}, 0, []uint32{1}) {
		t.Error("expected false for invalid seed length")
	}
}

func TestVerifyNilProof(t *testing.T) {
	if VerifyProof(nil) {
		t.Error("expected false for nil proof")
	}
}

func TestSolveInvalidParams(t *testing.T) {
	seed := make([]byte, 16)

	if _, err := Solve(0, 4, seed); err != ErrInvalidParams {
		t.Errorf("expected ErrInvalidParams for n=0, got %v", err)
	}

	if _, err := Solve(60, 4, []byte{1, 2, 3}); err != ErrInvalidSeedLen {
		t.Errorf("expected ErrInvalidSeedLen, got %v", err)
	}
}

func BenchmarkSolve(b *testing.B) {
	seed := make([]byte, 16)
	for i := 0; i < b.N; i++ {
		Solve(60, 4, seed)
	}
}

func BenchmarkVerify(b *testing.B) {
	seed := make([]byte, 16)
	proof, err := Solve(60, 4, seed)
	if err != nil {
		b.Fatalf("Solve failed: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(60, 4, seed, proof.Nonce, proof.Inputs)
	}
}
