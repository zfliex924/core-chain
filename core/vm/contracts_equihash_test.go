//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package vm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/crypto/equihash"
)

// encodeEquihashInput packs equihash verify parameters into the precompiled contract input format.
func encodeEquihashInput(n, k uint32, seed []byte, nonce uint32, inputs []uint32) []byte {
	buf := make([]byte, 28+len(inputs)*4)
	binary.BigEndian.PutUint32(buf[0:4], n)
	binary.BigEndian.PutUint32(buf[4:8], k)
	copy(buf[8:24], seed)
	binary.BigEndian.PutUint32(buf[24:28], nonce)
	for i, v := range inputs {
		binary.BigEndian.PutUint32(buf[28+i*4:28+(i+1)*4], v)
	}
	return buf
}

func TestEquihashVerify(t *testing.T) {
	n, k := uint32(60), uint32(4)
	seed := make([]byte, 16)

	proof, err := equihash.Solve(n, k, seed)
	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	c := &equihashVerify{}
	input := encodeEquihashInput(n, k, seed, proof.Nonce, proof.Inputs)

	result, err := c.Run(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(result, big1.Bytes()) {
		t.Fatalf("expected valid proof to return 0x01, got %x", result)
	}
}

func TestEquihashVerifyTampered(t *testing.T) {
	n, k := uint32(60), uint32(4)
	seed := make([]byte, 16)

	proof, err := equihash.Solve(n, k, seed)
	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	// Tamper with inputs
	badInputs := make([]uint32, len(proof.Inputs))
	copy(badInputs, proof.Inputs)
	badInputs[0] ^= 1

	c := &equihashVerify{}
	input := encodeEquihashInput(n, k, seed, proof.Nonce, badInputs)

	result, err := c.Run(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected tampered proof to return empty, got %x", result)
	}
}

func TestEquihashVerifyInvalidInput(t *testing.T) {
	c := &equihashVerify{}

	tests := []struct {
		name  string
		input []byte
	}{
		{"too short", make([]byte, 10)},
		{"empty", []byte{}},
		{"header only, n=0", encodeEquihashInput(0, 4, make([]byte, 16), 0, make([]uint32, 16))},
		{"header only, k=0", encodeEquihashInput(60, 0, make([]byte, 16), 0, nil)},
		{"k too large", encodeEquihashInput(60, 21, make([]byte, 16), 0, nil)},
		{"wrong input count", encodeEquihashInput(60, 4, make([]byte, 16), 0, make([]uint32, 8))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := c.Run(tt.input)
			if err != ErrExecutionReverted {
				t.Fatalf("expected ErrExecutionReverted, got %v", err)
			}
		})
	}
}

func TestEquihashVerifyRequiredGas(t *testing.T) {
	c := &equihashVerify{}

	tests := []struct {
		name        string
		inputLen    int
		expectedGas uint64
	}{
		{"empty", 0, 2000},
		{"header only", 28, 2000},
		{"with 16 inputs", 28 + 16*4, 2000 + 16*10},
		{"with 512 inputs", 28 + 512*4, 2000 + 512*10},
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

// TestEquihashVerifyZcashBlock verifies a real Zcash testnet block header
// (Equihash 200/9) using the Zcash-mode input format (magic byte 0x5A).
//
// Raw block layout (1487 bytes total):
//
//	[140 B] header  = version(4) + prevHash(32) + merkleRoot(32) +
//	                  hashReserved(32) + time(4) + bits(4) + nNonce(32)
//	[ 3 B]  VarInt  = fd 40 05  (→ 1344 bytes of solution follow)
//	[1344 B] solution (512 indices × 21 bits, MSB-first packed)
//
// Precompile input (Zcash mode):
//
//	0x5A | n=200 (4B BE) | k=9 (4B BE) | header (140B) | solution (1344B)
func TestEquihashVerifyZcashBlock(t *testing.T) {
	const rawHex = "04000000231eb0aaa8c654768e6e0b995965e38faec3ea1e15765c084beac9fa1144000093a54847b25fa24cd0a2b7c9ed05cd4e9bef01042c675975b54af9cd834665b92ddb82cbf95fba17f5687d018bef4cadda2688adff69472b946682b4b2389f7ad2f3dd69f590011f0400000099360000000000000000000000000001000000000000000000000000fd4005007a25e17e4615028c7863156b20e55ab3a6962f5718f10bf1a92113697e9f92916944865d267d8c57cf04ead2cd254c96c3738184080e26084188619f8c74064240b09b18d7ab1a40f3bb7c546d7900b8ef09770a3ac138f67117d5d48c25ccfd4b083aba737ba5281391fdd7420e1ccfb09372f9dfe5c565603ef426f7124d75aa15cb52df27b873dc23cac23e9d61366ef6306c653122ea22cfaf8585432cf3eb75edce9a3b0102f3515387972afb9aff01f53f19437e5f54fe35d60587057b93d87fc90a25a35cdf2183b0ed263cf1e503e1bcfae20b6460d69a01ad3779ce0d95ad7a7e1007124a915bd0b81b43ebf1666b48880487bf47ea34072367f7838e232f8fc590b4c7c9c8116d174f146513d9c8af862818f76b778197dcc00369e0f27c56ed0e60813903170629b920b41b3cfc3371e40a53bfb030c72d53cb506bac9100844c0663cdfdd7357d487b04ae5cd0998b205868ae93dd004eec5d7b5f5d975205a45e9941c1b578e00a413cfbba0e855e4b974d4c08f764c4f1a36f89953e50be30fc9704aaea0ab41420852eeef28ec040b748b6c5e54a4e09b45430f34a053b35025aa7fbab4fd8bc71c8767a8f552d3efcb3254adde2405593e9f7f837b0dbd9bf82955297dad71705c15cc0911c96d41d2b4d72eb3a46e295ddc5fb1e5cb27c88953c91e6e6469d2fdd127f26cfd9b3e407ca81476c4f67376ffb75613ce2eecb5b7f9bf89119646c840de2985344b0c1b59d3cdaf2023bd23264133a0f8ba5e2f679cc9467a339f87a53422d7fee1f40147be5d5e5b79fbd9a1477d56cfac1f14734564922395f387ad4d533c0c9831e469b3f8fad56fe13062a7ec9aa664bf365000912f108519e38c8753d2d25280c4efc70774621f2180390ce4921b1a805dc732542c8232bcb5aef0f466cda189dff77cf91837d898501066012af8b87ed21c5d1dc3eeecad76ac65bc5d10d8e644edf0ada578c46b74609586bf6c4fb787a4315885338b4885efbdd6ec517c5398d0b32977aaea12fc9eac1ccd40a4fd2c0f791d954537b0dacff5f970bbe8e4a6f990921f82f0387de766c44e473530c471104fe451e349cb7ae3ab203a44c896cce7cb0f67b12777314230e74271db12853eb5967823f2a55f5b11a327655e969e6b99371f96c58e9a002b92b59f52003c898e47dad3081a10937d5ad6b73b6e6b99af6643341850d44dae49b9128255f6deff6a6ce85bab9093db2ab749ae9acf3e028d58e19f5dd5a0c0e91dd0e4c78160406236c73b6e5f612074fd7fde65f7f775b16550f3b08b41e0db9e669f401eb0c7b59715b8a021c9aec88b75f1fd53bb2c3eef2a213252afc940fd44348ffaaac9a345336470765467cc7a24370bbdb4887bc072454ae53a78102a99aa2fd58cf1ad879121602f5e8254348ebcca9e243787079a946970915868e0462c8ae1b6a72bdff7170de9dcc444469678e7e031520d9fc01ce86caa56371cc15515c96b3b09eee4032a0df1bff281b39fa4134863831c4556e2ef2ddc3033cb82d3a850cb3bd784535912dc5d97bbe6eb401271b641831617935aaa7268509d68101bf81ba5f200a1f08aabde26023cceed678906a0e271a647bf3962305e31bdba5ec35fa1092bbf0b24ba699b8f897c4030c67b77502899966ee02087ea4b65b38c4dd50b105eb4c51a590b897a9336355fd78906e3dd73b340f0fabc9fa9f4db446d4e0e357387faeeea7f4367e871ad81a4867f9a789fe2f02a48861669a175c7c847116fc37d93c525b9f5f19f29988cc7e79433f3f36319851bcf4b866b5b5995c69acf871bc4ee4d5b9efdc18c8b157781c604da1d8c467d9aed239322d2cbd6320627f5bfd608cebdd4472ce00980894e0c05988ad"

	raw, err := hex.DecodeString(rawHex)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	// Zcash block: 140-byte header + 3-byte VarInt (fd 40 05) + 1344-byte solution
	const (
		headerLen   = 140
		varintLen   = 3    // fd 40 05  → 1344 bytes
		solutionLen = 1344 // 512 indices × 21 bits / 8
		n           = uint32(200)
		k           = uint32(9)
	)
	if len(raw) != headerLen+varintLen+solutionLen {
		t.Fatalf("unexpected raw length %d (want %d)", len(raw), headerLen+varintLen+solutionLen)
	}

	header := raw[:headerLen]
	solution := raw[headerLen+varintLen:] // skip the 3-byte VarInt

	// Build precompile input: [0x5A][n BE][k BE][header][solution]
	precompileInput := make([]byte, 1+4+4+headerLen+solutionLen)
	precompileInput[0] = 0x5A
	binary.BigEndian.PutUint32(precompileInput[1:5], n)
	binary.BigEndian.PutUint32(precompileInput[5:9], k)
	copy(precompileInput[9:9+headerLen], header)
	copy(precompileInput[9+headerLen:], solution)

	c := &equihashVerify{}
	result, err := c.Run(precompileInput)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(result, big1.Bytes()) {
		t.Fatalf("expected valid Zcash proof to return 0x01, got %x", result)
	}
}

func BenchmarkEquihashVerify(b *testing.B) {
	n, k := uint32(60), uint32(4)
	seed := make([]byte, 16)

	proof, err := equihash.Solve(n, k, seed)
	if err != nil {
		b.Fatalf("Solve failed: %v", err)
	}

	c := &equihashVerify{}
	input := encodeEquihashInput(n, k, seed, proof.Nonce, proof.Inputs)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Run(input)
	}
}
