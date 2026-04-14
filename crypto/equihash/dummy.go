//go:build dummy
// +build dummy

// This file is part of a workaround for `go mod vendor` which won't vendor
// C/C++ files if there's no Go file in the same directory.
//
// See this issue for reference: https://github.com/golang/go/issues/26366

package equihash

import (
	_ "github.com/ethereum/go-ethereum/crypto/equihash/libequihash"
	_ "github.com/ethereum/go-ethereum/crypto/equihash/libequihash/blake"
)
