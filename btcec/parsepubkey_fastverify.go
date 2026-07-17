// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build !nofastverify && (fastverify || (amd64 && !purego))

package btcec

import (
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/btcsuite/btcd/btcec/v2/internal/fastverify"
)

// ParsePubKey parses a public key for a koblitz curve from a bytestring into a
// ecdsa.Publickey, verifying that it is valid. It supports compressed,
// uncompressed and hybrid signature formats.
func ParsePubKey(pubKeyStr []byte) (*PublicKey, error) {
	point, ok := fastverify.DecodePubKey(pubKeyStr)
	if !ok {
		// Preserve the established error kinds and descriptions.
		return secp.ParsePubKey(pubKeyStr)
	}

	var x, y FieldVal
	x.SetByteSlice(point.X[:])
	y.SetByteSlice(point.Y[:])
	return NewPublicKey(&x, &y), nil
}
