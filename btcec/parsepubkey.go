// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build !fastverify

package btcec

import secp "github.com/decred/dcrd/dcrec/secp256k1/v4"

// ParsePubKey parses a public key for a koblitz curve from a bytestring into a
// ecdsa.Publickey, verifying that it is valid. It supports compressed,
// uncompressed and hybrid signature formats.
func ParsePubKey(pubKeyStr []byte) (*PublicKey, error) {
	return secp.ParsePubKey(pubKeyStr)
}
