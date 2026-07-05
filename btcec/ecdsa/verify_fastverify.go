// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build fastverify

package ecdsa

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/internal/fastverify"
)

// Verify returns whether or not the signature is valid for the provided hash
// and secp256k1 public key. It is the package level entry point for
// signature verification, allowing the verification backend to be selected
// at build time. This build uses the fastverify engine.
func Verify(sig *Signature, hash []byte, pubKey *btcec.PublicKey) bool {
	r, s := sig.R(), sig.S()
	return fastverify.VerifyECDSA(&r, &s, hash, pubKey)
}
