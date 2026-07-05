// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build fastverify

package schnorr

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/internal/fastverify"
	"github.com/btcsuite/btcd/chainhash/v2"
)

// verifySchnorr is the fastverify engine backend for Signature.Verify. It
// computes the BIP340 challenge and hands the algebra to the engine.
func verifySchnorr(sig *Signature, hash []byte, pubKey *btcec.PublicKey) bool {
	// BIP340 verification fails for any message that is not 32 bytes.
	if len(hash) != scalarSize {
		return false
	}

	var rBytes [32]byte
	sig.r.PutBytesUnchecked(rBytes[:])
	pBytes := SerializePubKey(pubKey)

	commitment := chainhash.TaggedHash(
		chainhash.TagBIP0340Challenge, rBytes[:], pBytes, hash,
	)
	var e btcec.ModNScalar
	e.SetBytes((*[32]byte)(commitment))

	return fastverify.VerifySchnorr(&rBytes, &sig.s, &e, pubKey)
}
