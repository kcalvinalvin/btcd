// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ecdsa

import (
	"crypto/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// TestVerifyMatchesSignatureVerify ensures the package level Verify agrees
// with Signature.Verify for valid signatures, corrupted digests, wrong
// public keys, high-S signatures, and zero scalars. When Verify is backed
// by an alternate verification backend, this is a differential test between
// that backend and the dcrec implementation.
func TestVerifyMatchesSignatureVerify(t *testing.T) {
	for i := 0; i < 256; i++ {
		privKey, err := btcec.NewPrivateKey()
		if err != nil {
			t.Fatalf("failed to generate private key: %v", err)
		}
		pubKey := privKey.PubKey()

		var hash [32]byte
		if _, err := rand.Read(hash[:]); err != nil {
			t.Fatalf("failed to read random hash: %v", err)
		}

		sig := Sign(privKey, hash[:])

		check := func(name string, sig *Signature, hash []byte,
			pubKey *btcec.PublicKey, want bool) {

			t.Helper()
			pure := sig.Verify(hash, pubKey)
			got := Verify(sig, hash, pubKey)
			if pure != want {
				t.Fatalf("iteration %d, %s: pure Go verify "+
					"returned %v, want %v", i, name, pure, want)
			}
			if got != want {
				t.Fatalf("iteration %d, %s: Verify returned "+
					"%v, want %v", i, name, got, want)
			}
		}

		check("valid signature", sig, hash[:], pubKey, true)

		var badHash [32]byte
		copy(badHash[:], hash[:])
		badHash[i%32] ^= 0x01
		check("corrupted digest", sig, badHash[:], pubKey, false)

		wrongKey, err := btcec.NewPrivateKey()
		if err != nil {
			t.Fatalf("failed to generate private key: %v", err)
		}
		check("wrong public key", sig, hash[:], wrongKey.PubKey(), false)

		// A signature stays valid when S is replaced with its negation
		// modulo the group order, since consensus does not require
		// low-S signatures.
		r, s := sig.R(), sig.S()
		s.Negate()
		highSSig := NewSignature(&r, &s)
		check("high-S signature", highSSig, hash[:], pubKey, true)

		var zero btcec.ModNScalar
		zeroSSig := NewSignature(&r, &zero)
		check("zero S", zeroSSig, hash[:], pubKey, false)
		sOrig := sig.S()
		zeroRSig := NewSignature(&zero, &sOrig)
		check("zero R", zeroRSig, hash[:], pubKey, false)
	}
}
