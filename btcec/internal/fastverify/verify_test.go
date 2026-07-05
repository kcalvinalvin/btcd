// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package fastverify

import (
	"crypto/rand"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

func randomScalar(t testing.TB) secp.ModNScalar {
	t.Helper()
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	var s secp.ModNScalar
	s.SetBytes(&raw)
	return s
}

func TestDualBaseMultMatchesDcrec(t *testing.T) {
	check := func(u1, u2 secp.ModNScalar, dq secp.JacobianPoint) {
		t.Helper()
		// Reference: u1*G + u2*Q via dcrec.
		var t1, t2, ref secp.JacobianPoint
		secp.ScalarBaseMultNonConst(&u1, &t1)
		secp.ScalarMultNonConst(&u2, &dq, &t2)
		secp.AddNonConst(&t1, &t2, &ref)

		// Engine input is affine.
		aq := dq
		aq.ToAffine()
		maJ := fromDcrecJacobian(t, &aq)
		q := AffinePoint{X: maJ.X, Y: maJ.Y}

		got := DualBaseMult(&u1, &u2, &q)
		comparePoints(t, "dual base mult", &got, &ref)
	}

	var zero, one secp.ModNScalar
	one.SetInt(1)
	nm1 := one
	nm1.Negate()

	base := randomDcrecPoint(t)
	check(zero, zero, base)
	check(one, zero, base)
	check(zero, one, base)
	check(nm1, nm1, base)
	check(endoLambda, endoLambda, base)

	for i := 0; i < 300; i++ {
		check(randomScalar(t), randomScalar(t), randomDcrecPoint(t))
	}
}

func TestVerifyECDSADifferential(t *testing.T) {
	for i := 0; i < 300; i++ {
		priv, err := secp.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		pub := priv.PubKey()
		var hash [32]byte
		if _, err := rand.Read(hash[:]); err != nil {
			t.Fatal(err)
		}
		sig := dcrecdsa.Sign(priv, hash[:])
		r, s := sig.R(), sig.S()

		if !VerifyECDSA(&r, &s, hash[:], pub) {
			t.Fatalf("valid signature rejected, iteration %d", i)
		}

		// High-S variant stays valid.
		hs := s
		hs.Negate()
		if !VerifyECDSA(&r, &hs, hash[:], pub) {
			t.Fatalf("high-S signature rejected, iteration %d", i)
		}

		// Corrupted digest fails.
		var bad [32]byte
		copy(bad[:], hash[:])
		bad[i%32] ^= 1
		if VerifyECDSA(&r, &s, bad[:], pub) {
			t.Fatalf("corrupted digest accepted, iteration %d", i)
		}

		// Wrong key fails.
		wrong, err := secp.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		if VerifyECDSA(&r, &s, hash[:], wrong.PubKey()) {
			t.Fatalf("wrong key accepted, iteration %d", i)
		}

		// Agreement with the dcrec verifier on a mangled r.
		rm := r
		var bump secp.ModNScalar
		bump.SetInt(1)
		rm.Add(&bump)
		want := dcrecdsa.NewSignature(&rm, &s).Verify(hash[:], pub)
		if got := VerifyECDSA(&rm, &s, hash[:], pub); got != want {
			t.Fatalf("disagreement with dcrec on mangled r: got %v want %v", got, want)
		}
	}
}

// schnorrChallenge computes the BIP340 challenge e for the given R x
// coordinate, public key x coordinate, and message.
func schnorrChallenge(rx, px *[32]byte, msg []byte) secp.ModNScalar {
	commitment := chainhash.TaggedHash(
		chainhash.TagBIP0340Challenge, rx[:], px[:], msg,
	)
	var e secp.ModNScalar
	e.SetBytes((*[32]byte)(commitment))
	return e
}

// signSchnorr produces a BIP340 signature with dcrec primitives only, so
// the engine test does not import the schnorr package it will later back.
func signSchnorr(t testing.TB, priv *secp.PrivateKey, msg [32]byte) (rx [32]byte, s secp.ModNScalar, px [32]byte) {
	t.Helper()

	// Even-y form of the key: d such that d*G has even y.
	d := priv.Key
	var pj secp.JacobianPoint
	secp.ScalarBaseMultNonConst(&d, &pj)
	pj.ToAffine()
	pj.Y.Normalize()
	if pj.Y.IsOdd() {
		d.Negate()
	}
	pj.X.Normalize()
	pj.X.PutBytesUnchecked(px[:])

	for {
		k := randomScalar(t)
		if k.IsZero() {
			continue
		}
		var rj secp.JacobianPoint
		secp.ScalarBaseMultNonConst(&k, &rj)
		rj.ToAffine()
		rj.Y.Normalize()
		if rj.Y.IsOdd() {
			k.Negate()
		}
		rj.X.Normalize()
		rj.X.PutBytesUnchecked(rx[:])

		e := schnorrChallenge(&rx, &px, msg[:])
		// s = k + e*d
		s = e
		s.Mul(&d)
		s.Add(&k)
		if !s.IsZero() {
			return rx, s, px
		}
	}
}

func TestVerifySchnorrEngine(t *testing.T) {
	for i := 0; i < 300; i++ {
		priv, err := secp.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		var msg [32]byte
		if _, err := rand.Read(msg[:]); err != nil {
			t.Fatal(err)
		}
		rx, s, px := signSchnorr(t, priv, msg)
		e := schnorrChallenge(&rx, &px, msg[:])

		if !VerifySchnorr(&rx, &s, &e, priv.PubKey()) {
			t.Fatalf("valid schnorr signature rejected, iteration %d", i)
		}

		// Corrupted message must fail under its recomputed challenge.
		var bad [32]byte
		copy(bad[:], msg[:])
		bad[i%32] ^= 1
		eBad := schnorrChallenge(&rx, &px, bad[:])
		if VerifySchnorr(&rx, &s, &eBad, priv.PubKey()) {
			t.Fatalf("corrupted schnorr message accepted, iteration %d", i)
		}

		// Corrupted s must fail.
		sBad := s
		var bump secp.ModNScalar
		bump.SetInt(1)
		sBad.Add(&bump)
		if VerifySchnorr(&rx, &sBad, &e, priv.PubKey()) {
			t.Fatalf("corrupted schnorr s accepted, iteration %d", i)
		}
	}
}

var benchSinkBool bool

func BenchmarkVerifyECDSAEngine(b *testing.B) {
	priv, err := secp.GeneratePrivateKey()
	if err != nil {
		b.Fatal(err)
	}
	pub := priv.PubKey()
	var hash [32]byte
	if _, err := rand.Read(hash[:]); err != nil {
		b.Fatal(err)
	}
	sig := dcrecdsa.Sign(priv, hash[:])
	r, s := sig.R(), sig.S()
	baseTable() // exclude one time table build
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSinkBool = VerifyECDSA(&r, &s, hash[:], pub)
	}
}

func BenchmarkVerifyECDSADcrec(b *testing.B) {
	priv, err := secp.GeneratePrivateKey()
	if err != nil {
		b.Fatal(err)
	}
	pub := priv.PubKey()
	var hash [32]byte
	if _, err := rand.Read(hash[:]); err != nil {
		b.Fatal(err)
	}
	sig := dcrecdsa.Sign(priv, hash[:])
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSinkBool = sig.Verify(hash[:], pub)
	}
}
