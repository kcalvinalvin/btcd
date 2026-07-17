// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package fastverify

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/internal/fastverify/internal/engine"
	"github.com/btcsuite/btcd/chainhash/v2"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

var benchSinkAffine engine.Affine

func randomScalar(t testing.TB) secp.ModNScalar {
	t.Helper()
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	var scalar secp.ModNScalar
	scalar.SetBytes(&raw)
	return scalar
}

func TestAffineFromPubKey(t *testing.T) {
	for i := 0; i < 100; i++ {
		priv, err := secp.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		pub := priv.PubKey()
		serialized := pub.SerializeUncompressed()
		got := affineFromPubKey(pub)
		if !bytes.Equal(got.X[:], serialized[1:33]) ||
			!bytes.Equal(got.Y[:], serialized[33:65]) {

			t.Fatalf("iteration %d: coordinate mismatch", i)
		}
	}

	priv, err := secp.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PubKey()
	if allocs := testing.AllocsPerRun(1000, func() {
		benchSinkAffine = affineFromPubKey(pub)
	}); allocs != 0 {
		t.Fatalf("affineFromPubKey allocated: got %.2f want 0", allocs)
	}
}

func TestPrepareECDSAEquationCandidates(t *testing.T) {
	priv, err := secp.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	var one secp.ModNScalar
	one.SetInt(1)

	equation, ok := prepareECDSAEquation(&one, &one, nil, priv.PubKey())
	if !ok {
		t.Fatal("nonzero scalars rejected")
	}
	if equation.NumXCandidates != 2 {
		t.Fatalf("candidate count: got %d want 2", equation.NumXCandidates)
	}
	if equation.XCandidates[0] != one.Bytes() ||
		equation.XCandidates[1] != addOrder(one.Bytes()) {

		t.Fatal("candidate coordinates do not match r and r+n")
	}
	if equation.U1 != (engine.Scalar{}) ||
		equation.U2 != engine.Scalar(one.Bytes()) {

		t.Fatal("equation scalars are not canonical e/s and r/s")
	}

	var threshold secp.ModNScalar
	threshold.SetBytes(&pMinusN)
	equation, ok = prepareECDSAEquation(
		&threshold, &one, nil, priv.PubKey(),
	)
	if !ok {
		t.Fatal("threshold scalar rejected")
	}
	if equation.NumXCandidates != 1 {
		t.Fatalf("threshold candidate count: got %d want 1",
			equation.NumXCandidates)
	}

	belowThreshold := pMinusN
	belowThreshold[31]--
	threshold.SetBytes(&belowThreshold)
	equation, ok = prepareECDSAEquation(
		&threshold, &one, nil, priv.PubKey(),
	)
	if !ok {
		t.Fatal("scalar below threshold rejected")
	}
	pMinusOne := primeBytes
	pMinusOne[31]--
	if equation.NumXCandidates != 2 ||
		equation.XCandidates[1] != pMinusOne {

		t.Fatal("largest second candidate is not p-1")
	}
}

func TestCanonicalFieldNegation(t *testing.T) {
	var one [32]byte
	one[31] = 1
	pMinusOne := primeBytes
	pMinusOne[31]--
	if got := negateField(one); got != pMinusOne {
		t.Fatalf("-1: got %x want %x", got, pMinusOne)
	}
	if got := negateField(pMinusOne); got != one {
		t.Fatalf("-(p-1): got %x want %x", got, one)
	}

	keyBytes := orderBytes
	keyBytes[31]--
	priv := secp.PrivKeyFromBytes(keyBytes[:])
	original := affineFromPubKey(priv.PubKey())
	if original.Y[31]&1 == 0 {
		t.Fatal("public key for scalar n-1 does not have odd y")
	}

	var zero [32]byte
	var scalarOne secp.ModNScalar
	scalarOne.SetInt(1)
	equation := prepareSchnorrEquation(
		&zero, &scalarOne, &scalarOne, priv.PubKey(),
	)
	negOne := scalarOne
	negOne.Negate()
	if equation.S != engine.Scalar(scalarOne.Bytes()) ||
		equation.NegE != engine.Scalar(negOne.Bytes()) {

		t.Fatal("Schnorr equation scalars are not canonical s and -e")
	}
	if equation.Q.X != original.X ||
		equation.Q.Y != negateField(original.Y) ||
		equation.Q.Y[31]&1 != 0 {

		t.Fatal("Schnorr public key was not mapped to even y")
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

	priv, err := secp.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	var zero, one secp.ModNScalar
	one.SetInt(1)
	var hash [32]byte
	if VerifyECDSA(&zero, &one, hash[:], priv.PubKey()) {
		t.Fatal("zero r accepted")
	}
	if VerifyECDSA(&one, &zero, hash[:], priv.PubKey()) {
		t.Fatal("zero s accepted")
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

func TestVerifyAllocations(t *testing.T) {
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
	r, ecdsaS := sig.R(), sig.S()
	if !VerifyECDSA(&r, &ecdsaS, hash[:], pub) {
		t.Fatal("valid ECDSA signature rejected during setup")
	}
	if allocs := testing.AllocsPerRun(100, func() {
		benchSinkBool = VerifyECDSA(&r, &ecdsaS, hash[:], pub)
	}); allocs != 0 {
		t.Fatalf("VerifyECDSA allocated: got %.2f want 0", allocs)
	}

	var msg [32]byte
	if _, err := rand.Read(msg[:]); err != nil {
		t.Fatal(err)
	}
	rx, schnorrS, px := signSchnorr(t, priv, msg)
	e := schnorrChallenge(&rx, &px, msg[:])
	if !VerifySchnorr(&rx, &schnorrS, &e, pub) {
		t.Fatal("valid Schnorr signature rejected during setup")
	}
	if allocs := testing.AllocsPerRun(100, func() {
		benchSinkBool = VerifySchnorr(&rx, &schnorrS, &e, pub)
	}); allocs != 0 {
		t.Fatalf("VerifySchnorr allocated: got %.2f want 0", allocs)
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
	if !VerifyECDSA(&r, &s, hash[:], pub) {
		b.Fatal("valid signature rejected during setup")
	}
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
