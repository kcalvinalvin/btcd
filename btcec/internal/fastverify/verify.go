// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package fastverify

import (
	"bytes"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	// orderFe is the group order n as a field element, used for the
	// second candidate x coordinate in ECDSA verification.
	orderFe = func() Fe {
		b := [32]byte{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
			0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
			0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
		}
		var f Fe
		f.SetBytes(&b)
		return f
	}()

	// pMinusN is p - n in big-endian form. An ECDSA r below this value has
	// two candidate x coordinates, r and r + n.
	pMinusN = [32]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x45, 0x51, 0x23, 0x19, 0x50, 0xB7, 0x5F, 0xC4,
		0x40, 0x2D, 0xA1, 0x72, 0x2F, 0xC9, 0xBA, 0xEE,
	}
)

// affineFromPubKey decodes a parsed public key into engine coordinates.
// Parsed public keys are always finite points on the curve.
func affineFromPubKey(pub *secp.PublicKey) AffinePoint {
	b := pub.SerializeUncompressed()
	var xb, yb [32]byte
	copy(xb[:], b[1:33])
	copy(yb[:], b[33:65])
	var a AffinePoint
	a.X.SetBytes(&xb)
	a.Y.SetBytes(&yb)
	return a
}

// VerifyECDSA reports whether the signature (r, s) over the given sig hash
// is valid for the public key. Both high-S and low-S signatures are
// accepted, matching the consensus rules. r and s must be nonzero, which
// signature parsing already guarantees.
func VerifyECDSA(r, s *secp.ModNScalar, sigHash []byte, pub *secp.PublicKey) bool {
	if r.IsZero() || s.IsZero() {
		return false
	}

	// u1 = e/s and u2 = r/s, with e the sig hash interpreted mod n.
	var e secp.ModNScalar
	e.SetByteSlice(sigHash)
	w := *s
	w.InverseNonConst()
	u1 := e
	u1.Mul(&w)
	u2 := *r
	u2.Mul(&w)

	q := affineFromPubKey(pub)
	rp := DualBaseMult(&u1, &u2, &q)
	if rp.Inf {
		return false
	}

	// The signature is valid when x(R) mod n equals r, checked without an
	// inversion by comparing X against candidate*Z^2 for the candidates r
	// and, when r < p - n, also r + n.
	var z2 Fe
	z2.Square(&rp.Z)
	xB := rp.X.Bytes()

	rb := r.Bytes()
	var rf Fe
	rf.SetBytes(&rb)
	var lhs Fe
	lhs.Mul(&rf, &z2)
	if lhs.Bytes() == xB {
		return true
	}

	if bytes.Compare(rb[:], pMinusN[:]) < 0 {
		rf.Add(&orderFe)
		lhs.Mul(&rf, &z2)
		if lhs.Bytes() == xB {
			return true
		}
	}

	return false
}

// VerifySchnorr reports whether a BIP340 signature with x only R
// coordinate rx and scalar s verifies for challenge e and the given public
// key: R = s*G - e*P must be a finite point with even y whose x coordinate
// equals rx. The caller computes the tagged challenge hash and reduces it
// mod n, and guarantees s < n and rx < p from signature parsing.
func VerifySchnorr(rx *[32]byte, s, e *secp.ModNScalar, pub *secp.PublicKey) bool {
	// BIP340 works with the even y representative of the public key.
	q := affineFromPubKey(pub)
	qy := q.Y
	qy.Normalize()
	if qy.IsOdd() {
		q.Y.Negate(1)
		q.Y.normalizeWeak()
	}

	negE := *e
	negE.Negate()
	rp := DualBaseMult(s, &negE, &q)
	if rp.Inf {
		return false
	}

	a := rp.ToAffine()
	a.Y.Normalize()
	if a.Y.IsOdd() {
		return false
	}
	return a.X.Bytes() == *rx
}
