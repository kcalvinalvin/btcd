// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package fastverify

import (
	"bytes"

	"github.com/btcsuite/btcd/btcec/v2/internal/fastverify/internal/engine"
	"github.com/btcsuite/btcd/btcec/v2/internal/fastverify/internal/modinv"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	// orderBytes is the group order n in big-endian form.
	orderBytes = [32]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
		0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
		0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
	}

	// pMinusN is p - n in big-endian form. An ECDSA r below this value has
	// two candidate x coordinates, r and r + n.
	pMinusN = [32]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x45, 0x51, 0x23, 0x19, 0x50, 0xB7, 0x5F, 0xC4,
		0x40, 0x2D, 0xA1, 0x72, 0x2F, 0xC9, 0xBA, 0xEE,
	}
)

// affineFromPubKey returns the canonical coordinates of a parsed public key.
// Parsed public keys are always finite points on the curve.
func affineFromPubKey(pub *secp.PublicKey) engine.Affine {
	serialized := pub.SerializeUncompressed()
	var a engine.Affine
	copy(a.X[:], serialized[1:33])
	copy(a.Y[:], serialized[33:65])
	return a
}

// addOrder returns x+n. The caller guarantees x < p-n, so the result is a
// canonical field element and the addition cannot overflow 256 bits.
func addOrder(x [32]byte) [32]byte {
	var carry uint16
	for i := len(x) - 1; i >= 0; i-- {
		sum := uint16(x[i]) + uint16(orderBytes[i]) + carry
		x[i] = byte(sum)
		carry = sum >> 8
	}
	return x
}

// negateField returns -v mod p for a canonical nonzero field element.
func negateField(v [32]byte) [32]byte {
	var borrow int
	for i := len(v) - 1; i >= 0; i-- {
		difference := int(primeBytes[i]) - int(v[i]) - borrow
		if difference < 0 {
			difference += 256
			borrow = 1
		} else {
			borrow = 0
		}
		v[i] = byte(difference)
	}
	return v
}

// prepareECDSAEquation validates the scalar inputs and constructs the
// representation-neutral ECDSA equation.
func prepareECDSAEquation(r, s *secp.ModNScalar, sigHash []byte,
	pub *secp.PublicKey) (engine.ECDSAEquation, bool) {

	var equation engine.ECDSAEquation
	if r.IsZero() || s.IsZero() {
		return equation, false
	}

	// u1 = e/s and u2 = r/s, with e the sig hash interpreted mod n.
	var e secp.ModNScalar
	e.SetByteSlice(sigHash)
	w := *s
	modinv.ScalarInverse(&w)
	u1 := e
	u1.Mul(&w)
	equation.U1 = engine.Scalar(u1.Bytes())
	u2 := *r
	u2.Mul(&w)
	equation.U2 = engine.Scalar(u2.Bytes())
	equation.Q = affineFromPubKey(pub)

	equation.XCandidates[0] = r.Bytes()
	equation.NumXCandidates = 1
	if bytes.Compare(equation.XCandidates[0][:], pMinusN[:]) < 0 {
		equation.XCandidates[1] = addOrder(equation.XCandidates[0])
		equation.NumXCandidates = 2
	}
	return equation, true
}

// VerifyECDSA reports whether the signature (r, s) over the given sig hash is
// valid for the public key. Both high-S and low-S signatures are accepted,
// matching the consensus rules.
func VerifyECDSA(r, s *secp.ModNScalar, sigHash []byte,
	pub *secp.PublicKey) bool {

	equation, ok := prepareECDSAEquation(r, s, sigHash, pub)
	return ok && verifyECDSAEquation(&equation)
}

// prepareSchnorrEquation constructs the representation-neutral BIP340
// equation with the even-y representative of the public key.
func prepareSchnorrEquation(rx *[32]byte, s, e *secp.ModNScalar,
	pub *secp.PublicKey) engine.SchnorrEquation {

	equation := engine.SchnorrEquation{
		S:  engine.Scalar(s.Bytes()),
		Q:  affineFromPubKey(pub),
		RX: *rx,
	}
	if equation.Q.Y[31]&1 != 0 {
		equation.Q.Y = negateField(equation.Q.Y)
	}
	negE := *e
	negE.Negate()
	equation.NegE = engine.Scalar(negE.Bytes())
	return equation
}

// VerifySchnorr reports whether a BIP340 signature with x-only R coordinate
// rx and scalar s verifies for challenge e and the given public key. The point
// R = s*G - e*P must be finite, have even y, and have x coordinate rx. The
// caller computes the tagged challenge hash, reduces it modulo n, and
// guarantees s < n and rx < p through signature parsing.
func VerifySchnorr(rx *[32]byte, s, e *secp.ModNScalar,
	pub *secp.PublicKey) bool {

	equation := prepareSchnorrEquation(rx, s, e, pub)
	return verifySchnorrEquation(&equation)
}
