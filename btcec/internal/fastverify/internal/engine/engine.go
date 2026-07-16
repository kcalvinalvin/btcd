// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package engine defines representation-neutral values exchanged between the
// fast verification facade and its arithmetic backends.
package engine

// Affine is a finite secp256k1 point in affine coordinates. X and Y are
// canonical 32-byte big-endian field elements.
type Affine struct {
	X, Y [32]byte
}

// Scalar is a canonical 32-byte big-endian integer in the range [0, n), where
// n is the secp256k1 group order.
type Scalar [32]byte

// ECDSAEquation contains the representation-neutral inputs needed to check an
// ECDSA verification equation. XCandidates holds the field x coordinates
// whose projective equivalents may match the result point. NumXCandidates is
// always one or two.
type ECDSAEquation struct {
	U1, U2         Scalar
	Q              Affine
	XCandidates    [2][32]byte
	NumXCandidates uint8
}

// SchnorrEquation contains the representation-neutral inputs needed to check
// a BIP340 verification equation. Q is the even-y representative of the
// public key.
type SchnorrEquation struct {
	S, NegE Scalar
	Q       Affine
	RX      [32]byte
}
