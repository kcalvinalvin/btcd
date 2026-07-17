// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package r52

import (
	"github.com/btcsuite/btcd/btcec/v2/internal/fastverify/internal/engine"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// affineFromEngine imports canonical coordinates into the radix-52 backend.
func affineFromEngine(p *engine.Affine) affinePoint {
	var a affinePoint
	a.X.SetBytes(&p.X)
	a.Y.SetBytes(&p.Y)
	return a
}

// scalarFromEngine imports a canonical scalar into the radix-52 backend's
// scalar implementation.
func scalarFromEngine(s *engine.Scalar) secp.ModNScalar {
	var scalar secp.ModNScalar
	scalar.SetBytes((*[32]byte)(s))
	return scalar
}

// VerifyECDSA checks an ECDSA equation with radix-52 field and group
// arithmetic.
func VerifyECDSA(equation *engine.ECDSAEquation) bool {
	q := affineFromEngine(&equation.Q)
	u1 := scalarFromEngine(&equation.U1)
	u2 := scalarFromEngine(&equation.U2)
	rp := dualBaseMult(&u1, &u2, &q)
	if rp.Inf {
		return false
	}

	// Compare X against candidate*Z^2 without a field inversion.
	var z2 fe
	z2.Square(&rp.Z)
	x := rp.X.Bytes()
	for i := uint8(0); i < equation.NumXCandidates; i++ {
		var candidate, lhs fe
		candidate.SetBytes(&equation.XCandidates[i])
		lhs.Mul(&candidate, &z2)
		if lhs.Bytes() == x {
			return true
		}
	}
	return false
}

// VerifySchnorr checks a BIP340 equation with radix-52 field and group
// arithmetic.
func VerifySchnorr(equation *engine.SchnorrEquation) bool {
	q := affineFromEngine(&equation.Q)
	s := scalarFromEngine(&equation.S)
	negE := scalarFromEngine(&equation.NegE)
	rp := dualBaseMult(&s, &negE, &q)
	if rp.Inf {
		return false
	}

	a := rp.ToAffine()
	a.Y.Normalize()
	if a.Y.IsOdd() {
		return false
	}
	return a.X.Bytes() == equation.RX
}
