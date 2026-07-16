// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package r52

import (
	"github.com/btcsuite/btcd/btcec/v2/internal/fastverify/internal/scalar"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// endoBeta is beta, the cube root of unity mod p realizing the curve
// endomorphism phi(x, y) = (beta*x, y) which acts as scalar multiplication
// by lambda.
var endoBeta = func() fe {
	b := [32]byte{
		0x7A, 0xE9, 0x6A, 0x2B, 0x65, 0x7C, 0x07, 0x10,
		0x6E, 0x64, 0x47, 0x9E, 0xAC, 0x34, 0x34, 0xE9,
		0x9C, 0xF0, 0x49, 0x75, 0x12, 0xF5, 0x89, 0x95,
		0xC1, 0x39, 0x6C, 0x28, 0x71, 0x95, 0x01, 0xEE,
	}
	var f fe
	f.SetBytes(&b)
	return f
}()

// oddMultiples fills table with the odd multiples 1q, 3q, ..., 15q for the
// width 5 wNAF loop, expressed on the curve rescaled by the returned frame
// Z. On that curve 2q is affine, so every chain step is a mixed addition.
// The chain never hits a degenerate case because that would require an odd
// multiple below 17q to be the point at infinity.
func oddMultiples(q *affinePoint, table *[8]jacobianPoint) fe {
	var one jacobianPoint
	one.SetAffine(q)
	var twoQ jacobianPoint
	twoQ.Double(&one)

	twoQAff := affinePoint{X: twoQ.X, Y: twoQ.Y}
	var zd2, zd3 fe
	zd2.Square(&twoQ.Z)
	zd3.Mul(&zd2, &twoQ.Z)
	table[0].X.Mul(&q.X, &zd2)
	table[0].X.normalizeWeak()
	table[0].Y.Mul(&q.Y, &zd3)
	table[0].Y.normalizeWeak()
	table[0].Z.SetUint64(1)
	table[0].Inf = false
	for i := 1; i < 8; i++ {
		table[i].AddMixed(&table[i-1], &twoQAff)
	}
	return twoQ.Z
}

// commonZ rescales the odd multiple table to a shared denominator zGlobal,
// without any field inversion, using prefix and suffix products of the
// entry Z coordinates. The outputs are effective-affine: (X', Y') such
// that the true point is (X'/zGlobal^2, Y'/zGlobal^3). Running the wNAF
// loop against them is working on the isomorphic rescaled curve, so the
// accumulator's true Z is its computed Z times zGlobal, undone once by the
// caller. Every table entry is a finite point, so all Z values are
// nonzero.
func commonZ(table *[8]jacobianPoint, out *[8]affinePoint) fe {
	// left[i] holds the product of the Z coordinates below entry i.
	var left [8]fe
	left[0].SetUint64(1)
	for i := 1; i < 8; i++ {
		left[i].Mul(&left[i-1], &table[i-1].Z)
	}

	var zGlobal fe
	zGlobal.Mul(&left[7], &table[7].Z)

	// Walking down, right holds the product of the Z coordinates above
	// entry i, so left[i]*right is zGlobal/Z_i without dividing.
	var right fe
	right.SetUint64(1)
	for i := 7; i >= 0; i-- {
		var t, t2, t3 fe
		t.Mul(&left[i], &right)
		t2.Square(&t)
		t3.Mul(&t2, &t)
		out[i].X.Mul(&table[i].X, &t2)
		out[i].X.normalizeWeak()
		out[i].Y.Mul(&table[i].Y, &t3)
		out[i].Y.normalizeWeak()
		right.Mul(&right, &table[i].Z)
	}
	return zGlobal
}

// addDigit adds digit*entry to acc where entry is table[|digit|/2] and
// digit is a nonzero odd wNAF digit, negated when neg is set.
func addDigit(acc *jacobianPoint, table *[8]affinePoint, digit int8, neg bool) {
	d := digit
	if neg {
		d = -d
	}
	idx := d
	if idx < 0 {
		idx = -idx
	}
	entry := table[idx/2]
	if d < 0 {
		entry.Y.Negate(1)
		entry.Y.normalizeWeak()
	}
	acc.AddMixed(acc, &entry)
}

// dualBaseMult computes u1*G + u2*Q using the fixed-point table for the G
// term and a GLV split Strauss wNAF loop for the Q term.
func dualBaseMult(u1, u2 *secp.ModNScalar, q *affinePoint) jacobianPoint {
	var acc jacobianPoint
	acc.SetInfinity()

	// Q term: split u2 and run two width 5 wNAF streams over shared
	// doublings, using phi to map the table for the lambda half.
	if !u2.IsZero() {
		k1, k2 := scalar.SplitK(u2)
		n1, w1 := scalar.SignedSmall(&k1)
		n2, w2 := scalar.SignedSmall(&k2)
		d1, l1 := scalar.WNAF5(w1)
		d2, l2 := scalar.WNAF5(w2)

		// The tables share one denominator so the loop runs entirely on
		// mixed additions. The phi map applies to the rescaled x
		// directly since it commutes with the isomorphism. The shared
		// denominator composes the odd multiple frame with the commonZ
		// frame.
		var qTableJ [8]jacobianPoint
		zd := oddMultiples(q, &qTableJ)
		var qTable, lqTable [8]affinePoint
		zGlobal := commonZ(&qTableJ, &qTable)
		zGlobal.Mul(&zGlobal, &zd)
		for i := range qTable {
			lqTable[i] = qTable[i]
			lqTable[i].X.Mul(&qTable[i].X, &endoBeta)
			lqTable[i].X.normalizeWeak()
		}

		l := l1
		if l2 > l {
			l = l2
		}
		for i := l - 1; i >= 0; i-- {
			acc.Double(&acc)
			if i < l1 && d1[i] != 0 {
				addDigit(&acc, &qTable, d1[i], n1)
			}
			if i < l2 && d2[i] != 0 {
				addDigit(&acc, &lqTable, d2[i], n2)
			}
		}

		// Leave the rescaled curve: the accumulator's true Z carries the
		// shared denominator.
		if !acc.Inf {
			acc.Z.Mul(&acc.Z, &zGlobal)
			acc.Z.normalizeWeak()
		}
	}

	// G term: base 256 windows over the fixed table, no doublings needed.
	if !u1.IsZero() {
		table := baseTable()
		b := u1.Bytes()
		for j := 0; j < 32; j++ {
			// Window j covers bits 8j..8j+7, byte 31-j in the big
			// endian encoding.
			if v := b[31-j]; v != 0 {
				acc.AddMixed(&acc, &table[j][v])
			}
		}
	}

	return acc
}
