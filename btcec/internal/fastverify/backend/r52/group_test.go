// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package r52

import (
	"crypto/rand"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// fromDcrecJacobian copies a dcrec Jacobian point into the engine
// representation.
func fromDcrecJacobian(t testing.TB, p *secp.JacobianPoint) jacobianPoint {
	t.Helper()
	if (p.X.IsZero() && p.Y.IsZero()) || p.Z.IsZero() {
		var inf jacobianPoint
		inf.SetInfinity()
		return inf
	}
	var out jacobianPoint
	var buf [32]byte
	x, y, z := p.X, p.Y, p.Z
	x.Normalize()
	y.Normalize()
	z.Normalize()
	x.PutBytesUnchecked(buf[:])
	out.X.SetBytes(&buf)
	y.PutBytesUnchecked(buf[:])
	out.Y.SetBytes(&buf)
	z.PutBytesUnchecked(buf[:])
	out.Z.SetBytes(&buf)
	return out
}

// dcrecIsInfinity reports whether a dcrec Jacobian point is the point at
// infinity.
func dcrecIsInfinity(p *secp.JacobianPoint) bool {
	return (p.X.IsZero() && p.Y.IsZero()) || p.Z.IsZero()
}

// affineBytes returns the canonical affine encoding of the engine point.
func affineBytes(t testing.TB, p *jacobianPoint) (xb, yb [32]byte) {
	t.Helper()
	if p.Inf {
		t.Fatal("affineBytes called on infinity")
	}
	a := p.ToAffine()
	return a.X.Bytes(), a.Y.Bytes()
}

// dcrecAffineBytes returns the canonical affine encoding of a dcrec point.
func dcrecAffineBytes(t testing.TB, p *secp.JacobianPoint) (xb, yb [32]byte) {
	t.Helper()
	q := *p
	q.ToAffine()
	q.X.Normalize()
	q.Y.Normalize()
	q.X.PutBytesUnchecked(xb[:])
	q.Y.PutBytesUnchecked(yb[:])
	return xb, yb
}

// randomDcrecPoint returns a uniformly chosen multiple of the base point.
func randomDcrecPoint(t testing.TB) secp.JacobianPoint {
	t.Helper()
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	var k secp.ModNScalar
	k.SetBytes(&raw)
	if k.IsZero() {
		k.SetInt(1)
	}
	var p secp.JacobianPoint
	secp.ScalarBaseMultNonConst(&k, &p)
	return p
}

// rescale multiplies a dcrec Jacobian point's coordinates by lambda^2,
// lambda^3, lambda, yielding a different representation of the same point.
func rescale(t testing.TB, p *secp.JacobianPoint) secp.JacobianPoint {
	t.Helper()
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	var l secp.FieldVal
	l.SetByteSlice(raw[:])
	l.Normalize()
	if l.IsZero() {
		l.SetInt(1)
	}
	var l2, l3 secp.FieldVal
	l2.SquareVal(&l)
	l3.Mul2(&l2, &l)
	out := *p
	out.X.Mul(&l2)
	out.Y.Mul(&l3)
	out.Z.Mul(&l)
	out.X.Normalize()
	out.Y.Normalize()
	out.Z.Normalize()
	return out
}

func comparePoints(t *testing.T, name string, mine *jacobianPoint, ref *secp.JacobianPoint) {
	t.Helper()
	if dcrecIsInfinity(ref) != mine.Inf {
		t.Fatalf("%s: infinity mismatch: mine=%v ref=%v", name, mine.Inf, dcrecIsInfinity(ref))
	}
	if mine.Inf {
		return
	}
	gx, gy := affineBytes(t, mine)
	wx, wy := dcrecAffineBytes(t, ref)
	if gx != wx || gy != wy {
		t.Fatalf("%s: point mismatch\ngot  x=%x y=%x\nwant x=%x y=%x", name, gx, gy, wx, wy)
	}
}

func TestDoubleMatchesDcrec(t *testing.T) {
	for i := 0; i < 1000; i++ {
		dp := randomDcrecPoint(t)
		if i%2 == 1 {
			dp = rescale(t, &dp) // exercise non-trivial Z
		}
		mp := fromDcrecJacobian(t, &dp)

		var dr secp.JacobianPoint
		secp.DoubleNonConst(&dp, &dr)

		var mr jacobianPoint
		mr.Double(&mp)
		comparePoints(t, "double", &mr, &dr)

		// In place.
		inPlace := mp
		inPlace.Double(&inPlace)
		comparePoints(t, "double in place", &inPlace, &dr)
	}

	var inf, r jacobianPoint
	inf.SetInfinity()
	r.Double(&inf)
	if !r.Inf {
		t.Fatal("double of infinity must be infinity")
	}
}

func TestAddMixedMatchesDcrec(t *testing.T) {
	for i := 0; i < 1000; i++ {
		da := randomDcrecPoint(t)
		if i%2 == 1 {
			da = rescale(t, &da)
		}
		db := randomDcrecPoint(t)
		db.ToAffine() // Z = 1

		ma := fromDcrecJacobian(t, &da)
		mbJ := fromDcrecJacobian(t, &db)
		mb := affinePoint{X: mbJ.X, Y: mbJ.Y}

		var dr secp.JacobianPoint
		secp.AddNonConst(&da, &db, &dr)

		var mr jacobianPoint
		mr.AddMixed(&ma, &mb)
		comparePoints(t, "add mixed", &mr, &dr)

		// In place.
		inPlace := ma
		inPlace.AddMixed(&inPlace, &mb)
		comparePoints(t, "add mixed in place", &inPlace, &dr)
	}

	// Degenerate: P + P through the mixed add hits the doubling branch,
	// with P given in a rescaled representation on the Jacobian side.
	dp := randomDcrecPoint(t)
	dp.ToAffine()
	dj := rescale(t, &dp)
	mj := fromDcrecJacobian(t, &dj)
	mpA := fromDcrecJacobian(t, &dp)
	aff := affinePoint{X: mpA.X, Y: mpA.Y}
	var want secp.JacobianPoint
	secp.DoubleNonConst(&dp, &want)
	var got jacobianPoint
	got.AddMixed(&mj, &aff)
	comparePoints(t, "add mixed doubling branch", &got, &want)

	// Degenerate: P + (-P) is infinity.
	neg := aff
	neg.Y.Negate(1)
	neg.Y.normalizeWeak()
	var infR jacobianPoint
	infR.AddMixed(&mj, &neg)
	if !infR.Inf {
		t.Fatal("P + (-P) must be infinity")
	}

	// Infinity + Q is Q.
	var inf jacobianPoint
	inf.SetInfinity()
	var r jacobianPoint
	r.AddMixed(&inf, &aff)
	gx, gy := affineBytes(t, &r)
	wx, wy := dcrecAffineBytes(t, &dp)
	if gx != wx || gy != wy {
		t.Fatal("infinity + Q must equal Q")
	}
}
