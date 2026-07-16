// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package r52

// affinePoint is a point on the secp256k1 curve in affine coordinates with
// weak-normalized coordinates. Tables only ever hold finite points, so the
// type cannot represent the point at infinity.
type affinePoint struct {
	X, Y fe
}

// jacobianPoint is a point in Jacobian projective coordinates, where the
// affine point is (X/Z^2, Y/Z^3). Coordinates are kept weak-normalized
// between operations. Infinity is tracked explicitly.
type jacobianPoint struct {
	X, Y, Z fe
	Inf     bool
}

// SetInfinity marks p as the point at infinity.
func (p *jacobianPoint) SetInfinity() {
	*p = jacobianPoint{Inf: true}
}

// SetAffine sets p to the finite affine point a.
func (p *jacobianPoint) SetAffine(a *affinePoint) {
	p.X = a.X
	p.Y = a.Y
	p.Z.SetUint64(1)
	p.Inf = false
}

// ToAffine converts p to affine coordinates with a single field inversion.
// It must not be called on the point at infinity.
func (p *jacobianPoint) ToAffine() affinePoint {
	var zi, zi2, zi3 fe
	zi.Inverse(&p.Z)
	zi2.Square(&zi)
	zi3.Mul(&zi2, &zi)
	var a affinePoint
	a.X.Mul(&p.X, &zi2)
	a.X.normalizeWeak()
	a.Y.Mul(&p.Y, &zi3)
	a.Y.normalizeWeak()
	return a
}

// Double sets p to 2*a using the dbl-2009-l formulas specialized to the
// curve coefficient a = 0, costing 3 multiplications and 4 squarings. The
// secp256k1 group has odd order, so no finite point has y = 0 and doubling
// a finite point never yields infinity.
func (p *jacobianPoint) Double(a *jacobianPoint) {
	if a.Inf {
		p.SetInfinity()
		return
	}
	jacDouble(p, a)
}

// doubleGeneric is the portable implementation backing Double. The input
// is always a finite point.
func doubleGeneric(p, a *jacobianPoint) {

	// Z3 = 2*Y*Z, computed first so that in place doubling can overwrite
	// the receiver coordinates below. The product limbs stay far below the
	// multiplication input bound, so no normalization is needed.
	var z3 fe
	z3.Mul(&a.Y, &a.Z)
	z3.MulInt(2)

	// A = X^2, B = Y^2, C = B^2. The quantity 2*((X+B)^2 - A - C) from
	// dbl-2009-l equals 4*X*B, so D is computed with one multiplication
	// instead of a squaring and two negations.
	var A, B, C, D, E, F fe
	A.Square(&a.X)
	B.Square(&a.Y)
	C.Square(&B)
	D.Mul(&a.X, &B)
	D.MulInt(4)

	// E = 3*A, F = E^2
	E = A
	E.MulInt(3)
	F.Square(&E)

	// X3 = F - 2*D
	var negTwoD fe
	negTwoD = D
	negTwoD.MulInt(2)
	negTwoD.Negate(7)
	p.X = F
	p.X.Add(&negTwoD)
	p.X.normalizeWeak()

	// Y3 = E*(D - X3) - 8*C
	var t fe
	t = p.X
	t.Negate(1)
	t.Add(&D)
	t.Mul(&t, &E)
	C.MulInt(8)
	C.Negate(7)
	p.Y = t
	p.Y.Add(&C)
	p.Y.normalizeWeak()

	p.Z = z3
	p.Inf = false
}

// AddMixed sets p to a + b where b is affine, using the madd-2007-bl
// formulas, costing 7 multiplications and 4 squarings, falling back to
// Double or infinity in the degenerate cases.
func (p *jacobianPoint) AddMixed(a *jacobianPoint, b *affinePoint) {
	if a.Inf {
		p.SetAffine(b)
		return
	}
	jacAddMixed(p, a, b)
}

// addMixedGeneric is the portable implementation backing AddMixed,
// including the degenerate branches. The Jacobian input is always a finite
// point.
func addMixedGeneric(p, a *jacobianPoint, b *affinePoint) {

	var z1z1, u2, s2 fe
	z1z1.Square(&a.Z)
	u2.Mul(&b.X, &z1z1)
	s2.Mul(&b.Y, &a.Z)
	s2.Mul(&s2, &z1z1)

	// H = U2 - X1, rr = 2*(S2 - Y1). H is fully normalized in place, both
	// for the degenerate-case check and for use in the formulas below.
	var h, rr fe
	h = a.X
	h.Negate(1)
	h.Add(&u2)
	h.Normalize()
	rr = a.Y
	rr.Negate(1)
	rr.Add(&s2)

	// Degenerate cases: same x coordinate means either a doubling or the
	// two points are inverses summing to infinity.
	if h.IsZero() {
		rz := rr
		rz.Normalize()
		if rz.IsZero() {
			var jb jacobianPoint
			jb.SetAffine(b)
			p.Double(&jb)
			return
		}
		p.SetInfinity()
		return
	}
	rr.MulInt(2)

	var hh, i, j, v fe
	hh.Square(&h)
	i = hh
	i.MulInt(4)
	j.Mul(&h, &i)
	v.Mul(&a.X, &i)

	// X3 = rr^2 - J - 2*V
	var negJ, twoV fe
	negJ = j
	negJ.Negate(1)
	twoV = v
	twoV.MulInt(2)
	twoV.Negate(2)
	p.X.Square(&rr)
	p.X.Add(&negJ)
	p.X.Add(&twoV)
	p.X.normalizeWeak()

	// Y3 = rr*(V - X3) - 2*Y1*J
	var t, yj fe
	t = p.X
	t.Negate(1)
	t.Add(&v)
	t.Mul(&t, &rr)
	yj.Mul(&a.Y, &j)
	yj.MulInt(2)
	yj.Negate(2)
	p.Y = t
	p.Y.Add(&yj)
	p.Y.normalizeWeak()

	// Z3 = (Z1 + H)^2 - Z1Z1 - HH
	var zh fe
	zh = a.Z
	zh.Add(&h)
	zh.Square(&zh)
	z1z1.Negate(1)
	hh.Negate(1)
	p.Z = zh
	p.Z.Add(&z1z1)
	p.Z.Add(&hh)
	p.Z.normalizeWeak()

	p.Inf = false
}

// Add sets p to a + b for two Jacobian points using the add-2007-bl
// formulas, costing 11 multiplications and 5 squarings, falling back to
// Double or infinity in the degenerate cases.
func (p *jacobianPoint) Add(a, b *jacobianPoint) {
	if a.Inf {
		*p = *b
		return
	}
	if b.Inf {
		*p = *a
		return
	}

	var z1z1, z2z2, u1, u2, s1, s2 fe
	z1z1.Square(&a.Z)
	z2z2.Square(&b.Z)
	u1.Mul(&a.X, &z2z2)
	u2.Mul(&b.X, &z1z1)
	s1.Mul(&a.Y, &b.Z)
	s1.Mul(&s1, &z2z2)
	s2.Mul(&b.Y, &a.Z)
	s2.Mul(&s2, &z1z1)

	// H = U2 - U1, rr = 2*(S2 - S1).
	var h, rr fe
	h = u1
	h.Negate(1)
	h.Add(&u2)
	rr = s1
	rr.Negate(1)
	rr.Add(&s2)

	var hz, rz fe
	hz = h
	hz.Normalize()
	if hz.IsZero() {
		rz = rr
		rz.Normalize()
		if rz.IsZero() {
			p.Double(a)
			return
		}
		p.SetInfinity()
		return
	}
	h.normalizeWeak()
	rr.normalizeWeak()
	rr.MulInt(2)

	// I = (2*H)^2, J = H*I, V = U1*I
	var i, j, v fe
	i = h
	i.MulInt(2)
	i.Square(&i)
	j.Mul(&h, &i)
	v.Mul(&u1, &i)

	// X3 = rr^2 - J - 2*V
	var negJ, twoV fe
	negJ = j
	negJ.Negate(1)
	twoV = v
	twoV.MulInt(2)
	twoV.Negate(2)
	p.X.Square(&rr)
	p.X.Add(&negJ)
	p.X.Add(&twoV)
	p.X.normalizeWeak()

	// Y3 = rr*(V - X3) - 2*S1*J
	var t, sj fe
	t = p.X
	t.Negate(1)
	t.Add(&v)
	t.Mul(&t, &rr)
	sj.Mul(&s1, &j)
	sj.MulInt(2)
	sj.Negate(2)
	p.Y = t
	p.Y.Add(&sj)
	p.Y.normalizeWeak()

	// Z3 = ((Z1 + Z2)^2 - Z1Z1 - Z2Z2) * H
	var zz fe
	zz = a.Z
	zz.Add(&b.Z)
	zz.Square(&zz)
	z1z1.Negate(1)
	z2z2.Negate(1)
	zz.Add(&z1z1)
	zz.Add(&z2z2)
	zz.Mul(&zz, &h)
	p.Z = zz
	p.Z.normalizeWeak()

	p.Inf = false
}
