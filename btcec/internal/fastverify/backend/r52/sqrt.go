// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package r52

// Equals reports whether two normalized field elements have equal limbs.
func (f *fe) Equals(a *fe) bool { return f.n == a.n }

// feSqrt sets r to the square root of a and reports whether a is a quadratic
// residue, which is exactly when the root exists. The candidate root is
// a^((p+1)/4), which is a root of a whenever a has one since p = 3 mod 4.
// r is fully normalized on success and unchanged on failure. a may be in
// loose form.
func feSqrt(r, a *fe) bool {
	// The binary representation of (p+1)/4 has 3 blocks of 1s with lengths
	// 223, 22 and 2. Build a^(2^n - 1) for the needed block lengths with an
	// addition chain and assemble them with a sliding window over the
	// exponent, 253 squarings and 13 multiplications in total.
	var x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t fe

	x2.Square(a)
	x2.Mul(&x2, a)

	x3.Square(&x2)
	x3.Mul(&x3, a)

	x6 = x3
	for i := 0; i < 3; i++ {
		x6.Square(&x6)
	}
	x6.Mul(&x6, &x3)

	x9 = x6
	for i := 0; i < 3; i++ {
		x9.Square(&x9)
	}
	x9.Mul(&x9, &x3)

	x11 = x9
	for i := 0; i < 2; i++ {
		x11.Square(&x11)
	}
	x11.Mul(&x11, &x2)

	x22 = x11
	for i := 0; i < 11; i++ {
		x22.Square(&x22)
	}
	x22.Mul(&x22, &x11)

	x44 = x22
	for i := 0; i < 22; i++ {
		x44.Square(&x44)
	}
	x44.Mul(&x44, &x22)

	x88 = x44
	for i := 0; i < 44; i++ {
		x88.Square(&x88)
	}
	x88.Mul(&x88, &x44)

	x176 = x88
	for i := 0; i < 88; i++ {
		x176.Square(&x176)
	}
	x176.Mul(&x176, &x88)

	x220 = x176
	for i := 0; i < 44; i++ {
		x220.Square(&x220)
	}
	x220.Mul(&x220, &x44)

	x223 = x220
	for i := 0; i < 3; i++ {
		x223.Square(&x223)
	}
	x223.Mul(&x223, &x3)

	t = x223
	for i := 0; i < 23; i++ {
		t.Square(&t)
	}
	t.Mul(&t, &x22)
	for i := 0; i < 6; i++ {
		t.Square(&t)
	}
	t.Mul(&t, &x2)
	t.Square(&t)
	t.Square(&t)

	// The candidate is a root exactly when its square is a.
	var check fe
	check.Square(&t)
	check.Normalize()
	want := *a
	want.Normalize()
	if !check.Equals(&want) {
		return false
	}

	t.Normalize()
	*r = t
	return true
}
