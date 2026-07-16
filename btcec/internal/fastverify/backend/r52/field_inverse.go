// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package r52

// squareN squares f in place n times.
func (f *fe) squareN(n int) {
	for i := 0; i < n; i++ {
		f.Square(f)
	}
}

// Inverse sets f to the multiplicative inverse of a using Fermat's little
// theorem, computing a^(p-2). The exponent p-2 is 2^223-1 followed by the
// 33 bits 0x0fffffc2d, giving the addition chain below with 255 squarings
// and 15 multiplications. The inverse of zero is zero.
func (f *fe) Inverse(a *fe) {
	var x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, result fe

	x2.Square(a)
	x2.Mul(&x2, a)

	x3.Square(&x2)
	x3.Mul(&x3, a)

	x6 = x3
	x6.squareN(3)
	x6.Mul(&x6, &x3)

	x9 = x6
	x9.squareN(3)
	x9.Mul(&x9, &x3)

	x11 = x9
	x11.squareN(2)
	x11.Mul(&x11, &x2)

	x22 = x11
	x22.squareN(11)
	x22.Mul(&x22, &x11)

	x44 = x22
	x44.squareN(22)
	x44.Mul(&x44, &x22)

	x88 = x44
	x88.squareN(44)
	x88.Mul(&x88, &x44)

	x176 = x88
	x176.squareN(88)
	x176.Mul(&x176, &x88)

	x220 = x176
	x220.squareN(44)
	x220.Mul(&x220, &x44)

	x223 = x220
	x223.squareN(3)
	x223.Mul(&x223, &x3)

	result = x223
	result.squareN(23)
	result.Mul(&result, &x22)
	result.squareN(5)
	result.Mul(&result, a)
	result.squareN(3)
	result.Mul(&result, &x2)
	result.squareN(2)
	result.Mul(&result, a)

	*f = result
}
