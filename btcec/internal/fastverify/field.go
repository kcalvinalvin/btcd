// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package fastverify provides a verification-only secp256k1 engine used to
// accelerate signature verification. Everything in this package is variable
// time, so it must never be given secret inputs. Signing stays on the
// constant time implementations in the btcec and dcrec packages.
//
// Field elements use five base 2^52 limbs held in uint64 words, with 128
// bit intermediate products built from math/bits intrinsics. The field
// prime is p = 2^256 - c with c = 0x1000003D1, so 2^256 = c (mod p) and
// 2^260 = 16*c = 0x1000003D10 =: r52 (mod p). A product of two five limb
// values has nine base 2^52 columns p0..p8. The value equals L + 2^260*H
// with L the low five columns and H the high four columns, so the product
// is congruent to L + r52*H. H is first carried into 52-bit digits so that
// every fold term r52*h fits well inside 128 bits. A final small wrap folds
// the 2^260 carry back into the low limbs, leaving limb bounds loose but
// safe for chained multiplication.
//
// Operations track a magnitude discipline in their documentation rather
// than at runtime: callers must keep limbs below 2^56 going into
// multiplication, which the stated output bounds of each operation
// guarantee by construction.
package fastverify

import "math/bits"

const (
	m52 = 0xFFFFFFFFFFFFF // 2^52 - 1
	m48 = 0xFFFFFFFFFFFF  // 2^48 - 1

	// fieldC is c in p = 2^256 - c.
	fieldC = 0x1000003D1

	// r52 is 2^260 mod p, the fold constant for base 2^52 columns.
	r52 = 0x1000003D10
)

// u128 is a 128-bit accumulator.
type u128 struct{ hi, lo uint64 }

func (u *u128) addMul(a, b uint64) {
	hi, lo := bits.Mul64(a, b)
	var c uint64
	u.lo, c = bits.Add64(u.lo, lo, 0)
	u.hi = u.hi + hi + c
}

func (u *u128) add(v u128) {
	var c uint64
	u.lo, c = bits.Add64(u.lo, v.lo, 0)
	u.hi = u.hi + v.hi + c
}

func (u *u128) addU64(v uint64) {
	var c uint64
	u.lo, c = bits.Add64(u.lo, v, 0)
	u.hi += c
}

func (u u128) shr52() u128 {
	return u128{hi: u.hi >> 52, lo: u.hi<<12 | u.lo>>52}
}

func (u u128) low52() uint64 { return u.lo & m52 }

// Fe is a field element as five base 2^52 limbs, least significant first.
// Limb 4 holds the top 48 bits when the value is fully normalized.
type Fe struct{ n [5]uint64 }

// SetBytes interprets b as a 32-byte big-endian value. The value must
// already be canonical (less than p) for Bytes round trips to compare
// equal.
func (f *Fe) SetBytes(b *[32]byte) {
	load := func(i int) uint64 {
		return uint64(b[i])<<56 | uint64(b[i+1])<<48 | uint64(b[i+2])<<40 |
			uint64(b[i+3])<<32 | uint64(b[i+4])<<24 | uint64(b[i+5])<<16 |
			uint64(b[i+6])<<8 | uint64(b[i+7])
	}
	w0 := load(24) // least significant 8 bytes
	w1 := load(16)
	w2 := load(8)
	w3 := load(0)
	f.n[0] = w0 & m52
	f.n[1] = (w0>>52 | w1<<12) & m52
	f.n[2] = (w1>>40 | w2<<24) & m52
	f.n[3] = (w2>>28 | w3<<36) & m52
	f.n[4] = w3 >> 16
}

// Normalize fully reduces f to its canonical value below p with limbs 0..3
// below 2^52 and limb 4 below 2^48.
func (f *Fe) Normalize() {
	n0, n1, n2, n3, n4 := f.n[0], f.n[1], f.n[2], f.n[3], f.n[4]

	// Carry into 52-bit digits.
	n1 += n0 >> 52
	n0 &= m52
	n2 += n1 >> 52
	n1 &= m52
	n3 += n2 >> 52
	n2 &= m52
	n4 += n3 >> 52
	n3 &= m52

	// Fold the bits at and above 2^256 down using 2^256 = c (mod p). The
	// fold adds less than 2^40 to limb 0, so one carry pass suffices.
	x := n4 >> 48
	n4 &= m48
	n0 += x * fieldC
	n1 += n0 >> 52
	n0 &= m52
	n2 += n1 >> 52
	n1 &= m52
	n3 += n2 >> 52
	n2 &= m52
	n4 += n3 >> 52
	n3 &= m52

	// The value is now below 2^256. Subtract p once if it is in [p, 2^256),
	// which is equivalent to adding c and dropping the 2^256 bit.
	if n4 == m48 && n3 == m52 && n2 == m52 && n1 == m52 && n0 >= (1<<52)-fieldC {
		n0 = (n0 + fieldC) & m52
		n1, n2, n3, n4 = 0, 0, 0, 0
	}

	f.n[0], f.n[1], f.n[2], f.n[3], f.n[4] = n0, n1, n2, n3, n4
}

// Bytes returns the canonical 32-byte big-endian encoding. It normalizes
// the receiver.
func (f *Fe) Bytes() [32]byte {
	f.Normalize()
	var b [32]byte
	w0 := f.n[0] | f.n[1]<<52
	w1 := f.n[1]>>12 | f.n[2]<<40
	w2 := f.n[2]>>24 | f.n[3]<<28
	w3 := f.n[3]>>36 | f.n[4]<<16
	store := func(i int, w uint64) {
		b[i] = byte(w >> 56)
		b[i+1] = byte(w >> 48)
		b[i+2] = byte(w >> 40)
		b[i+3] = byte(w >> 32)
		b[i+4] = byte(w >> 24)
		b[i+5] = byte(w >> 16)
		b[i+6] = byte(w >> 8)
		b[i+7] = byte(w)
	}
	store(24, w0)
	store(16, w1)
	store(8, w2)
	store(0, w3)
	return b
}

// Mul sets f to a*b mod p in loose form: limbs may slightly exceed 52 bits
// but remain far below the 2^56 bound that keeps chained multiplications
// overflow free. Inputs may be in loose form as well.
func (f *Fe) Mul(a, b *Fe) {
	feMul(f, a, b)
}

// Square sets f to a*a mod p in the same loose form as Mul, saving the
// duplicated cross products.
func (f *Fe) Square(a *Fe) {
	feSquare(f, a)
}

// mulGeneric is the portable implementation backing Mul.
func mulGeneric(f, a, b *Fe) {
	a0, a1, a2, a3, a4 := a.n[0], a.n[1], a.n[2], a.n[3], a.n[4]
	b0, b1, b2, b3, b4 := b.n[0], b.n[1], b.n[2], b.n[3], b.n[4]

	// Low columns p0..p4.
	var p0, p1, p2, p3, p4 u128
	p0.addMul(a0, b0)
	p1.addMul(a0, b1)
	p1.addMul(a1, b0)
	p2.addMul(a0, b2)
	p2.addMul(a1, b1)
	p2.addMul(a2, b0)
	p3.addMul(a0, b3)
	p3.addMul(a1, b2)
	p3.addMul(a2, b1)
	p3.addMul(a3, b0)
	p4.addMul(a0, b4)
	p4.addMul(a1, b3)
	p4.addMul(a2, b2)
	p4.addMul(a3, b1)
	p4.addMul(a4, b0)

	// High columns p5..p8.
	var p5, p6, p7, p8 u128
	p5.addMul(a1, b4)
	p5.addMul(a2, b3)
	p5.addMul(a3, b2)
	p5.addMul(a4, b1)
	p6.addMul(a2, b4)
	p6.addMul(a3, b3)
	p6.addMul(a4, b2)
	p7.addMul(a3, b4)
	p7.addMul(a4, b3)
	p8.addMul(a4, b4)

	// Carry the high part into 52-bit digits h0..h4 so each fold term
	// r52*h stays far inside 128 bits.
	h0 := p5.low52()
	c := p5.shr52()
	c.add(p6)
	h1 := c.low52()
	c = c.shr52()
	c.add(p7)
	h2 := c.low52()
	c = c.shr52()
	c.add(p8)
	h3 := c.low52()
	c = c.shr52()
	h4 := c.lo // fits a word, used only as a fold multiplier below

	// Fold: result = L + r52*H, accumulated column by column.
	t := p0
	t.addMul(r52, h0)
	r0 := t.low52()
	t = t.shr52()
	t.add(p1)
	t.addMul(r52, h1)
	r1 := t.low52()
	t = t.shr52()
	t.add(p2)
	t.addMul(r52, h2)
	r2 := t.low52()
	t = t.shr52()
	t.add(p3)
	t.addMul(r52, h3)
	r3 := t.low52()
	t = t.shr52()
	t.add(p4)
	t.addMul(r52, h4)
	r4 := t.low52()
	t = t.shr52()

	// Wrap the remaining 2^260 carry and the limb 4 excess above 48 bits
	// into the low limbs, so limb 4 keeps the same 2^48 scale as the top
	// limb of p. That keeps the magnitude discipline of Negate valid for
	// every limb. The ripple stops at limb 1, leaving it loose by well
	// under 2^53.
	var w u128
	w.lo = r0
	w.addMul(t.lo, r52)
	w.addMul(r4>>48, fieldC)
	r4 &= m48
	r0 = w.low52()
	r1 += w.shr52().lo

	f.n[0], f.n[1], f.n[2], f.n[3], f.n[4] = r0, r1, r2, r3, r4
}

// squareGeneric is the portable implementation backing Square.
func squareGeneric(f, a *Fe) {
	a0, a1, a2, a3, a4 := a.n[0], a.n[1], a.n[2], a.n[3], a.n[4]
	d0, d1, d2, d3 := a0<<1, a1<<1, a2<<1, a3<<1

	var p0, p1, p2, p3, p4 u128
	p0.addMul(a0, a0)
	p1.addMul(d0, a1)
	p2.addMul(d0, a2)
	p2.addMul(a1, a1)
	p3.addMul(d0, a3)
	p3.addMul(d1, a2)
	p4.addMul(d0, a4)
	p4.addMul(d1, a3)
	p4.addMul(a2, a2)

	var p5, p6, p7, p8 u128
	p5.addMul(d1, a4)
	p5.addMul(d2, a3)
	p6.addMul(d2, a4)
	p6.addMul(a3, a3)
	p7.addMul(d3, a4)
	p8.addMul(a4, a4)

	h0 := p5.low52()
	c := p5.shr52()
	c.add(p6)
	h1 := c.low52()
	c = c.shr52()
	c.add(p7)
	h2 := c.low52()
	c = c.shr52()
	c.add(p8)
	h3 := c.low52()
	c = c.shr52()
	h4 := c.lo

	t := p0
	t.addMul(r52, h0)
	r0 := t.low52()
	t = t.shr52()
	t.add(p1)
	t.addMul(r52, h1)
	r1 := t.low52()
	t = t.shr52()
	t.add(p2)
	t.addMul(r52, h2)
	r2 := t.low52()
	t = t.shr52()
	t.add(p3)
	t.addMul(r52, h3)
	r3 := t.low52()
	t = t.shr52()
	t.add(p4)
	t.addMul(r52, h4)
	r4 := t.low52()
	t = t.shr52()

	var w u128
	w.lo = r0
	w.addMul(t.lo, r52)
	w.addMul(r4>>48, fieldC)
	r4 &= m48
	r0 = w.low52()
	r1 += w.shr52().lo

	f.n[0], f.n[1], f.n[2], f.n[3], f.n[4] = r0, r1, r2, r3, r4
}

// twoP holds 2*p limb-wise, the base value for magnitude-aware negation.
var twoP = [5]uint64{0x1FFFFDFFFFF85E, 0x1FFFFFFFFFFFFE, 0x1FFFFFFFFFFFFE, 0x1FFFFFFFFFFFFE, 0x1FFFFFFFFFFFE}

// Set copies a into f.
func (f *Fe) Set(a *Fe) { *f = *a }

// SetUint64 sets f to the given small value in normalized form.
func (f *Fe) SetUint64(v uint64) {
	f.n[0] = v & m52
	f.n[1] = v >> 52
	f.n[2], f.n[3], f.n[4] = 0, 0, 0
}

// Add adds a into f limb-wise. Limb bounds add, so the caller must keep the
// running total within the multiplication input bound.
func (f *Fe) Add(a *Fe) {
	f.n[0] += a.n[0]
	f.n[1] += a.n[1]
	f.n[2] += a.n[2]
	f.n[3] += a.n[3]
	f.n[4] += a.n[4]
}

// Negate replaces f with its negation. The magnitude m must satisfy
// m*2^53 >= every limb of f, which holds when f is the sum of at most m
// normalized or freshly multiplied values. Output limbs are bounded by
// (m+1)*2^54.
func (f *Fe) Negate(m uint64) {
	f.n[0] = (m+1)*twoP[0] - f.n[0]
	f.n[1] = (m+1)*twoP[1] - f.n[1]
	f.n[2] = (m+1)*twoP[2] - f.n[2]
	f.n[3] = (m+1)*twoP[3] - f.n[3]
	f.n[4] = (m+1)*twoP[4] - f.n[4]
}

// MulInt multiplies every limb by the small constant v, scaling limb bounds
// by v.
func (f *Fe) MulInt(v uint64) {
	f.n[0] *= v
	f.n[1] *= v
	f.n[2] *= v
	f.n[3] *= v
	f.n[4] *= v
}

// IsOdd reports whether the value is odd. The receiver must be normalized.
func (f *Fe) IsOdd() bool { return f.n[0]&1 == 1 }

// IsZero reports whether the value is zero. The receiver must be
// normalized.
func (f *Fe) IsZero() bool {
	return f.n[0]|f.n[1]|f.n[2]|f.n[3]|f.n[4] == 0
}

// Equals reports whether f and a hold the same value. Both must be
// normalized.
func (f *Fe) Equals(a *Fe) bool { return f.n == a.n }

// sqrN squares f in place n times.
func (f *Fe) sqrN(n int) {
	for i := 0; i < n; i++ {
		f.Square(f)
	}
}

// Inverse sets f to the multiplicative inverse of a using Fermat's little
// theorem, computing a^(p-2). The exponent p-2 is 2^223-1 followed by the
// 33 bits 0x0FFFFFC2D, giving the addition chain below with 255 squarings
// and 15 multiplications. The inverse of zero is zero.
func (f *Fe) Inverse(a *Fe) {
	var x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t Fe

	x2.Square(a)
	x2.Mul(&x2, a)

	x3.Square(&x2)
	x3.Mul(&x3, a)

	x6.Set(&x3)
	x6.sqrN(3)
	x6.Mul(&x6, &x3)

	x9.Set(&x6)
	x9.sqrN(3)
	x9.Mul(&x9, &x3)

	x11.Set(&x9)
	x11.sqrN(2)
	x11.Mul(&x11, &x2)

	x22.Set(&x11)
	x22.sqrN(11)
	x22.Mul(&x22, &x11)

	x44.Set(&x22)
	x44.sqrN(22)
	x44.Mul(&x44, &x22)

	x88.Set(&x44)
	x88.sqrN(44)
	x88.Mul(&x88, &x44)

	x176.Set(&x88)
	x176.sqrN(88)
	x176.Mul(&x176, &x88)

	x220.Set(&x176)
	x220.sqrN(44)
	x220.Mul(&x220, &x44)

	x223.Set(&x220)
	x223.sqrN(3)
	x223.Mul(&x223, &x3)

	t.Set(&x223)
	t.sqrN(23)
	t.Mul(&t, &x22)
	t.sqrN(5)
	t.Mul(&t, a)
	t.sqrN(3)
	t.Mul(&t, &x2)
	t.sqrN(2)
	t.Mul(&t, a)

	f.Set(&t)
}

// normalizeWeak carries the limbs into their canonical widths and folds the
// overflow above 2^256 back down, without the final conditional subtraction
// of p. The result has limbs 0..3 below 2^52 and limb 4 below 2^48, but may
// still exceed p by a small amount, so canonical comparisons must use
// Normalize instead. Point operations use this to reset limb magnitudes
// mid-formula.
func (f *Fe) normalizeWeak() {
	n0, n1, n2, n3, n4 := f.n[0], f.n[1], f.n[2], f.n[3], f.n[4]

	n1 += n0 >> 52
	n0 &= m52
	n2 += n1 >> 52
	n1 &= m52
	n3 += n2 >> 52
	n2 &= m52
	n4 += n3 >> 52
	n3 &= m52

	x := n4 >> 48
	n4 &= m48
	n0 += x * fieldC
	n1 += n0 >> 52
	n0 &= m52
	n2 += n1 >> 52
	n1 &= m52
	n3 += n2 >> 52
	n2 &= m52
	n4 += n3 >> 52
	n3 &= m52

	f.n[0], f.n[1], f.n[2], f.n[3], f.n[4] = n0, n1, n2, n3, n4
}
