// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package modinv

import (
	"math/bits"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Variable-time modular inversion using the divsteps iteration of
// Bernstein and Yang's safegcd, following the batching structure of the
// 64-bit variable-time implementation in libsecp256k1: 62 divsteps at a
// time collapse into a 2x2 integer transition matrix applied to the full
// width state, so the full width numbers are touched only once per 62
// steps. Everything here is variable time and must never see secret
// inputs.

const m62 = int64(^uint64(0) >> 2)

// signed62 is a 256-bit-ish signed integer as five two's complement limbs
// of 62 bits, least significant first.
type signed62 struct {
	v [5]int64
}

// signed62FromBytes interprets b as an unsigned 32-byte big-endian value,
// which always fits the representation with headroom.
func signed62FromBytes(b *[32]byte) signed62 {
	load := func(i int) uint64 {
		return uint64(b[i])<<56 | uint64(b[i+1])<<48 | uint64(b[i+2])<<40 |
			uint64(b[i+3])<<32 | uint64(b[i+4])<<24 | uint64(b[i+5])<<16 |
			uint64(b[i+6])<<8 | uint64(b[i+7])
	}
	w0 := load(24)
	w1 := load(16)
	w2 := load(8)
	w3 := load(0)
	var s signed62
	s.v[0] = int64(w0 & uint64(m62))
	s.v[1] = int64((w0>>62 | w1<<2) & uint64(m62))
	s.v[2] = int64((w1>>60 | w2<<4) & uint64(m62))
	s.v[3] = int64((w2>>58 | w3<<6) & uint64(m62))
	s.v[4] = int64(w3 >> 56)
	return s
}

// bytes returns the 32-byte big-endian form. The value must be fully
// reduced with every limb in canonical range.
func (s *signed62) bytes() [32]byte {
	w0 := uint64(s.v[0]) | uint64(s.v[1])<<62
	w1 := uint64(s.v[1])>>2 | uint64(s.v[2])<<60
	w2 := uint64(s.v[2])>>4 | uint64(s.v[3])<<58
	w3 := uint64(s.v[3])>>6 | uint64(s.v[4])<<56
	var b [32]byte
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

// int128 is a two's complement 128-bit accumulator.
type int128 struct {
	hi, lo uint64
}

// mulI64 returns the full signed product a*b.
func mulI64(a, b int64) int128 {
	h, l := bits.Mul64(uint64(a), uint64(b))
	h -= uint64(a>>63) & uint64(b)
	h -= uint64(b>>63) & uint64(a)
	return int128{h, l}
}

func (x *int128) accum(a, b int64) {
	p := mulI64(a, b)
	var c uint64
	x.lo, c = bits.Add64(x.lo, p.lo, 0)
	x.hi += p.hi + c
}

func (x int128) shr62() int128 {
	return int128{uint64(int64(x.hi) >> 62), x.hi<<2 | x.lo>>62}
}

func (x int128) low62() int64 {
	return int64(x.lo & uint64(m62))
}

// modInfo carries a modulus in signed62 form together with the inverse of
// its low limb mod 2^62.
type modInfo struct {
	modulus signed62
	inv62   uint64
}

// newModInfo derives the modInfo for an odd modulus given big-endian.
func newModInfo(b [32]byte) modInfo {
	m := signed62FromBytes(&b)
	n0 := uint64(m.v[0])
	x := n0
	for i := 0; i < 6; i++ {
		x *= 2 - n0*x
	}
	return modInfo{modulus: m, inv62: x & uint64(m62)}
}

// scalarModInfo inverts modulo the group order n.
var scalarModInfo = newModInfo([32]byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
	0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
	0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
})

// fieldModInfo inverts modulo the field prime p.
var fieldModInfo = newModInfo([32]byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
})

// neginv256 holds the negated inverses of the odd bytes: entry i is
// -(2i+1)^-1 mod 2^8, used to cancel the low bits of g against f.
var neginv256 = func() [128]uint8 {
	var t [128]uint8
	for i := range t {
		f := uint8(2*i + 1)
		x := f
		x *= 2 - f*x
		x *= 2 - f*x
		t[i] = -x
	}
	return t
}()

// trans2x2 is a divsteps transition matrix with entries scaled by 2^62.
type trans2x2 struct {
	u, v, q, r int64
}

// divsteps62Var performs 62 divsteps on the bottom limbs of f and g,
// starting from eta = -delta, and returns the updated eta and the
// combined transition matrix. Multi-bit progress comes from cancelling up
// to eight low bits of g per inner round through the neginv256 table.
func divsteps62VarGeneric(eta int64, f0, g0 uint64, t *trans2x2) int64 {
	var u, v, q, r uint64 = 1, 0, 0, 1
	f, g := f0, g0
	i := 62
	tbl := &neginv256
	for {
		zeros := bits.TrailingZeros64(g | ^uint64(0)<<uint(i))
		g >>= uint(zeros)
		u <<= uint(zeros)
		v <<= uint(zeros)
		eta -= int64(zeros)
		i -= zeros
		if i == 0 {
			break
		}

		if eta < 0 {
			eta = -eta
			f, g = g, -f
			u, q = q, -u
			v, r = r, -v
		}

		// Cancel up to eight low bits of g against f through the negated
		// inverse table.
		limit := eta + 1
		if limit > int64(i) {
			limit = int64(i)
		}
		m := (^uint64(0) >> uint(64-limit)) & 255
		w := (g * uint64(tbl[(f>>1)&127])) & m
		g += f * w
		q += u * w
		r += v * w
	}
	*t = trans2x2{int64(u), int64(v), int64(q), int64(r)}
	return eta
}

// updateDE62 sets (d, e) to the transition matrix times (d, e) divided by
// 2^62, adding multiples of the modulus chosen so the division is exact
// and the results stay above -2 times the modulus.
func updateDE62(d, e *signed62, t trans2x2, mi *modInfo) {
	u, v, q, r := t.u, t.v, t.q, t.r
	sd := d.v[4] >> 63
	se := e.v[4] >> 63
	md := (u & sd) + (v & se)
	me := (q & sd) + (r & se)
	cd := mulI64(u, d.v[0])
	cd.accum(v, e.v[0])
	ce := mulI64(q, d.v[0])
	ce.accum(r, e.v[0])
	md -= int64((mi.inv62*cd.lo + uint64(md)) & uint64(m62))
	me -= int64((mi.inv62*ce.lo + uint64(me)) & uint64(m62))
	cd.accum(mi.modulus.v[0], md)
	ce.accum(mi.modulus.v[0], me)
	cd = cd.shr62()
	ce = ce.shr62()
	for i := 1; i < 5; i++ {
		cd.accum(u, d.v[i])
		cd.accum(v, e.v[i])
		ce.accum(q, d.v[i])
		ce.accum(r, e.v[i])
		if mv := mi.modulus.v[i]; mv != 0 {
			cd.accum(mv, md)
			ce.accum(mv, me)
		}
		d.v[i-1] = cd.low62()
		cd = cd.shr62()
		e.v[i-1] = ce.low62()
		ce = ce.shr62()
	}
	d.v[4] = int64(cd.lo)
	e.v[4] = int64(ce.lo)
}

// updateFG62Var sets (f, g) to the transition matrix times (f, g) divided
// by 2^62, which the divsteps construction makes exact, touching only the
// bottom length limbs.
func updateFG62Var(length int, f, g *signed62, t trans2x2) {
	u, v, q, r := t.u, t.v, t.q, t.r
	cf := mulI64(u, f.v[0])
	cf.accum(v, g.v[0])
	cg := mulI64(q, f.v[0])
	cg.accum(r, g.v[0])
	cf = cf.shr62()
	cg = cg.shr62()
	for i := 1; i < length; i++ {
		cf.accum(u, f.v[i])
		cf.accum(v, g.v[i])
		cg.accum(q, f.v[i])
		cg.accum(r, g.v[i])
		f.v[i-1] = cf.low62()
		cf = cf.shr62()
		g.v[i-1] = cg.low62()
		cg = cg.shr62()
	}
	f.v[length-1] = int64(cf.lo)
	g.v[length-1] = int64(cg.lo)
}

// normalize62 brings r from the update range above -2 times the modulus
// to the canonical range, negating first when sign is negative.
func normalize62(r *signed62, sign int64, mi *modInfo) {
	r0, r1, r2, r3, r4 := r.v[0], r.v[1], r.v[2], r.v[3], r.v[4]

	condAdd := r4 >> 63
	r0 += mi.modulus.v[0] & condAdd
	r1 += mi.modulus.v[1] & condAdd
	r2 += mi.modulus.v[2] & condAdd
	r3 += mi.modulus.v[3] & condAdd
	r4 += mi.modulus.v[4] & condAdd

	condNeg := sign >> 63
	r0 = (r0 ^ condNeg) - condNeg
	r1 = (r1 ^ condNeg) - condNeg
	r2 = (r2 ^ condNeg) - condNeg
	r3 = (r3 ^ condNeg) - condNeg
	r4 = (r4 ^ condNeg) - condNeg
	r1 += r0 >> 62
	r0 &= m62
	r2 += r1 >> 62
	r1 &= m62
	r3 += r2 >> 62
	r2 &= m62
	r4 += r3 >> 62
	r3 &= m62

	condAdd = r4 >> 63
	r0 += mi.modulus.v[0] & condAdd
	r1 += mi.modulus.v[1] & condAdd
	r2 += mi.modulus.v[2] & condAdd
	r3 += mi.modulus.v[3] & condAdd
	r4 += mi.modulus.v[4] & condAdd
	r1 += r0 >> 62
	r0 &= m62
	r2 += r1 >> 62
	r1 &= m62
	r3 += r2 >> 62
	r2 &= m62
	r4 += r3 >> 62
	r3 &= m62

	r.v[0], r.v[1], r.v[2], r.v[3], r.v[4] = r0, r1, r2, r3, r4
}

// invVar replaces x, reduced and in signed62 form, with its inverse
// modulo the modInfo modulus, or with zero when x is zero.
func (mi *modInfo) invVar(x *signed62) {
	var d, e signed62
	e.v[0] = 1
	f := mi.modulus
	g := *x
	length := 5
	eta := int64(-1)
	for {
		var t trans2x2
		eta = divsteps62Var(eta, uint64(f.v[0]), uint64(g.v[0]), &t)
		modinvUpdate(&d, &e, &f, &g, &t, mi, length)
		if g.v[0] == 0 {
			cond := int64(0)
			for j := 1; j < length; j++ {
				cond |= g.v[j]
			}
			if cond == 0 {
				break
			}
		}

		// Shrink the working length when the top limbs hold only sign
		// extension bits.
		fn, gn := f.v[length-1], g.v[length-1]
		cond := int64(length-2) >> 63
		cond |= fn ^ (fn >> 63)
		cond |= gn ^ (gn >> 63)
		if cond == 0 {
			f.v[length-2] |= fn << 62
			g.v[length-2] |= gn << 62
			length--
		}
	}
	normalize62(&d, f.v[length-1], mi)
	*x = d
}

// ScalarInverse replaces s with its multiplicative inverse modulo the
// group order in variable time. A zero scalar stays zero.
func ScalarInverse(s *secp.ModNScalar) {
	b := s.Bytes()
	x := signed62FromBytes(&b)
	scalarModInfo.invVar(&x)
	nb := x.bytes()
	s.SetBytes(&nb)
}

// FieldInverse returns the multiplicative inverse of the canonical field
// element b modulo the field prime in variable time. Zero maps to zero.
func FieldInverse(b [32]byte) [32]byte {
	x := signed62FromBytes(&b)
	fieldModInfo.invVar(&x)
	return x.bytes()
}
