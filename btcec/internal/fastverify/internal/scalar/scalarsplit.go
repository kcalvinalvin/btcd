// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package scalar

import (
	"math/bits"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// GLV endomorphism decomposition. The secp256k1 group has an efficiently
// computable endomorphism phi(x, y) = (beta*x, y) acting as multiplication
// by lambda, a cube root of unity mod the group order n. Any scalar k
// decomposes as k = k1 + k2*lambda (mod n) with both halves having signed
// magnitude below 2^129, halving the doublings in a double-scalar
// multiplication.
//
// The decomposition uses the standard lattice basis for secp256k1:
//
//	v1 = (a1, b1),  a1 = 0x3086D221A7D46BCDE86C90E49284EB15
//	                b1 = -0xE4437ED6010E88286F547FA90ABFE4C3
//	v2 = (a2, b2),  a2 = 0x114CA50F7A8E2F3F657C1108D9D44CFD8
//	                b2 = a1
//
// with a + b*lambda = 0 (mod n) for both vectors and determinant exactly n.
// The rounded projections are computed as c_i = round(k * g_i / 2^384)
// where g1 = round(2^384 * b2 / n) and g2 = round(2^384 * (-b1) / n), then
//
//	k1 = k - c1*a1 - c2*a2 (mod n)
//	k2 = -c1*b1 - c2*b2    (mod n)

// mustScalar parses a big-endian hex constant into a scalar.
func mustScalar(s string) secp.ModNScalar {
	var out secp.ModNScalar
	var buf [32]byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		default:
			panic("invalid hex in scalar constant")
		}
		idx := 32 - (len(s)-i+1)/2
		if (len(s)-i)%2 == 0 {
			buf[idx] |= v << 4
		} else {
			buf[idx] |= v
		}
	}
	if overflow := out.SetBytes(&buf); overflow != 0 {
		panic("scalar constant overflows the group order")
	}
	return out
}

var (
	endoA1  = mustScalar("3086d221a7d46bcde86c90e49284eb15")
	endoB1N = mustScalar("e4437ed6010e88286f547fa90abfe4c3") // -b1
	endoA2  = mustScalar("114ca50f7a8e2f3f657c1108d9d44cfd8")

	// endoG1 and endoG2 are round(2^384 * b2 / n) and
	// round(2^384 * (-b1) / n) as little-endian 64-bit words.
	endoG1 = [4]uint64{0xE893209A45DBB031, 0x3DAA8A1471E8CA7F, 0xE86C90E49284EB15, 0x3086D221A7D46BCD}
	endoG2 = [4]uint64{0x1571B4AE8AC47F71, 0x221208AC9DF506C6, 0x6F547FA90ABFE4C4, 0xE4437ED6010E8828}
)

// scalarWords converts a scalar to little-endian 64-bit words.
func scalarWords(s *secp.ModNScalar) [4]uint64 {
	b := s.Bytes()
	var w [4]uint64
	for i := 0; i < 4; i++ {
		off := 24 - 8*i
		w[i] = uint64(b[off])<<56 | uint64(b[off+1])<<48 |
			uint64(b[off+2])<<40 | uint64(b[off+3])<<32 |
			uint64(b[off+4])<<24 | uint64(b[off+5])<<16 |
			uint64(b[off+6])<<8 | uint64(b[off+7])
	}
	return w
}

// mulShift384Round returns round(a * g / 2^384) for 256-bit a and g, which
// is below 2^129 for the constants above.
func mulShift384Round(a, g [4]uint64) (lo, hi uint64) {
	// Schoolbook 4x4 into 8 words.
	var prod [8]uint64
	for i := 0; i < 4; i++ {
		var carry uint64
		for j := 0; j < 4; j++ {
			h, l := bits.Mul64(a[i], g[j])
			var c uint64
			l, c = bits.Add64(l, carry, 0)
			h += c
			prod[i+j], c = bits.Add64(prod[i+j], l, 0)
			carry = h + c
		}
		prod[i+4] += carry
	}

	// Round at bit 383 (bit 63 of word 5), then shift by 384.
	var c uint64
	_, c = bits.Add64(prod[5], 1<<63, 0)
	lo, c = bits.Add64(prod[6], 0, c)
	hi, _ = bits.Add64(prod[7], 0, c)
	return lo, hi
}

// wordsToScalar converts a value below 2^130 to a scalar.
func wordsToScalar(lo, hi uint64) secp.ModNScalar {
	var b [32]byte
	for i := 0; i < 8; i++ {
		b[31-i] = byte(lo >> (8 * i))
		b[23-i] = byte(hi >> (8 * i))
	}
	var s secp.ModNScalar
	s.SetBytes(&b)
	return s
}

// SplitK decomposes k into k1 + k2*lambda (mod n) with both halves of
// signed magnitude below 2^129.
func SplitK(k *secp.ModNScalar) (k1, k2 secp.ModNScalar) {
	kw := scalarWords(k)
	c1 := func() secp.ModNScalar { lo, hi := mulShift384Round(kw, endoG1); return wordsToScalar(lo, hi) }()
	c2 := func() secp.ModNScalar { lo, hi := mulShift384Round(kw, endoG2); return wordsToScalar(lo, hi) }()

	// k1 = k - c1*a1 - c2*a2
	t1 := c1
	t1.Mul(&endoA1)
	t2 := c2
	t2.Mul(&endoA2)
	t1.Add(&t2)
	t1.Negate()
	k1 = *k
	k1.Add(&t1)

	// k2 = c1*(-b1) - c2*b2, with b2 = a1.
	k2 = c1
	k2.Mul(&endoB1N)
	t2 = c2
	t2.Mul(&endoA1)
	t2.Negate()
	k2.Add(&t2)
	return k1, k2
}

// MaxWNAFLen bounds the digit count of a width 5 wNAF of a 130-bit value.
const MaxWNAFLen = 132

// SignedSmall extracts the sign and the magnitude words of a scalar whose
// signed magnitude is known to be below 2^130.
func SignedSmall(s *secp.ModNScalar) (neg bool, w [3]uint64) {
	t := *s
	if t.IsOverHalfOrder() {
		t.Negate()
		neg = true
	}
	b := t.Bytes()
	for i := 0; i < 8; i++ {
		w[0] |= uint64(b[31-i]) << (8 * i)
		w[1] |= uint64(b[23-i]) << (8 * i)
		w[2] |= uint64(b[15-i]) << (8 * i)
	}
	return neg, w
}

// WNAF5 computes the width 5 non-adjacent form of the value in w, least
// significant digit first. Digits are zero or odd with magnitude at most
// 15, and no two adjacent digits are both nonzero.
func WNAF5(w [3]uint64) (digits [MaxWNAFLen]int8, length int) {
	for w[0]|w[1]|w[2] != 0 {
		var d int8
		if w[0]&1 == 1 {
			m := w[0] & 31
			if m > 16 {
				d = int8(m) - 32
				// Add |d| back: w -= d with d negative.
				var c uint64
				w[0], c = bits.Add64(w[0], uint64(-d), 0)
				w[1], c = bits.Add64(w[1], 0, c)
				w[2], _ = bits.Add64(w[2], 0, c)
			} else {
				d = int8(m)
				var brw uint64
				w[0], brw = bits.Sub64(w[0], uint64(d), 0)
				w[1], brw = bits.Sub64(w[1], 0, brw)
				w[2], _ = bits.Sub64(w[2], 0, brw)
			}
		}
		digits[length] = d
		length++
		w[0] = w[0]>>1 | w[1]<<63
		w[1] = w[1]>>1 | w[2]<<63
		w[2] >>= 1
	}
	return digits, length
}
