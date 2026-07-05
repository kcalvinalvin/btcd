// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package fastverify

import (
	"bytes"
	"crypto/rand"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// canonical reduces raw bytes to a canonical field element encoding using
// dcrec as the reference implementation.
func canonical(t testing.TB, raw []byte) [32]byte {
	t.Helper()
	var fv secp.FieldVal
	fv.SetByteSlice(raw)
	fv.Normalize()
	var out [32]byte
	fv.PutBytesUnchecked(out[:])
	return out
}

func fixedVectors(t *testing.T) [][32]byte {
	t.Helper()
	pMinus1 := [32]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2e,
	}
	return [][32]byte{
		{},                  // zero
		{31: 0x01},          // one
		{31: 0x02},          // two
		pMinus1,             // p - 1
		{0: 0xff, 31: 0xff}, // high and low bits set
		canonical(t, bytes.Repeat([]byte{0xff}, 32)), // 2^256-1 mod p
	}
}

func TestFieldMulSquareMatchDcrec(t *testing.T) {
	check := func(aB, bB [32]byte) {
		t.Helper()
		var da, db, dr secp.FieldVal
		da.SetByteSlice(aB[:])
		db.SetByteSlice(bB[:])
		dr.Mul2(&da, &db)
		dr.Normalize()
		var want [32]byte
		dr.PutBytesUnchecked(want[:])

		var sa, sb, sr Fe
		sa.SetBytes(&aB)
		sb.SetBytes(&bB)
		sr.Mul(&sa, &sb)
		if got := sr.Bytes(); got != want {
			t.Fatalf("mul mismatch\n a=%x\n b=%x\ngot=%x\nwant=%x", aB, bB, got, want)
		}

		var ds secp.FieldVal
		ds.SquareVal(&da)
		ds.Normalize()
		var wantSq [32]byte
		ds.PutBytesUnchecked(wantSq[:])
		var ss Fe
		ss.Square(&sa)
		if gotSq := ss.Bytes(); gotSq != wantSq {
			t.Fatalf("square mismatch\n a=%x\ngot=%x\nwant=%x", aB, gotSq, wantSq)
		}
	}

	fixed := fixedVectors(t)
	for _, a := range fixed {
		for _, b := range fixed {
			check(a, b)
		}
	}

	var raw [64]byte
	for i := 0; i < 20000; i++ {
		if _, err := rand.Read(raw[:]); err != nil {
			t.Fatal(err)
		}
		check(canonical(t, raw[:32]), canonical(t, raw[32:]))
	}
}

// TestFieldLooseChain verifies that repeated multiplications in loose form
// stay correct, exercising the limb bounds the loose representation relies
// on.
func TestFieldLooseChain(t *testing.T) {
	var raw [64]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	aB := canonical(t, raw[:32])
	bB := canonical(t, raw[32:])

	var da, db secp.FieldVal
	da.SetByteSlice(aB[:])
	db.SetByteSlice(bB[:])
	var sa, sb Fe
	sa.SetBytes(&aB)
	sb.SetBytes(&bB)

	for i := 0; i < 10000; i++ {
		da.Mul2(&da, &db)
		da.Normalize()
		sa.Mul(&sa, &sb)

		db.SquareVal(&db)
		db.Normalize()
		sb.Square(&sb)
	}
	da.Normalize()
	db.Normalize()
	var wantA, wantB [32]byte
	da.PutBytesUnchecked(wantA[:])
	db.PutBytesUnchecked(wantB[:])
	if gotA := sa.Bytes(); gotA != wantA {
		t.Fatalf("chain mismatch a: got %x want %x", gotA, wantA)
	}
	if gotB := sb.Bytes(); gotB != wantB {
		t.Fatalf("chain mismatch b: got %x want %x", gotB, wantB)
	}
}

func TestFieldAddNegateMulInt(t *testing.T) {
	check := func(aB, bB [32]byte) {
		t.Helper()
		var da, db secp.FieldVal
		da.SetByteSlice(aB[:])
		db.SetByteSlice(bB[:])
		var sa, sb Fe
		sa.SetBytes(&aB)
		sb.SetBytes(&bB)

		// Add.
		dSum := da
		dSum.Add(&db)
		dSum.Normalize()
		var want [32]byte
		dSum.PutBytesUnchecked(want[:])
		sSum := sa
		sSum.Add(&sb)
		if got := sSum.Bytes(); got != want {
			t.Fatalf("add mismatch a=%x b=%x got=%x want=%x", aB, bB, got, want)
		}

		// Negate of a normalized value (magnitude 1).
		dNeg := da
		dNeg.Negate(1)
		dNeg.Normalize()
		dNeg.PutBytesUnchecked(want[:])
		sNeg := sa
		sNeg.Negate(1)
		if got := sNeg.Bytes(); got != want {
			t.Fatalf("negate mismatch a=%x got=%x want=%x", aB, got, want)
		}

		// MulInt for the small constants the group law uses.
		for v := uint64(2); v <= 8; v++ {
			dMi := da
			dMi.MulInt(uint8(v))
			dMi.Normalize()
			dMi.PutBytesUnchecked(want[:])
			sMi := sa
			sMi.MulInt(v)
			if got := sMi.Bytes(); got != want {
				t.Fatalf("mulint %d mismatch a=%x got=%x want=%x", v, aB, got, want)
			}
		}
	}

	fixed := fixedVectors(t)
	for _, a := range fixed {
		for _, b := range fixed {
			check(a, b)
		}
	}
	var raw [64]byte
	for i := 0; i < 5000; i++ {
		if _, err := rand.Read(raw[:]); err != nil {
			t.Fatal(err)
		}
		check(canonical(t, raw[:32]), canonical(t, raw[32:]))
	}
}

func TestFieldInverse(t *testing.T) {
	// Zero inverts to zero by the Fermat convention.
	var zero Fe
	var zInv Fe
	zInv.Inverse(&zero)
	if got := zInv.Bytes(); got != ([32]byte{}) {
		t.Fatalf("inverse of zero: got %x want zero", got)
	}

	check := func(aB [32]byte) {
		t.Helper()
		var da secp.FieldVal
		da.SetByteSlice(aB[:])
		da.Inverse()
		da.Normalize()
		var want [32]byte
		da.PutBytesUnchecked(want[:])

		var sa, sInv Fe
		sa.SetBytes(&aB)
		sInv.Inverse(&sa)
		if got := sInv.Bytes(); got != want {
			t.Fatalf("inverse mismatch a=%x got=%x want=%x", aB, got, want)
		}

		// a * a^-1 must be one for nonzero a.
		var one Fe
		one.Mul(&sa, &sInv)
		oneB := one.Bytes()
		wantOne := [32]byte{31: 0x01}
		if aB != ([32]byte{}) && oneB != wantOne {
			t.Fatalf("a*a^-1 != 1 for a=%x: got %x", aB, oneB)
		}
	}

	for _, a := range fixedVectors(t)[1:] { // skip zero, handled above
		check(a)
	}
	var raw [32]byte
	for i := 0; i < 500; i++ {
		if _, err := rand.Read(raw[:]); err != nil {
			t.Fatal(err)
		}
		check(canonical(t, raw[:]))
	}
}

var (
	benchSinkFe    Fe
	benchSinkDcrec secp.FieldVal
)

func benchFieldOperands(b *testing.B) (secp.FieldVal, secp.FieldVal, Fe, Fe) {
	b.Helper()
	var raw [64]byte
	if _, err := rand.Read(raw[:]); err != nil {
		b.Fatal(err)
	}
	var aB, bB [32]byte
	copy(aB[:], raw[:32])
	copy(bB[:], raw[32:])
	aB[0] &= 0x7f
	bB[0] &= 0x7f
	var da, db secp.FieldVal
	da.SetByteSlice(aB[:])
	db.SetByteSlice(bB[:])
	var sa, sb Fe
	sa.SetBytes(&aB)
	sb.SetBytes(&bB)
	return da, db, sa, sb
}

func BenchmarkFieldMulDcrec(b *testing.B) {
	da, db, _, _ := benchFieldOperands(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSinkDcrec.Mul2(&da, &db)
	}
}

func BenchmarkFieldMul(b *testing.B) {
	_, _, sa, sb := benchFieldOperands(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSinkFe.Mul(&sa, &sb)
	}
}

func BenchmarkFieldSquareDcrec(b *testing.B) {
	da, _, _, _ := benchFieldOperands(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSinkDcrec.SquareVal(&da)
	}
}

func BenchmarkFieldSquare(b *testing.B) {
	_, _, sa, _ := benchFieldOperands(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSinkFe.Square(&sa)
	}
}

func BenchmarkFieldInverseDcrec(b *testing.B) {
	da, _, _, _ := benchFieldOperands(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSinkDcrec = da
		benchSinkDcrec.Inverse()
	}
}

func BenchmarkFieldInverse(b *testing.B) {
	_, _, sa, _ := benchFieldOperands(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSinkFe.Inverse(&sa)
	}
}
