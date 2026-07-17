// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package r52

import (
	"crypto/rand"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func TestFieldInverse(t *testing.T) {
	var zero, zeroInverse fe
	zeroInverse.Inverse(&zero)
	if got := zeroInverse.Bytes(); got != ([32]byte{}) {
		t.Fatalf("inverse of zero: got %x want zero", got)
	}

	check := func(aBytes [32]byte) {
		t.Helper()

		var reference secp.FieldVal
		reference.SetByteSlice(aBytes[:])
		reference.Inverse()
		reference.Normalize()
		var want [32]byte
		reference.PutBytesUnchecked(want[:])

		var a, inverse fe
		a.SetBytes(&aBytes)
		inverse.Inverse(&a)
		if got := inverse.Bytes(); got != want {
			t.Fatalf("inverse mismatch a=%x got=%x want=%x", aBytes, got, want)
		}

		var product fe
		product.Mul(&a, &inverse)
		wantOne := [32]byte{31: 1}
		if aBytes != ([32]byte{}) && product.Bytes() != wantOne {
			t.Fatalf("a*a^-1 != 1 for a=%x: got %x", aBytes, product.Bytes())
		}
	}

	for _, a := range fixedVectors(t)[1:] {
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

func BenchmarkFieldInverseDcrec(b *testing.B) {
	a, _, _, _ := benchFieldOperands(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSinkDcrec = a
		benchSinkDcrec.Inverse()
	}
}

func BenchmarkFieldInverse(b *testing.B) {
	_, _, a, _ := benchFieldOperands(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSinkFe.Inverse(&a)
	}
}
