// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package modinv

import (
	"crypto/rand"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func randScalar(t testing.TB) secp.ModNScalar {
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
	return k
}

func BenchmarkScalarInverseDcrec(b *testing.B) {
	k := randScalar(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := k
		w.InverseNonConst()
	}
}

func scalarFromBytes(t *testing.T, b [32]byte) secp.ModNScalar {
	t.Helper()
	var k secp.ModNScalar
	k.SetBytes(&b)
	return k
}

// TestScalarInverseVarMatchesDcrec verifies the divsteps inverse against
// the dcrec inverse on random scalars and structural edges.
func TestScalarInverseVarMatchesDcrec(t *testing.T) {
	check := func(k secp.ModNScalar) {
		t.Helper()
		want := k
		want.InverseNonConst()
		got := k
		ScalarInverse(&got)
		if !got.Equals(&want) {
			t.Fatalf("inverse mismatch for %x:\ngot  %x\nwant %x",
				k.Bytes(), got.Bytes(), want.Bytes())
		}
		// And the defining property.
		prod := got
		prod.Mul(&k)
		var one secp.ModNScalar
		one.SetInt(1)
		if !k.IsZero() && !prod.Equals(&one) {
			t.Fatalf("k * inv(k) != 1 for %x", k.Bytes())
		}
	}

	for i := 0; i < 100000; i++ {
		check(randScalar(t))
	}

	// Edges: tiny values, values with long runs, boundary values.
	check(secp.ModNScalar{})
	var k secp.ModNScalar
	for _, v := range []uint32{1, 2, 3, 15, 16, 255, 65537} {
		k.SetInt(v)
		check(k)
	}
	nMinus1 := [32]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
		0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
		0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40,
	}
	check(scalarFromBytes(t, nMinus1))
	for bit := 0; bit < 256; bit++ {
		var b [32]byte
		b[31-bit/8] = 1 << (bit % 8)
		check(scalarFromBytes(t, b))
		for j := range b {
			b[j] = 0xFF
		}
		b[31-bit/8] ^= 1 << (bit % 8)
		check(scalarFromBytes(t, b))
	}
}

func BenchmarkScalarInverseVar(b *testing.B) {
	k := randScalar(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := k
		ScalarInverse(&w)
	}
}
