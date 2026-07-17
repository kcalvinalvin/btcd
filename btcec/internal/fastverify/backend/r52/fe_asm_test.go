// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build amd64 && !purego

package r52

import (
	"crypto/rand"
	"encoding/binary"
	"testing"
)

// looseFe returns a field element with limbs drawn from the full loose
// input range accepted by Mul and Square: limbs 0..3 below 2^56 and limb 4
// below 2^49.
func looseFe(t testing.TB) fe {
	t.Helper()
	var raw [40]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	var f fe
	for i := 0; i < 4; i++ {
		f.n[i] = binary.LittleEndian.Uint64(raw[8*i:]) & (1<<56 - 1)
	}
	f.n[4] = binary.LittleEndian.Uint64(raw[32:]) & (1<<49 - 1)
	return f
}

// TestFeAsmMatchesGeneric verifies that feMul and feSquare produce
// bit-identical limbs to the portable implementations across the whole loose
// input range, including aliased outputs.
func TestFeAsmMatchesGeneric(t *testing.T) {
	for i := 0; i < 200000; i++ {
		a := looseFe(t)
		b := looseFe(t)

		var got, want fe
		feMul(&got, &a, &b)
		mulGeneric(&want, &a, &b)
		if got.n != want.n {
			t.Fatalf("mul limb mismatch\n a=%x\n b=%x\ngot=%x\nwant=%x",
				a.n, b.n, got.n, want.n)
		}

		feSquare(&got, &a)
		squareGeneric(&want, &a)
		if got.n != want.n {
			t.Fatalf("square limb mismatch\n a=%x\ngot=%x\nwant=%x",
				a.n, got.n, want.n)
		}

		// Aliased forms.
		gotA := a
		feMul(&gotA, &gotA, &b)
		mulGeneric(&want, &a, &b)
		if gotA.n != want.n {
			t.Fatalf("mul alias r=a mismatch a=%x b=%x", a.n, b.n)
		}
		gotB := b
		feMul(&gotB, &a, &gotB)
		if gotB.n != want.n {
			t.Fatalf("mul alias r=b mismatch a=%x b=%x", a.n, b.n)
		}
		gotS := a
		feSquare(&gotS, &gotS)
		squareGeneric(&want, &a)
		if gotS.n != want.n {
			t.Fatalf("square alias mismatch a=%x", a.n)
		}
	}

	// Edge limbs: all zero, all at the loose bound, and single hot limbs.
	edges := []fe{
		{},
		{n: [5]uint64{1<<56 - 1, 1<<56 - 1, 1<<56 - 1, 1<<56 - 1, 1<<49 - 1}},
		{n: [5]uint64{1<<56 - 1, 0, 0, 0, 0}},
		{n: [5]uint64{0, 0, 0, 0, 1<<49 - 1}},
		{n: [5]uint64{1, 0, 0, 0, 0}},
	}
	for _, a := range edges {
		for _, b := range edges {
			var got, want fe
			feMul(&got, &a, &b)
			mulGeneric(&want, &a, &b)
			if got.n != want.n {
				t.Fatalf("edge mul mismatch a=%x b=%x", a.n, b.n)
			}
			feSquare(&got, &a)
			squareGeneric(&want, &a)
			if got.n != want.n {
				t.Fatalf("edge square mismatch a=%x", a.n)
			}
		}
	}
}

func BenchmarkFeMulGeneric(b *testing.B) {
	x := looseFe(b)
	y := looseFe(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mulGeneric(&benchSinkFe, &x, &y)
	}
}

func BenchmarkFeSquareGeneric(b *testing.B) {
	x := looseFe(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		squareGeneric(&benchSinkFe, &x)
	}
}
