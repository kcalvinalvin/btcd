// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build amd64 && !purego

package r52

import "testing"

// checkWeak52 fails the test unless every limb of f is below 2^52 with
// the top limb on the weak normalized 2^48 scale.
func checkWeak52(t *testing.T, name string, f *fe) {
	t.Helper()
	for i := 0; i < 4; i++ {
		if f.n[i] > m52 {
			t.Fatalf("%s limb %d out of range: %x", name, i, f.n[i])
		}
	}
	if f.n[4] > m48+1 {
		t.Fatalf("%s top limb out of range: %x", name, f.n[4])
	}
}

// checkSameValue fails the test unless the two field elements reduce to
// the same canonical value.
func checkSameValue(t *testing.T, name string, got, want *fe) {
	t.Helper()
	g, w := *got, *want
	g.Normalize()
	w.Normalize()
	if g.n != w.n {
		t.Fatalf("%s mismatch\ngot  %x\nwant %x", name, g.n, w.n)
	}
}

// TestJacDoubleIFMAMatchesGeneric verifies the fused IFMA doubling against
// doubleGeneric on random points, through long dependent chains, aliased,
// and on coordinate bound edges.
func TestJacDoubleIFMAMatchesGeneric(t *testing.T) {
	if !hasIFMA {
		t.Skip("no AVX-512 IFMA support")
	}

	for i := 0; i < 20000; i++ {
		p := randomDcrecPoint(t)
		jp := fromDcrecJacobian(t, &p)

		var want, got jacobianPoint
		doubleGeneric(&want, &jp)
		if ret := jacDoubleIFMA(&got, &jp); ret != 0 {
			t.Fatalf("unexpected bail on random point %d", i)
		}
		checkSameValue(t, "X", &got.X, &want.X)
		checkSameValue(t, "Y", &got.Y, &want.Y)
		checkSameValue(t, "Z", &got.Z, &want.Z)
		checkWeak52(t, "X", &got.X)
		checkWeak52(t, "Y", &got.Y)
		checkWeak52(t, "Z", &got.Z)

		// Aliased in place.
		aliased := jp
		if ret := jacDoubleIFMA(&aliased, &aliased); ret != 0 {
			t.Fatalf("unexpected bail on aliased point %d", i)
		}
		checkSameValue(t, "aliased X", &aliased.X, &want.X)
		checkSameValue(t, "aliased Y", &aliased.Y, &want.Y)
		checkSameValue(t, "aliased Z", &aliased.Z, &want.Z)
	}

	// Long dependent chains surface any drift between the loose forms the
	// two implementations feed back into themselves.
	p := randomDcrecPoint(t)
	gen := fromDcrecJacobian(t, &p)
	ifma := gen
	for i := 0; i < 50000; i++ {
		doubleGeneric(&gen, &gen)
		if ret := jacDoubleIFMA(&ifma, &ifma); ret != 0 {
			t.Fatalf("unexpected bail in chain step %d", i)
		}
		checkSameValue(t, "chain X", &ifma.X, &gen.X)
		checkSameValue(t, "chain Y", &ifma.Y, &gen.Y)
		checkSameValue(t, "chain Z", &ifma.Z, &gen.Z)
		checkWeak52(t, "chain X", &ifma.X)
		checkWeak52(t, "chain Y", &ifma.Y)
		checkWeak52(t, "chain Z", &ifma.Z)
	}

	// Coordinate bound edges: weak normalized forms with limbs at their
	// maxima are valid inputs even though random walks rarely reach them.
	edge := []fe{
		{n: [5]uint64{m52, m52, m52, m52, m48}},
		{n: [5]uint64{m52, m52, m52, m52, m48 + 1}},
		{n: [5]uint64{fieldC - 1, 0, 0, 0, 0}},
		{n: [5]uint64{1, 0, 0, 0, 0}},
	}
	for _, x := range edge {
		for _, y := range edge {
			for _, z := range edge {
				jp := jacobianPoint{X: x, Y: y, Z: z}
				var want, got jacobianPoint
				doubleGeneric(&want, &jp)
				if ret := jacDoubleIFMA(&got, &jp); ret != 0 {
					// A bail is allowed on adversarial edges, just not a
					// wrong result.
					continue
				}
				checkSameValue(t, "edge X", &got.X, &want.X)
				checkSameValue(t, "edge Y", &got.Y, &want.Y)
				checkSameValue(t, "edge Z", &got.Z, &want.Z)
			}
		}
	}
}

func BenchmarkJacDoubleIFMA(b *testing.B) {
	if !hasIFMA {
		b.Skip("no AVX-512 IFMA support")
	}
	p := randomDcrecPoint(b)
	jp := fromDcrecJacobian(b, &p)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if jacDoubleIFMA(&jp, &jp) != 0 {
			b.Fatal("bail")
		}
	}
	if jp.X.n[0] == 0 {
		b.Log("sink")
	}
}

func BenchmarkJacDoubleIFMAIndep2(b *testing.B) {
	if !hasIFMA {
		b.Skip("no AVX-512 IFMA support")
	}
	p1 := randomDcrecPoint(b)
	p2 := randomDcrecPoint(b)
	jp1 := fromDcrecJacobian(b, &p1)
	jp2 := fromDcrecJacobian(b, &p2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if jacDoubleIFMA(&jp1, &jp1) != 0 {
			b.Fatal("bail")
		}
		if jacDoubleIFMA(&jp2, &jp2) != 0 {
			b.Fatal("bail")
		}
	}
	if jp1.X.n[0] == jp2.X.n[0] {
		b.Log("sink")
	}
}
