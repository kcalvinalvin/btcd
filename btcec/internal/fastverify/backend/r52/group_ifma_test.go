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

// TestJacAddMixedIFMAMatchesGeneric verifies the IFMA mixed addition
// against addMixedGeneric on random points, dependent chains, aliasing,
// and the degenerate shared-x cases, which must bail rather than write.
func TestJacAddMixedIFMAMatchesGeneric(t *testing.T) {
	if !hasIFMA {
		t.Skip("no AVX-512 IFMA support")
	}

	for i := 0; i < 20000; i++ {
		q1 := randomDcrecPoint(t)
		q2 := randomDcrecPoint(t)
		jp := fromDcrecJacobian(t, &q1)
		jq := fromDcrecJacobian(t, &q2)
		ab := jq.ToAffine()

		var want, got jacobianPoint
		addMixedGeneric(&want, &jp, &ab)
		if ret := jacAddMixedIFMA(&got, &jp, &ab); ret != 0 {
			t.Fatalf("unexpected bail on random pair %d", i)
		}
		checkSameValue(t, "X", &got.X, &want.X)
		checkSameValue(t, "Y", &got.Y, &want.Y)
		checkSameValue(t, "Z", &got.Z, &want.Z)
		checkWeak52(t, "X", &got.X)
		checkWeak52(t, "Y", &got.Y)
		checkWeak52(t, "Z", &got.Z)

		aliased := jp
		if ret := jacAddMixedIFMA(&aliased, &aliased, &ab); ret != 0 {
			t.Fatalf("unexpected bail on aliased pair %d", i)
		}
		checkSameValue(t, "aliased X", &aliased.X, &want.X)
		checkSameValue(t, "aliased Y", &aliased.Y, &want.Y)
		checkSameValue(t, "aliased Z", &aliased.Z, &want.Z)
	}

	// A dependent chain akin to the ladder: acc = acc + b each step.
	q1 := randomDcrecPoint(t)
	q2 := randomDcrecPoint(t)
	gen := fromDcrecJacobian(t, &q1)
	jq := fromDcrecJacobian(t, &q2)
	ab := jq.ToAffine()
	ifma := gen
	for i := 0; i < 50000; i++ {
		addMixedGeneric(&gen, &gen, &ab)
		if ret := jacAddMixedIFMA(&ifma, &ifma, &ab); ret != 0 {
			t.Fatalf("unexpected bail in chain step %d", i)
		}
		checkSameValue(t, "chain X", &ifma.X, &gen.X)
		checkSameValue(t, "chain Y", &ifma.Y, &gen.Y)
		checkSameValue(t, "chain Z", &ifma.Z, &gen.Z)
	}

	// Degenerate shared-x cases must bail: doubling (a == b lifted) and
	// inverses summing to infinity, both with Z1 = 1 and with random Z.
	for i := 0; i < 200; i++ {
		q := randomDcrecPoint(t)
		q.ToAffine()
		qScaled := rescale(t, &q)
		qAffine := fromDcrecJacobian(t, &q)
		ab := affinePoint{X: qAffine.X, Y: qAffine.Y}
		var sameAffine jacobianPoint
		sameAffine.SetAffine(&ab)
		sameScaled := fromDcrecJacobian(t, &qScaled)

		cases := []struct {
			name  string
			point jacobianPoint
		}{
			{name: "affine", point: sameAffine},
			{name: "scaled", point: sameScaled},
		}
		for _, test := range cases {
			name, same := test.name, test.point
			sentinel := fromDcrecJacobian(t, &qScaled)
			out := sentinel
			if ret := jacAddMixedIFMA(&out, &same, &ab); ret == 0 {
				t.Fatalf("missed %s doubling degenerate %d", name, i)
			}
			if out != sentinel {
				t.Fatalf("%s doubling bail wrote output %d", name, i)
			}

			inverse := same
			inverse.Y.normalizeWeak()
			inverse.Y.Negate(1)
			inverse.Y.normalizeWeak()
			out = sentinel
			if ret := jacAddMixedIFMA(&out, &inverse, &ab); ret == 0 {
				t.Fatalf("missed %s infinity degenerate %d", name, i)
			}
			if out != sentinel {
				t.Fatalf("%s infinity bail wrote output %d", name, i)
			}
		}
	}
}

func BenchmarkJacAddMixedIFMA(b *testing.B) {
	if !hasIFMA {
		b.Skip("no AVX-512 IFMA support")
	}
	q1 := randomDcrecPoint(b)
	q2 := randomDcrecPoint(b)
	jp := fromDcrecJacobian(b, &q1)
	jq := fromDcrecJacobian(b, &q2)
	ab := jq.ToAffine()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if jacAddMixedIFMA(&jp, &jp, &ab) != 0 {
			b.Fatal("bail")
		}
	}
	if jp.X.n[0] == 0 {
		b.Log("sink")
	}
}
