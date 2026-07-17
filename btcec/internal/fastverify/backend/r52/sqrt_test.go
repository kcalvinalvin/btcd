// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package r52

import (
	"fmt"
	"math/rand"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func checkSqrt(t *testing.T, name string, value [32]byte) {
	t.Helper()
	var reference, referenceRoot secp.FieldVal
	reference.SetBytes(&value)
	wantOK := referenceRoot.SquareRootVal(&reference)

	var input fe
	input.SetBytes(&value)
	var root fe
	root.SetUint64(42)
	before := root
	gotOK := feSqrt(&root, &input)
	if gotOK != wantOK {
		t.Fatalf("%s: residue mismatch: got %v want %v",
			name, gotOK, wantOK)
	}
	if !gotOK {
		if root != before {
			t.Fatalf("%s: failure modified the output", name)
		}
		return
	}

	referenceRoot.Normalize()
	var want [32]byte
	referenceRoot.PutBytesUnchecked(want[:])
	if got := root.Bytes(); got != want {
		t.Fatalf("%s: root mismatch: got %x want %x", name, got, want)
	}
	var square fe
	square.Square(&root)
	if got := square.Bytes(); got != value {
		t.Fatalf("%s: root squared to %x want %x", name, got, value)
	}
}

func TestFeSqrtDifferential(t *testing.T) {
	for i, value := range fixedVectors(t) {
		checkSqrt(t, fmt.Sprintf("fixed %d", i), value)
	}

	rng := rand.New(rand.NewSource(0x5ec256))
	for i := 0; i < 5000; i++ {
		var raw [32]byte
		_, _ = rng.Read(raw[:])
		checkSqrt(t, fmt.Sprintf("random %d", i), canonical(t, raw[:]))
	}
}

func TestFeSqrtLooseInput(t *testing.T) {
	// p+1 is a valid loose representation of one.
	var loose fe
	for i := range loose.n {
		loose.n[i] = twoP[i] / 2
	}
	loose.n[0]++

	var root fe
	if !feSqrt(&root, &loose) {
		t.Fatal("square root rejected loose representation of one")
	}
	want := [32]byte{31: 1}
	if got := root.Bytes(); got != want {
		t.Fatalf("loose square root: got %x want %x", got, want)
	}
}
