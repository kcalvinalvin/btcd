// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build amd64 && !purego

package modinv

import (
	"fmt"
	"math/rand"
	"testing"
)

func modinvParityInputs(mi *modInfo) []signed62 {
	inputs := []signed62{{}}

	var one signed62
	one.v[0] = 1
	inputs = append(inputs, one)

	modMinusOne := mi.modulus
	modMinusOne.v[0]--
	inputs = append(inputs, modMinusOne)

	for bit := 0; bit < 256; bit++ {
		var raw [32]byte
		raw[31-bit/8] = 1 << uint(bit%8)
		inputs = append(inputs, signed62FromBytes(&raw))
	}

	// Keeping the top byte zero makes every value less than both moduli.
	rng := rand.New(rand.NewSource(0x5ec256))
	for i := 0; i < 256; i++ {
		var raw [32]byte
		_, _ = rng.Read(raw[1:])
		inputs = append(inputs, signed62FromBytes(&raw))
	}
	return inputs
}

func modinvTraceDone(g *signed62, length int) bool {
	if g.v[0] != 0 {
		return false
	}
	var rest int64
	for i := 1; i < length; i++ {
		rest |= g.v[i]
	}
	return rest == 0
}

func shrinkModinvTrace(f, g *signed62, length int) int {
	fn, gn := f.v[length-1], g.v[length-1]
	cond := int64(length-2) >> 63
	cond |= fn ^ (fn >> 63)
	cond |= gn ^ (gn >> 63)
	if cond != 0 {
		return length
	}

	f.v[length-2] |= fn << 62
	g.v[length-2] |= gn << 62
	return length - 1
}

func checkDivstepsTrace(t *testing.T, name string, mi *modInfo,
	input signed62) {

	t.Helper()
	f, g := mi.modulus, input
	eta, length := int64(-1), 5
	for round := 0; ; round++ {
		if round == 32 {
			t.Fatalf("%s: inversion trace did not terminate", name)
		}

		var wantT, gotT trans2x2
		wantEta := divsteps62VarGeneric(
			eta, uint64(f.v[0]), uint64(g.v[0]), &wantT,
		)
		gotEta := divsteps62Var(
			eta, uint64(f.v[0]), uint64(g.v[0]), &gotT,
		)
		if gotEta != wantEta || gotT != wantT {
			t.Fatalf("%s round %d length %d: divsteps mismatch\n"+
				"eta=%d f0=%#x g0=%#x\n"+
				"got eta=%d t=%+v\nwant eta=%d t=%+v",
				name, round, length, eta, uint64(f.v[0]),
				uint64(g.v[0]), gotEta, gotT, wantEta, wantT)
		}

		eta = wantEta
		updateFG62Var(length, &f, &g, wantT)
		if modinvTraceDone(&g, length) {
			return
		}
		length = shrinkModinvTrace(&f, &g, length)
	}
}

func TestDivsteps62VarAsmMatchesGeneric(t *testing.T) {
	moduli := []struct {
		name string
		mi   *modInfo
	}{
		{"scalar", &scalarModInfo},
		{"field", &fieldModInfo},
	}
	for _, modulus := range moduli {
		for i, input := range modinvParityInputs(modulus.mi) {
			name := fmt.Sprintf("%s input %d", modulus.name, i)
			checkDivstepsTrace(t, name, modulus.mi, input)
		}
	}
}

func checkUpdateTrace(t *testing.T, name string, mi *modInfo,
	input signed62) [6]bool {

	t.Helper()
	var d, e signed62
	e.v[0] = 1
	f, g := mi.modulus, input
	eta, length := int64(-1), 5
	var seen [6]bool
	for round := 0; ; round++ {
		if round == 32 {
			t.Fatalf("%s: inversion trace did not terminate", name)
		}
		seen[length] = true

		var trans trans2x2
		eta = divsteps62VarGeneric(
			eta, uint64(f.v[0]), uint64(g.v[0]), &trans,
		)

		wantD, wantE := d, e
		wantF, wantG := f, g
		updateDE62(&wantD, &wantE, trans, mi)
		updateFG62Var(length, &wantF, &wantG, trans)

		gotD, gotE := d, e
		gotF, gotG := f, g
		gotTrans := trans
		gotMI := *mi
		beforeMI := gotMI
		update62(&gotD, &gotE, &gotF, &gotG, &gotTrans, &gotMI,
			int64(length))
		if gotD != wantD || gotE != wantE ||
			gotF != wantF || gotG != wantG {

			t.Fatalf("%s round %d length %d: update mismatch\n"+
				"d got=%v want=%v\n"+
				"e got=%v want=%v\n"+
				"f got=%v want=%v\n"+
				"g got=%v want=%v",
				name, round, length, gotD.v, wantD.v,
				gotE.v, wantE.v, gotF.v, wantF.v, gotG.v, wantG.v)
		}
		if gotTrans != trans || gotMI != beforeMI {
			t.Fatalf("%s: update62 modified a read-only input", name)
		}

		d, e, f, g = wantD, wantE, wantF, wantG
		if modinvTraceDone(&g, length) {
			return seen
		}
		length = shrinkModinvTrace(&f, &g, length)
	}
}

func TestUpdate62AsmMatchesGeneric(t *testing.T) {
	moduli := []struct {
		name string
		mi   *modInfo
	}{
		{"scalar", &scalarModInfo},
		{"field", &fieldModInfo},
	}
	for _, modulus := range moduli {
		inputs := modinvParityInputs(modulus.mi)
		seen := checkUpdateTrace(t, modulus.name+" coverage",
			modulus.mi, inputs[1])
		for length := 1; length <= 5; length++ {
			if !seen[length] {
				t.Fatalf("%s: length %d was not exercised",
					modulus.name, length)
			}
		}

		for i, input := range inputs {
			name := fmt.Sprintf("%s input %d", modulus.name, i)
			checkUpdateTrace(t, name, modulus.mi, input)
		}
	}
}
