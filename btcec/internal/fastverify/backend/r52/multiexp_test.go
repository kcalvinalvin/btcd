// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package r52

import (
	"crypto/rand"
	"fmt"
	"testing"
	"unsafe"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// testEndoLambda is lambda, the cube root of unity modulo the group order.
// It exercises a structural scalar vector in the dual-base multiplication.
var testEndoLambda = func() secp.ModNScalar {
	b := [32]byte{
		0x53, 0x63, 0xad, 0x4c, 0xc0, 0x5c, 0x30, 0xe0,
		0xa5, 0x26, 0x1c, 0x02, 0x88, 0x12, 0x64, 0x5a,
		0x12, 0x2e, 0x22, 0xea, 0x20, 0x81, 0x66, 0x78,
		0xdf, 0x02, 0x96, 0x7c, 0x1b, 0x23, 0xbd, 0x72,
	}
	var s secp.ModNScalar
	s.SetBytes(&b)
	return s
}()

func randomScalar(t testing.TB) secp.ModNScalar {
	t.Helper()
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	var scalar secp.ModNScalar
	scalar.SetBytes(&raw)
	return scalar
}

func TestDigitEntry(t *testing.T) {
	var pos, neg [8]affinePoint
	for i := range pos {
		pos[i].X.SetUint64(uint64(i + 1))
		pos[i].Y.SetUint64(uint64(i + 17))
	}
	negateTable(&pos, &neg)
	for i := range pos {
		if neg[i].X.n != pos[i].X.n {
			t.Fatalf("entry %d: negation changed x", i)
		}
		wantY := pos[i].Y
		wantY.Negate(1)
		wantY.normalizeWeak()
		if neg[i].Y.n != wantY.n {
			t.Fatalf("entry %d: negated y mismatch", i)
		}
	}

	for digit := int8(-15); digit <= 15; digit += 2 {
		if digit == 0 {
			continue
		}
		for _, negate := range []bool{false, true} {
			d := digit
			if negate {
				d = -d
			}
			var want *affinePoint
			if d < 0 {
				want = &neg[-d/2]
			} else {
				want = &pos[d/2]
			}
			if got := digitEntry(&pos, &neg, digit, negate); got != want {
				t.Fatalf("digit %d negate %v: wrong table entry",
					digit, negate)
			}
		}
	}
}

func TestLadderOpABI(t *testing.T) {
	var op ladderOp
	if opDouble != 0 || opDoubleG != 1 || opAdd != 2 {
		t.Fatalf("unexpected op values: %d %d %d",
			opDouble, opDoubleG, opAdd)
	}
	if got := unsafe.Sizeof(op); got != 16 {
		t.Fatalf("ladderOp size: got %d want 16", got)
	}
	if got := unsafe.Offsetof(op.kind); got != 0 {
		t.Fatalf("kind offset: got %d want 0", got)
	}
	if got := unsafe.Offsetof(op.entry); got != 8 {
		t.Fatalf("entry offset: got %d want 8", got)
	}
}

func TestRunLadderGeneric(t *testing.T) {
	da := randomDcrecPoint(t)
	dg := randomDcrecPoint(t)
	db := randomDcrecPoint(t)
	dc := randomDcrecPoint(t)
	db.ToAffine()
	dc.ToAffine()

	acc := fromDcrecJacobian(t, &da)
	gacc := fromDcrecJacobian(t, &dg)
	mb := fromDcrecJacobian(t, &db)
	mc := fromDcrecJacobian(t, &dc)
	b := affinePoint{X: mb.X, Y: mb.Y}
	c := affinePoint{X: mc.X, Y: mc.Y}
	ops := []ladderOp{
		{kind: opDouble},
		{kind: opDoubleG, entry: &b},
		{kind: opAdd, entry: &c},
	}
	runLadderGeneric(&acc, &gacc, ops)

	var twoA, fourA, wantAcc, wantG secp.JacobianPoint
	secp.DoubleNonConst(&da, &twoA)
	secp.DoubleNonConst(&twoA, &fourA)
	secp.AddNonConst(&fourA, &dc, &wantAcc)
	secp.AddNonConst(&dg, &db, &wantG)
	comparePoints(t, "ladder accumulator", &acc, &wantAcc)
	comparePoints(t, "ladder G accumulator", &gacc, &wantG)

	// The portable runner also preserves the point wrappers' infinity
	// behavior, which is useful when replaying adversarial schedules.
	acc.SetInfinity()
	gacc.SetInfinity()
	runLadderGeneric(&acc, &gacc, []ladderOp{
		{kind: opDoubleG, entry: &b},
		{kind: opAdd, entry: &c},
	})
	comparePoints(t, "infinity accumulator", &acc, &dc)
	comparePoints(t, "infinity G accumulator", &gacc, &db)
}

func expectedWindow(bytes *[32]byte, window int) uint64 {
	start := gWindowBits * window
	var value uint64
	for bit := 0; bit < gWindowBits && start+bit < 256; bit++ {
		position := start + bit
		value |= uint64(bytes[31-position/8]>>uint(position%8)&1) <<
			uint(bit)
	}
	return value
}

func TestFixedWindowValue(t *testing.T) {
	check := func(name string, scalar secp.ModNScalar) {
		t.Helper()
		bytes := scalar.Bytes()
		words := scalarWordsLE(&scalar)
		for window := 0; window < gWindows; window++ {
			got := fixedWindowValue(&words, window)
			want := expectedWindow(&bytes, window)
			if got != want {
				t.Fatalf("%s window %d: got %#x want %#x",
					name, window, got, want)
			}
		}
	}

	// Every scalar bit exercises the positions on both sides of each
	// 12-bit and 64-bit boundary, including the four-bit top window.
	for bit := 0; bit < 256; bit++ {
		var raw [32]byte
		raw[31-bit/8] = 1 << uint(bit%8)
		var scalar secp.ModNScalar
		scalar.SetBytes(&raw)
		check(fmt.Sprintf("bit %d", bit), scalar)
	}

	var one secp.ModNScalar
	one.SetInt(1)
	orderMinusOne := one
	orderMinusOne.Negate()
	check("order minus one", orderMinusOne)
}

func TestGTableGeometry(t *testing.T) {
	if gWindowBits != 12 || gWindows != 22 || gTableSize != 4096 {
		t.Fatalf("unexpected geometry: bits=%d windows=%d size=%d",
			gWindowBits, gWindows, gTableSize)
	}
	const wantBytes = 7_208_960
	if got := unsafe.Sizeof([gWindows][gTableSize]affinePoint{}); got != wantBytes {
		t.Fatalf("table bytes: got %d want %d", got, wantBytes)
	}
}

var benchmarkGTable *[gWindows][gTableSize]affinePoint

func BenchmarkGenerateGTableCold(b *testing.B) {
	b.ReportAllocs()
	tableBytes := unsafe.Sizeof([gWindows][gTableSize]affinePoint{})
	b.ReportMetric(float64(tableBytes)/(1<<20), "MiB/table")
	for i := 0; i < b.N; i++ {
		benchmarkGTable = generateGTable()
	}
}

func TestDualBaseMultMatchesDcrec(t *testing.T) {
	check := func(u1, u2 secp.ModNScalar, q secp.JacobianPoint) {
		t.Helper()

		var gTerm, qTerm, want secp.JacobianPoint
		secp.ScalarBaseMultNonConst(&u1, &gTerm)
		secp.ScalarMultNonConst(&u2, &q, &qTerm)
		secp.AddNonConst(&gTerm, &qTerm, &want)

		q.ToAffine()
		engineQ := fromDcrecJacobian(t, &q)
		affineQ := affinePoint{X: engineQ.X, Y: engineQ.Y}
		got := dualBaseMult(&u1, &u2, &affineQ)
		comparePoints(t, "dual base mult", &got, &want)
	}

	var zero, one secp.ModNScalar
	one.SetInt(1)
	orderMinusOne := one
	orderMinusOne.Negate()

	base := randomDcrecPoint(t)
	check(zero, zero, base)
	check(one, zero, base)
	check(zero, one, base)
	check(orderMinusOne, orderMinusOne, base)
	check(testEndoLambda, testEndoLambda, base)

	for i := 0; i < 300; i++ {
		check(randomScalar(t), randomScalar(t), randomDcrecPoint(t))
	}
}
