// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build amd64 && !purego

package r52

import (
	"fmt"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func ladderTestPoint(t testing.TB, multiple uint32) (
	secp.JacobianPoint, jacobianPoint) {

	t.Helper()
	var scalar secp.ModNScalar
	scalar.SetInt(multiple)
	var point secp.JacobianPoint
	secp.ScalarBaseMultNonConst(&scalar, &point)
	return point, fromDcrecJacobian(t, &point)
}

func ladderTestAffine(t testing.TB, multiple uint32) affinePoint {
	t.Helper()
	point, _ := ladderTestPoint(t, multiple)
	point.ToAffine()
	engine := fromDcrecJacobian(t, &point)
	return affinePoint{X: engine.X, Y: engine.Y}
}

func checkLadderPoint(t *testing.T, name string, got,
	want *jacobianPoint) {

	t.Helper()
	if got.Inf != want.Inf {
		t.Fatalf("%s: infinity mismatch", name)
	}
	if got.Inf {
		return
	}
	checkSameValue(t, name+" X", &got.X, &want.X)
	checkSameValue(t, name+" Y", &got.Y, &want.Y)
	checkSameValue(t, name+" Z", &got.Z, &want.Z)
}

func TestLadderRunIFMAMatchesGeneric(t *testing.T) {
	if !hasIFMA {
		t.Skip("no AVX-512 IFMA support")
	}

	for i := uint32(0); i < 64; i++ {
		base := 100 * i
		_, acc := ladderTestPoint(t, base+1)
		_, gacc := ladderTestPoint(t, base+20)
		b := ladderTestAffine(t, base+3)
		c := ladderTestAffine(t, base+7)
		d := ladderTestAffine(t, base+11)
		e := ladderTestAffine(t, base+13)
		ops := []ladderOp{
			{kind: opDouble},
			{kind: opAdd, entry: &b},
			{kind: opDoubleG, entry: &c},
			{kind: opDouble},
			{kind: opAdd, entry: &d},
			{kind: opDoubleG, entry: &e},
		}

		wantAcc, wantG := acc, gacc
		runLadderGeneric(&wantAcc, &wantG, ops)
		gotAcc, gotG := acc, gacc
		if ret := ladderRunIFMA(&gotAcc, &gotG, ops); ret != 0 {
			t.Fatalf("case %d: unexpected assembly bailout", i)
		}
		name := fmt.Sprintf("case %d", i)
		checkLadderPoint(t, name+" accumulator", &gotAcc, &wantAcc)
		checkLadderPoint(t, name+" G accumulator", &gotG, &wantG)
	}
}

func TestRunLadderReplaysAfterIFMABail(t *testing.T) {
	if !hasIFMA {
		t.Skip("no AVX-512 IFMA support")
	}

	_, acc := ladderTestPoint(t, 1)
	_, gacc := ladderTestPoint(t, 3)
	gEntry := ladderTestAffine(t, 5)
	doubledAcc := ladderTestAffine(t, 2)
	ops := []ladderOp{
		{kind: opDoubleG, entry: &gEntry},
		{kind: opAdd, entry: &doubledAcc},
	}

	rawAcc, rawG := acc, gacc
	if ret := ladderRunIFMA(&rawAcc, &rawG, ops); ret == 0 {
		t.Fatal("shared-x addition did not force an assembly bailout")
	}
	if rawG == gacc {
		t.Fatal("test schedule bailed before partially updating G chain")
	}

	gotAcc, gotG := acc, gacc
	runLadder(&gotAcc, &gotG, ops)
	wantAcc, _ := ladderTestPoint(t, 4)
	wantG, _ := ladderTestPoint(t, 8)
	comparePoints(t, "replayed accumulator", &gotAcc, &wantAcc)
	comparePoints(t, "replayed G accumulator", &gotG, &wantG)
}
