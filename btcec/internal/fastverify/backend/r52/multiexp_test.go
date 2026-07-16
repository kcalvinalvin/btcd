// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package r52

import (
	"crypto/rand"
	"testing"

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
