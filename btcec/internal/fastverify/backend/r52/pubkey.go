// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package r52

// LiftX calculates the y coordinate with the requested parity for x and
// reports whether x is the coordinate of a point on secp256k1. The returned
// coordinate is canonical. The input x must be canonical.
func LiftX(x *[32]byte, odd bool) ([32]byte, bool) {
	var fx fe
	fx.SetBytes(x)

	// y = sqrt(x^3 + 7).
	var yy, b7 fe
	yy.Square(&fx)
	yy.Mul(&yy, &fx)
	b7.SetUint64(7)
	yy.Add(&b7)

	var y fe
	if !feSqrt(&y, &yy) {
		return [32]byte{}, false
	}
	if y.IsOdd() != odd {
		y.Negate(1)
	}
	return y.Bytes(), true
}

// IsOnCurve reports whether the affine coordinates satisfy the
// secp256k1 curve equation y^2 = x^3 + 7. Both inputs must be canonical.
func IsOnCurve(x, y *[32]byte) bool {
	var fx, fy fe
	fx.SetBytes(x)
	fy.SetBytes(y)

	var yy, xx, b7 fe
	yy.Square(&fy)
	yy.Normalize()
	xx.Square(&fx)
	xx.Mul(&xx, &fx)
	b7.SetUint64(7)
	xx.Add(&b7)
	xx.Normalize()
	return yy.Equals(&xx)
}
