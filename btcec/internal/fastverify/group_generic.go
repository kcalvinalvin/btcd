// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build !amd64 || purego

package fastverify

func jacDouble(p, a *JacobianPoint) {
	doubleGeneric(p, a)
}

func jacAddMixed(p, a *JacobianPoint, b *AffinePoint) {
	addMixedGeneric(p, a, b)
}
