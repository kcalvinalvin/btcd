// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build amd64 && !purego

package fastverify

// jacDoubleAsm computes the doubling formulas of doubleGeneric as one
// fused assembly routine with all field intermediates in its stack frame.
// The input must be a finite point. The output may alias the input.
//
//go:noescape
func jacDoubleAsm(p, a *JacobianPoint)

// jacAddMixedAsm computes the mixed addition formulas of addMixedGeneric
// as one fused assembly routine. The Jacobian input must be a finite
// point. It returns 1 without writing the result when the two points share
// an x coordinate, leaving the degenerate doubling and infinity cases to
// the caller. The output may alias the input.
//
//go:noescape
func jacAddMixedAsm(p, a *JacobianPoint, b *AffinePoint) uint64

func jacDouble(p, a *JacobianPoint) {
	jacDoubleAsm(p, a)
	p.Inf = false
}

func jacAddMixed(p, a *JacobianPoint, b *AffinePoint) {
	if jacAddMixedAsm(p, a, b) != 0 {
		addMixedGeneric(p, a, b)
		return
	}
	p.Inf = false
}
