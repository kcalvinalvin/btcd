// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build amd64 && !purego

package r52

// jacDoubleAsm computes the doubling formulas of doubleGeneric as one
// fused assembly routine with all field intermediates in its stack frame.
// The input must be a finite point. The output may alias the input.
//
//go:noescape
func jacDoubleAsm(p, a *jacobianPoint)

// jacAddMixedAsm computes the mixed addition formulas of addMixedGeneric
// as one fused assembly routine. The Jacobian input must be a finite
// point. It returns 1 without writing the result when the two points share
// an x coordinate, leaving the degenerate doubling and infinity cases to
// the caller. The output may alias the input.
//
//go:noescape
func jacAddMixedAsm(p, a *jacobianPoint, b *affinePoint) uint64

func jacDouble(p, a *jacobianPoint) {
	if hasIFMA && jacDoubleIFMA(p, a) == 0 {
		p.Inf = false
		return
	}
	jacDoubleAsm(p, a)
	p.Inf = false
}

func jacAddMixed(p, a *jacobianPoint, b *affinePoint) {
	if hasIFMA && jacAddMixedIFMA(p, a, b) == 0 {
		p.Inf = false
		return
	}
	if jacAddMixedAsm(p, a, b) != 0 {
		addMixedGeneric(p, a, b)
		return
	}
	p.Inf = false
}

// ladderRunIFMA runs a ladder schedule in one assembly call with the
// accumulator register-resident. It returns nonzero when an operation bails,
// leaving both points partially updated. The caller must ensure hasIFMA and
// finite inputs. Defined in group_ifma_ladder_amd64.s.
//
//go:noescape
func ladderRunIFMA(acc, gacc *jacobianPoint, ops []ladderOp) uint64

// runLadder uses the IFMA interpreter when available. A bailout restores both
// inputs before replaying the complete schedule portably.
func runLadder(acc, gacc *jacobianPoint, ops []ladderOp) {
	if hasIFMA && len(ops) > 0 {
		accSave, gaccSave := *acc, *gacc
		if ladderRunIFMA(acc, gacc, ops) == 0 {
			return
		}
		*acc, *gacc = accSave, gaccSave
	}
	runLadderGeneric(acc, gacc, ops)
}
