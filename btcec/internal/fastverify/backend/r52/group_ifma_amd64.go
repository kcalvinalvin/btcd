// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build amd64 && !purego

package r52

// jacDoubleIFMA computes the doubling formulas of doubleGeneric with the
// AVX-512 IFMA field core, keeping every field intermediate in vector
// registers. The input must be a finite point with weak-normalized
// coordinates. It returns nonzero without writing the result in the rare
// case that a carry pass leftover was detected, in which case the caller
// must redo the operation on another path. The output may alias the
// input. The caller must ensure hasIFMA.
//
//go:noescape
func jacDoubleIFMA(p, a *jacobianPoint) uint64

// jacAddMixedIFMA computes the mixed addition formulas of addMixedGeneric
// with the AVX-512 IFMA field core. The Jacobian input must be a finite
// point with weak-normalized coordinates. It returns nonzero without
// writing the result when the two points share an x coordinate or a carry
// pass leftover was detected, in which case the caller must redo the
// operation on another path. The output may alias the Jacobian input. The
// caller must ensure hasIFMA.
//
//go:noescape
func jacAddMixedIFMA(p, a *jacobianPoint, b *affinePoint) uint64
