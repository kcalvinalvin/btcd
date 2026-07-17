// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build !amd64 || purego

package r52

func jacDouble(p, a *jacobianPoint) {
	doubleGeneric(p, a)
}

func jacAddMixed(p, a *jacobianPoint, b *affinePoint) {
	addMixedGeneric(p, a, b)
}

func runLadder(acc, gacc *jacobianPoint, ops []ladderOp) {
	runLadderGeneric(acc, gacc, ops)
}

func oddChain(table *[8]jacobianPoint, twoQ *affinePoint) {
	for i := 1; i < 8; i++ {
		table[i].AddMixed(&table[i-1], twoQ)
	}
}
