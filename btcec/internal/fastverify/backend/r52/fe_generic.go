// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package r52

func feMul(r, a, b *fe) {
	mulGeneric(r, a, b)
}

func feSquare(r, a *fe) {
	squareGeneric(r, a)
}
