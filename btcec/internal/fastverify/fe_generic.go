// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build !amd64 || purego

package fastverify

func feMul(r, a, b *Fe) {
	mulGeneric(r, a, b)
}

func feSquare(r, a *Fe) {
	squareGeneric(r, a)
}
