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
