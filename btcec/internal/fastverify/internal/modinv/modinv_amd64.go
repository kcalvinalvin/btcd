// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build amd64 && !purego

package modinv

// divsteps62Var is the assembly form of divsteps62VarGeneric.
//
//go:noescape
func divsteps62Var(eta int64, f0, g0 uint64, t *trans2x2) int64

// update62 is the assembly form of updateDE62 followed by updateFG62Var.
//
//go:noescape
func update62(d, e, f, gg *signed62, t *trans2x2, mi *modInfo, length int64)

func modinvUpdate(d, e, f, g *signed62, t *trans2x2, mi *modInfo, length int) {
	update62(d, e, f, g, t, mi, int64(length))
}
