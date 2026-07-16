// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build amd64 && !purego

package modinv

// divsteps62Var is the assembly form of divsteps62VarGeneric.
//
//go:noescape
func divsteps62Var(eta int64, f0, g0 uint64, t *trans2x2) int64
