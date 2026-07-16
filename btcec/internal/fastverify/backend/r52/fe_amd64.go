// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build amd64 && !purego

package r52

// feMul sets r to a*b mod p in loose form. It computes the identical limb
// values as mulGeneric. The result pointer may alias either input.
//
//go:noescape
func feMul(r, a, b *fe)

// feSquare sets r to a*a mod p in loose form. It computes the identical
// limb values as squareGeneric. The result pointer may alias the input.
//
//go:noescape
func feSquare(r, a *fe)
