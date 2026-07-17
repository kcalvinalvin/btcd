// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package r52

import "github.com/btcsuite/btcd/btcec/v2/internal/fastverify/internal/modinv"

// Inverse sets f to the multiplicative inverse of a in variable time, or to
// zero when a represents zero.
func (f *fe) Inverse(a *fe) {
	v := *a
	v.Normalize()
	b := v.Bytes()
	nb := modinv.FieldInverse(b)
	f.SetBytes(&nb)
}
