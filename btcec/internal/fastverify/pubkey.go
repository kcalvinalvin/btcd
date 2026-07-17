// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package fastverify

import (
	"bytes"

	"github.com/btcsuite/btcd/btcec/v2/internal/fastverify/internal/engine"
)

// primeBytes is the field prime p in 32-byte big-endian form, used to check
// that serialized coordinates are canonical.
var primeBytes = [32]byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
}

// DecodePubKey decodes a serialized secp256k1 public key into canonical affine
// coordinates. It accepts exactly the encodings that dcrec's ParsePubKey
// accepts: the 33-byte compressed format with an even or odd y parity format
// byte, and the 65-byte uncompressed and hybrid formats.
func DecodePubKey(serialized []byte) (engine.Affine, bool) {
	var p engine.Affine
	switch len(serialized) {
	case 33:
		format := serialized[0]
		if format != 0x02 && format != 0x03 {
			return p, false
		}

		var x [32]byte
		copy(x[:], serialized[1:33])
		if bytes.Compare(x[:], primeBytes[:]) >= 0 {
			return p, false
		}
		p.X = x

		// Lift x and select the root required by the format's parity bit.
		var ok bool
		p.Y, ok = liftX(&p.X, format == 0x03)
		if !ok {
			return p, false
		}
		return p, true

	case 65:
		format := serialized[0]
		if format != 0x04 && format != 0x06 && format != 0x07 {
			return p, false
		}

		var x, y [32]byte
		copy(x[:], serialized[1:33])
		copy(y[:], serialized[33:65])
		if bytes.Compare(x[:], primeBytes[:]) >= 0 ||
			bytes.Compare(y[:], primeBytes[:]) >= 0 {
			return p, false
		}
		p.X, p.Y = x, y

		// The parity of a hybrid key's y coordinate must match its
		// format byte.
		if format != 0x04 && p.Y[31]&1 != format&1 {
			return p, false
		}

		if !isOnCurve(&p.X, &p.Y) {
			return p, false
		}
		return p, true
	}

	return p, false
}
