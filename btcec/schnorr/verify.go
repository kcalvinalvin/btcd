// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package schnorr

import (
	"github.com/btcsuite/btcd/btcec/v2"
)

// verifySchnorr is the verification backend for Signature.Verify, allowing
// the implementation to be selected at build time.
func verifySchnorr(sig *Signature, hash []byte, pubKey *btcec.PublicKey) bool {
	return schnorrVerify(sig, hash, SerializePubKey(pubKey)) == nil
}
