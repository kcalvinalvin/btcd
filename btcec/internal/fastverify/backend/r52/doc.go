// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package r52 implements variable-time secp256k1 arithmetic with five
// radix-2^52 field limbs. It must only be used with public inputs.
//
// The package exposes prepared-equation verification while keeping its field
// and point representations and fixed-base table private to the engine.
package r52
