// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package fastverify

import (
	"github.com/btcsuite/btcd/btcec/v2/internal/fastverify/backend/r52"
	"github.com/btcsuite/btcd/btcec/v2/internal/fastverify/internal/engine"
)

type backendID uint8

const (
	backendUnknown backendID = iota
	backendR52
)

// backendSelection identifies the complete arithmetic engine used by each
// coarse operation. An engine may select fused ISA kernels internally. Keeping
// the choices independent permits future engines to specialize only the
// operations for which they are faster.
type backendSelection struct {
	ecdsaVerify   backendID
	schnorrVerify backendID
}

var selectedBackends = selectBackends()

func selectBackends() backendSelection {
	return backendSelection{
		ecdsaVerify:   backendR52,
		schnorrVerify: backendR52,
	}
}

func verifyECDSAEquation(equation *engine.ECDSAEquation) bool {
	switch selectedBackends.ecdsaVerify {
	case backendR52:
		return r52.VerifyECDSA(equation)
	default:
		panic("fastverify: unknown ECDSA backend")
	}
}

func verifySchnorrEquation(equation *engine.SchnorrEquation) bool {
	switch selectedBackends.schnorrVerify {
	case backendR52:
		return r52.VerifySchnorr(equation)
	default:
		panic("fastverify: unknown Schnorr backend")
	}
}
