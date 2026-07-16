// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build amd64 && !purego

#include "textflag.h"

// Fused group operations built on AVX-512 IFMA 52-bit multiply-adds. Field
// values live in the low five lanes of ZMM registers for the whole
// routine, one base 2^52 limb per lane, so field intermediates never touch
// memory. The multiplication core mirrors the column arithmetic of
// mulGeneric: VPMADD52LUQ and VPMADD52HUQ accumulate the low and high
// halves of 52x52 bit products into column lanes, a relaxed fold reduces
// the high columns through r52 without first carrying them into digits,
// and short masked carry passes replace full normalization.
//
// VPMADD52 reads only the low 52 bits of each multiplier lane, so every
// multiplication input must be strictly below 2^52 per lane. Carry passes
// run enough rounds that a lane can exceed that bound only on carry
// ripples with probability around 2^-50 per operation. Every pass tests
// for the leftover and accumulates the result into K7; the routine then
// returns nonzero so the caller redoes the operation on the generic path,
// mirroring how the degenerate mixed addition falls back. Verification is
// variable time over public data, so the data dependent branch is fine.
//
// Register conventions, fixed for the whole file:
//
//	K1        0x1F, the five value lanes
//	K3        0x10, lane 4 only
//	K6        scratch mask for the leftover tests
//	K7        accumulated carry-pass leftovers, nonzero forces the bail
//	Z0..Z15   macro temporaries: Z1..Z5 operand alignments up by 1..5,
//	          Z6, Z7 operand alignments down by 3 and 4, Z8..Z12 column
//	          accumulators, Z0, Z13..Z15 scratch
//	Z16..Z20  field values
//	Z21       the 8*twoP negation constants of FESUB2X8W
//	Z22..Z25  broadcast lane indices 1..4 (index 0 broadcasts via Z26)
//	Z26       zero
//	Z28       2^52-1 in every lane
//	Z29       r52 in every lane
//	Z30       fieldC in every lane
//	Z31       the 2*twoP negation constants of FESUB2
//
// The larger negation constants and the weak normalization mask load from
// memory at their use sites.

#include "group_ifma_inc.h"

// func jacDoubleIFMA(p, a *jacobianPoint) uint64
TEXT ·jacDoubleIFMA(SB), NOSPLIT, $0-24
	MOVQ a+8(FP), SI
	IFMASETUP

	VMOVDQU64.Z 0(SI), K1, Z16  // X
	VMOVDQU64.Z 40(SI), K1, Z17 // Y
	VMOVDQU64.Z 80(SI), K1, Z18 // Z

	// The doubling avoids E = 3*A entirely: F = E^2 is 9*A^2 and
	// E*(D - X3) is 3*(A*(D - X3)), with the small scalings folded into
	// the column accumulators before reduction. X3 also skips its weak
	// normalization on the dependency spine: T = D - X3 negates the loose
	// X3 through the 512*twoP constants, and X3 normalizes for the store
	// in the shadow of the final multiplication.

	// A = X^2
	BALIGN(Z16)
	ZEROACC
	MROWS(Z16, Z16)
	MERGE
	REDFOLD(Z19)
	REDTAIL2(Z19)

	// B = Y^2
	BALIGN(Z17)
	ZEROACC
	MROWS(Z17, Z17)
	MERGE
	REDFOLD(Z20)
	REDTAIL2(Z20)

	// Z3 = 2*Y*Z, doubled by scaling the columns before reduction.
	BALIGN(Z18)
	ZEROACC
	MROWS(Z17, Z18)
	MERGE
	VPSLLQ $1, Z8, Z8
	VPSLLQ $1, Z10, Z10
	VPSLLQ $1, Z12, Z12
	REDFOLD(Z18)
	REDTAILW(Z18)

	// D = 4*X*B, scaled before reduction.
	BALIGN(Z20)
	ZEROACC
	MROWS(Z16, Z20)
	MERGE
	VPSLLQ $2, Z8, Z8
	VPSLLQ $2, Z10, Z10
	VPSLLQ $2, Z12, Z12
	REDFOLD(Z16)
	REDTAIL2(Z16)

	// C = B^2, into the register Y no longer needs. The top limb folds to
	// the 2^48 scale so that 8*C stays below the 8*twoP negation constants
	// in every limb.
	BALIGN(Z20)
	ZEROACC
	MROWS(Z20, Z20)
	MERGE
	REDFOLD(Z17)
	REDTAILW(Z17)

	// F = 9*A^2, into the register B no longer needs.
	BALIGN(Z19)
	ZEROACC
	MROWS(Z19, Z19)
	MERGE
	VPSLLQ $3, Z8, Z0
	VPADDQ Z0, Z8, Z8
	VPSLLQ $3, Z10, Z0
	VPADDQ Z0, Z10, Z10
	VPSLLQ $3, Z12, Z0
	VPADDQ Z0, Z12, Z12
	REDFOLD(Z20)
	REDTAIL2(Z20)

	// X3 = F - 2*D, left loose through the 32*twoP negation constants.
	VPSLLQ $1, Z16, Z0
	VMOVDQU64 ifmaC32<>(SB), Z13
	VPADDQ Z13, Z20, Z20
	VPSUBQ Z0, Z20, Z20

	// T = D - X3 with the 512*twoP negation constants covering the loose
	// X3.
	VMOVDQU64 ifmaC512<>(SB), Z13
	VPADDQ Z13, Z16, Z16
	VPSUBQ Z20, Z16, Z16
	PASSF2(Z16)

	// Y3 = 3*(A*T) - 8*C, with X3 normalizing for the store while the
	// multiplication reduces.
	BALIGN(Z16)
	ZEROACC
	MROWS(Z19, Z16)
	MERGE
	VPSLLQ $1, Z8, Z0
	VPADDQ Z0, Z8, Z8
	VPSLLQ $1, Z10, Z0
	VPADDQ Z0, Z10, Z10
	VPSLLQ $1, Z12, Z0
	VPADDQ Z0, Z12, Z12
	WEAKOUT2(Z20)
	REDFOLD(Z19)
	REDTAIL2(Z19)
	VPSLLQ $3, Z17, Z0
	VPADDQ Z21, Z19, Z19
	VPSUBQ Z0, Z19, Z19
	WEAKOUT2(Z19)

	KORTESTW K7, K7
	JNE bail

	MOVQ p+0(FP), DI
	VMOVDQU64 Z20, K1, 0(DI)
	VMOVDQU64 Z19, K1, 40(DI)
	VMOVDQU64 Z18, K1, 80(DI)
	MOVQ $0, ret+16(FP)
	VZEROUPPER
	RET

bail:
	MOVQ $1, ret+16(FP)
	VZEROUPPER
	RET
