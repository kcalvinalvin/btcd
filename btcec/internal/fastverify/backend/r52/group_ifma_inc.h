// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Shared macros and constants for the IFMA fused group operations. See
// group_ifma_amd64.s for the design commentary and the register
// conventions every macro assumes.

// The 2*twoP per-limb negation constants, as in FESUB2.
DATA ifmaC2<>+0(SB)/8, $0x3FFFFBFFFFF0BC
DATA ifmaC2<>+8(SB)/8, $0x3FFFFFFFFFFFFC
DATA ifmaC2<>+16(SB)/8, $0x3FFFFFFFFFFFFC
DATA ifmaC2<>+24(SB)/8, $0x3FFFFFFFFFFFFC
DATA ifmaC2<>+32(SB)/8, $0x3FFFFFFFFFFFC
DATA ifmaC2<>+40(SB)/8, $0
DATA ifmaC2<>+48(SB)/8, $0
DATA ifmaC2<>+56(SB)/8, $0
GLOBL ifmaC2<>(SB), RODATA, $64

// The 32*twoP per-limb negation constants, for subtrahends up to 2^53
// with an unfolded top limb.
DATA ifmaC32<>+0(SB)/8, $0x3FFFFBFFFFF0BC0
DATA ifmaC32<>+8(SB)/8, $0x3FFFFFFFFFFFFC0
DATA ifmaC32<>+16(SB)/8, $0x3FFFFFFFFFFFFC0
DATA ifmaC32<>+24(SB)/8, $0x3FFFFFFFFFFFFC0
DATA ifmaC32<>+32(SB)/8, $0x3FFFFFFFFFFFC0
DATA ifmaC32<>+40(SB)/8, $0
DATA ifmaC32<>+48(SB)/8, $0
DATA ifmaC32<>+56(SB)/8, $0
GLOBL ifmaC32<>(SB), RODATA, $64

// The 512*twoP per-limb negation constants, for subtrahends that skipped
// their weak normalization and sit below 2^59 per limb.
DATA ifmaC512<>+0(SB)/8, $0x3FFFFBFFFFF0BC00
DATA ifmaC512<>+8(SB)/8, $0x3FFFFFFFFFFFFC00
DATA ifmaC512<>+16(SB)/8, $0x3FFFFFFFFFFFFC00
DATA ifmaC512<>+24(SB)/8, $0x3FFFFFFFFFFFFC00
DATA ifmaC512<>+32(SB)/8, $0x3FFFFFFFFFFFC00
DATA ifmaC512<>+40(SB)/8, $0
DATA ifmaC512<>+48(SB)/8, $0
DATA ifmaC512<>+56(SB)/8, $0
GLOBL ifmaC512<>(SB), RODATA, $64

// Weak normalization mask: 52-bit lanes with a 48-bit top limb.
DATA ifmaWideMask<>+0(SB)/8, $0x000FFFFFFFFFFFFF
DATA ifmaWideMask<>+8(SB)/8, $0x000FFFFFFFFFFFFF
DATA ifmaWideMask<>+16(SB)/8, $0x000FFFFFFFFFFFFF
DATA ifmaWideMask<>+24(SB)/8, $0x000FFFFFFFFFFFFF
DATA ifmaWideMask<>+32(SB)/8, $0x0000FFFFFFFFFFFF
DATA ifmaWideMask<>+40(SB)/8, $0
DATA ifmaWideMask<>+48(SB)/8, $0
DATA ifmaWideMask<>+56(SB)/8, $0
GLOBL ifmaWideMask<>(SB), RODATA, $64

// The 8*twoP per-limb negation constants, as in FESUB2X8W.
DATA ifmaC8<>+0(SB)/8, $0xFFFFEFFFFFC2F0
DATA ifmaC8<>+8(SB)/8, $0xFFFFFFFFFFFFF0
DATA ifmaC8<>+16(SB)/8, $0xFFFFFFFFFFFFF0
DATA ifmaC8<>+24(SB)/8, $0xFFFFFFFFFFFFF0
DATA ifmaC8<>+32(SB)/8, $0xFFFFFFFFFFFF0
DATA ifmaC8<>+40(SB)/8, $0
DATA ifmaC8<>+48(SB)/8, $0
DATA ifmaC8<>+56(SB)/8, $0
GLOBL ifmaC8<>(SB), RODATA, $64

// IFMASETUP loads the fixed masks and constant registers.
#define IFMASETUP \
	MOVQ $0x1F, AX;                  \
	KMOVW AX, K1;                    \
	MOVQ $0x10, AX;                  \
	KMOVW AX, K3;                    \
	KXORW K7, K7, K7;                \
	VPXORQ Z26, Z26, Z26;            \
	MOVQ $0x000FFFFFFFFFFFFF, AX;    \
	VPBROADCASTQ AX, Z28;            \
	MOVQ $0x1000003D10, AX;          \
	VPBROADCASTQ AX, Z29;            \
	MOVQ $0x1000003D1, AX;           \
	VPBROADCASTQ AX, Z30;            \
	MOVQ $1, AX;                     \
	VPBROADCASTQ AX, Z22;            \
	MOVQ $2, AX;                     \
	VPBROADCASTQ AX, Z23;            \
	MOVQ $3, AX;                     \
	VPBROADCASTQ AX, Z24;            \
	MOVQ $4, AX;                     \
	VPBROADCASTQ AX, Z25;            \
	VMOVDQU64 ifmaC2<>(SB), Z31;     \
	VMOVDQU64 ifmaC8<>(SB), Z21

// ZEROACC clears the five column accumulators. The zeroing idiom is
// dependency breaking, so back to back operations never chain through
// stale accumulators.
#define ZEROACC \
	VPXORQ Z8, Z8, Z8;    \
	VPXORQ Z9, Z9, Z9;    \
	VPXORQ Z10, Z10, Z10; \
	VPXORQ Z11, Z11, Z11; \
	VPXORQ Z12, Z12, Z12

// BALIGN builds the lane alignments of the vector operand zb used by
// MROWS: up by 1..5 into Z1..Z5 for the column rows, down by 3 and 4 into
// Z6 and Z7 for the columns past lane 7.
#define BALIGN(zb) \
	VALIGNQ $7, Z26, zb, Z1; \
	VALIGNQ $6, Z26, zb, Z2; \
	VALIGNQ $5, Z26, zb, Z3; \
	VALIGNQ $4, Z26, zb, Z4; \
	VALIGNQ $3, Z26, zb, Z5; \
	VALIGNQ $3, zb, Z26, Z6; \
	VALIGNQ $4, zb, Z26, Z7

// MROWS accumulates the product columns of za*zb. Row i broadcasts limb i
// of za and multiplies the alignment that places b_j in lane i+j, low
// halves into Z8/Z9 and high halves into Z10/Z11. Lane 0 of Z12 collects
// column p8, lane 1 column p9. BALIGN(zb) and ZEROACC must run first.
#define MROWS(za, zb) \
	VPERMQ za, Z26, Z13;         \
	VPMADD52LUQ zb, Z13, Z8;     \
	VPMADD52HUQ Z1, Z13, Z10;    \
	VPERMQ za, Z22, Z14;         \
	VPMADD52LUQ Z1, Z14, Z9;     \
	VPMADD52HUQ Z2, Z14, Z11;    \
	VPERMQ za, Z23, Z15;         \
	VPMADD52LUQ Z2, Z15, Z8;     \
	VPMADD52HUQ Z3, Z15, Z10;    \
	VPERMQ za, Z24, Z13;         \
	VPMADD52LUQ Z3, Z13, Z9;     \
	VPMADD52HUQ Z4, Z13, Z11;    \
	VPERMQ za, Z25, Z14;         \
	VPMADD52LUQ Z4, Z14, Z8;     \
	VPMADD52HUQ Z5, Z14, Z10;    \
	VPMADD52LUQ Z7, Z14, Z12;    \
	VPMADD52HUQ Z6, Z14, Z12;    \
	VPMADD52HUQ Z7, Z13, Z12

// MERGE folds the split accumulators into Z8 (low halves, columns in
// lanes 0..7) and Z10 (high halves, columns in lanes 1..7).
#define MERGE \
	VPADDQ Z9, Z8, Z8; \
	VPADDQ Z11, Z10, Z10

// REDFOLD merges all columns into Z8 and folds the high ones through r52
// without a prior digit pass: relaxed reduction only needs each fold
// term at the right column, so every bucket splits into its low 52 bits
// and its small excess, with the fold terms accumulating on a side chain
// that joins Z8 once. Afterwards lanes 0..4 hold sums below 2^58 and
// lane 5 holds only fold spill below 2^44.
#define REDFOLD(zd) \
	VPADDQ Z10, Z8, zd;         \
	VALIGNQ $5, zd, Z12, Z13;   \
	VMOVDQU64.Z zd, K1, zd;     \
	VPSRLQ $52, Z13, Z14;       \
	VPANDQ Z28, Z13, Z13;       \
	VPXORQ Z0, Z0, Z0;          \
	VPMADD52LUQ Z13, Z29, zd;   \
	VALIGNQ $7, Z26, Z13, Z15;  \
	VPMADD52HUQ Z15, Z29, Z0;   \
	VALIGNQ $7, Z26, Z14, Z14;  \
	VPMADD52LUQ Z14, Z29, Z0;   \
	VPADDQ Z0, zd, zd

// REDTAIL2 finishes a reduction after REDFOLD with one masked carry
// round: the lane 5 spill and the lane 4 carry fold through r52 against
// the raw columns first, so the single round leaves every lane strict
// except with probability around 2^-45 per lane, which the closing test
// catches into K7.
#define REDTAIL2(zd) \
	VALIGNQ $5, zd, Z26, Z14;   \
	VPSRLQ.Z $52, zd, K3, Z13;  \
	VALIGNQ $4, Z13, Z26, Z13;  \
	VPMADD52LUQ Z14, Z29, zd;   \
	VPXORQ Z0, Z0, Z0;          \
	VPMADD52LUQ Z13, Z29, Z0;   \
	VALIGNQ $7, Z26, Z14, Z15;  \
	VPMADD52HUQ Z15, Z29, Z0;   \
	VPADDQ Z0, zd, zd;          \
	VPSRLQ $52, zd, Z13;        \
	VPANDQ.Z Z28, zd, K1, zd;   \
	VALIGNQ $7, Z26, Z13, Z14;  \
	VPADDQ Z14, zd, K1, zd;     \
	VPSRLQ $52, zd, Z13;        \
	VPTESTMQ Z13, Z13, K6;      \
	KORW K6, K7, K7

// REDTAILW is REDTAIL2 for stored coordinates: the limb 4 bits at and
// above 2^48 fold through fieldC and the round masks the top limb to the
// weak normalized 2^48 scale.
#define REDTAILW(zd) \
	VALIGNQ $5, zd, Z26, Z14;   \
	VPSRLQ.Z $48, zd, K3, Z13;  \
	VALIGNQ $4, Z13, Z26, Z13;  \
	VPMADD52LUQ Z14, Z29, zd;   \
	VPXORQ Z0, Z0, Z0;          \
	VPMADD52LUQ Z13, Z30, Z0;   \
	VALIGNQ $7, Z26, Z14, Z15;  \
	VPMADD52HUQ Z15, Z29, Z0;   \
	VPADDQ Z0, zd, zd;          \
	VPSRLQ $52, zd, Z13;        \
	VMOVDQU64 ifmaWideMask<>(SB), Z14; \
	VPANDQ.Z Z14, zd, K1, zd;   \
	VALIGNQ $7, Z26, Z13, Z14;  \
	VPADDQ Z14, zd, K1, zd;     \
	VPSRLQ $52, zd, Z13;        \
	VPTESTMQ Z13, Z13, K6;      \
	KORW K6, K7, K7

// PASSF2 carries a loose value zv, lanes below 2^63 with lanes 5..7
// zero, back under 2^52 per lane with one masked round, folding the
// lane 4 carry through r52 first.
#define PASSF2(zv) \
	VPSRLQ.Z $52, zv, K3, Z13; \
	VALIGNQ $4, Z13, Z26, Z13; \
	VPMADD52LUQ Z13, Z29, zv;  \
	VPSRLQ $52, zv, Z13;       \
	VPANDQ.Z Z28, zv, K1, zv;  \
	VALIGNQ $7, Z26, Z13, Z14; \
	VPADDQ Z14, zv, K1, zv;    \
	VPSRLQ $52, zv, Z13;       \
	VPTESTMQ Z13, Z13, K6;     \
	KORW K6, K7, K7

// WEAKOUT2 is PASSF2 for stored coordinates, folding the limb 4 bits at
// and above 2^48 through fieldC and masking the top limb to the 2^48
// scale.
#define WEAKOUT2(zv) \
	VPSRLQ.Z $48, zv, K3, Z13; \
	VALIGNQ $4, Z13, Z26, Z13; \
	VPMADD52LUQ Z13, Z30, zv;  \
	VPSRLQ $52, zv, Z13;       \
	VMOVDQU64 ifmaWideMask<>(SB), Z14; \
	VPANDQ.Z Z14, zv, K1, zv;  \
	VALIGNQ $7, Z26, Z13, Z14; \
	VPADDQ Z14, zv, K1, zv;    \
	VPSRLQ $52, zv, Z13;       \
	VPTESTMQ Z13, Z13, K6;     \
	KORW K6, K7, K7
// The field prime p in weak normalized limbs, for the degenerate check
// of the mixed addition.
DATA ifmaPrime<>+0(SB)/8, $0xFFFFEFFFFFC2F
DATA ifmaPrime<>+8(SB)/8, $0x000FFFFFFFFFFFFF
DATA ifmaPrime<>+16(SB)/8, $0x000FFFFFFFFFFFFF
DATA ifmaPrime<>+24(SB)/8, $0x000FFFFFFFFFFFFF
DATA ifmaPrime<>+32(SB)/8, $0x0000FFFFFFFFFFFF
DATA ifmaPrime<>+40(SB)/8, $0
DATA ifmaPrime<>+48(SB)/8, $0
DATA ifmaPrime<>+56(SB)/8, $0
GLOBL ifmaPrime<>(SB), RODATA, $64
