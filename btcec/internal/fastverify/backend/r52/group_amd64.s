// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build amd64 && !purego

#include "textflag.h"

// Fused group operations. Each routine keeps every field intermediate in
// its own stack frame and mirrors the formulas of doubleGeneric and
// addMixedGeneric, so the differential tests validate these directly. The
// field macros below are the fe_amd64.s multiply and square with their
// operands parameterized as base register plus constant offset. Register
// conventions shared by every macro:
//
//	R13       52-bit mask, loaded once per routine and never clobbered
//	0..32(SP) five word scratch area owned by FEMUL and FESQR
//	SI, BX    input pointers, preserved by every macro
//
// The macros clobber AX, CX, DX, DI, R8-R12, R14 and R15. Negation
// constants are the multiples (m+1)*twoP of the field.go negation base for
// the magnitudes m used by the formulas, precomputed per limb.

// FEMUL computes the 5x52 field multiplication of fe_amd64.s from
// (ao)(ab) times (bo)(bb) into (do)(db) in loose form. The destination may
// alias either operand because it is written only after every read.
#define FEMUL(db, do, ab, ao, bb, bo) \
	MOVQ (ao+0)(ab), R8;    \
	MOVQ (ao+8)(ab), R9;    \
	MOVQ (ao+16)(ab), R10;  \
	MOVQ (ao+24)(ab), R11;  \
	MOVQ (ao+32)(ab), R12;  \
	MOVQ R9, AX;            \
	MULQ (bo+32)(bb);       \
	MOVQ AX, R15;           \
	MOVQ DX, R14;           \
	MOVQ R10, AX;           \
	MULQ (bo+24)(bb);       \
	ADDQ AX, R15;           \
	ADCQ DX, R14;           \
	MOVQ R11, AX;           \
	MULQ (bo+16)(bb);       \
	ADDQ AX, R15;           \
	ADCQ DX, R14;           \
	MOVQ R12, AX;           \
	MULQ (bo+8)(bb);        \
	ADDQ AX, R15;           \
	ADCQ DX, R14;           \
	MOVQ R15, DI;           \
	ANDQ R13, DI;           \
	MOVQ DI, 0(SP);         \
	SHRQ $52, R14, R15;     \
	SHRQ $52, R14;          \
	MOVQ R10, AX;           \
	MULQ (bo+32)(bb);       \
	ADDQ AX, R15;           \
	ADCQ DX, R14;           \
	MOVQ R11, AX;           \
	MULQ (bo+24)(bb);       \
	ADDQ AX, R15;           \
	ADCQ DX, R14;           \
	MOVQ R12, AX;           \
	MULQ (bo+16)(bb);       \
	ADDQ AX, R15;           \
	ADCQ DX, R14;           \
	MOVQ R15, DI;           \
	ANDQ R13, DI;           \
	MOVQ DI, 8(SP);         \
	SHRQ $52, R14, R15;     \
	SHRQ $52, R14;          \
	MOVQ R11, AX;           \
	MULQ (bo+32)(bb);       \
	ADDQ AX, R15;           \
	ADCQ DX, R14;           \
	MOVQ R12, AX;           \
	MULQ (bo+24)(bb);       \
	ADDQ AX, R15;           \
	ADCQ DX, R14;           \
	MOVQ R15, DI;           \
	ANDQ R13, DI;           \
	MOVQ DI, 16(SP);        \
	SHRQ $52, R14, R15;     \
	SHRQ $52, R14;          \
	MOVQ R12, AX;           \
	MULQ (bo+32)(bb);       \
	ADDQ AX, R15;           \
	ADCQ DX, R14;           \
	MOVQ R15, DI;           \
	ANDQ R13, DI;           \
	MOVQ DI, 24(SP);        \
	SHRQ $52, R14, R15;     \
	MOVQ R15, 32(SP);       \
	MOVQ R8, AX;            \
	MULQ (bo+0)(bb);        \
	MOVQ AX, DI;            \
	MOVQ DX, CX;            \
	MOVQ $0x1000003D10, AX; \
	MULQ 0(SP);             \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ DI, R14;           \
	ANDQ R13, R14;          \
	MOVQ R14, 0(SP);        \
	SHRQ $52, CX, DI;       \
	SHRQ $52, CX;           \
	MOVQ R8, AX;            \
	MULQ (bo+8)(bb);        \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ R9, AX;            \
	MULQ (bo+0)(bb);        \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ $0x1000003D10, AX; \
	MULQ 8(SP);             \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ DI, R14;           \
	ANDQ R13, R14;          \
	MOVQ R14, 8(SP);        \
	SHRQ $52, CX, DI;       \
	SHRQ $52, CX;           \
	MOVQ R8, AX;            \
	MULQ (bo+16)(bb);       \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ R9, AX;            \
	MULQ (bo+8)(bb);        \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ R10, AX;           \
	MULQ (bo+0)(bb);        \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ $0x1000003D10, AX; \
	MULQ 16(SP);            \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ DI, R14;           \
	ANDQ R13, R14;          \
	MOVQ R14, 16(SP);       \
	SHRQ $52, CX, DI;       \
	SHRQ $52, CX;           \
	MOVQ R8, AX;            \
	MULQ (bo+24)(bb);       \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ R9, AX;            \
	MULQ (bo+16)(bb);       \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ R10, AX;           \
	MULQ (bo+8)(bb);        \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ R11, AX;           \
	MULQ (bo+0)(bb);        \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ $0x1000003D10, AX; \
	MULQ 24(SP);            \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ DI, R14;           \
	ANDQ R13, R14;          \
	MOVQ R14, 24(SP);       \
	SHRQ $52, CX, DI;       \
	SHRQ $52, CX;           \
	MOVQ R8, AX;            \
	MULQ (bo+32)(bb);       \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ R9, AX;            \
	MULQ (bo+24)(bb);       \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ R10, AX;           \
	MULQ (bo+16)(bb);       \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ R11, AX;           \
	MULQ (bo+8)(bb);        \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ R12, AX;           \
	MULQ (bo+0)(bb);        \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ $0x1000003D10, AX; \
	MULQ 32(SP);            \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ DI, R14;           \
	ANDQ R13, R14;          \
	SHRQ $52, CX, DI;       \
	MOVQ $0x1000003D10, AX; \
	MULQ DI;                \
	MOVQ AX, DI;            \
	MOVQ DX, CX;            \
	MOVQ R14, AX;           \
	SHRQ $48, AX;           \
	MOVQ $0x1000003D1, R9;  \
	MULQ R9;                \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	ADDQ 0(SP), DI;         \
	ADCQ $0, CX;            \
	MOVQ R13, R10;          \
	SHRQ $4, R10;           \
	ANDQ R10, R14;          \
	MOVQ DI, R11;           \
	ANDQ R13, R11;          \
	SHRQ $52, CX, DI;       \
	ADDQ 8(SP), DI;         \
	MOVQ R11, (do+0)(db);   \
	MOVQ DI, (do+8)(db);    \
	MOVQ 16(SP), AX;        \
	MOVQ AX, (do+16)(db);   \
	MOVQ 24(SP), AX;        \
	MOVQ AX, (do+24)(db);   \
	MOVQ R14, (do+32)(db)

// FESQR computes the 5x52 field squaring of fe_amd64.s from (ao)(ab) into
// (do)(db) in loose form. The destination may alias the operand.
#define FESQR(db, do, ab, ao) \
	MOVQ (ao+0)(ab), R8;    \
	MOVQ (ao+8)(ab), R9;    \
	MOVQ (ao+16)(ab), R10;  \
	MOVQ (ao+24)(ab), R11;  \
	MOVQ (ao+32)(ab), R12;  \
	MOVQ R9, AX;            \
	ADDQ AX, AX;            \
	MULQ R12;               \
	MOVQ AX, R15;           \
	MOVQ DX, R14;           \
	MOVQ R10, AX;           \
	ADDQ AX, AX;            \
	MULQ R11;               \
	ADDQ AX, R15;           \
	ADCQ DX, R14;           \
	MOVQ R15, DI;           \
	ANDQ R13, DI;           \
	MOVQ DI, 0(SP);         \
	SHRQ $52, R14, R15;     \
	SHRQ $52, R14;          \
	MOVQ R10, AX;           \
	ADDQ AX, AX;            \
	MULQ R12;               \
	ADDQ AX, R15;           \
	ADCQ DX, R14;           \
	MOVQ R11, AX;           \
	MULQ R11;               \
	ADDQ AX, R15;           \
	ADCQ DX, R14;           \
	MOVQ R15, DI;           \
	ANDQ R13, DI;           \
	MOVQ DI, 8(SP);         \
	SHRQ $52, R14, R15;     \
	SHRQ $52, R14;          \
	MOVQ R11, AX;           \
	ADDQ AX, AX;            \
	MULQ R12;               \
	ADDQ AX, R15;           \
	ADCQ DX, R14;           \
	MOVQ R15, DI;           \
	ANDQ R13, DI;           \
	MOVQ DI, 16(SP);        \
	SHRQ $52, R14, R15;     \
	SHRQ $52, R14;          \
	MOVQ R12, AX;           \
	MULQ R12;               \
	ADDQ AX, R15;           \
	ADCQ DX, R14;           \
	MOVQ R15, DI;           \
	ANDQ R13, DI;           \
	MOVQ DI, 24(SP);        \
	SHRQ $52, R14, R15;     \
	MOVQ R15, 32(SP);       \
	MOVQ R8, AX;            \
	MULQ R8;                \
	MOVQ AX, DI;            \
	MOVQ DX, CX;            \
	MOVQ $0x1000003D10, AX; \
	MULQ 0(SP);             \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ DI, R14;           \
	ANDQ R13, R14;          \
	MOVQ R14, 0(SP);        \
	SHRQ $52, CX, DI;       \
	SHRQ $52, CX;           \
	MOVQ R8, AX;            \
	ADDQ AX, AX;            \
	MULQ R9;                \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ $0x1000003D10, AX; \
	MULQ 8(SP);             \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ DI, R14;           \
	ANDQ R13, R14;          \
	MOVQ R14, 8(SP);        \
	SHRQ $52, CX, DI;       \
	SHRQ $52, CX;           \
	MOVQ R8, AX;            \
	ADDQ AX, AX;            \
	MULQ R10;               \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ R9, AX;            \
	MULQ R9;                \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ $0x1000003D10, AX; \
	MULQ 16(SP);            \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ DI, R14;           \
	ANDQ R13, R14;          \
	MOVQ R14, 16(SP);       \
	SHRQ $52, CX, DI;       \
	SHRQ $52, CX;           \
	MOVQ R8, AX;            \
	ADDQ AX, AX;            \
	MULQ R11;               \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ R9, AX;            \
	ADDQ AX, AX;            \
	MULQ R10;               \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ $0x1000003D10, AX; \
	MULQ 24(SP);            \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ DI, R14;           \
	ANDQ R13, R14;          \
	MOVQ R14, 24(SP);       \
	SHRQ $52, CX, DI;       \
	SHRQ $52, CX;           \
	MOVQ R8, AX;            \
	ADDQ AX, AX;            \
	MULQ R12;               \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ R9, AX;            \
	ADDQ AX, AX;            \
	MULQ R11;               \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ R10, AX;           \
	MULQ R10;               \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ $0x1000003D10, AX; \
	MULQ 32(SP);            \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	MOVQ DI, R14;           \
	ANDQ R13, R14;          \
	SHRQ $52, CX, DI;       \
	MOVQ $0x1000003D10, AX; \
	MULQ DI;                \
	MOVQ AX, DI;            \
	MOVQ DX, CX;            \
	MOVQ R14, AX;           \
	SHRQ $48, AX;           \
	MOVQ $0x1000003D1, R9;  \
	MULQ R9;                \
	ADDQ AX, DI;            \
	ADCQ DX, CX;            \
	ADDQ 0(SP), DI;         \
	ADCQ $0, CX;            \
	MOVQ R13, R10;          \
	SHRQ $4, R10;           \
	ANDQ R10, R14;          \
	MOVQ DI, R11;           \
	ANDQ R13, R11;          \
	SHRQ $52, CX, DI;       \
	ADDQ 8(SP), DI;         \
	MOVQ R11, (do+0)(db);   \
	MOVQ DI, (do+8)(db);    \
	MOVQ 16(SP), AX;        \
	MOVQ AX, (do+16)(db);   \
	MOVQ 24(SP), AX;        \
	MOVQ AX, (do+24)(db);   \
	MOVQ R14, (do+32)(db)

// FECOPY copies the five limbs at (so)(sb) to (do)(db).
#define FECOPY(db, do, sb, so) \
	MOVOU (so+0)(sb), X0;  \
	MOVOU X0, (do+0)(db);  \
	MOVOU (so+16)(sb), X0; \
	MOVOU X0, (do+16)(db); \
	MOVQ (so+32)(sb), AX;  \
	MOVQ AX, (do+32)(db)

// FEADD adds the limbs at (so)(sb) into (do)(db).
#define FEADD(db, do, sb, so) \
	MOVQ (so+0)(sb), AX;  \
	ADDQ AX, (do+0)(db);  \
	MOVQ (so+8)(sb), AX;  \
	ADDQ AX, (do+8)(db);  \
	MOVQ (so+16)(sb), AX; \
	ADDQ AX, (do+16)(db); \
	MOVQ (so+24)(sb), AX; \
	ADDQ AX, (do+24)(db); \
	MOVQ (so+32)(sb), AX; \
	ADDQ AX, (do+32)(db)

// FEMULINT multiplies every limb at (o)(b) by the small constant k.
#define FEMULINT(b, o, k) \
	IMUL3Q $k, (o+0)(b), AX;  \
	MOVQ AX, (o+0)(b);        \
	IMUL3Q $k, (o+8)(b), AX;  \
	MOVQ AX, (o+8)(b);        \
	IMUL3Q $k, (o+16)(b), AX; \
	MOVQ AX, (o+16)(b);       \
	IMUL3Q $k, (o+24)(b), AX; \
	MOVQ AX, (o+24)(b);       \
	IMUL3Q $k, (o+32)(b), AX; \
	MOVQ AX, (o+32)(b)

// FESHL shifts every limb at (o)(b) left by the constant s, multiplying
// by a power of two directly in memory.
#define FESHL(b, o, s) \
	SHLQ $s, (o+0)(b);  \
	SHLQ $s, (o+8)(b);  \
	SHLQ $s, (o+16)(b); \
	SHLQ $s, (o+24)(b); \
	SHLQ $s, (o+32)(b)

// The composite macros below fold a negation, an optional small scaling,
// an addition, and an optional weak normalization into one register pass
// per coordinate. Negation subtracts from a multiple of the field.go
// negation base twoP, chosen for the magnitude of the subtrahend exactly
// as the generic code chooses its Negate argument: C2 is 2*twoP for
// Negate(1), C3 is 3*twoP for Negate(2), C8 is 8*twoP for Negate(7).

// WEAKSTORE carries limbs held in R8..R12 as normalizeWeak does and
// stores them to (o)(b). Clobbers AX, CX and DX.
#define WEAKSTORE(b, o) \
	MOVQ R8, AX;           \
	SHRQ $52, AX;          \
	ANDQ R13, R8;          \
	ADDQ AX, R9;           \
	MOVQ R9, AX;           \
	SHRQ $52, AX;          \
	ANDQ R13, R9;          \
	ADDQ AX, R10;          \
	MOVQ R10, AX;          \
	SHRQ $52, AX;          \
	ANDQ R13, R10;         \
	ADDQ AX, R11;          \
	MOVQ R11, AX;          \
	SHRQ $52, AX;          \
	ANDQ R13, R11;         \
	ADDQ AX, R12;          \
	MOVQ R12, AX;          \
	SHRQ $48, AX;          \
	MOVQ R13, CX;          \
	SHRQ $4, CX;           \
	ANDQ CX, R12;          \
	MOVQ $0x1000003D1, DX; \
	IMULQ DX, AX;          \
	ADDQ AX, R8;           \
	MOVQ R8, AX;           \
	SHRQ $52, AX;          \
	ANDQ R13, R8;          \
	ADDQ AX, R9;           \
	MOVQ R9, AX;           \
	SHRQ $52, AX;          \
	ANDQ R13, R9;          \
	ADDQ AX, R10;          \
	MOVQ R10, AX;          \
	SHRQ $52, AX;          \
	ANDQ R13, R10;         \
	ADDQ AX, R11;          \
	MOVQ R11, AX;          \
	SHRQ $52, AX;          \
	ANDQ R13, R11;         \
	ADDQ AX, R12;          \
	MOVQ R8, (o+0)(b);     \
	MOVQ R9, (o+8)(b);     \
	MOVQ R10, (o+16)(b);   \
	MOVQ R11, (o+24)(b);   \
	MOVQ R12, (o+32)(b)

// FESUB2 sets (do)(db) to the value at (mo)(mb) minus the value at
// (so)(sb), negating with the C2 constants.
#define FESUB2(db, do, mb, mo, sb, so) \
	MOVQ $0x3FFFFBFFFFF0BC, AX; \
	SUBQ (so+0)(sb), AX;        \
	ADDQ (mo+0)(mb), AX;        \
	MOVQ AX, (do+0)(db);        \
	MOVQ $0x3FFFFFFFFFFFFC, AX; \
	SUBQ (so+8)(sb), AX;        \
	ADDQ (mo+8)(mb), AX;        \
	MOVQ AX, (do+8)(db);        \
	MOVQ $0x3FFFFFFFFFFFFC, AX; \
	SUBQ (so+16)(sb), AX;       \
	ADDQ (mo+16)(mb), AX;       \
	MOVQ AX, (do+16)(db);       \
	MOVQ $0x3FFFFFFFFFFFFC, AX; \
	SUBQ (so+24)(sb), AX;       \
	ADDQ (mo+24)(mb), AX;       \
	MOVQ AX, (do+24)(db);       \
	MOVQ $0x3FFFFFFFFFFFC, AX;  \
	SUBQ (so+32)(sb), AX;       \
	ADDQ (mo+32)(mb), AX;       \
	MOVQ AX, (do+32)(db)

// FESUBIN subtracts the value at (so)(sb) from (do)(db) in place,
// negating with the C2 constants.
#define FESUBIN(db, do, sb, so) \
	MOVQ $0x3FFFFBFFFFF0BC, AX; \
	SUBQ (so+0)(sb), AX;        \
	ADDQ AX, (do+0)(db);        \
	MOVQ $0x3FFFFFFFFFFFFC, AX; \
	SUBQ (so+8)(sb), AX;        \
	ADDQ AX, (do+8)(db);        \
	MOVQ $0x3FFFFFFFFFFFFC, AX; \
	SUBQ (so+16)(sb), AX;       \
	ADDQ AX, (do+16)(db);       \
	MOVQ $0x3FFFFFFFFFFFFC, AX; \
	SUBQ (so+24)(sb), AX;       \
	ADDQ AX, (do+24)(db);       \
	MOVQ $0x3FFFFFFFFFFFC, AX;  \
	SUBQ (so+32)(sb), AX;       \
	ADDQ AX, (do+32)(db)

// FESUBINW subtracts the value at (so)(sb) from (do)(db) with the C2
// constants, then weak normalizes and stores the result.
#define FESUBINW(db, do, sb, so) \
	MOVQ $0x3FFFFBFFFFF0BC, R8; \
	SUBQ (so+0)(sb), R8;        \
	ADDQ (do+0)(db), R8;        \
	MOVQ $0x3FFFFFFFFFFFFC, R9; \
	SUBQ (so+8)(sb), R9;        \
	ADDQ (do+8)(db), R9;        \
	MOVQ $0x3FFFFFFFFFFFFC, R10; \
	SUBQ (so+16)(sb), R10;      \
	ADDQ (do+16)(db), R10;      \
	MOVQ $0x3FFFFFFFFFFFFC, R11; \
	SUBQ (so+24)(sb), R11;      \
	ADDQ (do+24)(db), R11;      \
	MOVQ $0x3FFFFFFFFFFFC, R12; \
	SUBQ (so+32)(sb), R12;      \
	ADDQ (do+32)(db), R12;      \
	WEAKSTORE(db, do)

// FESUB2X3W subtracts twice the value at (so)(sb) from (do)(db) with the
// C3 constants, then weak normalizes and stores the result.
#define FESUB2X3W(db, do, sb, so) \
	MOVQ (so+0)(sb), AX;        \
	ADDQ AX, AX;                \
	MOVQ $0x5FFFF9FFFFE91A, R8; \
	SUBQ AX, R8;                \
	ADDQ (do+0)(db), R8;        \
	MOVQ (so+8)(sb), AX;        \
	ADDQ AX, AX;                \
	MOVQ $0x5FFFFFFFFFFFFA, R9; \
	SUBQ AX, R9;                \
	ADDQ (do+8)(db), R9;        \
	MOVQ (so+16)(sb), AX;       \
	ADDQ AX, AX;                \
	MOVQ $0x5FFFFFFFFFFFFA, R10; \
	SUBQ AX, R10;               \
	ADDQ (do+16)(db), R10;      \
	MOVQ (so+24)(sb), AX;       \
	ADDQ AX, AX;                \
	MOVQ $0x5FFFFFFFFFFFFA, R11; \
	SUBQ AX, R11;               \
	ADDQ (do+24)(db), R11;      \
	MOVQ (so+32)(sb), AX;       \
	ADDQ AX, AX;                \
	MOVQ $0x5FFFFFFFFFFFA, R12; \
	SUBQ AX, R12;               \
	ADDQ (do+32)(db), R12;      \
	WEAKSTORE(db, do)

// FESUB2X8W subtracts twice the value at (so)(sb) from (do)(db) with the
// C8 constants, then weak normalizes and stores the result.
#define FESUB2X8W(db, do, sb, so) \
	MOVQ (so+0)(sb), AX;        \
	ADDQ AX, AX;                \
	MOVQ $0xFFFFEFFFFFC2F0, R8; \
	SUBQ AX, R8;                \
	ADDQ (do+0)(db), R8;        \
	MOVQ (so+8)(sb), AX;        \
	ADDQ AX, AX;                \
	MOVQ $0xFFFFFFFFFFFFF0, R9; \
	SUBQ AX, R9;                \
	ADDQ (do+8)(db), R9;        \
	MOVQ (so+16)(sb), AX;       \
	ADDQ AX, AX;                \
	MOVQ $0xFFFFFFFFFFFFF0, R10; \
	SUBQ AX, R10;               \
	ADDQ (do+16)(db), R10;      \
	MOVQ (so+24)(sb), AX;       \
	ADDQ AX, AX;                \
	MOVQ $0xFFFFFFFFFFFFF0, R11; \
	SUBQ AX, R11;               \
	ADDQ (do+24)(db), R11;      \
	MOVQ (so+32)(sb), AX;       \
	ADDQ AX, AX;                \
	MOVQ $0xFFFFFFFFFFFF0, R12; \
	SUBQ AX, R12;               \
	ADDQ (do+32)(db), R12;      \
	WEAKSTORE(db, do)

// FESUB8X8W subtracts eight times the value at (so)(sb) from (do)(db)
// with the C8 constants, then weak normalizes and stores the result.
#define FESUB8X8W(db, do, sb, so) \
	MOVQ (so+0)(sb), AX;        \
	SHLQ $3, AX;                \
	MOVQ $0xFFFFEFFFFFC2F0, R8; \
	SUBQ AX, R8;                \
	ADDQ (do+0)(db), R8;        \
	MOVQ (so+8)(sb), AX;        \
	SHLQ $3, AX;                \
	MOVQ $0xFFFFFFFFFFFFF0, R9; \
	SUBQ AX, R9;                \
	ADDQ (do+8)(db), R9;        \
	MOVQ (so+16)(sb), AX;       \
	SHLQ $3, AX;                \
	MOVQ $0xFFFFFFFFFFFFF0, R10; \
	SUBQ AX, R10;               \
	ADDQ (do+16)(db), R10;      \
	MOVQ (so+24)(sb), AX;       \
	SHLQ $3, AX;                \
	MOVQ $0xFFFFFFFFFFFFF0, R11; \
	SUBQ AX, R11;               \
	ADDQ (do+24)(db), R11;      \
	MOVQ (so+32)(sb), AX;       \
	SHLQ $3, AX;                \
	MOVQ $0xFFFFFFFFFFFF0, R12; \
	SUBQ AX, R12;               \
	ADDQ (do+32)(db), R12;      \
	WEAKSTORE(db, do)

// FEWEAK applies normalizeWeak in place to the value at (o)(b).
#define FEWEAK(b, o) \
	MOVQ (o+0)(b), R8;     \
	MOVQ (o+8)(b), R9;     \
	MOVQ (o+16)(b), R10;   \
	MOVQ (o+24)(b), R11;   \
	MOVQ (o+32)(b), R12;   \
	MOVQ R8, AX;           \
	SHRQ $52, AX;          \
	ANDQ R13, R8;          \
	ADDQ AX, R9;           \
	MOVQ R9, AX;           \
	SHRQ $52, AX;          \
	ANDQ R13, R9;          \
	ADDQ AX, R10;          \
	MOVQ R10, AX;          \
	SHRQ $52, AX;          \
	ANDQ R13, R10;         \
	ADDQ AX, R11;          \
	MOVQ R11, AX;          \
	SHRQ $52, AX;          \
	ANDQ R13, R11;         \
	ADDQ AX, R12;          \
	MOVQ R12, AX;          \
	SHRQ $48, AX;          \
	MOVQ R13, CX;          \
	SHRQ $4, CX;           \
	ANDQ CX, R12;          \
	MOVQ $0x1000003D1, DX; \
	IMULQ DX, AX;          \
	ADDQ AX, R8;           \
	MOVQ R8, AX;           \
	SHRQ $52, AX;          \
	ANDQ R13, R8;          \
	ADDQ AX, R9;           \
	MOVQ R9, AX;           \
	SHRQ $52, AX;          \
	ANDQ R13, R9;          \
	ADDQ AX, R10;          \
	MOVQ R10, AX;          \
	SHRQ $52, AX;          \
	ANDQ R13, R10;         \
	ADDQ AX, R11;          \
	MOVQ R11, AX;          \
	SHRQ $52, AX;          \
	ANDQ R13, R11;         \
	ADDQ AX, R12;          \
	MOVQ R8, (o+0)(b);     \
	MOVQ R9, (o+8)(b);     \
	MOVQ R10, (o+16)(b);   \
	MOVQ R11, (o+24)(b);   \
	MOVQ R12, (o+32)(b)

// Frame temps for jacDoubleAsm, after the 40 byte macro scratch area.
#define DBL_A  40
#define DBL_B  80
#define DBL_C  120
#define DBL_D  160
#define DBL_X3 200
#define DBL_Y3 240
#define DBL_Z3 280

// func jacDoubleAsm(p, a *jacobianPoint)
TEXT ·jacDoubleAsm(SB), NOSPLIT, $320-16
	MOVQ a+8(FP), SI
	MOVQ $0x000FFFFFFFFFFFFF, R13

	// Z3 = 2*Y*Z
	FEMUL(SP, DBL_Z3, SI, 40, SI, 80)
	FESHL(SP, DBL_Z3, 1)

	// A = X^2, B = Y^2, C = B^2, D = 4*X*B
	FESQR(SP, DBL_A, SI, 0)
	FESQR(SP, DBL_B, SI, 40)
	FESQR(SP, DBL_C, SP, DBL_B)
	FEMUL(SP, DBL_D, SI, 0, SP, DBL_B)
	FESHL(SP, DBL_D, 2)

	// E = 3*A in place, then X3 = E^2 - 2*D
	FEMULINT(SP, DBL_A, 3)
	FESQR(SP, DBL_X3, SP, DBL_A)
	FESUB2X8W(SP, DBL_X3, SP, DBL_D)

	// Y3 = E*(D - X3) - 8*C
	FESUB2(SP, DBL_Y3, SP, DBL_D, SP, DBL_X3)
	FEMUL(SP, DBL_Y3, SP, DBL_Y3, SP, DBL_A)
	FESUB8X8W(SP, DBL_Y3, SP, DBL_C)

	MOVQ p+0(FP), DI
	FECOPY(DI, 0, SP, DBL_X3)
	FECOPY(DI, 40, SP, DBL_Y3)
	FECOPY(DI, 80, SP, DBL_Z3)
	RET

// Frame temps for jacAddMixedAsm, after the 40 byte macro scratch area.
// The TMP slot is reused for the negated j, the doubled v, and the Y3
// accumulator once its previous holder is dead.
#define ADD_Z2  40
#define ADD_TMP 80
#define ADD_S2  120
#define ADD_H   160
#define ADD_RR  200
#define ADD_HH  240
#define ADD_I   280
#define ADD_J   320
#define ADD_V   360
#define ADD_X3  400

// func jacAddMixedAsm(p, a *jacobianPoint, b *affinePoint) uint64
TEXT ·jacAddMixedAsm(SB), NOSPLIT, $440-32
	MOVQ a+8(FP), SI
	MOVQ b+16(FP), BX
	MOVQ $0x000FFFFFFFFFFFFF, R13

	// z1z1 = Z1^2, u2 = X2*z1z1, s2 = Y2*Z1*z1z1
	FESQR(SP, ADD_Z2, SI, 80)
	FEMUL(SP, ADD_TMP, BX, 0, SP, ADD_Z2)
	FEMUL(SP, ADD_S2, BX, 40, SI, 80)
	FEMUL(SP, ADD_S2, SP, ADD_S2, SP, ADD_Z2)

	// h = u2 - X1, carried to its 52-bit digits for the check below
	FESUB2(SP, ADD_H, SP, ADD_TMP, SI, 0)
	FEWEAK(SP, ADD_H)

	// The points share an x coordinate exactly when h is congruent to
	// zero, which after the weak normalization means the value zero or
	// the value p. Those cases return to the generic fallback.
	MOVQ (ADD_H+0)(SP), R8
	MOVQ (ADD_H+8)(SP), R9
	MOVQ (ADD_H+16)(SP), R10
	MOVQ (ADD_H+24)(SP), R11
	MOVQ (ADD_H+32)(SP), R12
	MOVQ R8, AX
	ORQ  R9, AX
	ORQ  R10, AX
	ORQ  R11, AX
	ORQ  R12, AX
	JZ   degenerate
	MOVQ $0xFFFFEFFFFFC2F, AX
	XORQ R8, AX
	MOVQ R9, DX
	XORQ R13, DX
	ORQ  DX, AX
	MOVQ R10, DX
	XORQ R13, DX
	ORQ  DX, AX
	MOVQ R11, DX
	XORQ R13, DX
	ORQ  DX, AX
	MOVQ R13, CX
	SHRQ $4, CX
	MOVQ R12, DX
	XORQ CX, DX
	ORQ  DX, AX
	JZ   degenerate

	// rr = 2*(s2 - Y1)
	FESUB2(SP, ADD_RR, SP, ADD_S2, SI, 40)
	FESHL(SP, ADD_RR, 1)

	// hh = h^2, i = 4*hh, j = h*i, v = X1*i
	FESQR(SP, ADD_HH, SP, ADD_H)
	FECOPY(SP, ADD_I, SP, ADD_HH)
	FESHL(SP, ADD_I, 2)
	FEMUL(SP, ADD_J, SP, ADD_H, SP, ADD_I)
	FEMUL(SP, ADD_V, SI, 0, SP, ADD_I)

	// X3 = rr^2 - j - 2*v
	FESQR(SP, ADD_X3, SP, ADD_RR)
	FESUBIN(SP, ADD_X3, SP, ADD_J)
	FESUB2X3W(SP, ADD_X3, SP, ADD_V)

	// Y3 = rr*(v - X3) - 2*Y1*j
	FESUB2(SP, ADD_TMP, SP, ADD_V, SP, ADD_X3)
	FEMUL(SP, ADD_TMP, SP, ADD_TMP, SP, ADD_RR)
	FEMUL(SP, ADD_J, SI, 40, SP, ADD_J)
	FESUB2X3W(SP, ADD_TMP, SP, ADD_J)

	// Z3 = (Z1 + h)^2 - z1z1 - hh, reusing the dead rr slot
	FECOPY(SP, ADD_RR, SI, 80)
	FEADD(SP, ADD_RR, SP, ADD_H)
	FESQR(SP, ADD_RR, SP, ADD_RR)
	FESUBIN(SP, ADD_RR, SP, ADD_Z2)
	FESUBINW(SP, ADD_RR, SP, ADD_HH)

	MOVQ p+0(FP), DI
	FECOPY(DI, 0, SP, ADD_X3)
	FECOPY(DI, 40, SP, ADD_TMP)
	FECOPY(DI, 80, SP, ADD_RR)
	MOVQ $0, ret+24(FP)
	RET

degenerate:
	MOVQ $1, ret+24(FP)
	RET
