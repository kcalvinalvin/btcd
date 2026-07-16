// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build amd64 && !purego

#include "textflag.h"

// func divsteps62Var(eta int64, f0, g0 uint64, t *trans2x2) int64
// Register use: R8 f, R9 g, R10 u, R11 v, R12 q, R13 r, R14 eta, R15 i,
// BX the neginv256 table, CX shift counts, AX/DI/SI scratch.
TEXT ·divsteps62Var(SB), NOSPLIT, $0-40
	MOVQ eta+0(FP), R14
	MOVQ f0+8(FP), R8
	MOVQ g0+16(FP), R9
	MOVQ $1, R10
	XORQ R11, R11
	XORQ R12, R12
	MOVQ $1, R13
	MOVQ $62, R15
	LEAQ ·neginv256(SB), BX

divRound:
	// zeros = trailing zeros of g with the mask capping at i
	MOVQ $-1, AX
	MOVQ R15, CX
	SHLQ CL, AX
	ORQ R9, AX
	TZCNTQ AX, CX
	SHRQ CL, R9
	SHLQ CL, R10
	SHLQ CL, R11
	SUBQ CX, R14
	SUBQ CX, R15
	JZ divDone

	// swap and negate when eta is negative
	TESTQ R14, R14
	JNS divNoSwap
	NEGQ R14
	MOVQ R8, AX
	MOVQ R9, R8
	NEGQ AX
	MOVQ AX, R9
	MOVQ R10, AX
	MOVQ R12, R10
	NEGQ AX
	MOVQ AX, R12
	MOVQ R11, AX
	MOVQ R13, R11
	NEGQ AX
	MOVQ AX, R13

divNoSwap:
	// limit = min(eta+1, i), m = ((1 << limit) - 1) & 255
	LEAQ 1(R14), CX
	CMPQ R15, CX
	CMOVQLT R15, CX
	MOVQ $1, DI
	SHLQ CL, DI
	DECQ DI
	ANDQ $255, DI

	// w = (g * neginv256[(f >> 1) & 127]) & m
	MOVQ R8, AX
	SHRQ $1, AX
	ANDQ $127, AX
	MOVBLZX (BX)(AX*1), AX
	IMULQ R9, AX
	ANDQ DI, AX

	// g += f*w, q += u*w, r += v*w
	MOVQ R8, DI
	IMULQ AX, DI
	ADDQ DI, R9
	MOVQ R10, DI
	IMULQ AX, DI
	ADDQ DI, R12
	MOVQ R11, DI
	IMULQ AX, DI
	ADDQ DI, R13
	JMP divRound

divDone:
	MOVQ t+24(FP), DI
	MOVQ R10, 0(DI)
	MOVQ R11, 8(DI)
	MOVQ R12, 16(DI)
	MOVQ R13, 24(DI)
	MOVQ R14, ret+32(FP)
	RET
