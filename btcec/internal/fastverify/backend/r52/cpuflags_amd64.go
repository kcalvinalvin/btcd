// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build amd64 && !purego

package r52

// cpuidex executes CPUID with the given leaf and subleaf.
//
//go:noescape
func cpuidex(leaf, sub uint32) (eax, ebx, ecx, edx uint32)

// xgetbv0 reads extended control register 0.
//
//go:noescape
func xgetbv0() (eax, edx uint32)

// hasIFMA reports whether the processor and operating system support the
// AVX-512 subset used by the IFMA field routines: foundation, doubleword
// and quadword instructions, vector length extensions, and the 52-bit
// integer fused multiply-add.
var hasIFMA = detectIFMA()

func detectIFMA() bool {
	maxLeaf, _, _, _ := cpuidex(0, 0)
	if maxLeaf < 7 {
		return false
	}

	// The OS must save extended state and expose the opmask and ZMM
	// register files through XCR0.
	_, _, c1, _ := cpuidex(1, 0)
	const osxsave = 1 << 27
	if c1&osxsave == 0 {
		return false
	}
	xlo, _ := xgetbv0()
	const xcr0Need = 1<<1 | 1<<2 | 1<<5 | 1<<6 | 1<<7
	if xlo&xcr0Need != xcr0Need {
		return false
	}

	_, b7, _, _ := cpuidex(7, 0)
	const avx512F = 1 << 16
	const avx512DQ = 1 << 17
	const avx512IFMA = 1 << 21
	const avx512VL = 1 << 31
	const need = avx512F | avx512DQ | avx512IFMA | avx512VL
	return b7&need == need
}
