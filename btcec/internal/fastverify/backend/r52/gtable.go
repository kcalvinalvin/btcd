// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package r52

import "sync"

// Base point G of secp256k1 in affine coordinates.
var (
	gxBytes = [32]byte{
		0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
		0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
		0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
		0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
	}
	gyBytes = [32]byte{
		0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
		0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
		0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
		0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8,
	}
)

// gTable holds points[j][v] = v * 2^(8j) * G in affine coordinates for
// window j of a base 256 fixed-point multiplication, so a full 256-bit
// scalar multiple of G costs at most 32 mixed additions and no doublings.
// Row entry 0 is unused. The table is about 640 KiB and is built once on
// first use.
var (
	gTableOnce sync.Once
	gTable     *[32][256]affinePoint
)

// batchToAffine converts a slice of finite Jacobian points to affine using
// a single field inversion via the Montgomery batch trick.
func batchToAffine(points []jacobianPoint, out []affinePoint) {
	n := len(points)
	if n == 0 {
		return
	}
	// prefix[i] = Z_0 * ... * Z_i
	prefix := make([]fe, n)
	prefix[0] = points[0].Z
	for i := 1; i < n; i++ {
		prefix[i].Mul(&prefix[i-1], &points[i].Z)
	}
	var inv fe
	inv.Inverse(&prefix[n-1])
	for i := n - 1; i >= 0; i-- {
		var zi fe
		if i == 0 {
			zi = inv
		} else {
			zi.Mul(&inv, &prefix[i-1])
			inv.Mul(&inv, &points[i].Z)
		}
		var zi2, zi3 fe
		zi2.Square(&zi)
		zi3.Mul(&zi2, &zi)
		out[i].X.Mul(&points[i].X, &zi2)
		out[i].X.normalizeWeak()
		out[i].Y.Mul(&points[i].Y, &zi3)
		out[i].Y.normalizeWeak()
	}
}

// buildGTable computes the fixed-point table for G.
func buildGTable() {
	table := new([32][256]affinePoint)

	var g affinePoint
	g.X.SetBytes(&gxBytes)
	g.Y.SetBytes(&gyBytes)

	// Window bases 2^(8j) * G as Jacobian points.
	var bases [32]jacobianPoint
	bases[0].SetAffine(&g)
	for j := 1; j < 32; j++ {
		bases[j] = bases[j-1]
		for d := 0; d < 8; d++ {
			bases[j].Double(&bases[j])
		}
	}
	var basesAff [32]affinePoint
	batchToAffine(bases[:], basesAff[:])

	// Each row accumulates v * base with mixed additions, then the whole
	// table converts to affine with one inversion.
	rows := make([]jacobianPoint, 32*255)
	for j := 0; j < 32; j++ {
		var acc jacobianPoint
		acc.SetAffine(&basesAff[j])
		rows[j*255] = acc
		for v := 2; v <= 255; v++ {
			acc.AddMixed(&acc, &basesAff[j])
			rows[j*255+v-1] = acc
		}
	}
	rowsAff := make([]affinePoint, 32*255)
	batchToAffine(rows, rowsAff)
	for j := 0; j < 32; j++ {
		for v := 1; v <= 255; v++ {
			table[j][v] = rowsAff[j*255+v-1]
		}
	}

	gTable = table
}

// baseTable returns the lazily built fixed-point table for G.
func baseTable() *[32][256]affinePoint {
	gTableOnce.Do(buildGTable)
	return gTable
}
