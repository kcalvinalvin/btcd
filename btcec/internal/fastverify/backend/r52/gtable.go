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

// G table geometry: base 2^gWindowBits windows over the scalar, so a
// full multiple of G costs at most gWindows mixed additions and no
// doublings. Larger windows trade table memory for fewer additions; 12
// bits lands at about 7 MiB, comparable to the large fixed tables the C
// implementations configure for verification hosts.
const (
	gWindowBits = 12
	gWindows    = (256 + gWindowBits - 1) / gWindowBits
	gTableSize  = 1 << gWindowBits
)

// gTable holds points[j][v] = v * 2^(gWindowBits*j) * G in affine
// coordinates for window j. Row entry 0 is unused. The table builds once
// on first use.
var (
	gTableOnce sync.Once
	gTable     *[gWindows][gTableSize]affinePoint
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

// generateGTable computes the fixed-point table for G.
func generateGTable() *[gWindows][gTableSize]affinePoint {
	table := new([gWindows][gTableSize]affinePoint)

	var g affinePoint
	g.X.SetBytes(&gxBytes)
	g.Y.SetBytes(&gyBytes)

	// Window bases 2^(gWindowBits*j) * G as Jacobian points.
	var bases [gWindows]jacobianPoint
	bases[0].SetAffine(&g)
	for j := 1; j < gWindows; j++ {
		bases[j] = bases[j-1]
		for d := 0; d < gWindowBits; d++ {
			bases[j].Double(&bases[j])
		}
	}
	var basesAff [gWindows]affinePoint
	batchToAffine(bases[:], basesAff[:])

	// Each row accumulates v * base with mixed additions, then the whole
	// table converts to affine with one inversion. The top window only
	// needs the values its remaining scalar bits can take.
	rowSize := make([]int, gWindows)
	total := 0
	for j := 0; j < gWindows; j++ {
		bits := 256 - gWindowBits*j
		if bits > gWindowBits {
			bits = gWindowBits
		}
		rowSize[j] = 1<<bits - 1
		total += rowSize[j]
	}
	rows := make([]jacobianPoint, total)
	base := 0
	for j := 0; j < gWindows; j++ {
		var acc jacobianPoint
		acc.SetAffine(&basesAff[j])
		rows[base] = acc
		for v := 2; v <= rowSize[j]; v++ {
			acc.AddMixed(&acc, &basesAff[j])
			rows[base+v-1] = acc
		}
		base += rowSize[j]
	}
	rowsAff := make([]affinePoint, total)
	batchToAffine(rows, rowsAff)
	base = 0
	for j := 0; j < gWindows; j++ {
		for v := 1; v <= rowSize[j]; v++ {
			table[j][v] = rowsAff[base+v-1]
		}
		base += rowSize[j]
	}

	return table
}

func buildGTable() {
	gTable = generateGTable()
}

// baseTable returns the lazily built fixed-point table for G.
func baseTable() *[gWindows][gTableSize]affinePoint {
	gTableOnce.Do(buildGTable)
	return gTable
}
