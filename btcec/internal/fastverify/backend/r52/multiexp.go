// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package r52

import (
	"github.com/btcsuite/btcd/btcec/v2/internal/fastverify/internal/scalar"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// endoBeta is beta, the cube root of unity mod p realizing the curve
// endomorphism phi(x, y) = (beta*x, y) which acts as scalar multiplication
// by lambda.
var endoBeta = func() fe {
	b := [32]byte{
		0x7A, 0xE9, 0x6A, 0x2B, 0x65, 0x7C, 0x07, 0x10,
		0x6E, 0x64, 0x47, 0x9E, 0xAC, 0x34, 0x34, 0xE9,
		0x9C, 0xF0, 0x49, 0x75, 0x12, 0xF5, 0x89, 0x95,
		0xC1, 0x39, 0x6C, 0x28, 0x71, 0x95, 0x01, 0xEE,
	}
	var f fe
	f.SetBytes(&b)
	return f
}()

// oddMultiples fills table with the odd multiples 1q, 3q, ..., 15q for the
// width 5 wNAF loop, expressed on the curve rescaled by the returned frame
// Z. On that curve 2q is affine, so every chain step is a mixed addition.
// The chain never hits a degenerate case because that would require an odd
// multiple below 17q to be the point at infinity.
func oddMultiples(q *affinePoint, table *[8]jacobianPoint) fe {
	var one jacobianPoint
	one.SetAffine(q)
	var twoQ jacobianPoint
	twoQ.Double(&one)

	twoQAff := affinePoint{X: twoQ.X, Y: twoQ.Y}
	var zd2, zd3 fe
	zd2.Square(&twoQ.Z)
	zd3.Mul(&zd2, &twoQ.Z)
	table[0].X.Mul(&q.X, &zd2)
	table[0].X.normalizeWeak()
	table[0].Y.Mul(&q.Y, &zd3)
	table[0].Y.normalizeWeak()
	table[0].Z.SetUint64(1)
	table[0].Inf = false
	oddChain(table, &twoQAff)
	return twoQ.Z
}

// commonZ rescales the odd multiple table to a shared denominator zGlobal,
// without any field inversion, using prefix and suffix products of the
// entry Z coordinates. The outputs are effective-affine: (X', Y') such
// that the true point is (X'/zGlobal^2, Y'/zGlobal^3). Running the wNAF
// loop against them is working on the isomorphic rescaled curve, so the
// accumulator's true Z is its computed Z times zGlobal, undone once by the
// caller. Every table entry is a finite point, so all Z values are
// nonzero.
func commonZ(table *[8]jacobianPoint, out *[8]affinePoint) fe {
	// left[i] holds the product of the Z coordinates below entry i.
	var left [8]fe
	left[0].SetUint64(1)
	for i := 1; i < 8; i++ {
		left[i].Mul(&left[i-1], &table[i-1].Z)
	}

	var zGlobal fe
	zGlobal.Mul(&left[7], &table[7].Z)

	// Walking down, right holds the product of the Z coordinates above
	// entry i, so left[i]*right is zGlobal/Z_i without dividing.
	var right fe
	right.SetUint64(1)
	for i := 7; i >= 0; i-- {
		var t, t2, t3 fe
		t.Mul(&left[i], &right)
		t2.Square(&t)
		t3.Mul(&t2, &t)
		out[i].X.Mul(&table[i].X, &t2)
		out[i].X.normalizeWeak()
		out[i].Y.Mul(&table[i].Y, &t3)
		out[i].Y.normalizeWeak()
		right.Mul(&right, &table[i].Z)
	}
	return zGlobal
}

// negateTable fills neg with the negated points of table, so digit signs
// resolve to a table pick instead of a per-use negation.
func negateTable(table, neg *[8]affinePoint) {
	for i := range table {
		neg[i].X = table[i].X
		y := table[i].Y
		y.Negate(1)
		y.normalizeWeak()
		neg[i].Y = y
	}
}

// digitEntry returns the table entry for a nonzero odd wNAF digit, picking
// the negated table when the signs work out negative.
func digitEntry(pos, neg *[8]affinePoint, digit int8,
	negate bool) *affinePoint {

	d := digit
	if negate {
		d = -d
	}
	if d < 0 {
		return &neg[-d/2]
	}
	return &pos[d/2]
}

// Ladder op kinds: a doubling, a doubling paired with a G-chain addition,
// and an accumulator addition.
const (
	opDouble uint64 = iota
	opDoubleG
	opAdd

	// A schedule has at most scalar.MaxWNAFLen-1 doublings and two nonzero
	// digits per five positions. Round that 185-op bound up for headroom.
	maxLadderOps = 192
)

// ladderOp is one step of a precomputed ladder schedule. Every digit and
// pairing decision is resolved up front so the runner sees only finite point
// operations on prebuilt table entries.
type ladderOp struct {
	kind  uint64
	entry *affinePoint
}

// runLadderGeneric walks a ladder schedule with portable point operations.
func runLadderGeneric(acc, gacc *jacobianPoint, ops []ladderOp) {
	for i := range ops {
		op := &ops[i]
		switch op.kind {
		case opDouble:
			acc.Double(acc)
		case opDoubleG:
			acc.Double(acc)
			gacc.AddMixed(gacc, op.entry)
		case opAdd:
			acc.AddMixed(acc, op.entry)
		}
	}
}

// scalarWordsLE returns the scalar as four little-endian 64-bit words.
func scalarWordsLE(s *secp.ModNScalar) [4]uint64 {
	b := s.Bytes()
	var words [4]uint64
	for i := range words {
		for j := 0; j < 8; j++ {
			words[i] |= uint64(b[31-8*i-j]) << (8 * j)
		}
	}
	return words
}

// fixedWindowValue extracts one gWindowBits-wide fixed-base window.
func fixedWindowValue(words *[4]uint64, window int) uint64 {
	bit := gWindowBits * window
	word := bit / 64
	shift := bit % 64
	value := words[word] >> shift
	if shift > 64-gWindowBits && word+1 < len(words) {
		value |= words[word+1] << (64 - shift)
	}
	return value & (gTableSize - 1)
}

// dualBaseMult computes u1*G + u2*Q using the fixed-point table for the G
// term and a GLV split Strauss wNAF loop for the Q term. The G term
// accumulates on its own chain in the unscaled frame so its additions can be
// interleaved with the ladder doublings. The two chains combine with one full
// addition at the end.
func dualBaseMult(u1, u2 *secp.ModNScalar, q *affinePoint) jacobianPoint {
	var acc jacobianPoint
	acc.SetInfinity()

	// G term: fixed windows over the precomputed table, no doublings needed.
	var gEntries [gWindows]*affinePoint
	nG := 0
	if !u1.IsZero() {
		table := baseTable()
		words := scalarWordsLE(u1)
		for j := 0; j < gWindows; j++ {
			if v := fixedWindowValue(&words, j); v != 0 {
				gEntries[nG] = &table[j][v]
				nG++
			}
		}
	}
	var gacc jacobianPoint
	gacc.SetInfinity()
	gi := 0
	if nG > 0 {
		gacc.SetAffine(gEntries[0])
		gi = 1
	}

	// Q term: split u2 and run two width 5 wNAF streams over shared
	// doublings, using phi to map the table for the lambda half.
	if !u2.IsZero() {
		k1, k2 := scalar.SplitK(u2)
		n1, w1 := scalar.SignedSmall(&k1)
		n2, w2 := scalar.SignedSmall(&k2)
		d1, l1 := scalar.WNAF5(w1)
		d2, l2 := scalar.WNAF5(w2)

		// The tables share one denominator so the loop runs entirely on
		// mixed additions. The phi map applies to the rescaled x
		// directly since it commutes with the isomorphism. The shared
		// denominator composes the odd multiple frame with the commonZ
		// frame.
		var qTableJ [8]jacobianPoint
		zd := oddMultiples(q, &qTableJ)
		var qTable, lqTable, negQTable, negLqTable [8]affinePoint
		zGlobal := commonZ(&qTableJ, &qTable)
		zGlobal.Mul(&zGlobal, &zd)
		for i := range qTable {
			lqTable[i] = qTable[i]
			lqTable[i].X.Mul(&qTable[i].X, &endoBeta)
			lqTable[i].X.normalizeWeak()
		}
		negateTable(&qTable, &negQTable)
		negateTable(&lqTable, &negLqTable)

		l := l1
		if l2 > l {
			l = l2
		}
		// Seed the accumulator from the top digits, then compile the rest
		// into a schedule of finite point operations.
		var ops [maxLadderOps]ladderOp
		nOps := 0
		seeded := false
		for i := l - 1; i >= 0; i-- {
			var e1, e2 *affinePoint
			if i < l1 && d1[i] != 0 {
				e1 = digitEntry(&qTable, &negQTable, d1[i], n1)
			}
			if i < l2 && d2[i] != 0 {
				e2 = digitEntry(&lqTable, &negLqTable, d2[i], n2)
			}
			if !seeded {
				if e1 == nil && e2 == nil {
					continue
				}
				if e1 != nil {
					acc.SetAffine(e1)
					if e2 != nil {
						acc.AddMixed(&acc, e2)
					}
				} else {
					acc.SetAffine(e2)
				}
				seeded = true
				continue
			}
			if gi < nG {
				ops[nOps] = ladderOp{
					kind: opDoubleG, entry: gEntries[gi],
				}
				gi++
			} else {
				ops[nOps] = ladderOp{kind: opDouble}
			}
			nOps++
			if e1 != nil {
				ops[nOps] = ladderOp{kind: opAdd, entry: e1}
				nOps++
			}
			if e2 != nil {
				ops[nOps] = ladderOp{kind: opAdd, entry: e2}
				nOps++
			}
		}
		runLadder(&acc, &gacc, ops[:nOps])

		// Leave the rescaled curve: the accumulator's true Z carries the
		// shared denominator.
		if !acc.Inf {
			acc.Z.Mul(&acc.Z, &zGlobal)
			acc.Z.normalizeWeak()
		}
	}

	// Drain the G additions the ladder did not consume, then fold the G
	// chain into the result.
	for ; gi < nG; gi++ {
		gacc.AddMixed(&gacc, gEntries[gi])
	}
	if nG > 0 {
		acc.Add(&acc, &gacc)
	}

	return acc
}
