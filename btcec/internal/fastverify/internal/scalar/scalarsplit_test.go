// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package scalar

import (
	"crypto/rand"
	"math/big"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// endoLambda is lambda, the cube root of unity modulo the group order. It is
// only needed to exercise a structural scalar-split vector.
var endoLambda = mustScalar("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72")

var (
	orderN, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	lambdaN, _ = new(big.Int).SetString("5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72", 16)
)

func scalarToBig(s *secp.ModNScalar) *big.Int {
	b := s.Bytes()
	return new(big.Int).SetBytes(b[:])
}

func TestSplitKProperty(t *testing.T) {
	check := func(k secp.ModNScalar) {
		t.Helper()
		k1, k2 := SplitK(&k)

		// k1 + k2*lambda must equal k mod n.
		got := new(big.Int).Mul(scalarToBig(&k2), lambdaN)
		got.Add(got, scalarToBig(&k1))
		got.Mod(got, orderN)
		if got.Cmp(scalarToBig(&k)) != 0 {
			t.Fatalf("split does not recombine: k=%x", k.Bytes())
		}

		// Both halves must have signed magnitude below 2^129.
		for name, half := range map[string]*secp.ModNScalar{"k1": &k1, "k2": &k2} {
			_, w := SignedSmall(half)
			if w[2] > 1 {
				t.Fatalf("%s magnitude too large: words %x for k=%x", name, w, k.Bytes())
			}
		}
	}

	// Fixed edges.
	var k secp.ModNScalar
	check(k) // zero
	k.SetInt(1)
	check(k)
	k.Negate() // n - 1... k was 1, negate gives n-1
	check(k)
	check(endoLambda)

	var raw [32]byte
	for i := 0; i < 10000; i++ {
		if _, err := rand.Read(raw[:]); err != nil {
			t.Fatal(err)
		}
		var kr secp.ModNScalar
		kr.SetBytes(&raw)
		check(kr)
	}
}

func TestWnaf5Reconstruction(t *testing.T) {
	check := func(w [3]uint64) {
		t.Helper()
		val := new(big.Int).SetUint64(w[2])
		val.Lsh(val, 64)
		val.Add(val, new(big.Int).SetUint64(w[1]))
		val.Lsh(val, 64)
		val.Add(val, new(big.Int).SetUint64(w[0]))

		digits, length := WNAF5(w)
		sum := new(big.Int)
		for i := length - 1; i >= 0; i-- {
			sum.Lsh(sum, 1)
			sum.Add(sum, big.NewInt(int64(digits[i])))
			d := digits[i]
			if d != 0 && (d&1 == 0 || d > 15 || d < -15) {
				t.Fatalf("invalid digit %d at %d", d, i)
			}
			// Width 5 non-adjacency: a nonzero digit is followed by
			// at least four zeros.
			if d != 0 {
				for j := i + 1; j < i+5 && j < length; j++ {
					if digits[j] != 0 {
						t.Fatalf("adjacent nonzero digits at %d and %d", i, j)
					}
				}
			}
		}
		if sum.Cmp(val) != 0 {
			t.Fatalf("wnaf reconstruction mismatch for %x: got %v want %v", w, sum, val)
		}
		if length > MaxWNAFLen {
			t.Fatalf("wnaf length %d exceeds max", length)
		}
	}

	check([3]uint64{0, 0, 0})
	check([3]uint64{1, 0, 0})
	check([3]uint64{15, 0, 0})
	check([3]uint64{^uint64(0), ^uint64(0), 3}) // near 2^130

	var raw [24]byte
	for i := 0; i < 10000; i++ {
		if _, err := rand.Read(raw[:]); err != nil {
			t.Fatal(err)
		}
		var w [3]uint64
		for j := 0; j < 8; j++ {
			w[0] |= uint64(raw[j]) << (8 * j)
			w[1] |= uint64(raw[8+j]) << (8 * j)
			w[2] |= uint64(raw[16+j]) << (8 * j)
		}
		w[2] &= 3 // keep within the 2^130 contract
		check(w)
	}
}
