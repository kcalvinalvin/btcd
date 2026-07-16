// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package fastverify

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/internal/fastverify/internal/engine"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// TestPrimeBytes guards against a mistyped field-prime constant.
func TestPrimeBytes(t *testing.T) {
	if !bytes.Equal(primeBytes[:], secp.Params().P.Bytes()) {
		t.Fatal("primeBytes does not encode the field prime")
	}
}

// checkDecodeMatchesDcrec requires DecodePubKey to accept exactly the keys
// dcrec's ParsePubKey accepts and to produce the same point.
func checkDecodeMatchesDcrec(t *testing.T, serialized []byte) {
	t.Helper()

	pt, ok := DecodePubKey(serialized)
	pub, err := secp.ParsePubKey(serialized)
	if ok != (err == nil) {
		t.Fatalf("accept mismatch for %x: got %v, dcrec err %v",
			serialized, ok, err)
	}
	if !ok {
		return
	}

	var j secp.JacobianPoint
	pub.AsJacobian(&j)
	var wantX, wantY [32]byte
	j.X.PutBytes(&wantX)
	j.Y.PutBytes(&wantY)
	if pt.X != wantX || pt.Y != wantY {
		t.Fatalf("point mismatch for %x", serialized)
	}
}

// TestDecodePubKeyDifferential compares DecodePubKey against dcrec's
// ParsePubKey across compressed, uncompressed and hybrid candidates, format
// byte corruption, off curve points, and out of range coordinates.
func TestDecodePubKeyDifferential(t *testing.T) {
	rng := rand.New(rand.NewSource(0xdec0de))
	// Fixed edge cases: empty, truncated, x of zero, coordinates at and
	// around the field prime.
	checkDecodeMatchesDcrec(t, nil)
	checkDecodeMatchesDcrec(t, []byte{0x02})
	for _, format := range []byte{0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07} {
		zero := make([]byte, 33)
		zero[0] = format
		checkDecodeMatchesDcrec(t, zero)

		atPrime := make([]byte, 33)
		atPrime[0] = format
		copy(atPrime[1:], primeBytes[:])
		checkDecodeMatchesDcrec(t, atPrime)

		belowPrime := make([]byte, 33)
		belowPrime[0] = format
		copy(belowPrime[1:], primeBytes[:])
		belowPrime[32]-- // p - 1
		checkDecodeMatchesDcrec(t, belowPrime)

		zero65 := make([]byte, 65)
		zero65[0] = format
		checkDecodeMatchesDcrec(t, zero65)

		yAtPrime := make([]byte, 65)
		yAtPrime[0] = format
		yAtPrime[32] = 0x01
		copy(yAtPrime[33:], primeBytes[:])
		checkDecodeMatchesDcrec(t, yAtPrime)
	}

	for i := 0; i < 3000; i++ {
		var raw [65]byte
		if _, err := rng.Read(raw[:]); err != nil {
			t.Fatal(err)
		}

		// Random compressed candidate: roughly half the x values have
		// no matching curve point.
		compressed := make([]byte, 33)
		copy(compressed, raw[:33])
		compressed[0] = 0x02 | compressed[0]&1
		checkDecodeMatchesDcrec(t, compressed)

		// Corrupted format byte on the same payload.
		corrupted := make([]byte, 33)
		copy(corrupted, compressed)
		corrupted[0] = raw[33]
		checkDecodeMatchesDcrec(t, corrupted)

		// Random uncompressed candidate, almost surely off curve.
		uncompressed := make([]byte, 65)
		copy(uncompressed, raw[:])
		uncompressed[0] = 0x04
		checkDecodeMatchesDcrec(t, uncompressed)

		// Random length garbage.
		checkDecodeMatchesDcrec(t, raw[:int(raw[64])%66])

		// When the compressed candidate is a valid key, exercise the
		// uncompressed and hybrid encodings of the same point along
		// with parity and curve equation violations.
		pub, err := secp.ParsePubKey(compressed)
		if err != nil {
			continue
		}
		valid := pub.SerializeUncompressed()
		checkDecodeMatchesDcrec(t, valid)

		hybrid := make([]byte, 65)
		copy(hybrid, valid)
		hybrid[0] = 0x06
		checkDecodeMatchesDcrec(t, hybrid)
		hybrid[0] = 0x07
		checkDecodeMatchesDcrec(t, hybrid)

		offCurve := make([]byte, 65)
		copy(offCurve, valid)
		offCurve[64] ^= 0x01
		checkDecodeMatchesDcrec(t, offCurve)
	}
}

var (
	decodeSink   engine.Affine
	decodeOKSink bool
)

func TestDecodePubKeyAllocations(t *testing.T) {
	priv, err := secp.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	keys := [][]byte{
		priv.PubKey().SerializeCompressed(),
		priv.PubKey().SerializeUncompressed(),
	}
	for _, serialized := range keys {
		if allocs := testing.AllocsPerRun(100, func() {
			decodeSink, decodeOKSink = DecodePubKey(serialized)
		}); allocs != 0 {
			t.Fatalf("DecodePubKey allocated: got %.2f want 0", allocs)
		}
		if !decodeOKSink {
			t.Fatal("DecodePubKey rejected valid benchmark key")
		}
	}
}

// BenchmarkDecodePubKey measures the engine decode of a compressed key.
func BenchmarkDecodePubKey(b *testing.B) {
	priv, err := secp.GeneratePrivateKey()
	if err != nil {
		b.Fatal(err)
	}
	serialized := priv.PubKey().SerializeCompressed()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := DecodePubKey(serialized); !ok {
			b.Fatal("decode failed")
		}
	}
}

// BenchmarkParsePubKeyDcrec measures the dcrec parse of the same compressed
// key form for comparison.
func BenchmarkParsePubKeyDcrec(b *testing.B) {
	priv, err := secp.GeneratePrivateKey()
	if err != nil {
		b.Fatal(err)
	}
	serialized := priv.PubKey().SerializeCompressed()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := secp.ParsePubKey(serialized); err != nil {
			b.Fatal(err)
		}
	}
}
