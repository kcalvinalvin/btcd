// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcec

import (
	"bytes"
	"errors"
	"math/rand"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func checkParsePubKeyMatchesDcrec(t *testing.T, serialized []byte) {
	t.Helper()
	got, gotErr := ParsePubKey(serialized)
	want, wantErr := secp.ParsePubKey(serialized)
	if (gotErr == nil) != (wantErr == nil) {
		t.Fatalf("acceptance mismatch for %x: got %v want %v",
			serialized, gotErr, wantErr)
	}
	if gotErr != nil {
		var gotKind, wantKind secp.ErrorKind
		if !errors.As(gotErr, &gotKind) || !errors.As(wantErr, &wantKind) {
			t.Fatalf("missing error kind for %x: got %T want %T",
				serialized, gotErr, wantErr)
		}
		if gotKind != wantKind || gotErr.Error() != wantErr.Error() {
			t.Fatalf("error mismatch for %x:\n"+
				"got  kind=%v message=%q\n"+
				"want kind=%v message=%q",
				serialized, gotKind, gotErr, wantKind, wantErr)
		}
		return
	}

	if !bytes.Equal(got.SerializeCompressed(), want.SerializeCompressed()) ||
		!bytes.Equal(got.SerializeUncompressed(), want.SerializeUncompressed()) {

		t.Fatalf("point mismatch for %x", serialized)
	}
}

func TestParsePubKeyMatchesDcrec(t *testing.T) {
	prime := [32]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
	}
	checkParsePubKeyMatchesDcrec(t, nil)
	checkParsePubKeyMatchesDcrec(t, []byte{0x02})
	for _, format := range []byte{0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07} {
		compressed := make([]byte, 33)
		compressed[0] = format
		copy(compressed[1:], prime[:])
		checkParsePubKeyMatchesDcrec(t, compressed)

		uncompressed := make([]byte, 65)
		uncompressed[0] = format
		copy(uncompressed[1:33], prime[:])
		copy(uncompressed[33:], prime[:])
		checkParsePubKeyMatchesDcrec(t, uncompressed)
	}

	rng := rand.New(rand.NewSource(0xdec0de))
	for i := 0; i < 1000; i++ {
		var raw [65]byte
		_, _ = rng.Read(raw[:])
		checkParsePubKeyMatchesDcrec(t, raw[:int(raw[64])%66])

		compressed := raw[:33]
		compressed[0] = 0x02 | compressed[0]&1
		checkParsePubKeyMatchesDcrec(t, compressed)

		uncompressed := raw[:]
		uncompressed[0] = 0x04
		checkParsePubKeyMatchesDcrec(t, uncompressed)
	}

	for multiple := uint32(1); multiple <= 128; multiple++ {
		var scalar secp.ModNScalar
		scalar.SetInt(multiple)
		var point secp.JacobianPoint
		secp.ScalarBaseMultNonConst(&scalar, &point)
		point.ToAffine()
		pub := secp.NewPublicKey(&point.X, &point.Y)
		checkParsePubKeyMatchesDcrec(t, pub.SerializeCompressed())
		uncompressed := pub.SerializeUncompressed()
		checkParsePubKeyMatchesDcrec(t, uncompressed)

		hybrid := append([]byte(nil), uncompressed...)
		hybrid[0] = 0x06 | pub.SerializeCompressed()[0]&1
		checkParsePubKeyMatchesDcrec(t, hybrid)
		hybrid[0] ^= 1
		checkParsePubKeyMatchesDcrec(t, hybrid)
	}
}
