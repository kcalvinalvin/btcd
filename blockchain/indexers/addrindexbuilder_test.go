// Copyright (c) 2024 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// TestAddrSpillRoundTrip ensures records survive a spill to the staging shards
// and back, are routed to the shard for their address hash160, and that none are
// lost.
func TestAddrSpillRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	spiller, err := newAddrSpiller(dir)
	if err != nil {
		t.Fatalf("newAddrSpiller: %v", err)
	}

	// Build a set of records with shard bytes spread across the range so more
	// than one shard is exercised.
	rng := rand.New(rand.NewSource(2))
	want := make([]addrRecord, 0, 500)
	for i := 0; i < 500; i++ {
		var key [addrKeySize]byte
		key[0] = byte(rng.Intn(5))
		key[1] = byte(rng.Intn(256))
		key[addrKeySize-1] = byte(i)
		rec := addrRecord{
			addrKey: key,
			blockID: uint32(i),
			txStart: uint32(i * 7),
			txLen:   uint32(i + 1),
		}
		want = append(want, rec)

		ak := key
		err := spiller.add(&ak, rec.blockID, wire.TxLoc{
			TxStart: int(rec.txStart),
			TxLen:   int(rec.txLen),
		})
		if err != nil {
			t.Fatalf("spiller.add: %v", err)
		}
	}

	for i := range spiller.shards {
		if err := spiller.shards[i].buf.Flush(); err != nil {
			t.Fatalf("flush shard %d: %v", i, err)
		}
	}

	// Read every record back and confirm the routing put each in the shard for
	// its hash160 byte.
	var got []addrRecord
	for i := range spiller.shards {
		recs, err := readAddrSpillShard(spiller.shards[i].f)
		if err != nil {
			t.Fatalf("readAddrSpillShard %d: %v", i, err)
		}
		for _, rec := range recs {
			if int(rec.addrKey[1]) != i {
				t.Fatalf("record with hash160 byte %d found in shard %d",
					rec.addrKey[1], i)
			}
		}
		got = append(got, recs...)
	}
	spiller.cleanup()

	if len(got) != len(want) {
		t.Fatalf("record count mismatch: got %d, want %d", len(got), len(want))
	}

	less := func(recs []addrRecord) func(a, b int) bool {
		return func(a, b int) bool { return recs[a].less(&recs[b]) }
	}
	sort.Slice(want, less(want))
	sort.Slice(got, less(got))
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("record %d mismatch: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestAddrBuildManifestRoundTrip ensures the scan checkpoint manifest round
// trips all of its fields, and that a missing, truncated, or wrong-magic
// manifest is rejected.
func TestAddrBuildManifestRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if _, ok := readAddrBuildManifest(dir); ok {
		t.Fatal("read a valid manifest from an empty staging directory")
	}

	want := addrBuildManifest{
		completed:    123456,
		baseHeight:   100000,
		targetHeight: 200000,
	}
	for i := range want.baseHash {
		want.baseHash[i] = byte(i)
		want.targetHash[i] = byte(255 - i)
	}
	if err := writeAddrBuildManifest(dir, &want); err != nil {
		t.Fatalf("writeAddrBuildManifest: %v", err)
	}

	got, ok := readAddrBuildManifest(dir)
	if !ok {
		t.Fatal("manifest did not read back as valid")
	}
	if got != want {
		t.Fatalf("manifest mismatch: got %+v, want %+v", got, want)
	}

	// A base height of -1, which marks a build from scratch, must round trip
	// as well.
	want.baseHeight = -1
	want.baseHash = chainhash.Hash{}
	if err := writeAddrBuildManifest(dir, &want); err != nil {
		t.Fatalf("writeAddrBuildManifest: %v", err)
	}
	got, ok = readAddrBuildManifest(dir)
	if !ok || got != want {
		t.Fatalf("manifest mismatch: got %+v, want %+v", got, want)
	}

	path := filepath.Join(dir, addrBuildManifestName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if err := os.WriteFile(path, data[:len(data)-1], 0600); err != nil {
		t.Fatalf("write truncated manifest: %v", err)
	}
	if _, ok := readAddrBuildManifest(dir); ok {
		t.Fatal("truncated manifest read back as valid")
	}

	data[0] ^= 0xff
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write wrong-magic manifest: %v", err)
	}
	if _, ok := readAddrBuildManifest(dir); ok {
		t.Fatal("wrong-magic manifest read back as valid")
	}
}
