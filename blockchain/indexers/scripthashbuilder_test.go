// Copyright (c) 2024 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/database"
	_ "github.com/btcsuite/btcd/database/ffldb"
	"github.com/btcsuite/btcd/wire/v2"
)

// TestScriptHashSpillerWriteToDB spills a set of mappings with duplicates and
// verifies writeToDB populates the script hash index bucket so every mapping
// resolves through the normal database read path.
func TestScriptHashSpillerWriteToDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "ffldb")
	db, err := database.Create("ffldb", dbPath, wire.MainNet)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	err = db.Update(func(dbTx database.Tx) error {
		_, err := dbTx.Metadata().CreateBucket(scriptHashIndexKey)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	stagingDir := filepath.Join(t.TempDir(), "staging")
	if err := os.MkdirAll(stagingDir, 0700); err != nil {
		t.Fatal(err)
	}
	spiller, err := newScriptHashSpiller(stagingDir)
	if err != nil {
		t.Fatal(err)
	}

	rng := rand.New(rand.NewSource(2))
	const n = 3000
	want := make(map[chainhash.Hash][addrKeySize]byte, n)
	for len(want) < n {
		var sh chainhash.Hash
		rng.Read(sh[:])
		if _, ok := want[sh]; ok {
			continue
		}
		var addrKey [addrKeySize]byte
		rng.Read(addrKey[:])
		want[sh] = addrKey
	}
	for sh, addrKey := range want {
		for reps := 1 + rng.Intn(3); reps > 0; reps-- {
			if err := spiller.add(&sh, &addrKey); err != nil {
				t.Fatal(err)
			}
		}
	}

	if err := spiller.writeToDB(db); err != nil {
		t.Fatal(err)
	}
	spiller.cleanup()

	err = db.View(func(dbTx database.Tx) error {
		for sh, addrKey := range want {
			got, ok := dbFetchScriptHashEntry(dbTx, sh)
			if !ok {
				t.Fatalf("script hash %s not found", sh)
			}
			if got != addrKey {
				t.Fatalf("addrKey for %s = %x, want %x", sh, got, addrKey)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestScriptHashSpillerWriteToDBManyBatches writes more entries than fit in a
// single batch, with a small batch size, so every mapping must still resolve
// correctly after the batch backing is cycled several times.  It guards against
// reusing a batch backing array whose values the database retains by reference
// until its cache flushes.
func TestScriptHashSpillerWriteToDBManyBatches(t *testing.T) {
	oldBatchSize := bucketBatchSize
	bucketBatchSize = 64
	defer func() { bucketBatchSize = oldBatchSize }()

	dbPath := filepath.Join(t.TempDir(), "ffldb")
	db, err := database.Create("ffldb", dbPath, wire.MainNet)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	err = db.Update(func(dbTx database.Tx) error {
		_, err := dbTx.Metadata().CreateBucket(scriptHashIndexKey)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	stagingDir := filepath.Join(t.TempDir(), "staging")
	if err := os.MkdirAll(stagingDir, 0700); err != nil {
		t.Fatal(err)
	}
	spiller, err := newScriptHashSpiller(stagingDir)
	if err != nil {
		t.Fatal(err)
	}

	rng := rand.New(rand.NewSource(5))
	const n = 5000
	want := make(map[chainhash.Hash][addrKeySize]byte, n)
	for len(want) < n {
		var sh chainhash.Hash
		rng.Read(sh[:])
		if _, ok := want[sh]; ok {
			continue
		}
		var addrKey [addrKeySize]byte
		rng.Read(addrKey[:])
		want[sh] = addrKey
	}
	for sh, addrKey := range want {
		if err := spiller.add(&sh, &addrKey); err != nil {
			t.Fatal(err)
		}
	}

	if err := spiller.writeToDB(db); err != nil {
		t.Fatal(err)
	}
	spiller.cleanup()

	// Gather any mismatch inside the view and report it after the view returns
	// so a failure does not abandon the read transaction.
	var (
		missing  chainhash.Hash
		haveMiss bool
		badHash  chainhash.Hash
		badGot   [addrKeySize]byte
		badWant  [addrKeySize]byte
		haveBad  bool
	)
	err = db.View(func(dbTx database.Tx) error {
		for sh, addrKey := range want {
			got, ok := dbFetchScriptHashEntry(dbTx, sh)
			if !ok {
				missing, haveMiss = sh, true
				return nil
			}
			if got != addrKey {
				badHash, badGot, badWant, haveBad = sh, got, addrKey, true
				return nil
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if haveMiss {
		t.Fatalf("script hash %s not found", missing)
	}
	if haveBad {
		t.Fatalf("addrKey for %s = %x, want %x", badHash, badGot, badWant)
	}
}

// TestScriptHashSpillerResume spills half the mappings, checkpoints, simulates
// an interrupted write with a torn record, then resumes with a fresh spiller
// and verifies writeToDB populates every mapping.
func TestScriptHashSpillerResume(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "ffldb")
	db, err := database.Create("ffldb", dbPath, wire.MainNet)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	err = db.Update(func(dbTx database.Tx) error {
		_, err := dbTx.Metadata().CreateBucket(scriptHashIndexKey)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	stagingDir := filepath.Join(t.TempDir(), "staging")
	if err := os.MkdirAll(stagingDir, 0700); err != nil {
		t.Fatal(err)
	}

	rng := rand.New(rand.NewSource(3))
	const n = 4000
	want := make(map[chainhash.Hash][addrKeySize]byte, n)
	for len(want) < n {
		var sh chainhash.Hash
		rng.Read(sh[:])
		if _, ok := want[sh]; ok {
			continue
		}
		var addrKey [addrKeySize]byte
		rng.Read(addrKey[:])
		want[sh] = addrKey
	}

	type pair struct {
		scriptHash chainhash.Hash
		addrKey    [addrKeySize]byte
	}
	var all []pair
	for sh, addrKey := range want {
		all = append(all, pair{sh, addrKey})
	}
	half := len(all) / 2

	// First run: spill the first half, checkpoint, then stop.
	spiller1, err := newScriptHashSpiller(stagingDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range all[:half] {
		if err := spiller1.add(&p.scriptHash, &p.addrKey); err != nil {
			t.Fatal(err)
		}
	}
	if err := spiller1.sync(); err != nil {
		t.Fatal(err)
	}
	if err := writeScriptHashManifest(stagingDir, 12345); err != nil {
		t.Fatal(err)
	}
	spiller1.closeShards()

	if h, ok := readScriptHashManifest(stagingDir); !ok || h != 12345 {
		t.Fatalf("manifest = (%d, %v), want (12345, true)", h, ok)
	}

	// Simulate an interrupted write by appending a torn partial record.
	f, err := os.OpenFile(filepath.Join(stagingDir, "shard-000.tmp"),
		os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{1, 2, 3, 4, 5}); err != nil {
		t.Fatal(err)
	}
	f.Close()

	// Second run: resume, spill the rest, and write to the database.
	spiller2, err := openScriptHashSpiller(stagingDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range all[half:] {
		if err := spiller2.add(&p.scriptHash, &p.addrKey); err != nil {
			t.Fatal(err)
		}
	}
	if err := spiller2.writeToDB(db); err != nil {
		t.Fatal(err)
	}
	spiller2.cleanup()

	err = db.View(func(dbTx database.Tx) error {
		for sh, addrKey := range want {
			got, ok := dbFetchScriptHashEntry(dbTx, sh)
			if !ok {
				t.Fatalf("script hash %s not found after resume", sh)
			}
			if got != addrKey {
				t.Fatalf("addrKey for %s = %x, want %x after resume", sh, got, addrKey)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
