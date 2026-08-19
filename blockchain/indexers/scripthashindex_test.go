// Copyright (c) 2024 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// TestScriptHashAddrKey verifies that every standard output script type the
// script hash index records maps to a 21-byte address index key with the
// expected type byte. This is the value the index stores and what the read
// path uses to query the address index, so it must match the address index's
// own keying for each standard type.
func TestScriptHashAddrKey(t *testing.T) {
	t.Parallel()

	h20 := bytes.Repeat([]byte{0x01}, 20)
	h32 := bytes.Repeat([]byte{0x02}, 32)

	mkScript := func(parts ...[]byte) []byte {
		return bytes.Join(parts, nil)
	}

	tests := []struct {
		name     string
		pkScript []byte
		wantType byte
		// wantHash is the expected key hash (key[1:]); nil for the witness
		// script hash and taproot types whose 32-byte push is hash160'd.
		wantHash []byte
	}{
		{
			name:     "p2pkh",
			pkScript: mkScript([]byte{0x76, 0xa9, 0x14}, h20, []byte{0x88, 0xac}),
			wantType: addrKeyTypePubKeyHash,
			wantHash: h20,
		},
		{
			name:     "p2sh",
			pkScript: mkScript([]byte{0xa9, 0x14}, h20, []byte{0x87}),
			wantType: addrKeyTypeScriptHash,
			wantHash: h20,
		},
		{
			name:     "p2wpkh",
			pkScript: mkScript([]byte{0x00, 0x14}, h20),
			wantType: addrKeyTypeWitnessPubKeyHash,
			wantHash: h20,
		},
		{
			name:     "p2wsh",
			pkScript: mkScript([]byte{0x00, 0x20}, h32),
			wantType: addrKeyTypeWitnessScriptHash,
		},
		{
			name:     "p2tr",
			pkScript: mkScript([]byte{0x51, 0x20}, h32),
			wantType: addrKeyTypeTaprootPubKey,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(
				test.pkScript, &chaincfg.MainNetParams)
			if err != nil {
				t.Fatalf("ExtractPkScriptAddrs: %v", err)
			}
			if len(addrs) != 1 {
				t.Fatalf("got %d addresses, want 1", len(addrs))
			}

			key, err := addrToKey(addrs[0])
			if err != nil {
				t.Fatalf("addrToKey: %v", err)
			}
			if key[0] != test.wantType {
				t.Errorf("type byte = %d, want %d", key[0], test.wantType)
			}
			if test.wantHash != nil && !bytes.Equal(key[1:], test.wantHash) {
				t.Errorf("key hash = %x, want %x", key[1:], test.wantHash)
			}
		})
	}
}

// TestScriptHashIndexVersionDrop verifies that an index whose on disk format
// version does not match the current one is dropped on startup so it gets
// rebuilt, and that an index carrying the current version is left alone.
func TestScriptHashIndexVersionDrop(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "ffldb")
	db, err := database.Create("ffldb", dbPath, wire.MainNet)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Simulate an index written before format versions were recorded: the
	// tip and the bucket exist, an entry holds an address string, and there
	// is no version key.
	var scriptHash chainhash.Hash
	err = db.Update(func(dbTx database.Tx) error {
		meta := dbTx.Metadata()
		_, err := meta.CreateBucketIfNotExists(indexTipsBucketName)
		if err != nil {
			return err
		}
		err = dbPutIndexerTip(dbTx, scriptHashIndexKey, &chainhash.Hash{}, 5)
		if err != nil {
			return err
		}
		bucket, err := meta.CreateBucket(scriptHashIndexKey)
		if err != nil {
			return err
		}
		return bucket.Put(scriptHash[:],
			[]byte("1BdywN8HyrX87gyQKuKVkA9qjNKoThiXti"))
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := maybeDropStaleScriptHashIndex(db, nil); err != nil {
		t.Fatal(err)
	}

	// The unversioned index must be gone, tip included.
	err = db.View(func(dbTx database.Tx) error {
		meta := dbTx.Metadata()
		if meta.Bucket(scriptHashIndexKey) != nil {
			t.Error("the unversioned index bucket was not dropped")
		}
		if meta.Bucket(indexTipsBucketName).Get(scriptHashIndexKey) != nil {
			t.Error("the unversioned index tip was not dropped")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Recreate the index the way the manager does and check that it comes
	// out stamped with the current version and survives the next check.
	idx := NewScriptHashIndex(db, &chaincfg.MainNetParams, t.TempDir())
	err = db.Update(func(dbTx database.Tx) error {
		if err := idx.Create(dbTx); err != nil {
			return err
		}
		return dbPutIndexerTip(dbTx, scriptHashIndexKey, &chainhash.Hash{}, -1)
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := maybeDropStaleScriptHashIndex(db, nil); err != nil {
		t.Fatal(err)
	}

	err = db.View(func(dbTx database.Tx) error {
		version := dbFetchScriptHashIndexVersion(dbTx)
		if version != scriptHashIndexFormatVersion {
			t.Errorf("version %d on disk, want %d", version,
				scriptHashIndexFormatVersion)
		}
		if dbTx.Metadata().Bucket(scriptHashIndexKey) == nil {
			t.Error("the current format index was dropped")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
