// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/database"
	_ "github.com/btcsuite/btcd/database/ffldb"
	"github.com/btcsuite/btcd/wire/v2"
)

// TestDropIndex ensures dropping an index removes its bucket, tip entry, and
// in-progress drop marker, and that resuming a drop whose bucket is already
// gone still cleans up and succeeds.
func TestDropIndex(t *testing.T) {
	t.Parallel()

	db, err := database.Create("ffldb", filepath.Join(t.TempDir(), "db"),
		wire.MainNet)
	if err != nil {
		t.Fatalf("database.Create: %v", err)
	}
	defer db.Close()

	// Create the index tip entry and a populated index bucket.
	err = db.Update(func(dbTx database.Tx) error {
		meta := dbTx.Metadata()
		tips, err := meta.CreateBucket(indexTipsBucketName)
		if err != nil {
			return err
		}
		tip := serializeIndexerTip(&chainhash.Hash{}, 0)
		if err := tips.Put(addrIndexKey, tip); err != nil {
			return err
		}
		bucket, err := meta.CreateBucket(addrIndexKey)
		if err != nil {
			return err
		}
		for i := 0; i < 100; i++ {
			key := []byte(fmt.Sprintf("key-%03d", i))
			if err := bucket.Put(key, []byte{byte(i)}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("setup index: %v", err)
	}

	if err := dropIndex(db, addrIndexKey, addrIndexName, nil); err != nil {
		t.Fatalf("dropIndex: %v", err)
	}

	checkDropped := func(context string) {
		t.Helper()
		err := db.View(func(dbTx database.Tx) error {
			meta := dbTx.Metadata()
			if meta.Bucket(addrIndexKey) != nil {
				t.Fatalf("%s: index bucket still exists", context)
			}
			tips := meta.Bucket(indexTipsBucketName)
			if tips.Get(addrIndexKey) != nil {
				t.Fatalf("%s: index tip still exists", context)
			}
			if tips.Get(indexDropKey(addrIndexKey)) != nil {
				t.Fatalf("%s: drop marker still exists", context)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("%s: %v", context, err)
		}
	}
	checkDropped("after drop")

	// Recreate the state left behind by a drop that was interrupted after
	// it removed the bucket but before it removed the tip and marker, and
	// ensure resuming the drop cleans up and succeeds.
	err = db.Update(func(dbTx database.Tx) error {
		tips := dbTx.Metadata().Bucket(indexTipsBucketName)
		tip := serializeIndexerTip(&chainhash.Hash{}, 0)
		if err := tips.Put(addrIndexKey, tip); err != nil {
			return err
		}
		return tips.Put(indexDropKey(addrIndexKey), addrIndexKey)
	})
	if err != nil {
		t.Fatalf("setup interrupted drop: %v", err)
	}

	if err := dropIndex(db, addrIndexKey, addrIndexName, nil); err != nil {
		t.Fatalf("resumed dropIndex: %v", err)
	}
	checkDropped("after resumed drop")
}
