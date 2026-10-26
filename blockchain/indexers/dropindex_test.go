// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/database"
	_ "github.com/btcsuite/btcd/database/ffldb"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

var (
	testDropIndexKey  = []byte("testdropidx")
	testDropIndexName = "test drop index"
)

// createDropTestDB returns a database with an index tip for the test index
// and creates the bucket paths beneath the index bucket.
func createDropTestDB(t *testing.T, paths ...[][]byte) database.DB {
	t.Helper()
	db, err := database.Create(
		"ffldb", filepath.Join(t.TempDir(), "db"), wire.MainNet,
	)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	err = db.Update(func(dbTx database.Tx) error {
		meta := dbTx.Metadata()
		_, err := meta.CreateBucketIfNotExists(indexTipsBucketName)
		if err != nil {
			return err
		}
		err = dbPutIndexerTip(
			dbTx, testDropIndexKey, &chainhash.Hash{}, 0,
		)
		if err != nil {
			return err
		}
		for _, path := range paths {
			bucket := meta
			for _, name := range path {
				bucket, err = bucket.CreateBucketIfNotExists(
					name,
				)
				if err != nil {
					return err
				}
			}
			err := bucket.Put([]byte("key"), []byte("value"))
			if err != nil {
				return err
			}
		}
		return nil
	})
	require.NoError(t, err)
	return db
}

// requireDropped ensures the index bucket, tip, and in-progress drop flag are
// gone.
func requireDropped(t *testing.T, db database.DB, idxKey []byte) {
	t.Helper()
	var bucketExists, tipExists, flagExists bool
	require.NoError(t, db.View(func(dbTx database.Tx) error {
		meta := dbTx.Metadata()
		tips := meta.Bucket(indexTipsBucketName)
		bucketExists = meta.Bucket(idxKey) != nil
		tipExists = tips.Get(idxKey) != nil
		flagExists = tips.Get(indexDropKey(idxKey)) != nil
		return nil
	}))
	require.False(t, bucketExists, "index bucket")
	require.False(t, tipExists, "index tip")
	require.False(t, flagExists, "in-progress drop flag")
}

// TestDropIndexNestedBuckets drops an index whose nested buckets have
// siblings deep enough for their cataloged paths to share storage if the
// paths are not copied.
func TestDropIndexNestedBuckets(t *testing.T) {
	key := testDropIndexKey
	db := createDropTestDB(t,
		[][]byte{key, []byte("a"), []byte("b"), []byte("c1")},
		[][]byte{key, []byte("a"), []byte("b"), []byte("c2")},
		[][]byte{key, []byte("a"), []byte("b"), []byte("c3")},
	)
	require.NoError(t, dropIndex(db, key, testDropIndexName, nil))
	requireDropped(t, db, key)
}

// TestDropIndexFinishesWithoutBuckets resumes drops that stopped after the
// index buckets were already deleted.
func TestDropIndexFinishesWithoutBuckets(t *testing.T) {
	tests := []struct {
		name    string
		idxKey  []byte
		idxName string
	}{
		{"index_bucket", testDropIndexKey, testDropIndexName},
		{"block_id_buckets", txIndexKey, txIndexName},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db := createDropTestDB(t)
			err := db.Update(func(dbTx database.Tx) error {
				meta := dbTx.Metadata()
				tips := meta.Bucket(indexTipsBucketName)
				err := dbPutIndexerTip(dbTx, test.idxKey,
					&chainhash.Hash{}, 0)
				if err != nil {
					return err
				}
				dropKey := indexDropKey(test.idxKey)
				return tips.Put(dropKey, test.idxKey)
			})
			require.NoError(t, err)
			err = dropIndex(db, test.idxKey, test.idxName, nil)
			require.NoError(t, err)
			requireDropped(t, db, test.idxKey)
		})
	}
}
