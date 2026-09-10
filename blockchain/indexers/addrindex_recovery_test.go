// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/database"
	_ "github.com/btcsuite/btcd/database/ffldb"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

type interruptAddrUpdateDB struct {
	database.DB
	interrupt chan struct{}
	done      bool
}

func (db *interruptAddrUpdateDB) Update(fn func(database.Tx) error) error {
	if err := db.DB.Update(fn); err != nil {
		return err
	}
	if !db.done {
		close(db.interrupt)
		db.done = true
	}
	return nil
}

type failAddrFlushDB struct {
	database.DB
	err        error
	successful int
}

func (db *failAddrFlushDB) Flush() error {
	if db.successful > 0 {
		db.successful--
		return flushAddrIndexDB(db.DB)
	}
	return db.err
}

type noAddrFlushDB struct {
	database.DB
}

type interruptedAddrBuild struct {
	rootDir string
	db      database.DB
	chain   *blockchain.BlockChain
	addr    address.Address
}

func setupInterruptedAddrBuild(t *testing.T) *interruptedAddrBuild {
	t.Helper()

	rootDir := t.TempDir()
	db, err := database.Create(
		"ffldb", filepath.Join(rootDir, "db"), wire.MainNet,
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, db.Close())
	})

	params := &chaincfg.MainNetParams
	chain, err := blockchain.New(&blockchain.Config{
		DB:          db,
		ChainParams: params,
		TimeSource:  blockchain.NewMedianTime(),
		SigCache:    txscript.NewSigCache(1000),
	})
	require.NoError(t, err)

	idx := NewAddrIndexWithDataDir(db, params, rootDir)
	manager := NewManager(db, []Indexer{NewTxIndex(db), idx})
	err = db.Update(func(dbTx database.Tx) error {
		meta := dbTx.Metadata()
		if _, err := meta.CreateBucketIfNotExists(indexTipsBucketName); err != nil {
			return err
		}
		return manager.maybeCreateIndexes(dbTx)
	})
	require.NoError(t, err)

	stager, _, err := idx.buildAddrIndexRecords(
		chain, -1, chainhash.Hash{}, nil,
	)
	require.NoError(t, err)
	interrupt := make(chan struct{})
	wrappedDB := &interruptAddrUpdateDB{DB: db, interrupt: interrupt}
	writer := &AddrIndex{db: wrappedDB}
	err = writer.writeAddrIndexToDB(stager, 0, interrupt)
	require.ErrorIs(t, err, errInterruptRequested)
	stager.close()

	pkScript := params.GenesisBlock.Transactions[0].TxOut[0].PkScript
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript, params)
	require.NoError(t, err)
	require.Len(t, addrs, 1)

	return &interruptedAddrBuild{
		rootDir: rootDir,
		db:      db,
		chain:   chain,
		addr:    addrs[0],
	}
}

func requireGenesisAddrIndex(t *testing.T, build *interruptedAddrBuild,
	idx *AddrIndex) {

	t.Helper()
	err := build.db.View(func(dbTx database.Tx) error {
		hash, height, err := dbFetchIndexerTip(dbTx, addrIndexKey)
		if err != nil {
			return err
		}
		if height != 0 || !hash.IsEqual(chaincfg.MainNetParams.GenesisHash) {
			return fmt.Errorf("address index tip is (%d, %s)", height, hash)
		}
		return nil
	})
	require.NoError(t, err)

	regions, skipped, err := idx.TxRegionsForAddress(
		nil, build.addr, 0, 1, false,
	)
	require.NoError(t, err)
	require.Zero(t, skipped)
	require.Len(t, regions, 1)
	require.True(t, regions[0].Hash.IsEqual(
		chaincfg.MainNetParams.GenesisHash,
	))
	_, exists := AddrIndexFastBuildDir(build.rootDir)
	require.False(t, exists)
}

func TestInterruptedAddrBuildReplay(t *testing.T) {
	build := setupInterruptedAddrBuild(t)
	idx := NewAddrIndexWithDataDir(
		build.db, &chaincfg.MainNetParams, build.rootDir,
	)
	manager := NewManager(build.db, []Indexer{NewTxIndex(build.db), idx})
	require.NoError(t, manager.Init(build.chain, nil))
	requireGenesisAddrIndex(t, build, idx)
}

func TestFastBuildReorgRebuildsAddressIndex(t *testing.T) {
	build := setupInterruptedAddrBuild(t)
	stagingDir := filepath.Join(
		build.rootDir, addrIndexBuildDirName, "staging",
	)
	manifest, ok := readAddrBuildManifest(stagingDir)
	require.True(t, ok)
	manifest.BaseHeight = 0
	manifest.BaseHash = chainhash.Hash{1}
	manifest.TargetHeight = 1
	manifest.TargetHash = chainhash.Hash{2}
	require.NoError(t, writeAddrBuildManifest(stagingDir, &manifest))
	require.NoError(t, build.db.Update(func(dbTx database.Tx) error {
		return dbPutIndexerTip(
			dbTx, addrIndexKey, &manifest.BaseHash, manifest.BaseHeight,
		)
	}))
	require.NoError(t, flushAddrIndexDB(build.db))

	idx := NewAddrIndexWithDataDir(
		build.db, &chaincfg.MainNetParams, build.rootDir,
	)
	manager := NewManager(build.db, []Indexer{NewTxIndex(build.db), idx})
	require.NoError(t, manager.Init(build.chain, nil))
	requireGenesisAddrIndex(t, build, idx)
}

func TestAddrIndexInitRemovesCompletedStaging(t *testing.T) {
	build := setupInterruptedAddrBuild(t)
	require.NoError(t, build.db.Update(func(dbTx database.Tx) error {
		return dbPutIndexerTip(dbTx, addrIndexKey,
			chaincfg.MainNetParams.GenesisHash, 0)
	}))
	require.NoError(t, flushAddrIndexDB(build.db))

	idx := NewAddrIndexWithDataDir(
		build.db, &chaincfg.MainNetParams, build.rootDir,
	)
	require.NoError(t, idx.Init())
	_, exists := AddrIndexFastBuildDir(build.rootDir)
	require.False(t, exists)
}

func TestAddrIndexInitRemovesUnpublishedStaging(t *testing.T) {
	rootDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(
		rootDir, addrIndexBuildDirName, "staging.tmp",
	), 0700))
	require.NoError(t, os.Mkdir(
		filepath.Join(rootDir, addrIndexBuildDirName)+".delete", 0700,
	))
	idx := NewAddrIndexWithDataDir(nil, nil, rootDir)
	require.NoError(t, idx.Init())
	_, exists := AddrIndexFastBuildDir(rootDir)
	require.False(t, exists)
	_, err := os.Stat(filepath.Join(rootDir, addrIndexBuildDirName) + ".delete")
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestFastBuildFlushFailureRetainsStaging(t *testing.T) {
	build := setupInterruptedAddrBuild(t)
	flushErr := errors.New("flush failure")
	db := &failAddrFlushDB{
		DB: build.db, err: flushErr, successful: 1,
	}
	idx := NewAddrIndexWithDataDir(
		db, &chaincfg.MainNetParams, build.rootDir,
	)
	require.ErrorIs(t, idx.FastBuild(build.chain, nil), flushErr)
	_, exists := AddrIndexFastBuildDir(build.rootDir)
	require.True(t, exists)

	// The matching tip is visible through the cache, but Init must retain
	// staging when that tip cannot be flushed.
	require.ErrorIs(t, idx.Init(), flushErr)
	_, exists = AddrIndexFastBuildDir(build.rootDir)
	require.True(t, exists)
}

func TestInterruptedIndexDropsRetainAddrBuild(t *testing.T) {
	tests := []struct {
		name string
		drop func(database.DB, string, <-chan struct{}) error
	}{
		{"address index", DropAddrIndexWithDataDir},
		{"transaction index", DropTxIndexWithDataDir},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			build := setupInterruptedAddrBuild(t)
			interrupt := make(chan struct{})
			close(interrupt)
			require.ErrorIs(t, test.drop(
				build.db, build.rootDir, interrupt,
			), errInterruptRequested)
			_, exists := AddrIndexFastBuildDir(build.rootDir)
			require.True(t, exists)

			idx := NewAddrIndexWithDataDir(
				build.db, &chaincfg.MainNetParams, build.rootDir,
			)
			manager := NewManager(build.db, []Indexer{
				NewTxIndex(build.db), idx,
			})
			require.NoError(t, manager.Init(build.chain, nil))
			requireGenesisAddrIndex(t, build, idx)
		})
	}
}

func TestManagerFinishesDropWithoutIndexBucket(t *testing.T) {
	build := setupInterruptedAddrBuild(t)
	require.NoError(t, build.db.Update(func(dbTx database.Tx) error {
		meta := dbTx.Metadata()
		tips := meta.Bucket(indexTipsBucketName)
		if err := tips.Put(indexDropKey(addrIndexKey), addrIndexKey); err != nil {
			return err
		}
		return meta.DeleteBucket(addrIndexKey)
	}))

	idx := NewAddrIndexWithDataDir(
		build.db, &chaincfg.MainNetParams, build.rootDir,
	)
	manager := NewManager(build.db, []Indexer{NewTxIndex(build.db), idx})
	require.NoError(t, manager.Init(build.chain, nil))
	requireGenesisAddrIndex(t, build, idx)
}

func TestInterruptedExtensionDropDiscardsStaging(t *testing.T) {
	build := setupInterruptedAddrBuild(t)
	stagingDir := filepath.Join(
		build.rootDir, addrIndexBuildDirName, "staging",
	)
	manifest, ok := readAddrBuildManifest(stagingDir)
	require.True(t, ok)
	manifest.BaseHeight = 0
	manifest.BaseHash = *chaincfg.MainNetParams.GenesisHash
	require.NoError(t, writeAddrBuildManifest(stagingDir, &manifest))
	require.NoError(t, build.db.Update(func(dbTx database.Tx) error {
		return dbPutIndexerTip(dbTx, addrIndexKey,
			chaincfg.MainNetParams.GenesisHash, 0)
	}))
	require.NoError(t, flushAddrIndexDB(build.db))

	interrupt := make(chan struct{})
	close(interrupt)
	require.ErrorIs(t, DropAddrIndexWithDataDir(
		build.db, build.rootDir, interrupt,
	), errInterruptRequested)

	idx := NewAddrIndexWithDataDir(
		build.db, &chaincfg.MainNetParams, build.rootDir,
	)
	manager := NewManager(build.db, []Indexer{NewTxIndex(build.db), idx})
	require.NoError(t, manager.Init(build.chain, nil))
	requireGenesisAddrIndex(t, build, idx)
}

func TestIndexDropFlushFailureRetainsAddrBuild(t *testing.T) {
	build := setupInterruptedAddrBuild(t)
	flushErr := errors.New("flush failure")
	db := &failAddrFlushDB{DB: build.db, err: flushErr}
	require.ErrorIs(t, DropAddrIndexWithDataDir(
		db, build.rootDir, nil,
	), flushErr)
	_, exists := AddrIndexFastBuildDir(build.rootDir)
	require.True(t, exists)

	require.NoError(t, DropAddrIndexWithDataDir(
		build.db, build.rootDir, nil,
	))
	_, exists = AddrIndexFastBuildDir(build.rootDir)
	require.False(t, exists)
}

func TestIndexDropChecksFlushBeforeMutation(t *testing.T) {
	build := setupInterruptedAddrBuild(t)
	db := &noAddrFlushDB{DB: build.db}
	require.Error(t, DropAddrIndexWithDataDir(
		db, build.rootDir, nil,
	))

	require.NoError(t, build.db.View(func(dbTx database.Tx) error {
		meta := dbTx.Metadata()
		tips := meta.Bucket(indexTipsBucketName)
		require.Nil(t, tips.Get(indexDropKey(addrIndexKey)))
		require.NotNil(t, meta.Bucket(addrIndexKey))
		return nil
	}))
}
