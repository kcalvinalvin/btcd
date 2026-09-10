// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"math/rand"
	"path/filepath"
	"sort"
	"testing"

	"github.com/btcsuite/btcd/database"
	_ "github.com/btcsuite/btcd/database/ffldb"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func addrBuildTestEntry(i int) (uint32, wire.TxLoc) {
	return uint32(i/3 + 1), wire.TxLoc{TxStart: i * 4, TxLen: i + 1}
}

func addrBuildTestRecords(addrKey [addrKeySize]byte, start,
	end int) []addrRecord {

	records := make([]addrRecord, 0, end-start)
	for i := start; i < end; i++ {
		blockID, txLoc := addrBuildTestEntry(i)
		records = append(records, makeAddrRecord(&addrKey, blockID, txLoc))
	}
	return records
}

func putAddrBuildTestEntries(t *testing.T, bucket internalBucket,
	addrKey [addrKeySize]byte, start, end int) {

	t.Helper()
	for i := start; i < end; i++ {
		blockID, txLoc := addrBuildTestEntry(i)
		require.NoError(t, dbPutAddrIndexEntry(
			bucket, addrKey, blockID, txLoc,
		))
	}
}

func addrBuildTestLevels(bucket *addrIndexBucket,
	addrKey [addrKeySize]byte) [][]byte {

	var levels [][]byte
	for level := uint8(0); ; level++ {
		value := bucket.levels[keyForLevel(addrKey, level)]
		if value == nil {
			return levels
		}
		levels = append(levels, append([]byte(nil), value...))
	}
}

func requireAddrBuildLevels(t *testing.T, got,
	want map[[levelKeySize]byte][]byte) {

	t.Helper()
	require.Len(t, got, len(want))
	for key, value := range want {
		require.Equalf(t, value, got[key], "level %x", key)
	}
}

func applyAddrBuildRecords(t *testing.T, bucket *addrIndexBucket,
	records []addrRecord, baseBlockID uint32) {

	t.Helper()
	sort.Sort(addrRecords(records))
	for start := 0; start < len(records); {
		addrKey := records[start].key()
		end := start + 1
		for end < len(records) && records[end].key() == addrKey {
			end++
		}

		existing := addrBuildTestLevels(bucket, addrKey)
		levels, err := buildAddrLevelValues(
			records[start:end], existing, baseBlockID, nil,
		)
		require.NoError(t, err)
		for level := 0; level < max(len(levels), len(existing)); level++ {
			key := keyForLevel(addrKey, uint8(level))
			if level >= len(levels) {
				require.NoError(t, bucket.Delete(key[:]))
				continue
			}
			require.NoError(t, bucket.Put(key[:], levels[level]))
		}
		start = end
	}
}

func TestAddrLevelEntryCounts(t *testing.T) {
	t.Parallel()

	var addrKey [addrKeySize]byte
	bucket := &addrIndexBucket{levels: make(map[[levelKeySize]byte][]byte)}
	for numEntries := 0; numEntries <= 10000; numEntries++ {
		if numEntries > 0 {
			putAddrBuildTestEntries(
				t, bucket, addrKey, numEntries-1, numEntries,
			)
		}

		counts := addrLevelEntryCounts(numEntries)
		require.Len(t, counts, len(bucket.levels))
		for level, count := range counts {
			key := keyForLevel(addrKey, uint8(level))
			require.Equal(t, len(bucket.levels[key])/txEntrySize, count)
		}
	}
}

func TestAddrIndexFastBuildParity(t *testing.T) {
	t.Parallel()

	counts := []int{
		1, level0MaxEntries, level0MaxEntries + 1,
		level0MaxEntries*5 + 1, 250, 777, 1000,
	}
	reference := &addrIndexBucket{
		levels: make(map[[levelKeySize]byte][]byte),
	}
	var records []addrRecord
	for i, count := range counts {
		var addrKey [addrKeySize]byte
		addrKey[0] = byte(i % 5)
		addrKey[1] = byte(i * 31)
		addrKey[addrKeySize-1] = byte(i + 1)
		putAddrBuildTestEntries(t, reference, addrKey, 0, count)
		records = append(records, addrBuildTestRecords(addrKey, 0, count)...)
	}

	rng := rand.New(rand.NewSource(1))
	rng.Shuffle(len(records), func(i, j int) {
		records[i], records[j] = records[j], records[i]
	})
	got := &addrIndexBucket{levels: make(map[[levelKeySize]byte][]byte)}
	applyAddrBuildRecords(t, got, records, 0)
	requireAddrBuildLevels(t, got.levels, reference.levels)
}

func TestAddrIndexFastBuildExtensionParity(t *testing.T) {
	t.Parallel()

	const (
		baseBlockID = 5
		covered     = baseBlockID * 3
	)
	tests := []struct {
		target   int
		existing int
	}{
		{covered + 1, covered},
		{covered + 100, covered},
		{covered + 100, covered + 50},
		{covered + 100, covered + 100},
		{covered + 3, covered + level0MaxEntries*8},
	}

	reference := &addrIndexBucket{
		levels: make(map[[levelKeySize]byte][]byte),
	}
	current := &addrIndexBucket{
		levels: make(map[[levelKeySize]byte][]byte),
	}
	var records []addrRecord
	for i, test := range tests {
		var addrKey [addrKeySize]byte
		addrKey[1] = byte(i * 37)
		addrKey[addrKeySize-1] = byte(i + 1)
		putAddrBuildTestEntries(t, reference, addrKey, 0, test.target)
		putAddrBuildTestEntries(t, current, addrKey, 0, test.existing)
		records = append(records,
			addrBuildTestRecords(addrKey, covered, test.target)...)
	}

	got := current.Clone()
	applyAddrBuildRecords(t, got, records, baseBlockID)
	requireAddrBuildLevels(t, got.levels, reference.levels)
}

func TestWriteAddrIndexToDB(t *testing.T) {
	db, err := database.Create(
		"ffldb", filepath.Join(t.TempDir(), "db"), wire.MainNet,
	)
	require.NoError(t, err)
	defer db.Close()
	require.NoError(t, db.Update(func(dbTx database.Tx) error {
		_, err := dbTx.Metadata().CreateBucket(addrIndexKey)
		return err
	}))

	stager, err := newAddrStager(t.TempDir())
	require.NoError(t, err)
	reference := &addrIndexBucket{
		levels: make(map[[levelKeySize]byte][]byte),
	}
	for shard, count := range map[byte]int{
		0: 1, 31: level0MaxEntries + 1, 200: level0MaxEntries*5 + 1,
	} {
		var addrKey [addrKeySize]byte
		addrKey[1] = shard
		for i := count - 1; i >= 0; i-- {
			blockID, txLoc := addrBuildTestEntry(i)
			require.NoError(t, stager.add(&addrKey, blockID, txLoc))
		}
		putAddrBuildTestEntries(t, reference, addrKey, 0, count)
	}
	manifest := addrBuildManifest{
		Completed: -1, BaseHeight: -1, TargetHeight: 0,
	}
	require.NoError(t, stager.checkpoint(&manifest, nil))

	idx := &AddrIndex{db: db}
	require.NoError(t, idx.writeAddrIndexToDB(stager, 0, nil))
	got := make(map[[levelKeySize]byte][]byte)
	require.NoError(t, db.View(func(dbTx database.Tx) error {
		return dbTx.Metadata().Bucket(addrIndexKey).ForEach(
			func(key, value []byte) error {
				var levelKey [levelKeySize]byte
				copy(levelKey[:], key)
				got[levelKey] = append([]byte(nil), value...)
				return nil
			},
		)
	}))
	requireAddrBuildLevels(t, got, reference.levels)
}
