// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// addrBuildTestSpec describes one address key and how many entries it has for
// the fast build parity test.
type addrBuildTestSpec struct {
	addrKey    [addrKeySize]byte
	numEntries int
}

// entryLoc returns the block id and transaction location of the i'th entry (in
// oldest-to-newest order) for an address in the parity test.  Several
// entries share a block id to exercise the within-block tiebreak, while the
// block id and transaction offset are both strictly increasing with i so the
// canonical order is unambiguous.
func entryLoc(i int) (uint32, wire.TxLoc) {
	return uint32(i / 3), wire.TxLoc{TxStart: i * 4, TxLen: i + 1}
}

// TestAddrIndexFastBuildParity ensures the fast build write path produces a
// level layout byte-identical to the incremental path.  The reference is built
// by inserting each address's entries in canonical order directly through
// dbPutAddrIndexEntry, while the staged records are sorted with the same
// ordering as the on-disk sorter.  This also proves the record ordering is
// correct.
func TestAddrIndexFastBuildParity(t *testing.T) {
	t.Parallel()

	// mkKey builds an address key with the given type byte, shard byte, and a
	// distinguishing tail byte.
	mkKey := func(typ, shard, tail byte) [addrKeySize]byte {
		var key [addrKeySize]byte
		key[0] = typ
		key[1] = shard
		key[addrKeySize-1] = tail
		return key
	}

	// The specs span several shards (byte 1), multiple keys per shard, several
	// address types (byte 0), and entry counts that exercise level 0 through a
	// handful of higher levels.
	specs := []addrBuildTestSpec{
		{mkKey(0, 0, 1), 1},
		{mkKey(0, 0, 2), level0MaxEntries - 1},
		{mkKey(1, 0, 3), level0MaxEntries},
		{mkKey(2, 0, 4), level0MaxEntries + 1},
		{mkKey(0, 1, 1), level0MaxEntries*2 + 1},
		{mkKey(3, 1, 2), level0MaxEntries*5 + 1},
		{mkKey(4, 5, 1), level0MaxEntries*12 + 1},
		{mkKey(0, 5, 2), 250},
		{mkKey(1, 200, 1), 1000},
		{mkKey(2, 255, 1), 777},
	}

	// Build the reference bucket by inserting each address's entries in
	// canonical order, exactly as the incremental path does.
	reference := &addrIndexBucket{
		levels: make(map[[levelKeySize]byte][]byte),
	}
	for _, spec := range specs {
		for i := 0; i < spec.numEntries; i++ {
			blockID, txLoc := entryLoc(i)
			err := dbPutAddrIndexEntry(reference, spec.addrKey, blockID, txLoc)
			require.NoError(t, err)
		}
	}

	// Build the flat record slice the fast path consumes, then recover canonical
	// order with the ordering used by the on-disk sorter.
	var records []addrRecord
	for _, spec := range specs {
		for i := 0; i < spec.numEntries; i++ {
			blockID, txLoc := entryLoc(i)
			records = append(records, addrRecord{
				addrKey: spec.addrKey,
				blockID: uint64(blockID),
				txStart: uint64(txLoc.TxStart),
				txLen:   uint64(txLoc.TxLen),
			})
		}
	}
	rng := rand.New(rand.NewSource(1))
	rng.Shuffle(len(records), func(a, b int) {
		records[a], records[b] = records[b], records[a]
	})
	sort.Sort(addrRecords(records))

	// Run the fast build write path and collect the level entries it emits.
	got := make(map[[levelKeySize]byte][]byte)
	memBucket := &memAddrBucket{levels: make(map[[levelKeySize]byte][]byte)}
	err := emitSortedAddrLevelEntries(records, nil, 0, memBucket,
		func(key [levelKeySize]byte, value []byte) error {
			got[key] = append([]byte(nil), value...)
			return nil
		}, func() error { return nil })
	require.NoError(t, err)

	// The emitted level entries must exactly match the reference.
	require.Len(t, got, len(reference.levels))
	for key, want := range reference.levels {
		have, ok := got[key]
		require.Truef(t, ok, "fast build missing level key %x", key)
		require.Equalf(t, want, have, "value for level key %x", key)
	}
}

// TestAddrLevelEntryCounts ensures direct level construction uses the same
// level occupancy as incremental insertion across level rollover boundaries.
func TestAddrLevelEntryCounts(t *testing.T) {
	t.Parallel()

	var addrKey [addrKeySize]byte
	bucket := &addrIndexBucket{levels: make(map[[levelKeySize]byte][]byte)}
	for numEntries := 0; numEntries <= 10000; numEntries++ {
		if numEntries > 0 {
			blockID, txLoc := entryLoc(numEntries - 1)
			err := dbPutAddrIndexEntry(bucket, addrKey, blockID, txLoc)
			require.NoError(t, err)
		}

		got, err := addrLevelEntryCountsInterruptible(numEntries)
		require.NoError(t, err)
		require.Lenf(t, got, len(bucket.levels), "%d entries", numEntries)
		for level, gotEntries := range got {
			key := keyForLevel(addrKey, uint8(level))
			wantEntries := len(bucket.levels[key]) / txEntrySize
			require.Equalf(t, wantEntries, gotEntries,
				"%d entries at level %d", numEntries, level)
		}
	}
}

// insertAddrEntries inserts entries from (inclusive) to (exclusive) of the
// canonical entryLoc sequence for the address into the bucket through
// dbPutAddrIndexEntry, exactly as the incremental path would.
func insertAddrEntries(t *testing.T, bucket internalBucket,
	addrKey [addrKeySize]byte, from, to int) {

	t.Helper()
	for i := from; i < to; i++ {
		blockID, txLoc := entryLoc(i)
		err := dbPutAddrIndexEntry(bucket, addrKey, blockID, txLoc)
		require.NoError(t, err)
	}
}

// addrLevelValues returns copies of the address's level values from the bucket
// in ascending level order, or nil when the address has none.
func addrLevelValues(bucket *addrIndexBucket,
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

// addrRecordsRange returns the records for entries from (inclusive) to
// (exclusive) of the canonical entryLoc sequence for the address.
func addrRecordsRange(addrKey [addrKeySize]byte, from, to int) []addrRecord {
	records := make([]addrRecord, 0, to-from)
	for i := from; i < to; i++ {
		blockID, txLoc := entryLoc(i)
		records = append(records, addrRecord{
			addrKey: addrKey,
			blockID: uint64(blockID),
			txStart: uint64(txLoc.TxStart),
			txLen:   uint64(txLoc.TxLen),
		})
	}
	return records
}

// applyAddrLevelEmissions returns an emit callback that applies puts and nil
// value deletes to the bucket, the same way the write phase applies them to
// the database.
func applyAddrLevelEmissions(
	bucket *addrIndexBucket) func([levelKeySize]byte, []byte) error {
	return func(key [levelKeySize]byte, value []byte) error {
		if value == nil {
			return bucket.Delete(key[:])
		}
		return bucket.Put(key[:], append([]byte(nil), value...))
	}
}

// assertLevelsEqual fails the test when the two level maps differ.
func assertLevelsEqual(t *testing.T, got, want map[[levelKeySize]byte][]byte) {
	t.Helper()
	require.Len(t, got, len(want))
	for key, wantValue := range want {
		gotValue, ok := got[key]
		require.Truef(t, ok, "missing level key %x", key)
		require.Equalf(t, wantValue, gotValue, "value for level key %x", key)
	}
}

// TestAddrIndexFastBuildMergeParity ensures the write path of a build that
// extends a partially built index produces exactly the level layout the
// incremental path would have.  Each address's entries through the base are
// inserted incrementally as the existing index state, the remainder is
// replayed through emitSortedAddrLevelEntries as staged records, and the
// combined result must match a reference built by inserting the full sequence
// incrementally.
func TestAddrIndexFastBuildMergeParity(t *testing.T) {
	t.Parallel()

	// entryLoc assigns three entries per block id, so the first numCovered
	// entries have block ids at most baseBlockID and are covered by the base.
	const baseBlockID = 5
	const numCovered = (baseBlockID + 1) * 3

	mkKey := func(typ, shard, tail byte) [addrKeySize]byte {
		var key [addrKeySize]byte
		key[0] = typ
		key[1] = shard
		key[addrKeySize-1] = tail
		return key
	}

	// The entry counts cover addresses the base fully covers, which stage no
	// records at all, an address that barely extends past the base, and
	// addresses whose staged entries grow the levels well past the existing
	// ones.
	specs := []addrBuildTestSpec{
		{mkKey(0, 0, 1), 5},
		{mkKey(0, 0, 2), numCovered},
		{mkKey(1, 0, 3), numCovered + 1},
		{mkKey(2, 4, 1), numCovered + level0MaxEntries*3 + 1},
		{mkKey(0, 4, 2), numCovered + 400},
	}

	reference := &addrIndexBucket{levels: make(map[[levelKeySize]byte][]byte)}
	existingBucket := &addrIndexBucket{levels: make(map[[levelKeySize]byte][]byte)}
	existing := make(map[[addrKeySize]byte][][]byte)
	var records []addrRecord
	for _, spec := range specs {
		insertAddrEntries(t, reference, spec.addrKey, 0, spec.numEntries)

		covered := spec.numEntries
		if covered > numCovered {
			covered = numCovered
		}
		insertAddrEntries(t, existingBucket, spec.addrKey, 0, covered)
		if levels := addrLevelValues(existingBucket, spec.addrKey); levels != nil {
			existing[spec.addrKey] = levels
		}
		records = append(records,
			addrRecordsRange(spec.addrKey, covered, spec.numEntries)...)
	}

	rng := rand.New(rand.NewSource(4))
	rng.Shuffle(len(records), func(a, b int) {
		records[a], records[b] = records[b], records[a]
	})
	sort.Sort(addrRecords(records))

	// Apply the emitted puts and deletes on top of the existing state, the
	// same way the write phase applies them to the database.
	got := existingBucket.Clone()
	memBucket := &memAddrBucket{levels: make(map[[levelKeySize]byte][]byte)}
	err := emitSortedAddrLevelEntries(records, existing, baseBlockID, memBucket,
		applyAddrLevelEmissions(got), func() error { return nil })
	require.NoError(t, err)

	assertLevelsEqual(t, got.levels, reference.levels)
}

// TestAddrIndexFastBuildMergeHealsInterruptedWrite ensures a merge whose
// staged entries were already partially written to the index, which is the
// state an interrupted write phase leaves behind, strips those entries from
// the seeded levels and replays them to the same result.  An address the
// interrupted write already finished must produce no emissions at all since
// every level value it has is already correct.
func TestAddrIndexFastBuildMergeHealsInterruptedWrite(t *testing.T) {
	t.Parallel()

	const baseBlockID = 4
	const numCovered = (baseBlockID + 1) * 3
	const numEntries = numCovered + level0MaxEntries*6 + 2

	// mergedPartway had about half of its staged entries written before the
	// interruption, mergedFully had all of them, and mergedNone had none.
	var mergedPartway, mergedFully, mergedNone [addrKeySize]byte
	mergedPartway[1], mergedPartway[2] = 10, 1
	mergedFully[1], mergedFully[2] = 10, 2
	mergedNone[1], mergedNone[2] = 90, 3

	mergedThrough := map[[addrKeySize]byte]int{
		mergedPartway: numCovered + (numEntries-numCovered)/2,
		mergedFully:   numEntries,
		mergedNone:    numCovered,
	}

	reference := &addrIndexBucket{levels: make(map[[levelKeySize]byte][]byte)}
	existingBucket := &addrIndexBucket{levels: make(map[[levelKeySize]byte][]byte)}
	existing := make(map[[addrKeySize]byte][][]byte)
	var records []addrRecord
	for addrKey, through := range mergedThrough {
		insertAddrEntries(t, reference, addrKey, 0, numEntries)
		insertAddrEntries(t, existingBucket, addrKey, 0, through)
		existing[addrKey] = addrLevelValues(existingBucket, addrKey)
		records = append(records,
			addrRecordsRange(addrKey, numCovered, numEntries)...)
	}
	rng := rand.New(rand.NewSource(5))
	rng.Shuffle(len(records), func(a, b int) {
		records[a], records[b] = records[b], records[a]
	})
	sort.Sort(addrRecords(records))

	got := existingBucket.Clone()
	apply := applyAddrLevelEmissions(got)
	fullyMergedEmissions := 0
	memBucket := &memAddrBucket{levels: make(map[[levelKeySize]byte][]byte)}
	err := emitSortedAddrLevelEntries(records, existing, baseBlockID, memBucket,
		func(key [levelKeySize]byte, value []byte) error {
			var addrKey [addrKeySize]byte
			copy(addrKey[:], key[:addrKeySize])
			if addrKey == mergedFully {
				fullyMergedEmissions++
			}
			return apply(key, value)
		}, func() error { return nil })
	require.NoError(t, err)
	require.Zero(t, fullyMergedEmissions)
	assertLevelsEqual(t, got.levels, reference.levels)
}

// TestAddrIndexFastBuildMergeDeletesExtraLevels ensures a seeded level that no
// longer exists after the strip and replay is emitted with a nil value so the
// caller removes its key.  The seeded state holds far more entries beyond the
// base than the staged records put back, so the address ends up with fewer
// levels than it had.
func TestAddrIndexFastBuildMergeDeletesExtraLevels(t *testing.T) {
	t.Parallel()

	const baseBlockID = 0
	const numCovered = 3
	const numSeeded = numCovered + level0MaxEntries*5
	const numEntries = numCovered + 3

	var addrKey [addrKeySize]byte
	addrKey[1] = 77

	reference := &addrIndexBucket{levels: make(map[[levelKeySize]byte][]byte)}
	insertAddrEntries(t, reference, addrKey, 0, numEntries)

	existingBucket := &addrIndexBucket{levels: make(map[[levelKeySize]byte][]byte)}
	insertAddrEntries(t, existingBucket, addrKey, 0, numSeeded)
	existing := map[[addrKeySize]byte][][]byte{
		addrKey: addrLevelValues(existingBucket, addrKey),
	}
	require.Greater(t, len(existing[addrKey]),
		len(addrLevelValues(reference, addrKey)))

	got := existingBucket.Clone()
	apply := applyAddrLevelEmissions(got)
	numDeletes := 0
	memBucket := &memAddrBucket{levels: make(map[[levelKeySize]byte][]byte)}
	err := emitSortedAddrLevelEntries(
		addrRecordsRange(addrKey, numCovered, numEntries), existing,
		baseBlockID, memBucket,
		func(key [levelKeySize]byte, value []byte) error {
			if value == nil {
				numDeletes++
			}
			return apply(key, value)
		}, func() error { return nil })
	require.NoError(t, err)
	require.Positive(t, numDeletes)
	assertLevelsEqual(t, got.levels, reference.levels)
}

// TestAddrStagingRoundTrip ensures records round trip through the staging
// shards, are placed in the shard for their address hash160, and are not lost.
func TestAddrStagingRoundTrip(t *testing.T) {
	t.Parallel()

	// Exercise both routing extremes: repeatedly writing one shard and
	// distributing records across every shard.
	tests := []struct {
		name       string
		numRecords int
		firstShard int
		numShards  int
	}{
		{
			name:       "single shard",
			numRecords: 50,
			firstShard: 42,
			numShards:  1,
		},
		{
			name:       "all shards",
			numRecords: 500,
			firstShard: 0,
			numShards:  numAddrStagingShards,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			stager, err := newAddrStager(dir)
			require.NoError(t, err)
			t.Cleanup(stager.closeShards)

			// Keep each input record as the oracle for the later readback.
			want := make([]addrRecord, 0, test.numRecords)
			for i := 0; i < test.numRecords; i++ {
				var key [addrKeySize]byte
				// Cycle through every supported address type.
				key[0] = byte(i % 5)

				// The first hash160 byte selects the staging shard.
				key[1] = byte(test.firstShard + i%test.numShards)

				// Vary the final byte of the address hash.
				key[addrKeySize-1] = byte(i)
				rec := addrRecord{
					addrKey: key,
					blockID: uint64(i),
					// Use a non-unit stride so offsets vary independently from
					// block IDs.
					txStart: uint64(i * 7),
					// Keep transaction lengths nonzero while varying them between
					// records.
					txLen: uint64(i + 1),
				}
				want = append(want, rec)

				err := stager.add(&key, uint32(rec.blockID), wire.TxLoc{
					TxStart: int(rec.txStart),
					TxLen:   int(rec.txLen),
				})
				require.NoError(t, err)
			}

			// Flush the buffered writers before reading directly from the shard
			// files.
			for i := range stager.shards {
				err := stager.shards[i].buf.Flush()
				require.NoErrorf(t, err, "flush shard %d", i)
			}

			// Read every shard in full and verify each record was routed by its
			// first hash160 byte.
			var got []addrRecord
			for i := range stager.shards {
				numRecords := int(stager.shards[i].numRecords)
				recs, err := readAddrStagingShardRecords(
					stager.shards[i].f, numRecords,
				)
				require.NoErrorf(t, err, "read staging shard %d", i)
				for _, rec := range recs {
					require.Equalf(t, i, int(rec.addrKey[1]),
						"record read from shard %d", i)
				}
				got = append(got, recs...)
			}
			require.Len(t, got, len(want))

			// Reading shard-by-shard groups records differently than insertion
			// order, so sort both sets into canonical record order before
			// comparing them.
			less := func(recs []addrRecord) func(a, b int) bool {
				return func(a, b int) bool { return recs[a].less(&recs[b]) }
			}
			sort.Slice(want, less(want))
			sort.Slice(got, less(got))
			for i := range want {
				require.Equalf(t, want[i], got[i], "record %d", i)
			}
		})
	}
}

// TestAddrStagingVarintBoundaries ensures uint64 values round trip across wire
// varint size boundaries.
func TestAddrStagingVarintBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value      uint64
		varintSize int
	}{
		{0, 1},
		{0xfc, 1},
		{0xfd, 3},
		{1<<16 - 1, 3},
		{1 << 16, 5},
		{1<<32 - 1, 5},
		{1 << 32, 9},
		{^uint64(0), 9},
	}
	for _, test := range tests {
		record := addrRecord{
			blockID: test.value,
			txStart: test.value,
			txLen:   test.value,
		}
		var (
			varIntBuf [addrVarIntScratchSize]byte
			buf       bytes.Buffer
		)
		err := writeAddrRecord(&buf, &record, &varIntBuf)
		require.NoErrorf(t, err, "write record for %d", test.value)
		wantSize := addrKeySize + 3*test.varintSize
		require.Equalf(t, wantSize, buf.Len(), "serialized size for %d",
			test.value)

		var got addrRecord
		var readBuf [addrVarIntScratchSize]byte
		err = readAddrRecord(&buf, &got, &readBuf)
		require.NoErrorf(t, err, "read record for %d", test.value)
		require.Equalf(t, record, got, "record for %d", test.value)
	}
}

type interruptAddrStagingReader struct {
	r         *bytes.Reader
	interrupt chan struct{}
	closed    bool
}

func (r *interruptAddrStagingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if !r.closed {
		close(r.interrupt)
		r.closed = true
	}
	return n, err
}

// TestReadAddrStagingRecordsInterrupt ensures a long staging read observes an
// interrupt that arrives after it starts.
func TestReadAddrStagingRecordsInterrupt(t *testing.T) {
	t.Parallel()

	const numRecords = addrStagingInterruptCheckRecords + 1
	record := make([]byte, addrKeySize+3)
	interrupt := make(chan struct{})
	r := &interruptAddrStagingReader{
		r:         bytes.NewReader(bytes.Repeat(record, numRecords)),
		interrupt: interrupt,
	}
	_, err := readAddrStagingRecords(r, numRecords, interrupt)
	require.Same(t, errInterruptRequested, err)
}

// TestSortAddrStagingShards ensures staging shards are sorted independently
// without losing records or leaving replacement files behind.
func TestSortAddrStagingShards(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	stager, err := newAddrStager(dir)
	require.NoError(t, err)
	t.Cleanup(stager.closeShards)

	// Populate several independent shards while leaving the remaining shards
	// empty to exercise both paths through the sorter.
	const (
		numShards  = 4
		numRecords = 1000
	)
	want := make([][]addrRecord, numShards)
	for i := 0; i < numRecords; i++ {
		shard := i % numShards
		var key [addrKeySize]byte
		// Cycle through all five supported address types.
		key[0] = byte(i % 5)

		// The first hash160 byte selects the staging shard.
		key[1] = byte(shard)

		// Vary the final hash byte in reverse order so insertion order is not
		// already sorted.
		key[addrKeySize-1] = byte(255 - i)
		record := addrRecord{
			addrKey: key,
			// Descending block IDs further scramble the staged order.
			blockID: uint64(numRecords - i),
			// Use a non-unit stride so offsets vary independently from block IDs.
			txStart: uint64(i * 7),
			// Keep transaction lengths nonzero while varying them between records.
			txLen: uint64(i + 1),
		}
		want[shard] = append(want[shard], record)
		err := stager.add(&key, uint32(record.blockID), wire.TxLoc{
			TxStart: int(record.txStart),
			TxLen:   int(record.txLen),
		})
		require.NoError(t, err)
	}

	err = sortAddrStagingShards(stager, func(int) {}, nil)
	require.NoError(t, err)
	for shard := range want {
		_, path := addrStagingShardPaths(dir, shard)
		f, err := os.Open(path)
		require.NoErrorf(t, err, "open sorted shard %d", shard)
		got, err := readAddrStagingShardRecords(f, len(want[shard]))
		f.Close()
		require.NoErrorf(t, err, "read sorted shard %d", shard)
		require.Truef(t, sort.IsSorted(addrRecords(got)),
			"shard %d is not sorted", shard)

		sort.Sort(addrRecords(want[shard]))
		require.Equalf(t, want[shard], got, "records for shard %d", shard)

		unsortedPath, _ := addrStagingShardPaths(dir, shard)
		_, err = os.Stat(unsortedPath)
		require.Truef(t, os.IsNotExist(err), "unsorted shard %q remains",
			unsortedPath)
	}
}

// TestOpenAddrStagerInterrupt ensures staging recovery honors an interrupt and
// leaves the staged records intact for the next attempt.
func TestOpenAddrStagerInterrupt(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	stager, err := newAddrStager(dir)
	require.NoError(t, err)
	t.Cleanup(stager.closeShards)

	var addrKey [addrKeySize]byte
	addrKey[1] = 7
	err = stager.add(&addrKey, 1, wire.TxLoc{
		TxStart: 2,
		TxLen:   3,
	})
	require.NoError(t, err)
	err = stager.sync()
	require.NoError(t, err)
	manifest := addrBuildManifest{
		completed:    0,
		baseHeight:   -1,
		targetHeight: 1,
	}
	err = stager.recordShardStates(&manifest)
	require.NoError(t, err)
	stager.closeShards()

	interrupt := make(chan struct{})
	close(interrupt)
	_, err = openAddrStager(dir, true, &manifest, interrupt)
	require.Same(t, errInterruptRequested, err)

	path, _ := addrStagingShardPaths(dir, int(addrKey[1]))
	f, err := os.Open(path)
	require.NoError(t, err)
	records, err := readAddrStagingShardRecords(f, 1)
	f.Close()
	require.NoError(t, err)
	require.Len(t, records, 1)
}

// TestOpenAddrStagerRecoveryState ensures recovery restores the exact shard
// prefix recorded in the manifest.
func TestOpenAddrStagerRecoveryState(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	stager, err := newAddrStager(dir)
	require.NoError(t, err)
	t.Cleanup(func() {
		stager.closeShards()
	})

	var addrKey [addrKeySize]byte
	addrKey[1] = 7
	err = stager.add(&addrKey, 1, wire.TxLoc{
		TxStart: 2,
		TxLen:   3,
	})
	require.NoError(t, err)
	err = stager.sync()
	require.NoError(t, err)
	manifest := addrBuildManifest{
		completed:    100,
		baseHeight:   -1,
		targetHeight: 200,
	}
	err = stager.recordShardStates(&manifest)
	require.NoError(t, err)
	wantSize := manifest.shards[addrKey[1]].fileSize

	err = stager.add(&addrKey, 2, wire.TxLoc{
		TxStart: 4,
		TxLen:   5,
	})
	require.NoError(t, err)
	err = stager.sync()
	require.NoError(t, err)
	stager.closeShards()

	stager, err = openAddrStager(dir, true, &manifest, nil)
	require.NoError(t, err)
	shard := &stager.shards[addrKey[1]]
	require.Equal(t, uint64(1), shard.numRecords)
	info, err := os.Stat(shard.path)
	require.NoError(t, err)
	require.Equal(t, wantSize, uint64(info.Size()))

	f, err := os.Open(shard.path)
	require.NoError(t, err)
	records, err := readAddrStagingShardRecords(f, 1)
	f.Close()
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.Equal(t, uint64(1), records[0].blockID)
}

// TestSortAddrStagingShardsResume ensures shards published as sorted are
// skipped when an interrupted sort resumes.
func TestSortAddrStagingShardsResume(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	stager, err := newAddrStager(dir)
	require.NoError(t, err, "newAddrStager")
	t.Cleanup(func() {
		stager.closeShards()
	})

	for i := 0; i < 100; i++ {
		var key [addrKeySize]byte
		key[1] = byte(i % 2)
		key[addrKeySize-1] = byte(100 - i)
		err := stager.add(&key, uint32(100-i), wire.TxLoc{
			TxStart: i * 7,
			TxLen:   i + 1,
		})
		require.NoError(t, err, "stager.add")
	}
	err = stager.sync()
	require.NoError(t, err, "stager.sync")
	manifest := addrBuildManifest{
		completed:    1,
		baseHeight:   -1,
		targetHeight: 1,
	}
	err = stager.recordShardStates(&manifest)
	require.NoError(t, err, "recordShardStates")
	stager.closeShards()

	unsortedPath, sortedPath := addrStagingShardPaths(dir, 0)
	numRecords := int(stager.shards[0].numRecords)
	limiter := newAddrMergeFileLimiter(addrBuildSortMaxMergeFiles)
	err = sortAddrStagingShard(unsortedPath, sortedPath, numRecords, 7,
		limiter)
	require.NoError(t, err, "sortAddrStagingShard")

	resumed, err := openAddrStager(dir, false, &manifest, nil)
	require.NoError(t, err, "openAddrStager")
	stager = resumed

	// A nonempty temporary directory makes sorting shard zero fail if it is
	// queued again.  A successful resume therefore proves the .sorted name
	// was honored.
	trapPath := unsortedPath + ".sorting"
	err = os.Mkdir(trapPath, 0700)
	require.NoError(t, err, "create sort trap")
	trapFile := filepath.Join(trapPath, "keep")
	err = os.WriteFile(trapFile, nil, 0600)
	require.NoError(t, err, "populate sort trap")
	err = sortAddrStagingShards(stager, func(int) {}, nil)
	require.NoError(t, err, "resumed sortAddrStagingShards")
	_, err = os.Stat(trapFile)
	require.NoError(t, err, "sorted shard was processed again")
}

// TestSortAddrStagingShardsReportsReady ensures a completed shard is reported
// before the overall parallel sort returns.
func TestSortAddrStagingShardsReportsReady(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	stager, err := newAddrStager(dir)
	require.NoError(t, err, "newAddrStager")
	t.Cleanup(stager.closeShards)

	// Block the first ready callback after it reports its shard.  This proves a
	// shard is reported before the overall parallel sort is allowed to return.
	firstReady := make(chan int, 1)
	release := make(chan struct{})
	sortDone := make(chan error, 1)
	go func() {
		sortDone <- sortAddrStagingShards(stager, func(shard int) {
			select {
			case firstReady <- shard:
				<-release
			default:
			}
		}, nil)
	}()

	select {
	case <-firstReady:
	case <-time.After(5 * time.Second):
		require.FailNow(t, "sort did not report a ready shard")
	}
	select {
	case err := <-sortDone:
		require.FailNowf(t, "sort returned before ready shard was released",
			"error: %v", err)
	default:
	}

	close(release)
	select {
	case err := <-sortDone:
		require.NoError(t, err, "sortAddrStagingShards")
	case <-time.After(5 * time.Second):
		require.FailNow(t, "sort did not finish")
	}
}

// TestOpenAddrStagerForAppend ensures resuming a scan invalidates completed
// shard sorts before new records are appended.
func TestOpenAddrStagerForAppend(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	stager, err := newAddrStager(dir)
	require.NoError(t, err, "newAddrStager")
	t.Cleanup(func() {
		stager.closeShards()
	})

	var key [addrKeySize]byte
	key[1] = 10
	err = stager.add(&key, 1, wire.TxLoc{TxStart: 2, TxLen: 3})
	require.NoError(t, err, "stager.add")
	err = stager.sync()
	require.NoError(t, err, "stager.sync")
	manifest := addrBuildManifest{
		completed:    0,
		baseHeight:   -1,
		targetHeight: 1,
	}
	err = stager.recordShardStates(&manifest)
	require.NoError(t, err, "recordShardStates")
	err = sortAddrStagingShards(stager, func(int) {}, nil)
	require.NoError(t, err, "sortAddrStagingShards")

	reopened, err := openAddrStager(dir, true, &manifest, nil)
	require.NoError(t, err, "openAddrStager")
	stager = reopened
	for shard := range stager.shards {
		unsortedPath, sortedPath := addrStagingShardPaths(dir, shard)
		require.Falsef(t, stager.shards[shard].sorted,
			"shard %d still marked sorted", shard)
		require.Equalf(t, unsortedPath, stager.shards[shard].path,
			"path for shard %d", shard)
		_, err := os.Stat(sortedPath)
		require.Truef(t, os.IsNotExist(err), "sorted shard %q remains",
			sortedPath)
	}
}

// TestSortAddrStagingShardRuns ensures a shard larger than one in-memory run
// is merged into a single sorted staging file.
func TestSortAddrStagingShardRuns(t *testing.T) {
	t.Parallel()

	const (
		numRecords = 100
		shard      = 42

		// This forces multiple runs and a partially filled final run.
		maxRunRecords = 7
	)
	dir := t.TempDir()
	path := filepath.Join(dir, "shard.tmp")
	sortedPath := filepath.Join(dir, "shard.sorted")
	records := make([]addrRecord, numRecords)
	for i := range records {
		// Cycle through all five supported address types.
		records[i].addrKey[0] = byte(i % 5)

		// Keep every record in the same staging shard.
		records[i].addrKey[1] = shard

		// Reverse the final hash byte and block ID so the input needs sorting.
		records[i].addrKey[addrKeySize-1] = byte(255 - i)
		records[i].blockID = uint64(numRecords - i)

		// Vary transaction locations independently and keep lengths nonzero.
		records[i].txStart = uint64(i * 7)
		records[i].txLen = uint64(i + 1)
	}
	// Preserve the deliberately unsorted input while constructing the sorted
	// oracle.
	want := append([]addrRecord(nil), records...)
	sort.Sort(addrRecords(want))
	// The input is a disposable test fixture, so no fsync is needed.
	err := writeAddrStagingShard(path, records, false)
	require.NoError(t, err, "writeAddrStagingShard")
	limiter := newAddrMergeFileLimiter(addrBuildSortMaxMergeFiles)
	err = sortAddrStagingShard(path, sortedPath, len(records), maxRunRecords,
		limiter)
	require.NoError(t, err, "sortAddrStagingShard")

	f, err := os.Open(sortedPath)
	require.NoError(t, err, "open sorted shard")
	got, err := readAddrStagingShardRecords(f, len(want))
	f.Close()
	require.NoError(t, err, "read sorted shard")
	require.Len(t, got, len(want), "record count")
	for i := range got {
		require.Equalf(t, want[i], got[i], "record %d", i)
	}

	// Successful publication removes the source and every run or sorting
	// intermediate derived from it.
	matches, err := filepath.Glob(path + ".*")
	require.NoError(t, err, "glob sort files")
	require.Empty(t, matches, "sort files remain")
	_, err = os.Stat(path)
	require.Truef(t, os.IsNotExist(err), "unsorted shard remains: %v", err)
}

// TestSortAddrStagingShardMergeLimit ensures concurrent multi-pass merges
// complete and release their reservations under a small shared file limit.
func TestSortAddrStagingShardMergeLimit(t *testing.T) {
	t.Parallel()

	// One-record runs create 40 inputs per shard.  A five-file limit permits one
	// output plus four inputs per merge, forcing multiple passes while the two
	// concurrent shard sorts compete for the shared budget.
	const (
		numShards     = 2
		numRecords    = 40
		maxRunRecords = 1
		maxFiles      = 5
	)
	dir := t.TempDir()
	limiter := newAddrMergeFileLimiter(maxFiles)
	// shardPaths holds the unsorted input and sorted output paths for one shard.
	type shardPaths struct {
		// path is the unsorted input path.
		path string

		// sortedPath is the expected published output path.
		sortedPath string
	}
	paths := make([]shardPaths, numShards)
	for shard := range paths {
		paths[shard].path = filepath.Join(dir,
			fmt.Sprintf("shard-%d.tmp", shard))
		paths[shard].sortedPath = filepath.Join(dir,
			fmt.Sprintf("shard-%d.sorted", shard))
		records := make([]addrRecord, numRecords)
		for i := range records {
			records[i].addrKey[1] = byte(shard)
			// Descending block IDs ensure each run set needs merging in a
			// different order.
			records[i].blockID = uint64(numRecords - i)
		}
		// The input files are disposable test fixtures, so no fsync is needed.
		err := writeAddrStagingShard(paths[shard].path, records, false)
		require.NoError(t, err, "writeAddrStagingShard")
	}

	// Run both shard sorts concurrently against the same descriptor limiter.
	done := make(chan error, numShards)
	for shard := range paths {
		shard := shard
		go func() {
			done <- sortAddrStagingShard(paths[shard].path,
				paths[shard].sortedPath, numRecords, maxRunRecords,
				limiter)
		}()
	}
	for range paths {
		err := <-done
		require.NoError(t, err, "sortAddrStagingShard")
	}

	// Every successful merge must return its descriptor reservations.
	limiter.mu.Lock()
	open := limiter.open
	limiter.mu.Unlock()
	require.Zero(t, open, "merge file reservations remain")
	for shard := range paths {
		f, err := os.Open(paths[shard].sortedPath)
		require.NoError(t, err, "open sorted shard")
		records, err := readAddrStagingShardRecords(f, numRecords)
		f.Close()
		require.NoError(t, err, "read sorted shard")
		require.Truef(t, sort.IsSorted(addrRecords(records)),
			"shard %d is not sorted", shard)
	}
}

// TestAddrBuildManifestRoundTrip ensures the build manifest round trips all of
// its fields, and that invalid manifests are rejected.
func TestAddrBuildManifestRoundTrip(t *testing.T) {
	t.Parallel()

	manifest := addrBuildManifest{
		completed:     200000,
		baseHeight:    100000,
		targetHeight:  200000,
		writtenShards: 123,
	}
	manifest.shards[0] = addrBuildShardState{
		numRecords: 123,
		fileSize:   3000,
	}
	manifest.shards[numAddrStagingShards-1] = addrBuildShardState{
		numRecords: 1,
		fileSize:   addrKeySize + 3,
	}
	for i := range manifest.baseHash {
		manifest.baseHash[i] = byte(i)
		manifest.targetHash[i] = byte(255 - i)
	}

	fromScratch := manifest
	fromScratch.baseHeight = -1
	fromScratch.baseHash = chainhash.Hash{}
	tooManyWritten := manifest
	tooManyWritten.writtenShards = numAddrStagingShards + 1

	tests := []struct {
		name          string
		manifest      addrBuildManifest
		writeManifest bool
		mutate        func([]byte) []byte
		wantValid     bool
	}{
		{
			name:          "existing base",
			manifest:      manifest,
			writeManifest: true,
			wantValid:     true,
		},
		{
			name:          "from scratch",
			manifest:      fromScratch,
			writeManifest: true,
			wantValid:     true,
		},
		{
			name:      "missing",
			wantValid: false,
		},
		{
			name:          "truncated",
			manifest:      manifest,
			writeManifest: true,
			mutate: func(data []byte) []byte {
				return data[:len(data)-1]
			},
			wantValid: false,
		},
		{
			name:          "wrong magic",
			manifest:      manifest,
			writeManifest: true,
			mutate: func(data []byte) []byte {
				data[0] ^= 0xff
				return data
			},
			wantValid: false,
		},
		{
			name:          "too many written shards",
			manifest:      tooManyWritten,
			writeManifest: true,
			wantValid:     false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if test.writeManifest {
				err := writeAddrBuildManifest(dir, &test.manifest)
				require.NoError(t, err, "writeAddrBuildManifest")
			}

			if test.mutate != nil {
				path := filepath.Join(dir, addrBuildManifestName)
				data, err := os.ReadFile(path)
				require.NoError(t, err, "read manifest")
				err = os.WriteFile(path, test.mutate(data), 0600)
				require.NoError(t, err, "mutate manifest")
			}

			got, ok := readAddrBuildManifest(dir)
			require.Equal(t, test.wantValid, ok, "manifest validity")
			if ok {
				require.Equal(t, test.manifest, got, "manifest")
			}
		})
	}
}
