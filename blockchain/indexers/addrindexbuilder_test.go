// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

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
