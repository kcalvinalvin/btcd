// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"bytes"
	"sort"
	"testing"

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
				return func(a, b int) bool {
					if c := bytes.Compare(recs[a].addrKey[:],
						recs[b].addrKey[:]); c != 0 {

						return c < 0
					}
					if recs[a].blockID != recs[b].blockID {
						return recs[a].blockID < recs[b].blockID
					}
					return recs[a].txStart < recs[b].txStart
				}
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
