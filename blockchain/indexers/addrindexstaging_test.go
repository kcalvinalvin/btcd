// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestAddrStagingRecord(t *testing.T) {
	t.Parallel()

	var firstKey, secondKey [addrKeySize]byte
	firstKey[1] = 2
	secondKey[1] = 1
	first := makeAddrRecord(
		&firstKey, 10, wire.TxLoc{TxStart: 20, TxLen: 30},
	)
	second := makeAddrRecord(
		&secondKey, 11, wire.TxLoc{TxStart: 21, TxLen: 31},
	)

	require.Equal(t, firstKey, first.key())
	require.Equal(t, uint32(10), first.blockID())
	require.Equal(t, serializeAddrIndexEntry(
		10, wire.TxLoc{TxStart: 20, TxLen: 30},
	), first[addrKeySize:])

	records := addrRecords{first, second}
	sort.Sort(records)
	require.Equal(t, secondKey, records[0].key())
}

func TestAddrStagingCheckpointResume(t *testing.T) {
	dir := t.TempDir()
	stager, err := newAddrStager(dir)
	require.NoError(t, err)

	var firstKey, secondKey [addrKeySize]byte
	firstKey[1] = 3
	secondKey[1] = 200
	require.NoError(t, stager.add(
		&firstKey, 1, wire.TxLoc{TxStart: 2, TxLen: 3},
	))
	require.NoError(t, stager.add(
		&secondKey, 4, wire.TxLoc{TxStart: 5, TxLen: 6},
	))

	manifest := addrBuildManifest{
		Completed:    10,
		BaseHeight:   -1,
		TargetHeight: 20,
		TargetHash:   chainhash.Hash{1},
	}
	require.NoError(t, stager.checkpoint(&manifest, nil))
	checkpointSizes := manifest.ShardSizes

	// This record is durable but is not part of the checkpoint.
	require.NoError(t, stager.add(
		&firstKey, 7, wire.TxLoc{TxStart: 8, TxLen: 9},
	))
	shard := &stager.shards[firstKey[1]]
	require.NoError(t, shard.buf.Flush())
	require.NoError(t, shard.f.Sync())
	stager.close()

	saved, ok := readAddrBuildManifest(dir)
	require.True(t, ok)
	require.Equal(t, manifest, saved)
	resumed, err := openAddrStager(dir, &saved, nil)
	require.NoError(t, err)
	defer resumed.close()

	for i, size := range checkpointSizes {
		info, err := os.Stat(addrStagingShardPath(dir, i))
		require.NoError(t, err)
		require.Equalf(t, size, info.Size(), "shard %d", i)
	}
	firstRecords, err := readAddrStagingShard(
		addrStagingShardPath(dir, int(firstKey[1])), nil,
	)
	require.NoError(t, err)
	require.Len(t, firstRecords, 1)
	secondRecords, err := readAddrStagingShard(
		addrStagingShardPath(dir, int(secondKey[1])), nil,
	)
	require.NoError(t, err)
	require.Len(t, secondRecords, 1)
}

func TestAddrStagingManifestValidation(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(
		addrStagingShardPath(dir, 0), []byte{1}, 0600,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, addrBuildManifestName), []byte("invalid"), 0600,
	))
	_, ok := readAddrBuildManifest(dir)
	require.False(t, ok)

	shortManifest, err := json.Marshal(addrBuildManifest{
		Version:      addrBuildManifestVersion,
		Completed:    -1,
		BaseHeight:   -1,
		TargetHeight: 0,
		ShardSizes:   []int64{0},
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, addrBuildManifestName), shortManifest, 0600,
	))
	_, ok = readAddrBuildManifest(dir)
	require.False(t, ok)

	interrupt := make(chan struct{})
	close(interrupt)
	manifest := addrBuildManifest{
		ShardSizes: make([]int64, numAddrStagingShards),
	}
	_, err = openAddrStager(dir, &manifest, interrupt)
	require.ErrorIs(t, err, errInterruptRequested)
}

func TestRemoveAddrIndexBuildDir(t *testing.T) {
	dataDir := t.TempDir()
	buildDir := filepath.Join(dataDir, addrIndexBuildDirName)
	require.NoError(t, os.MkdirAll(
		filepath.Join(buildDir, "staging"), 0700,
	))
	require.NoError(t, os.Mkdir(buildDir+".delete", 0700))

	require.NoError(t, removeAddrIndexBuildDir(dataDir))
	_, err := os.Stat(buildDir)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(buildDir + ".delete")
	require.ErrorIs(t, err, os.ErrNotExist)
}
