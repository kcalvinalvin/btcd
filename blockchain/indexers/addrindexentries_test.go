// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"math"
	"testing"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestAddrEntryBlockID(t *testing.T) {
	t.Parallel()

	for _, blockID := range []uint32{
		0, 1, 255, 256, 65535, 65536, 1 << 24, math.MaxInt32, math.MaxUint32,
	} {
		var entry [txEntrySize]byte
		byteOrder.PutUint32(entry[:], blockID)
		require.Equal(t, blockID, addrEntryBlockID(entry[:]))
	}
}

func TestAppendAddrEntryCapacity(t *testing.T) {
	t.Parallel()

	backing := make([]byte, 3*txEntrySize)
	for i := range backing {
		backing[i] = 0xff
	}
	before := append([]byte(nil), backing...)
	var entry [txEntrySize]byte
	for i := range entry {
		entry[i] = byte(i + 1)
	}

	end := appendAddrEntry(backing, entry[:], txEntrySize)
	require.Equal(t, 2*txEntrySize, end)
	require.Equal(t, before[:txEntrySize], backing[:txEntrySize])
	require.Equal(t, entry[:], backing[txEntrySize:end])
	require.Equal(t, before[end:], backing[end:])
}

func TestBuildAddrLevelValuesBatches(t *testing.T) {
	t.Parallel()

	baseCount := addrStagingInterruptCheckRecords + 1
	records := make([]addrRecord, 2*baseCount+1)
	var addrKey [addrKeySize]byte
	var expected []byte
	for i := range records {
		records[i] = makeAddrRecord(&addrKey, uint32(i+1),
			wire.TxLoc{TxStart: i * 4, TxLen: i + 1})
		expected = append(expected, records[i][addrKeySize:]...)
	}

	// A previous write can include staged entries beyond the base block.
	existingBytes := append([]byte(nil), expected[:len(expected)-txEntrySize]...)
	existing := addrLevelValues(existingBytes)
	staged := records[baseCount:]
	stagedBefore := append([]addrRecord(nil), staged...)
	levels, err := buildAddrLevelValues(staged, existing, uint32(baseCount), nil)
	require.NoError(t, err)
	var actual []byte
	for level := len(levels) - 1; level >= 0; level-- {
		actual = append(actual, levels[level]...)
	}
	require.Equal(t, expected, actual)
	require.Equal(t, expected[:len(existingBytes)], existingBytes)
	require.Equal(t, stagedBefore, staged)

	replayed, err := buildAddrLevelValues(staged, levels, uint32(baseCount), nil)
	require.NoError(t, err)
	require.Equal(t, levels, replayed)

	interrupt := make(chan struct{})
	close(interrupt)
	_, err = buildAddrLevelValues(staged, existing, uint32(baseCount), interrupt)
	require.ErrorIs(t, err, errInterruptRequested)
	_, err = buildAddrLevelValues(staged, nil, uint32(baseCount), interrupt)
	require.ErrorIs(t, err, errInterruptRequested)
	_, err = buildAddrLevelValues(nil, [][]byte{{1}}, 0, nil)
	require.ErrorContains(t, err, "malformed address index entry")
}
