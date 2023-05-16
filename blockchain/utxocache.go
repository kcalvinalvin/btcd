// Copyright (c) 2023 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"github.com/btcsuite/btcd/wire"
)

// mapSlice is a slice of maps for utxo entries.  The slice of maps are needed to
// guarantee that the map will only take up N amount of bytes.  As of v1.20, the
// go runtime will allocate 2^N + few extra buckets, meaning that for large N, we'll
// allocate a lot of extra memory if the amount of entries goes over the previously
// allocated buckets.  A slice of maps allows us to have a better control of how much
// total memory gets allocated by all the maps.
type mapSlice struct {
	maps []map[wire.OutPoint]*UtxoEntry

	// maxEntries is the maximum amount of elemnts that the map is allocated for.
	maxEntries []int

	// maxTotalMemoryUsage is the maximum memory usage in bytes that the state
	// should contain in normal circumstances.
	maxTotalMemoryUsage uint64
}

// length returns the length of all the maps in the map slice added together.
func (ms *mapSlice) length() int {
	var l int
	for _, m := range ms.maps {
		l += len(m)
	}

	return l
}

// size returns the size of all the maps in the map slice added together.
func (ms *mapSlice) size() int {
	var size int
	for _, num := range ms.maxEntries {
		size += calculateRoughMapSize(num, bucketSize)
	}

	return size
}

// get looks for the outpoint in all the maps in the map slice and returns
// the entry.  nil and false is returned if the outpoint is not found.
func (ms *mapSlice) get(op wire.OutPoint) (*UtxoEntry, bool) {
	var entry *UtxoEntry
	var found bool

	for _, m := range ms.maps {
		entry, found = m[op]
		if found {
			return entry, found
		}
	}

	return entry, found
}

// put puts the outpoint and the entry into one of the maps in the map slice.  If the
// existing maps are all full, it will allocate a new map based on how much memory we
// have left over.  Leftover memory is calculated as:
// maxTotalMemoryUsage - (totalEntryMemory + mapSlice.size())
func (ms *mapSlice) put(op wire.OutPoint, entry *UtxoEntry, totalEntryMemory uint64) {
	for i, maxNum := range ms.maxEntries {
		m := ms.maps[i]
		_, found := m[op]
		if found {
			// If the key is found, overwrite it.
			m[op] = entry
			return // Return as we were successful in adding the entry.
		}
		if len(m) >= maxNum {
			// Don't try to insert if the map already at max since
			// that'll force the map to allocate double the memory it's
			// currently taking up.
			continue
		}

		m[op] = entry
		return // Return as we were successful in adding the entry.
	}

	// We only reach this code if we've failed to insert into the map above as
	// all the current maps were full.  We thus make a new map and insert into
	// it.
	ms.makeNewMap(totalEntryMemory)
	m := ms.maps[len(ms.maps)-1] // new maps are appended to the map slice.
	m[op] = entry
}

// delete attempts to delete the given outpoint in all of the maps. No-op if the
// outpoint doesn't exist.
func (ms *mapSlice) delete(op wire.OutPoint) {
	for i := 0; i < len(ms.maps); i++ {
		delete(ms.maps[i], op)
	}
}

// makeNewMap makes and appends the new map into the map slice.
func (ms *mapSlice) makeNewMap(totalEntryMemory uint64) {
	// Get the size of the leftover memory.
	memSize := ms.maxTotalMemoryUsage - totalEntryMemory
	for _, maxNum := range ms.maxEntries {
		memSize -= uint64(calculateRoughMapSize(maxNum, bucketSize))
	}

	// Get a new map that's sized to house inside the leftover memory.
	numMaxElements := calculateMinEntries(int(memSize), bucketSize+avgEntrySize)
	numMaxElements -= 1
	ms.maxEntries = append(ms.maxEntries, numMaxElements)
	ms.maps = append(ms.maps, make(map[wire.OutPoint]*UtxoEntry, numMaxElements))
}

// deleteMaps deletes all maps except for the first one which should be the biggest.
func (ms *mapSlice) deleteMaps() {
	size := ms.maxEntries[0]
	ms.maxEntries = []int{size}
	ms.maps = []map[wire.OutPoint]*UtxoEntry{make(map[wire.OutPoint]*UtxoEntry, size)}
}
