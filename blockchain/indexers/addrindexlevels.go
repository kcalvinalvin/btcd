// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"bytes"
	"sort"

	"github.com/btcsuite/btcd/database"
)

const addrBuildWriteBatchBytes = 32 * 1024 * 1024

// addrLevelEntryCounts returns the final number of entries in each address
// index level after inserting numEntries entries.
func addrLevelEntryCounts(numEntries int) []int {
	if numEntries == 0 {
		return nil
	}

	levelCounts := []int{(numEntries-1)%level0MaxEntries + 1}
	remaining := numEntries - levelCounts[0]
	for maxEntries := level0MaxEntries * 2; remaining > 0; maxEntries *= 2 {
		levelEntries := maxEntries / 2
		if remaining%maxEntries == 0 {
			levelEntries = maxEntries
		}
		levelCounts = append(levelCounts, levelEntries)
		remaining -= levelEntries
	}
	return levelCounts
}

// buildAddrLevelValues constructs the complete level layout for one address.
// Existing entries beyond baseBlockID are discarded before staged records are
// appended.
func buildAddrLevelValues(records []addrRecord, existing [][]byte,
	baseBlockID uint32, interrupt <-chan struct{}) ([][]byte, error) {

	capacity := len(records) * txEntrySize
	for _, value := range existing {
		capacity += len(value)
	}
	entries := make([]byte, capacity)
	entryOffset := 0
	for sourceLevel := len(existing) - 1; sourceLevel >= 0; sourceLevel-- {
		value := existing[sourceLevel]
		if len(value)%txEntrySize != 0 {
			return nil, errDeserialize("malformed address index entry")
		}
		for offset := 0; offset < len(value); {
			if interruptRequested(interrupt) {
				return nil, errInterruptRequested
			}
			end := offset + min(len(value)-offset,
				addrStagingInterruptCheckRecords*txEntrySize)
			entryOffset = appendAddrLevelEntries(entries, value[offset:end],
				entryOffset, baseBlockID)
			offset = end
		}
	}
	for start := 0; start < len(records); {
		if interruptRequested(interrupt) {
			return nil, errInterruptRequested
		}
		end := start + min(len(records)-start, addrStagingInterruptCheckRecords)
		entryOffset = appendAddrRecordEntries(entries, records[start:end], entryOffset)
		start = end
	}

	return addrLevelValues(entries[:entryOffset]), nil
}

// addrLevelValues partitions serialized entries into address index levels.
// Entries must be complete and ordered from oldest to newest. The values
// share the entries buffer, with older entries in higher levels.
func addrLevelValues(entries []byte) [][]byte {
	counts := addrLevelEntryCounts(len(entries) / txEntrySize)
	levels := make([][]byte, len(counts))
	offset := 0
	for level := len(counts) - 1; level >= 0; level -= 1 {
		end := offset + counts[level]*txEntrySize
		levels[level] = entries[offset:end]
		offset = end
	}
	return levels
}

func fetchAddrLevelValues(bucket internalBucket,
	addrKey [addrKeySize]byte) [][]byte {

	var levels [][]byte
	for level := uint8(0); ; level++ {
		key := keyForLevel(addrKey, level)
		value := bucket.Get(key[:])
		if value == nil {
			return levels
		}
		levels = append(levels, value)
	}
}

func writeAddrLevelValues(bucket internalBucket, records []addrRecord,
	baseBlockID uint32, interrupt <-chan struct{}) (int, error) {

	addrKey := records[0].key()
	existing := fetchAddrLevelValues(bucket, addrKey)
	levels, err := buildAddrLevelValues(
		records, existing, baseBlockID, interrupt,
	)
	if err != nil {
		return 0, err
	}

	levelBytes := 0
	for level := 0; level < max(len(levels), len(existing)); level++ {
		var value []byte
		if level < len(levels) {
			value = levels[level]
		}
		levelBytes += len(value) + levelKeySize
		if level < len(existing) && bytes.Equal(value, existing[level]) {
			continue
		}

		key := keyForLevel(addrKey, uint8(level))
		if value == nil {
			if err := bucket.Delete(key[:]); err != nil {
				return 0, err
			}
		} else if err := bucket.Put(key[:], value); err != nil {
			return 0, err
		}
	}
	return levelBytes, nil
}

// writeAddrIndexToDB sorts and writes one staging shard at a time.  Database
// transactions stop at address boundaries once they reach the batch target.
func (idx *AddrIndex) writeAddrIndexToDB(stager *addrStager,
	baseBlockID uint32, interrupt <-chan struct{}) error {

	stager.close()
	for shard := 0; shard < numAddrStagingShards; shard++ {
		if interruptRequested(interrupt) {
			return errInterruptRequested
		}

		records, err := readAddrStagingShard(
			addrStagingShardPath(stager.dir, shard), interrupt,
		)
		if err != nil {
			return err
		}
		sort.Sort(addrRecords(records))

		for start := 0; start < len(records); {
			next := start
			err := idx.db.Update(func(dbTx database.Tx) error {
				bucket := dbTx.Metadata().Bucket(addrIndexKey)
				batchBytes := 0
				for next < len(records) {
					if interruptRequested(interrupt) {
						return errInterruptRequested
					}

					addrKey := records[next].key()
					end := next + 1
					for end < len(records) && records[end].key() == addrKey {
						if (end-next)%addrStagingInterruptCheckRecords == 0 &&
							interruptRequested(interrupt) {

							return errInterruptRequested
						}
						end++
					}

					written, err := writeAddrLevelValues(
						bucket, records[next:end], baseBlockID, interrupt,
					)
					if err != nil {
						return err
					}
					batchBytes += written
					next = end
					if batchBytes >= addrBuildWriteBatchBytes {
						break
					}
				}
				return nil
			})
			if err != nil {
				return err
			}
			start = next
		}

		if (shard+1)%16 == 0 {
			log.Infof("Address index write: %d/%d shards", shard+1,
				numAddrStagingShards)
		}
	}
	return nil
}
