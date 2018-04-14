// Copyright (c) 2015-2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"container/list"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcd/wire"
)

const (
	// utxoFlushPeriodicInterval is the interval at which a flush is performed
	// when the flush mode FlushPeriodic is used.  This is used when the initial
	// block download is complete and it's useful to flush periodically in case
	// of unforseen shutdowns.
	utxoFlushPeriodicInterval = time.Minute * 5

	// outpointSize is the size of an outpoint.
	//
	// This value is calculated by running the following:
	//	unsafe.Sizeof(wire.OutPoint{})
	outpointSize = 36

	// uint64Size is the size of an uint64.
	uint64Size = 8

	// This value is calculated by running the following on a 64-bit system:
	//   unsafe.Sizeof(UtxoEntry{})
	baseEntrySize = 40

	// bucketSize is the size of the bucket in the cache map.
	bucketSize = 16 + uint64Size*outpointSize + uint64Size*uint64Size

	// pubKeyHashLen is the length of a P2PKH script.
	pubKeyHashLen = 25

	// avgEntrySize is how much each entry we expect it to be.  Since most
	// txs are p2pkh, we can assume the entry to be more or less the size
	// of a p2pkh tx.  We add on 7 to make it 32 since 64 bit systems will
	// align by 8 bytes.
	avgEntrySize = baseEntrySize + (pubKeyHashLen + 7)
)

// FlushMode is used to indicate the different urgency types for a flush.
type FlushMode uint8

const (
	// FlushRequired is the flush mode that means a flush must be performed
	// regardless of the cache state.  For example right before shutting down.
	FlushRequired FlushMode = iota

	// FlushPeriodic is the flush mode that means a flush can be performed
	// when it would be almost needed.  This is used to periodically signal when
	// no I/O heavy operations are expected soon, so there is time to flush.
	FlushPeriodic

	// FlushIfNeeded is the flush mode that means a flush must be performed only
	// if the cache is exceeding a safety threshold very close to its maximum
	// size.  This is used mostly internally in between operations that can
	// increase the cache size.
	FlushIfNeeded
)

// mapSlice is a slice of maps for Utxo entries.  The slice of maps are needed to
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
		size += CalculateRoughMapSize(num, bucketSize)
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
		memSize -= uint64(CalculateRoughMapSize(maxNum, bucketSize))
	}

	// Get a new map that's sized to house inside the leftover memory.
	numMaxElements := CalculateMinEntries(int(memSize), bucketSize+avgEntrySize)
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

// utxoCache is a cached utxo view in the chainstate of a BlockChain.
//
// It implements the utxoView interface, but should only be used as such with the
// state mutex held.  It also implements the utxoByHashSource interface.
type utxoCache struct {
	db database.DB

	// maxTotalMemoryUsage is the maximum memory usage in bytes that the state
	// should contain in normal circumstances.
	maxTotalMemoryUsage uint64

	// This mutex protects the internal state.
	// A simple mutex instead of a read-write mutex is chosen because the main
	// read method also possibly does a write on a cache miss.
	mtx sync.Mutex

	// cachedEntries keeps the internal cache of the utxo state.  The tfModified
	// flag indicates that the state of the entry (potentially) deviates from the
	// state in the database.  Explicit nil values in the map are used to
	// indicate that the database does not contain the entry.
	cachedEntries    mapSlice
	totalEntryMemory uint64 // Total memory usage in bytes.

	// Below fields are used to indicate when the last flush happened.
	lastFlushHash chainhash.Hash
	lastFlushTime time.Time
}

// newUtxoCache initiates a new utxo cache instance with its memory usage limited
// to the given maximum.
func newUtxoCache(db database.DB, maxTotalMemoryUsage uint64) *utxoCache {
	// While the entry isn't included in the map size, add the average size to the
	// bucket size so we get some leftover space for entries to take up.
	numMaxElements := CalculateMinEntries(int(maxTotalMemoryUsage), bucketSize+avgEntrySize)
	numMaxElements -= 1

	log.Infof("Pre-alloacting for %d MiB: ", maxTotalMemoryUsage/(1024*1024)+1)

	m := make(map[wire.OutPoint]*UtxoEntry, numMaxElements)

	return &utxoCache{
		db:                  db,
		maxTotalMemoryUsage: maxTotalMemoryUsage,
		cachedEntries: mapSlice{
			maps:                []map[wire.OutPoint]*UtxoEntry{m},
			maxEntries:          []int{numMaxElements},
			maxTotalMemoryUsage: maxTotalMemoryUsage,
		},
	}
}

// totalMemoryUsage returns the total memory usage in bytes of the UTXO cache.
//
// This method should be called with the state lock held.
func (s *utxoCache) totalMemoryUsage() uint64 {
	// Total memory is the map size + the size that the utxo entries are
	// taking up.
	size := uint64(s.cachedEntries.size())
	size += s.totalEntryMemory

	return size
}

// TotalMemoryUsage returns the total memory usage in bytes of the UTXO cache.
//
// This method is safe for concurrent access.
func (s *utxoCache) TotalMemoryUsage() uint64 {
	s.mtx.Lock()
	tmu := s.totalMemoryUsage()
	s.mtx.Unlock()
	return tmu
}

// fetchEntries returns the UTXO entries for the given outpoints.  It returns nil if
// there is no entry for the outpoint in the UTXO state.
//
// This method should be called with the state lock held.
// The returned entries are NOT safe for concurrent access.
func (s *utxoCache) fetchEntries(outpoints []wire.OutPoint) ([]*UtxoEntry, error) {
	entries := make([]*UtxoEntry, len(outpoints))
	missingOps := make([]wire.OutPoint, 0, len(outpoints))
	missingOpsIdx := make([]int, 0, len(outpoints))
	for i, op := range outpoints {
		if entry, ok := s.cachedEntries.get(op); ok {
			entries[i] = entry
			continue
		}

		missingOpsIdx = append(missingOpsIdx, i)
		missingOps = append(missingOps, op)
	}

	// Fetch the missing outpoints in the cache from the database.
	dbEntries := make([]*UtxoEntry, len(missingOps))
	err := s.db.View(func(dbTx database.Tx) error {
		utxoBucket := dbTx.Metadata().Bucket(utxoSetBucketName)

		for i, op := range missingOps {
			entry, err := dbFetchUtxoEntry(dbTx, utxoBucket, op)
			if err != nil {
				return err
			}

			dbEntries[i] = entry
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// Add each of the entries to the UTXO cache and update their memory
	// usage.
	//
	// NOTE: When the fetched entry is nil, it is still added to the cache
	// as a miss; this prevents future lookups to perform the same database
	// fetch.
	for i, entry := range dbEntries {
		s.totalEntryMemory += entry.memoryUsage()
		s.cachedEntries.put(missingOps[i], entry, s.totalEntryMemory)
	}

	// Fill in the entries with the ones fetched from the database.
	for i, idx := range missingOpsIdx {
		entries[idx] = dbEntries[i]
	}

	return entries, nil
}

// getEntryByHash attempts to find any available UTXO for the given hash by
// searching the entire set of possible outputs for the given hash.
//
// This method is part of the utxoByHashSource interface.
// This method should be called with the state lock held.
func (s *utxoCache) fetchEntryByHash(hash *chainhash.Hash) (*UtxoEntry, error) {
	// First attempt to find a utxo with the provided hash in the cache.
	prevOut := wire.OutPoint{Hash: *hash}
	for idx := uint32(0); idx < MaxOutputsPerBlock; idx++ {
		prevOut.Index = idx
		if entry, _ := s.cachedEntries.get(prevOut); entry != nil {
			return entry, nil
		}
	}

	// Then fall back to the database.
	var entry *UtxoEntry
	err := s.db.View(func(dbTx database.Tx) error {
		var err error
		entry, err = dbFetchUtxoEntryByHash(dbTx, hash)
		return err
	})

	// Since we don't know the entries outpoint, we can't cache it.
	// This method is only called during disconnects where we flush every
	// block so it's ok not to cache it.  It's also only called with older
	// btcd versions with the legacy spend journal formats so it's rarely
	// called.
	return entry, err
}

// FetchEntryByHash attempts to find any available UTXO for the given hash by
// searching the entire set of possible outputs for the given hash.
//
// This method is safe for concurrent access.
func (s *utxoCache) FetchEntryByHash(hash *chainhash.Hash) (*UtxoEntry, error) {
	s.mtx.Lock()
	entry, err := s.fetchEntryByHash(hash)
	s.mtx.Unlock()
	return entry.Clone(), err
}

// spendEntry marks the output as spent.  Spending an output that is already
// spent has no effect.  Entries that need not be stored anymore after being
// spent will be removed from the cache.
//
// This method is part of the utxoView interface.
// This method should be called with the state lock held.
func (s *utxoCache) spendEntry(outpoint wire.OutPoint, entry *UtxoEntry) error {
	// Attempt to delete the entry from the map.  If the map's length
	// is different, we successfully deleted it.
	beforeLen := s.cachedEntries.length()
	s.cachedEntries.delete(outpoint)
	afterLen := s.cachedEntries.length()
	if beforeLen != afterLen {
		s.totalEntryMemory -= entry.memoryUsage()
	}

	// If an entry is fresh it indicates that this entry was spent before it could be
	// flushed to the database. Because of this, we can return now.
	if entry.isFresh() {
		return nil
	}

	// Since we don't need it anymore, drop the pkscript value of the entry.
	entry.pkScript = nil

	// We need to add in the spent entry to the cache so that during
	// a flush, the entry will be removed in the database.
	s.cachedEntries.put(outpoint, entry, s.totalEntryMemory)
	s.totalEntryMemory += entry.memoryUsage()

	return nil
}

// addEntry adds a new unspent entry.
//
// This method is part of the utxoView interface.
// This method should be called with the state lock held.
func (s *utxoCache) addEntry(outpoint wire.OutPoint, entry *UtxoEntry) {
	// If the entry is not fresh when we're adding an entry, it means that
	// this is an entry that's overwriting an exisiting entry.  Thus we need
	// to subtract the existing entry's memory usage.
	// Note that this is impossible to happen before height 1,983,702, the next
	// height where a coinbase tx can be collided. Refer to comment in bitcoind
	// github.com/bitcoin/bitcoin/blob/aebcd18c654a1706954a9e2c9cbfe97dfe531357/src/validation.cpp#L2176-L2201
	// for more info.
	if !entry.isFresh() {
		log.Infof("Entry %s is being overwritten at height %d",
			outpoint.String(), entry.BlockHeight())

		// Attempt to subtract the memory usage from the total entry
		// memory. It's ok if the entry is nil as it could be in the
		// database and memory usage will just be 0.
		cachedEntry, _ := s.cachedEntries.get(outpoint)
		s.totalEntryMemory -= cachedEntry.memoryUsage()
	}

	s.totalEntryMemory += entry.memoryUsage()
	s.cachedEntries.put(outpoint, entry, s.totalEntryMemory)
}

// commit commits all the entries in the view to the cache.  All the entries in
// the view are removed as the entries now belong to the cache (this avoids cloning
// of those entries).
//
// This method should be called with the state lock held.
func (s *utxoCache) commit(view *UtxoViewpoint) error {
	for outpoint, entry := range view.Entries() {
		// No need to update the cache if the entry was not modified.
		if entry == nil || !entry.isModified() {
			continue
		}

		if entry.IsSpent() {
			err := s.spendEntry(outpoint, entry)
			if err != nil {
				return err
			}
		} else {
			s.addEntry(outpoint, entry)
		}
	}

	// This marks the old map to be garbage collected.
	view.entries = make(map[wire.OutPoint]*UtxoEntry)

	return nil
}

// flush flushes the UTXO state to the database.
//
// This method should be called with the state lock held.
func (s *utxoCache) flush(bestState *BestState) error {
	// If we performed a flush in the current best state, we have nothing to do.
	if bestState.Hash == s.lastFlushHash {
		return nil
	}

	// Add one to round up the integer division.
	totalMiB := s.totalMemoryUsage() / ((1024 * 1024) + 1)

	log.Infof("Flushing UTXO cache of %d MiB with %d entries to disk. For large sizes, "+
		"this can take up to several minutes...", totalMiB, s.cachedEntries.length())

	// Flush the database so that the pending bucket write for the utxo state consistency
	// gets written.  This ensures that we correctly mark the state as inconsistent.
	err := s.db.Flush()
	if err != nil {
		return err
	}

	// Update commits and flushes the cache to the database.
	// NOTE: The database has its own cache which gets atomically written
	// to leveldb.
	err = s.db.Update(func(dbTx database.Tx) error {
		for i := range s.cachedEntries.maps {
			for outpoint, entry := range s.cachedEntries.maps[i] {
				// No need to update the cache if the entry is nil.  This
				// means that it's been created and spent before the database
				// saw it.
				if entry == nil {
					//delete(s.cachedEntries.maps[i], outpoint)
					continue
				}

				// No need to update the cache if the entry was not modified.
				if !entry.isModified() {
					continue
				}

				// If the entry is spent, remove the entry from the database
				// and the cache.
				if entry.IsSpent() {
					err = dbDeleteUtxoEntry(dbTx, outpoint)
					if err != nil {
						return err
					}

					//s.totalEntryMemory -= entry.memoryUsage()
					//delete(s.cachedEntries.maps[i], outpoint)

					continue
				}

				err = dbPutUtxoEntry(dbTx, outpoint, entry)
				if err != nil {
					return err
				}

				//if entry.BlockHeight() < evictHeight {
				//	//s.totalEntryMemory -= entry.memoryUsage()
				//	//delete(s.cachedEntries.maps[i], outpoint)
				//	continue
				//}

				//// Clear the modified and fresh flags since it has been updated
				//// in the database.
				//entry.packedFlags &^= tfModified
				//entry.packedFlags &^= tfFresh
			}

			// Set map to nil after we're done with it so it can be garbage collected.
			s.cachedEntries.maps[i] = nil
		}
		s.cachedEntries.deleteMaps()
		s.totalEntryMemory = 0

		// When done, store the best state hash in the database to indicate the state
		// is consistent until that hash.
		return dbPutUtxoStateConsistency(dbTx, ucsConsistent, &bestState.Hash)
	})
	if err != nil {
		return err
	}

	// The best state is the new last flush hash.
	s.lastFlushHash = bestState.Hash
	s.lastFlushTime = time.Now()

	log.Debug("Done flushing UTXO cache to disk")
	return nil
}

// Flush flushes the UTXO state to the database.
//
// This function is safe for concurrent access.
func (s *utxoCache) Flush(mode FlushMode, bestState *BestState) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	var threshold uint64
	switch mode {
	case FlushRequired:
		threshold = 0

	case FlushIfNeeded:
		threshold = s.maxTotalMemoryUsage

	case FlushPeriodic:
		// If the time since the last flush is over the periodic interval,
		// force a flush.  Otherwise just flush when the cache is full.
		if time.Since(s.lastFlushTime) > utxoFlushPeriodicInterval {
			threshold = 0
		} else {
			threshold = s.maxTotalMemoryUsage
		}
	}

	if s.totalMemoryUsage() >= threshold {
		return s.flush(bestState)
	}
	return nil
}

// InitConsistentState checks the consistency status of the utxo state and
// replays blocks if it lags behind the best state of the blockchain.
//
// It needs to be ensured that the chainView passed to this method does not
// get changed during the execution of this method.
func (b *BlockChain) InitConsistentState(tip *blockNode, interrupt <-chan struct{}) error {
	s := b.utxoCache
	// Load the consistency status from the database.
	var statusCode byte
	var statusHash *chainhash.Hash
	err := s.db.View(func(dbTx database.Tx) error {
		var err error
		statusCode, statusHash, err = dbFetchUtxoStateConsistency(dbTx)

		return err
	})
	if err != nil {
		return err
	}

	log.Debugf("UTXO cache consistency status from disk: [%d] hash %v",
		statusCode, statusHash)

	// If no status was found, the database is old and didn't have a cached utxo
	// state yet. In that case, we set the status to the best state and write
	// this to the database.
	if statusCode == ucsEmpty {
		log.Debugf("Database didn't specify UTXO state consistency: consistent "+
			"to best chain tip (%v)", tip.hash)
		err := s.db.Update(func(dbTx database.Tx) error {
			return dbPutUtxoStateConsistency(dbTx, ucsConsistent, &tip.hash)
		})

		// Set the last flush hash as it's the default value of 0s.
		s.lastFlushHash = tip.hash

		return err
	}

	// If state is consistent, we are done.
	if statusCode == ucsConsistent && *statusHash == tip.hash {
		log.Debugf("UTXO state consistent (%d:%v)", tip.height, tip.hash)

		// The last flush hash is set to the default value of all 0s. Set
		// it to the tip since we checked it's consistent.
		s.lastFlushHash = tip.hash

		return nil
	}

	log.Info("Reconstructing UTXO state after unclean shutdown. This may take " +
		"a long time...")

	lastFlushNode := b.index.LookupNode(statusHash)
	fork := b.bestChain.FindFork(lastFlushNode)

	// Even though this should always be true, make sure the fetched hash is in
	// the best chain.
	if fork == nil {
		return AssertError(fmt.Sprintf("last utxo consistency status contains "+
			"hash that is not in best chain: %v", statusHash))
	}

	// We only roll back blocks if the node was disconnecting blocks when it suddenly
	// shut down.
	log.Infof("Rolling back %d blocks to rebuild the UTXO state...",
		lastFlushNode.height-fork.height)

	node := lastFlushNode
	view := NewUtxoViewpoint()
	for node != nil && node != fork {
		var block *btcutil.Block
		var stxos []SpentTxOut
		err = s.db.Update(func(dbTx database.Tx) error {
			block, err = dbFetchBlockByNode(dbTx, node)
			if err != nil {
				return err
			}

			stxos, err = dbFetchSpendJournalEntry(dbTx, block)
			if err != nil {
				return err
			}

			return nil
		})
		if err != nil {
			return err
		}

		err = view.fetchInputUtxos(b.utxoCache, block)
		if err != nil {
			return err
		}

		err = view.disconnectTransactions(b.utxoCache, block, stxos)
		if err != nil {
			return err
		}

		err = b.utxoCache.commit(view)
		if err != nil {
			return err
		}

		view.commit()

		node = node.parent

		// Flush the utxo cache if needed.
		if s.totalMemoryUsage() >= s.maxTotalMemoryUsage {
			err = s.flush(&BestState{Hash: node.hash, Height: node.height})
			if err != nil {
				return err
			}
			s.cachedEntries.deleteMaps()
			s.totalEntryMemory = 0
		}

		if interruptRequested(interrupt) {
			log.Warn("UTXO state reconstruction interrupted")

			return errInterruptRequested
		}
	}

	log.Infof("Replaying %d blocks to rebuild UTXO state...",
		tip.height-node.height+1)

	// Then we replay the blocks from the last consistent state up to the best
	// state. Iterate forward from the consistent node to the tip of the best
	// chain. After every batch, we can also update the consistency state to
	// avoid redoing the work when interrupted.
	attachNodes := list.New()
	for n := tip; n.height >= 0; n = n.parent {
		if n == fork {
			break
		}
		attachNodes.PushFront(n)
	}

	for e := attachNodes.Front(); e != nil; e = e.Next() {
		node = e.Value.(*blockNode)

		var block *btcutil.Block
		err := s.db.View(func(dbTx database.Tx) error {
			block, err = dbFetchBlockByNode(dbTx, node)
			if err != nil {
				return err
			}

			return err
		})
		if err != nil {
			return err
		}

		err = view.fetchInputUtxos(b.utxoCache, block)
		if err != nil {
			return err
		}

		err = view.connectTransactions(block, nil)
		if err != nil {
			return err
		}

		err = b.utxoCache.commit(view)
		if err != nil {
			return err
		}

		view.commit()

		// Flush the utxo cache if needed.
		if s.totalMemoryUsage() >= s.maxTotalMemoryUsage {
			err = s.flush(&BestState{Hash: node.hash, Height: node.height})
			if err != nil {
				return err
			}
			s.cachedEntries.deleteMaps()
			s.totalEntryMemory = 0
		}

		if interruptRequested(interrupt) {
			log.Warn("UTXO state reconstruction interrupted")

			return errInterruptRequested
		}
	}
	log.Debug("UTXO state reconstruction done")

	// Set the last flush hash as it's the default value of 0s.
	s.lastFlushHash = tip.hash

	s.lastFlushTime = time.Now()

	return nil
}
