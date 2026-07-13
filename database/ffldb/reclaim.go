// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ffldb

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/database"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

const (
	// reclaimBatchSize is the maximum number of stale keys deleted in a
	// single leveldb batch while reclaiming the space of dropped buckets.
	reclaimBatchSize = 65536

	// reclaimLogInterval is the number of reclaim batches between progress
	// log messages.
	reclaimLogInterval = 512
)

// reclaimKeyPrefix is the prefix of the internal keys that track buckets
// which have been dropped but whose keys have not been removed from the
// underlying database yet.
//
// The serialized format of a reclaim record is:
//
//	<reclaimkeyprefix><bucketid> = <resumekey>
//
// where resumekey is the key the reclaim resumes iterating from.  Keys under
// the bucket ID that sort before the resume key have already been deleted.
var reclaimKeyPrefix = []byte("ffldb-reclaim-")

// reclaimRecordKey returns the internal key that tracks reclamation of the
// keys under the provided bucket ID.
func reclaimRecordKey(bucketID []byte) []byte {
	recordKey := make([]byte, len(reclaimKeyPrefix)+len(bucketID))
	copy(recordKey, reclaimKeyPrefix)
	copy(recordKey[len(reclaimKeyPrefix):], bucketID)
	return recordKey
}

// DropBucket removes the bucket named by bucketPath along with its nested
// buckets and all of their keys.  Each bucketPath element names one nested
// bucket from the metadata root.  Instead of deleting each key, it unlinks
// the buckets from the bucket index and writes a reclaim record for each of
// their bucket IDs.  Bucket IDs are never reused, so the keys under the
// unlinked IDs are unreachable as soon as the unlink commits, and the
// background reclaim deletes them from the underlying database over time.
//
// This function is part of the optional database.BucketDropper interface
// implementation.
func (db *db) DropBucket(bucketPath [][]byte) error {
	if len(bucketPath) == 0 {
		str := "drop bucket requires a bucket path"
		return makeDbErr(database.ErrBucketNameRequired, str, nil)
	}

	tx, err := db.begin(true)
	if err != nil {
		return err
	}
	defer rollbackOnPanic(tx)

	// Resolve the parent bucket of the bucket being dropped.
	parent := tx.metaBucket
	for _, bucketName := range bucketPath[:len(bucketPath)-1] {
		childBucket := parent.Bucket(bucketName)
		if childBucket == nil {
			_ = tx.Rollback()
			str := fmt.Sprintf("bucket %q does not exist", bucketName)
			return makeDbErr(database.ErrBucketNotFound, str, nil)
		}
		parent = childBucket.(*bucket)
	}

	dropName := bucketPath[len(bucketPath)-1]
	bidxKey := bucketIndexKey(parent.id, dropName)
	dropID := tx.fetchKey(bidxKey)
	if dropID == nil {
		_ = tx.Rollback()
		str := fmt.Sprintf("bucket %q does not exist", dropName)
		return makeDbErr(database.ErrBucketNotFound, str, nil)
	}
	dropID = copySlice(dropID)

	// Unlink all nested buckets from the bucket index, collecting the IDs
	// of every bucket in the subtree.
	staleIDs := [][]byte{dropID}
	for stack := [][]byte{dropID}; len(stack) > 0; {
		childID := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		bucketCursor := newCursor(parent, childID, ctBuckets)
		for ok := bucketCursor.First(); ok; ok = bucketCursor.Next() {
			nestedID := bucketCursor.rawValue()
			staleIDs = append(staleIDs, nestedID)
			stack = append(stack, nestedID)
			tx.deleteKey(bucketCursor.rawKey(), false)
		}
		cursorFinalizer(bucketCursor)
	}

	// Unlink the dropped bucket itself.
	tx.deleteKey(bidxKey, true)

	// Write a reclaim record for each unlinked bucket ID.  The record
	// value is the key the reclaim resumes from, which starts at the
	// beginning of the bucket ID's key range.
	for _, staleID := range staleIDs {
		if err := tx.putKey(reclaimRecordKey(staleID), staleID); err != nil {
			_ = tx.Rollback()
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	// Flush the cache so the unlink, the reclaim records, and any cached
	// writes to the dropped buckets reach the underlying database before
	// the background reclaim deletes keys from it directly.  Without this,
	// a later cache flush could write stale cached entries back under a
	// bucket ID the reclaim already swept.  The write lock serializes this
	// flush with the flushes triggered by transaction commits.
	db.writeLock.Lock()
	err = db.cache.flush()
	db.writeLock.Unlock()
	if err != nil {
		return err
	}

	// Wake the background reclaim.
	select {
	case db.reclaimWake <- struct{}{}:
	default:
	}
	return nil
}

// reclaimLoop runs in its own goroutine and deletes the keys of dropped
// buckets from the underlying database.  It wakes up whenever DropBucket
// writes new reclaim records and exits when the database is closed.  Progress
// is persisted along the way, so any work that remains when the database
// closes resumes the next time the database is opened.
func (db *db) reclaimLoop() {
	defer db.reclaimWg.Done()

	for {
		// Sweep reclaim records until none remain.
		for {
			select {
			case <-db.reclaimQuit:
				return
			default:
			}

			found, err := db.reclaimNext()
			if err != nil {
				log.Errorf("Unable to reclaim dropped bucket "+
					"space: %v", err)
				break
			}
			if !found {
				break
			}
		}

		select {
		case <-db.reclaimWake:
		case <-db.reclaimQuit:
			return
		}
	}
}

// reclaimNext finds the first reclaim record and deletes the keys that remain
// under its bucket ID from the underlying database in bounded batches.  Each
// batch atomically updates the record's resume key, and the record itself is
// deleted along with the final batch, so an interrupted reclaim picks up
// where it left off.  It returns whether a record was found.
//
// The keys are deleted directly from the underlying database rather than
// through a database transaction.  This is safe because a reclaim record only
// becomes visible here through a cache flush, which also wrote any cached
// entries for the dropped bucket, and no new entries can be created under its
// bucket ID since the bucket is no longer linked in the bucket index.
func (db *db) reclaimNext() (bool, error) {
	// Load the first reclaim record along with the key its sweep resumes
	// from.
	ldb := db.cache.ldb
	recordIter := ldb.NewIterator(util.BytesPrefix(reclaimKeyPrefix), nil)
	found := recordIter.Next()
	var recordKey, resumeKey []byte
	if found {
		recordKey = copySlice(recordIter.Key())
		resumeKey = copySlice(recordIter.Value())
	}
	recordIter.Release()
	if err := recordIter.Error(); err != nil {
		return found, convertErr("failed to load reclaim record", err)
	}
	if !found {
		return false, nil
	}

	// Discard a malformed record rather than let it send the sweep into
	// other buckets' key ranges.
	bucketID := recordKey[len(reclaimKeyPrefix):]
	if len(bucketID) != 4 {
		log.Errorf("Discarding malformed reclaim record %q", recordKey)
		if err := ldb.Delete(recordKey, nil); err != nil {
			return true, convertErr("failed to delete malformed "+
				"reclaim record", err)
		}
		return true, nil
	}

	// Never resume from before the start of the bucket's key range.
	if bytes.Compare(resumeKey, bucketID) < 0 {
		resumeKey = bucketID
	}

	keyLimit := util.BytesPrefix(bucketID).Limit
	log.Infof("Reclaiming disk space from dropped bucket %x", bucketID)

	var totalDeleted uint64
	for numBatches := 1; ; numBatches++ {
		// Collect up to one batch of keys to delete, remembering the
		// last collected key so the sweep can resume from it.  The
		// resume key itself is always already deleted, so starting the
		// iterator at it lands on the next remaining key.
		batch := new(leveldb.Batch)
		numDeleted := 0
		keyRange := &util.Range{Start: resumeKey, Limit: keyLimit}
		keyIter := ldb.NewIterator(keyRange, nil)
		for numDeleted < reclaimBatchSize && keyIter.Next() {
			key := keyIter.Key()
			batch.Delete(key)
			numDeleted++
			if numDeleted == reclaimBatchSize {
				resumeKey = copySlice(key)
			}
		}
		keyIter.Release()
		if err := keyIter.Error(); err != nil {
			return true, convertErr("failed to iterate dropped "+
				"bucket keys", err)
		}

		// Delete the reclaim record along with the final batch.  Until
		// then, persist the resume key with each batch instead.
		done := numDeleted < reclaimBatchSize
		if done {
			batch.Delete(recordKey)
		} else {
			batch.Put(recordKey, resumeKey)
		}
		if err := ldb.Write(batch, nil); err != nil {
			return true, convertErr("failed to delete dropped "+
				"bucket keys", err)
		}

		totalDeleted += uint64(numDeleted)
		if done {
			log.Infof("Reclaimed %d keys from dropped bucket %x",
				totalDeleted, bucketID)
			return true, nil
		}
		if numBatches%reclaimLogInterval == 0 {
			log.Infof("Reclaimed %d keys so far from dropped "+
				"bucket %x", totalDeleted, bucketID)
		}

		// Stop when the database is closing.  The resume key persisted
		// with the last batch carries the sweep across the restart.
		select {
		case <-db.reclaimQuit:
			return true, nil
		default:
		}
	}
}
