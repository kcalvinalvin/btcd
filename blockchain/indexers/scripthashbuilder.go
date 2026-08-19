// Copyright (c) 2024 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcd/txscript/v2"
)

const (
	// scriptHashIndexDirName is the subdirectory of the data dir that holds
	// the script hash build staging files.
	scriptHashIndexDirName = "scripthashindex"

	// scriptHashLen is the length of a script hash, a sha256 of a pkScript.
	scriptHashLen = chainhash.HashSize

	// scriptHashRecordSize is the size of a spilled record: the script hash
	// followed by the address key it maps to.
	scriptHashRecordSize = scriptHashLen + addrKeySize

	// scriptHashManifestVersion is the version of the scan checkpoint manifest.
	scriptHashManifestVersion = 1

	// numSpillShards is the number of staging shards records are partitioned
	// into during a build, keyed by the top byte of the script hash.  Keeping
	// it at 256 makes a shard exactly one top-byte value, so processing shards
	// in order yields globally ascending script hashes.
	numSpillShards = 256

	// scriptHashScanChunkSize is the number of contiguous block heights scanned
	// between checkpoints.  After each chunk the spilled records are synced and
	// a manifest records the height reached so an interrupted build resumes
	// from there rather than restarting.
	scriptHashScanChunkSize = 50000

	// scriptHashManifestName is the file in the staging directory that records
	// the highest checkpointed scan height.
	scriptHashManifestName = "manifest"

	// scriptHashProgressInterval is how often scan progress is logged.
	scriptHashProgressInterval = 15 * time.Second
)

// scriptHashManifestMagic identifies the scan checkpoint manifest.
var scriptHashManifestMagic = [4]byte{'s', 'h', 's', 'c'}

// scriptHashPair is a single script hash to address key mapping.
type scriptHashPair struct {
	scriptHash chainhash.Hash
	addrKey    [addrKeySize]byte
}

// scriptHashEntry derives the script hash and address key for a pkScript.  The
// bool is false for scripts the index does not map: non-standard scripts, bare
// multisig (more than one address), and address types the address index does
// not support.  This mirrors the inclusion rule in ConnectBlock so the bulk
// build and the incremental path index exactly the same set.
func scriptHashEntry(pkScript []byte,
	chainParams *chaincfg.Params) (chainhash.Hash, [addrKeySize]byte, bool) {

	var addrKey [addrKeySize]byte
	scriptHash := chainhash.HashH(pkScript)

	_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript, chainParams)
	if err != nil || len(addrs) != 1 {
		return scriptHash, addrKey, false
	}

	addrKey, err = addrToKey(addrs[0])
	if err != nil {
		return scriptHash, addrKey, false
	}
	return scriptHash, addrKey, true
}

// spillShard is one staging file that records are appended to during a build.
type spillShard struct {
	mu  sync.Mutex
	f   *os.File
	buf *bufio.Writer
	rec [scriptHashRecordSize]byte
}

// scriptHashSpiller partitions script hash records into staging shards keyed by
// the top byte of the script hash, then merges them into a sorted table.  Its
// add method is safe for concurrent use across shards.
type scriptHashSpiller struct {
	dir    string
	shards [numSpillShards]spillShard
}

// newScriptHashSpiller creates a spiller with a staging file per shard in dir.
func newScriptHashSpiller(dir string) (*scriptHashSpiller, error) {
	s := &scriptHashSpiller{dir: dir}
	for i := range s.shards {
		path := filepath.Join(dir, fmt.Sprintf("shard-%03d.tmp", i))
		f, err := os.Create(path)
		if err != nil {
			s.closeShards()
			return nil, err
		}
		s.shards[i].f = f
		s.shards[i].buf = bufio.NewWriterSize(f, 64*1024)
	}
	return s, nil
}

// openScriptHashSpiller reopens the staging shards of an interrupted build for
// appending.  Each shard is truncated to a whole number of records so a torn
// trailing record from an interrupted write is dropped.
func openScriptHashSpiller(dir string) (*scriptHashSpiller, error) {
	s := &scriptHashSpiller{dir: dir}
	for i := range s.shards {
		path := filepath.Join(dir, fmt.Sprintf("shard-%03d.tmp", i))
		f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0666)
		if err != nil {
			s.closeShards()
			return nil, err
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			s.closeShards()
			return nil, err
		}
		if rem := info.Size() % scriptHashRecordSize; rem != 0 {
			if err := f.Truncate(info.Size() - rem); err != nil {
				f.Close()
				s.closeShards()
				return nil, err
			}
		}
		s.shards[i].f = f
		s.shards[i].buf = bufio.NewWriterSize(f, 64*1024)
	}
	return s, nil
}

// sync flushes and fsyncs every shard so the records written so far are durable
// before a checkpoint manifest referring to them is written.
func (s *scriptHashSpiller) sync() error {
	for i := range s.shards {
		if err := s.shards[i].buf.Flush(); err != nil {
			return err
		}
		if err := s.shards[i].f.Sync(); err != nil {
			return err
		}
	}
	return nil
}

// writeScriptHashManifest atomically records the highest checkpointed scan
// height in the staging directory.
func writeScriptHashManifest(stagingDir string, height int32) error {
	var buf [9]byte
	copy(buf[0:4], scriptHashManifestMagic[:])
	buf[4] = scriptHashManifestVersion
	byteOrder.PutUint32(buf[5:9], uint32(height))

	tmpPath := filepath.Join(stagingDir, scriptHashManifestName+".tmp")
	f, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	if _, err := f.Write(buf[:]); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, filepath.Join(stagingDir, scriptHashManifestName))
}

// readScriptHashManifest returns the checkpointed scan height, and whether a
// valid manifest was present.
func readScriptHashManifest(stagingDir string) (int32, bool) {
	data, err := os.ReadFile(filepath.Join(stagingDir, scriptHashManifestName))
	if err != nil || len(data) != 9 {
		return 0, false
	}
	if !bytes.Equal(data[0:4], scriptHashManifestMagic[:]) ||
		data[4] != scriptHashManifestVersion {
		return 0, false
	}
	return int32(byteOrder.Uint32(data[5:9])), true
}

// add appends a record to the shard for its script hash.
func (s *scriptHashSpiller) add(scriptHash *chainhash.Hash, addrKey *[addrKeySize]byte) error {
	sh := &s.shards[scriptHash[0]]
	sh.mu.Lock()
	defer sh.mu.Unlock()

	copy(sh.rec[:scriptHashLen], scriptHash[:])
	copy(sh.rec[scriptHashLen:], addrKey[:])
	_, err := sh.buf.Write(sh.rec[:])
	return err
}

// bucketBatchSize is the number of entries written per database transaction
// when building the script hash index into the main database.  It is a variable
// rather than a constant so tests can force many small batches.
var bucketBatchSize = 500000

// writeToDB sorts and deduplicates each shard and streams the pairs into the
// script hash index bucket in batched transactions.  Shards are written in
// prefix order and each shard is sorted, so the database receives ascending
// keys and the bucket handle is resolved once per batch instead of per entry.
func (s *scriptHashSpiller) writeToDB(db database.DB) error {
	for i := range s.shards {
		if err := s.shards[i].buf.Flush(); err != nil {
			return err
		}
	}

	batch := make([]scriptHashPair, 0, bucketBatchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		err := db.Update(func(dbTx database.Tx) error {
			bucket := dbTx.Metadata().Bucket(scriptHashIndexKey)
			for j := range batch {
				err := bucket.Put(batch[j].scriptHash[:], batch[j].addrKey[:])
				if err != nil {
					return err
				}
			}
			return nil
		})

		// The database retains the address key value slices passed to Put by
		// reference until its cache flushes to disk, and those slices point into
		// the batch backing array.  A fresh backing array is allocated for the
		// next batch so the committed values are not overwritten before the
		// cache flush copies them.
		batch = make([]scriptHashPair, 0, bucketBatchSize)
		return err
	}

	var (
		prev     chainhash.Hash
		havePrev bool
	)
	for i := range s.shards {
		pairs, err := readSpillShard(s.shards[i].f)
		if err != nil {
			return err
		}
		sort.Slice(pairs, func(a, b int) bool {
			return bytes.Compare(pairs[a].scriptHash[:], pairs[b].scriptHash[:]) < 0
		})
		for j := range pairs {
			if havePrev && pairs[j].scriptHash == prev {
				continue
			}
			prev = pairs[j].scriptHash
			havePrev = true

			batch = append(batch, pairs[j])
			if len(batch) >= bucketBatchSize {
				if err := flush(); err != nil {
					return err
				}
			}
		}
	}
	return flush()
}

// closeShards closes all open shard files.
func (s *scriptHashSpiller) closeShards() {
	for i := range s.shards {
		if s.shards[i].f != nil {
			s.shards[i].f.Close()
		}
	}
}

// cleanup closes the shard files and removes the staging directory.
func (s *scriptHashSpiller) cleanup() {
	s.closeShards()
	os.RemoveAll(s.dir)
}

// readSpillShard reads all records from a staging shard file into memory.
func readSpillShard(f *os.File) ([]scriptHashPair, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	if len(data)%scriptHashRecordSize != 0 {
		return nil, fmt.Errorf("script hash spill shard has a truncated record")
	}

	pairs := make([]scriptHashPair, len(data)/scriptHashRecordSize)
	for i := range pairs {
		off := i * scriptHashRecordSize
		copy(pairs[i].scriptHash[:], data[off:off+scriptHashLen])
		copy(pairs[i].addrKey[:], data[off+scriptHashLen:off+scriptHashRecordSize])
	}
	return pairs, nil
}

// scanHeightRange scans the block heights in [start, end] with a pool of
// workers, spilling the derived pairs, and increments scanned for every block
// processed.  Reads are done through read-only views, which is safe to do
// concurrently.
func scanHeightRange(chain *blockchain.BlockChain, chainParams *chaincfg.Params,
	spiller *scriptHashSpiller, start, end int32, numWorkers int,
	scanned *int64, interrupt <-chan struct{}) error {

	heights := make(chan int32, numWorkers*4)
	var (
		wg       sync.WaitGroup
		errOnce  sync.Once
		firstErr error
		stop     = make(chan struct{})
	)
	fail := func(e error) {
		errOnce.Do(func() {
			firstErr = e
			close(stop)
		})
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for height := range heights {
				block, err := chain.BlockByHeight(height)
				if err != nil {
					fail(err)
					return
				}
				for _, tx := range block.Transactions() {
					for _, txOut := range tx.MsgTx().TxOut {
						scriptHash, addrKey, ok := scriptHashEntry(
							txOut.PkScript, chainParams)
						if !ok {
							continue
						}
						if err := spiller.add(&scriptHash, &addrKey); err != nil {
							fail(err)
							return
						}
					}
				}
				atomic.AddInt64(scanned, 1)
			}
		}()
	}

feed:
	for height := start; height <= end; height++ {
		select {
		case <-stop:
			break feed
		case <-interrupt:
			fail(errInterruptRequested)
			break feed
		case heights <- height:
		}
	}
	close(heights)
	wg.Wait()
	return firstErr
}

// buildScriptHashPairs scans every block up to the current best height in
// parallel, deriving the script hash to address key mapping for each output and
// spilling the pairs into prefix shards.  It returns the populated spiller,
// which the caller is responsible for cleaning up, along with the height and
// hash it scanned to.
//
// The scan proceeds in chunks and checkpoints its progress after each one, so
// an interrupted build resumes from the last checkpoint rather than restarting.
// It is meant to run during index initialization, while the chain is quiescent
// and no blocks are being connected.  Any blocks that arrive after the target
// height is read are connected by the manager's per-block catchup afterwards.
func buildScriptHashPairs(chain *blockchain.BlockChain,
	chainParams *chaincfg.Params, dataDir string, numWorkers int,
	interrupt <-chan struct{}) (*scriptHashSpiller, chainhash.Hash, int32, error) {

	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}

	best := chain.BestSnapshot()
	targetHeight := best.Height
	targetHash := best.Hash

	stagingDir := filepath.Join(dataDir, scriptHashIndexDirName, "staging")
	if err := os.MkdirAll(stagingDir, 0700); err != nil {
		return nil, chainhash.Hash{}, 0, err
	}

	// Resume from a prior checkpoint if the staging directory holds one,
	// otherwise start a fresh scan.  A staging directory that cannot be
	// reopened is discarded and rebuilt from scratch.
	var (
		spiller     *scriptHashSpiller
		startHeight int32
		err         error
	)
	if completed, ok := readScriptHashManifest(stagingDir); ok {
		spiller, err = openScriptHashSpiller(stagingDir)
		if err != nil {
			log.Warnf("Cannot resume script hash scan (%v); starting over", err)
			os.RemoveAll(stagingDir)
			if err := os.MkdirAll(stagingDir, 0700); err != nil {
				return nil, chainhash.Hash{}, 0, err
			}
			spiller, err = newScriptHashSpiller(stagingDir)
			if err != nil {
				return nil, chainhash.Hash{}, 0, err
			}
			startHeight = 1
		} else {
			startHeight = completed + 1
			log.Infof("Resuming script hash scan from height %d of %d",
				startHeight, targetHeight)
		}
	} else {
		spiller, err = newScriptHashSpiller(stagingDir)
		if err != nil {
			return nil, chainhash.Hash{}, 0, err
		}
		startHeight = 1
	}

	// The scan already reached the tip on a previous run; leave the write to
	// the caller.
	if startHeight > targetHeight {
		return spiller, targetHash, targetHeight, nil
	}

	log.Infof("Scanning blocks %d to %d for script hashes using %d workers",
		startHeight, targetHeight, numWorkers)

	// Log progress periodically off a shared counter the workers advance.
	scanned := int64(startHeight - 1)
	progressDone := make(chan struct{})
	var progressWg sync.WaitGroup
	progressWg.Add(1)
	go func() {
		defer progressWg.Done()
		ticker := time.NewTicker(scriptHashProgressInterval)
		defer ticker.Stop()
		for {
			select {
			case <-progressDone:
				return
			case <-ticker.C:
				n := atomic.LoadInt64(&scanned)
				log.Infof("Script hash scan: %d/%d blocks (%.1f%%)", n,
					targetHeight, float64(n)/float64(targetHeight)*100)
			}
		}
	}()

	// Scan in chunks, checkpointing after each so the build can resume.
	var scanErr error
	for chunkStart := startHeight; chunkStart <= targetHeight; chunkStart += scriptHashScanChunkSize {
		chunkEnd := chunkStart + scriptHashScanChunkSize - 1
		if chunkEnd > targetHeight {
			chunkEnd = targetHeight
		}

		scanErr = scanHeightRange(chain, chainParams, spiller, chunkStart,
			chunkEnd, numWorkers, &scanned, interrupt)
		if scanErr != nil {
			break
		}
		if scanErr = spiller.sync(); scanErr != nil {
			break
		}
		if scanErr = writeScriptHashManifest(stagingDir, chunkEnd); scanErr != nil {
			break
		}
		log.Debugf("Checkpointed script hash scan at height %d", chunkEnd)
	}

	close(progressDone)
	progressWg.Wait()

	if scanErr != nil {
		// Keep the staging directory so the scan can resume, but release the
		// file handles.
		spiller.closeShards()
		return nil, chainhash.Hash{}, 0, scanErr
	}

	return spiller, targetHash, targetHeight, nil
}

// buildScriptHashBucketFromChain builds the script hash index into the script
// hash index bucket of the main database.  It returns the height and hash it
// was built to.
func buildScriptHashBucketFromChain(chain *blockchain.BlockChain, db database.DB,
	chainParams *chaincfg.Params, dataDir string, numWorkers int,
	interrupt <-chan struct{}) (chainhash.Hash, int32, error) {

	spiller, targetHash, targetHeight, err := buildScriptHashPairs(chain,
		chainParams, dataDir, numWorkers, interrupt)
	if err != nil {
		return chainhash.Hash{}, 0, err
	}

	log.Infof("Writing script hash index into the database")
	if err := spiller.writeToDB(db); err != nil {
		// Keep the completed scan staged so a retry skips straight to the
		// write rather than rescanning.
		spiller.closeShards()
		return chainhash.Hash{}, 0, err
	}

	spiller.cleanup()
	log.Infof("Built script hash index into the database at height %d (%s)",
		targetHeight, targetHash)
	return targetHash, targetHeight, nil
}
