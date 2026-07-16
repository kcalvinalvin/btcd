// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"bufio"
	"bytes"
	"container/heap"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcd/wire/v2"
)

const (
	// addrRecordMaxSize is the address key followed by three maximum-size
	// uint64 varints.
	addrRecordMaxSize = addrKeySize + 3*wire.MaxVarIntPayload

	// addrVarIntScratchSize is the largest scratch buffer required by the wire
	// varint helpers.  The nine-byte encoding writes its one-byte discriminant
	// separately, then reuses the buffer for the eight-byte payload.
	addrVarIntScratchSize = wire.MaxVarIntPayload - 1

	// addrBuildManifestVersion is the version of the address build manifest.
	addrBuildManifestVersion = 1

	// numAddrStagingShards is the number of shards used to stage records during
	// a build.  The first byte of the address hash160 selects the shard.  That
	// byte is uniformly distributed for hashed address types, so records spread
	// evenly while every entry for an address remains in the same shard.
	numAddrStagingShards = 256

	// addrBuildManifestName is the file in the staging directory that records
	// scan progress, the block being targeted, and the number of shards written
	// to the database.
	addrBuildManifestName = "manifest"

	// addrBuildWriteBatchBytes is the approximate number of value bytes buffered
	// before a database transaction is committed during the write phase.  It
	// bounds the memory a single transaction holds since address index values
	// vary widely in size.
	addrBuildWriteBatchBytes = 32 * 1024 * 1024

	// addrBuildSortMemoryBytes is the approximate combined memory limit for
	// in-memory runs being sorted concurrently.
	addrBuildSortMemoryBytes = 256 * 1024 * 1024

	// addrBuildSortMaxWorkers limits concurrent shard sorts to avoid excessive
	// contention between their staging file reads and run writes.
	addrBuildSortMaxWorkers = 8

	// addrBuildSortMergeFanIn limits the number of runs merged in one pass.
	// Larger shards use additional passes instead of opening every run at once.
	addrBuildSortMergeFanIn = 96

	// addrBuildSortMaxMergeFiles bounds the aggregate files opened by concurrent
	// run merges, leaving headroom for LevelDB and block file descriptors.
	addrBuildSortMaxMergeFiles = 256

	// addrBuildProgressInterval is how often build progress is logged.
	addrBuildProgressInterval = 15 * time.Second

	// addrStagingInterruptCheckRecords is the number of staged records processed
	// between interrupt checks during long-running staging operations.
	addrStagingInterruptCheckRecords = 65536
)

// addrBuildManifestMagic identifies a serialized address index build manifest.
var addrBuildManifestMagic = [4]byte{'a', 'd', 'r', 'b'}

// addrBuildInterruptRequested returns whether any of the provided interrupt
// channels has been closed.
func addrBuildInterruptRequested(interrupts ...<-chan struct{}) bool {
	for _, interrupt := range interrupts {
		if interruptRequested(interrupt) {
			return true
		}
	}
	return false
}

// addrRecord is a single address index entry keyed by the address it maps to.
type addrRecord struct {
	addrKey [addrKeySize]byte
	blockID uint64
	txStart uint64
	txLen   uint64
}

// addrRecords implements sort.Interface for address records.
type addrRecords []addrRecord

func (r addrRecords) Len() int           { return len(r) }
func (r addrRecords) Less(i, j int) bool { return r[i].less(&r[j]) }
func (r addrRecords) Swap(i, j int)      { r[i], r[j] = r[j], r[i] }

// addrRecordMergeItem holds the next unmerged record from one sorted run and
// identifies the run to advance after the record is emitted.
type addrRecordMergeItem struct {
	// record is the next unmerged record from the source run.
	record addrRecord

	// run is the source run's index in the active merge.
	run int
}

// addrRecordMergeHeap implements heap.Interface as a min-heap whose root is the
// next record to emit during a k-way merge.
type addrRecordMergeHeap []addrRecordMergeItem

func (h addrRecordMergeHeap) Len() int { return len(h) }
func (h addrRecordMergeHeap) Less(i, j int) bool {
	return h[i].record.less(&h[j].record)
}
func (h addrRecordMergeHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *addrRecordMergeHeap) Push(value any) {
	*h = append(*h, value.(addrRecordMergeItem))
}
func (h *addrRecordMergeHeap) Pop() any {
	old := *h
	last := len(old) - 1
	item := old[last]
	*h = old[:last]
	return item
}

// addrMergeFileLimiter atomically reserves file descriptors for a complete
// merge so concurrent workers cannot deadlock while each holds a partial set.
type addrMergeFileLimiter struct {
	// mu protects open and changed.
	mu sync.Mutex

	// maxFiles is the maximum number of merge file descriptors reserved at once.
	maxFiles int

	// open is the number of file descriptors currently reserved.
	open int

	// changed is closed and replaced when descriptors are released so blocked
	// reservations wake and retry.
	changed chan struct{}
}

// newAddrMergeFileLimiter returns a limiter with capacity for maxFiles merge
// file descriptors.
func newAddrMergeFileLimiter(maxFiles int) *addrMergeFileLimiter {
	return &addrMergeFileLimiter{
		maxFiles: maxFiles,
		changed:  make(chan struct{}),
	}
}

// acquire reserves all numFiles descriptors as one unit, waiting until they
// are available or either cancellation channel is closed.
func (l *addrMergeFileLimiter) acquire(numFiles int, interrupt,
	stop <-chan struct{}) error {

	if numFiles > l.maxFiles {
		return fmt.Errorf("address index merge needs %d file descriptors, "+
			"but the limit is %d", numFiles, l.maxFiles)
	}
	for {
		l.mu.Lock()
		if l.open+numFiles <= l.maxFiles {
			l.open += numFiles
			l.mu.Unlock()
			return nil
		}
		// Capture the notification channel while holding the lock so a release
		// between unlocking and waiting cannot be missed.
		changed := l.changed
		l.mu.Unlock()

		select {
		case <-changed:
		case <-interrupt:
			return errInterruptRequested
		case <-stop:
			return errInterruptRequested
		}
	}
}

// release returns numFiles descriptors to the shared merge budget and wakes
// all blocked reservations.
func (l *addrMergeFileLimiter) release(numFiles int) {
	l.mu.Lock()
	l.open -= numFiles
	close(l.changed)
	l.changed = make(chan struct{})
	l.mu.Unlock()
}

// less orders records by address key, then by the order the incremental path
// would have inserted the entry: block id ascending, then transaction offset
// ascending within the block.  Grouping by address key and following that order
// is what lets the write phase reproduce the on-disk level layout exactly.
func (r *addrRecord) less(o *addrRecord) bool {
	if c := bytes.Compare(r.addrKey[:], o.addrKey[:]); c != 0 {
		return c < 0
	}
	if r.blockID != o.blockID {
		return r.blockID < o.blockID
	}
	return r.txStart < o.txStart
}

// -----------------------------------------------------------------------------
// During a fast build, the address index writes temporary records to 256
// append-only shard files.  The first byte of the address hash selects the
// shard for each record.  This keeps every record for a given address in one
// shard while distributing writes across independent files.  Each shard has
// its own lock, so scan-workers writing different shards do not contend with
// one another.
//
// Callers append unsorted records to these files.  Each record includes its
// complete address key because staging performs no sorting or index-level
// construction.
//
// Sorting splits each shard into bounded in-memory runs.  Shards are sorted
// concurrently under a shared memory limit, while the runs for each shard are
// merged on disk into a sorted replacement file.  Since an address never spans
// shards, each shard can be sorted independently without retaining all sorted
// records in memory.
//
// Unsorted shards end in .tmp.  A completed shard is published with a .sorted
// suffix only after the sorted contents have been synced.  Recovery recognizes
// the suffix and skips sorting that shard again.
//
// The database writer consumes sorted shards in shard order while the remaining
// shards continue sorting.  This keeps database writes sequential and bounds
// replay memory to one shard.
//
// Records are appended without a length prefix because every record has one
// fixed-width address key followed by exactly three self-delimiting wire
// varints.
//
// The build manifest records the exact durable record count and byte size for
// each shard.  Recovery restores that prefix without reparsing the file and
// discards any records beyond the prefix stored in the manifest.
//
// The serialized format is:
//
//   [<address type><address hash160><block id><tx offset><tx length>],...
//
//   Field               Type      Size
//   address type        byte      1 byte
//   address hash160     [20]byte  20 bytes
//   block id            varint    1, 3, 5, or 9 bytes
//   transaction offset  varint    1, 3, 5, or 9 bytes
//   transaction length  varint    1, 3, 5, or 9 bytes
//
// The shard reuses a record and wire varint scratch buffer so appending does
// not allocate for each entry.
// -----------------------------------------------------------------------------

// addrStagingShard holds the state for one staging shard.
type addrStagingShard struct {
	// mu protects buf, rec, varIntBuf, and numRecords during concurrent appends.
	mu sync.Mutex

	// written is true when the shard was committed to the database and its
	// progress was recorded in the manifest.
	written bool

	// f is the shard's backing file.
	f *os.File

	// buf batches varint-encoded record appends to f.
	buf *bufio.Writer

	// path is the current backing file.  Its suffix records whether the shard
	// still needs to be sorted.
	path string

	// sorted is true when path names a completed sorted shard.
	sorted bool

	// numRecords is the number of complete records in the shard.
	numRecords uint64

	// rec is reused for each append to avoid creating garbage for every address
	// index entry.
	rec addrRecord

	// varIntBuf is reused by wire varint serialization to avoid allocating per
	// append.
	varIntBuf [addrVarIntScratchSize]byte
}

// addrStager owns the hash-prefix shards for one address index fast build.
// Routing by the first hash160 byte keeps each address in one shard and permits
// concurrent appends and independent sorting.
type addrStager struct {
	// dir contains the staging shard and manifest files.
	dir string

	// manifest is the latest durable build state.  It is nil until the first
	// manifest is written.
	manifest *addrBuildManifest

	// shards holds the independently locked staging files.
	shards [numAddrStagingShards]addrStagingShard
}

// addrStagingShardPaths returns the unsorted and sorted paths for a shard.
func addrStagingShardPaths(dir string, shard int) (string, string) {
	base := filepath.Join(dir, fmt.Sprintf("shard-%03d", shard))
	return base + ".tmp", base + ".sorted"
}

// newAddrStager creates an address record stager in dir.
func newAddrStager(dir string) (*addrStager, error) {
	s := &addrStager{dir: dir}
	for i := range s.shards {
		path, _ := addrStagingShardPaths(dir, i)
		f, err := os.Create(path)
		if err != nil {
			s.closeShards()
			return nil, err
		}
		s.shards[i].path = path
		s.shards[i].f = f
		s.shards[i].buf = bufio.NewWriterSize(f, 64*1024)
	}
	return s, nil
}

// openAddrStager reopens the staging shards of an interrupted build for
// appending or writing.  When appendRecords is true, sorted shards are renamed
// to unsorted shards because appending new records invalidates their order.
// Shards already committed according to manifest no longer need files.  Each
// remaining shard is restored to the record count and byte size in the
// manifest.
func openAddrStager(dir string, appendRecords bool,
	manifest *addrBuildManifest,
	interrupt <-chan struct{}) (*addrStager, error) {

	writtenShards := manifest.writtenShards
	if writtenShards > numAddrStagingShards {
		return nil, fmt.Errorf("invalid number of written address staging shards")
	}
	if appendRecords && writtenShards != 0 {
		return nil, fmt.Errorf("address staging write began before scan completed")
	}

	numShards := numAddrStagingShards - int(writtenShards)
	if numShards > 0 {
		log.Infof("Restoring %d address index staging shards from the "+
			"build manifest", numShards)
	}

	s := &addrStager{
		dir:      dir,
		manifest: manifest,
	}
	for i := range s.shards {
		if interruptRequested(interrupt) {
			s.closeShards()
			return nil, errInterruptRequested
		}

		path, sortedPath := addrStagingShardPaths(dir, i)
		if i < int(writtenShards) {
			s.shards[i].written = true
			continue
		}

		_, err := os.Stat(sortedPath)
		sorted := err == nil
		if err != nil && !os.IsNotExist(err) {
			s.closeShards()
			return nil, err
		}
		if sorted {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				s.closeShards()
				return nil, err
			}
			if appendRecords {
				if err := os.Rename(sortedPath, path); err != nil {
					s.closeShards()
					return nil, err
				}
				sorted = false
			} else {
				path = sortedPath
			}
		}

		f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0666)
		if err != nil {
			s.closeShards()
			return nil, err
		}
		state := manifest.shards[i]
		if err := restoreAddrStagingShard(f, i, appendRecords, state); err != nil {
			f.Close()
			s.closeShards()
			return nil, err
		}
		s.shards[i].path = path
		s.shards[i].sorted = sorted
		s.shards[i].numRecords = state.numRecords
		s.shards[i].f = f
		s.shards[i].buf = bufio.NewWriterSize(f, 64*1024)
	}
	return s, nil
}

// restoreAddrStagingShard restores a shard to the state recorded in the
// manifest without parsing its records.  Appending resumes at the exact durable
// byte offset, while the sort and write phases require the recorded file size
// to be unchanged.
func restoreAddrStagingShard(f *os.File, shard int, appendRecords bool,
	state addrBuildShardState) error {

	const maxFileSize = uint64(1<<63 - 1)
	if state.fileSize > maxFileSize {
		return fmt.Errorf("address staging shard %d is too large", shard)
	}
	expectedSize := int64(state.fileSize)
	stat, err := f.Stat()
	if err != nil {
		return err
	}
	if appendRecords {
		if stat.Size() < expectedSize {
			return fmt.Errorf("address staging shard %d is shorter "+
				"than the size recorded in the manifest", shard)
		}
		if stat.Size() != expectedSize {
			if err := f.Truncate(expectedSize); err != nil {
				return err
			}
		}
	} else if stat.Size() != expectedSize {
		return fmt.Errorf("address staging shard %d size does not "+
			"match the size recorded in the manifest", shard)
	}
	return nil
}

// sync flushes and fsyncs every shard so the records written so far are durable
// before a manifest referring to them is written.
func (s *addrStager) sync() error {
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

// recordShardStates records the durable record count and file size for every
// shard.  The caller must sync the shards before writing the manifest.
func (s *addrStager) recordShardStates(manifest *addrBuildManifest) error {
	for i := range s.shards {
		sh := &s.shards[i]
		if sh.written {
			continue
		}
		info, err := os.Stat(sh.path)
		if err != nil {
			return err
		}
		manifest.shards[i] = addrBuildShardState{
			numRecords: sh.numRecords,
			fileSize:   uint64(info.Size()),
		}
	}
	return nil
}

// add appends an address index entry to the shard for its address key.
func (s *addrStager) add(addrKey *[addrKeySize]byte, blockID uint32,
	txLoc wire.TxLoc) error {
	sh := &s.shards[addrKey[1]]
	sh.mu.Lock()
	defer sh.mu.Unlock()

	sh.rec.addrKey = *addrKey
	sh.rec.blockID = uint64(blockID)
	sh.rec.txStart = uint64(txLoc.TxStart)
	sh.rec.txLen = uint64(txLoc.TxLen)
	if err := writeAddrRecord(sh.buf, &sh.rec, &sh.varIntBuf); err != nil {
		return err
	}
	sh.numRecords++
	return nil
}

// closeShards closes all open shard files.
func (s *addrStager) closeShards() {
	for i := range s.shards {
		if s.shards[i].f != nil {
			s.shards[i].f.Close()
			s.shards[i].f = nil
			s.shards[i].buf = nil
		}
	}
}

// markShardWritten records that shard and every shard before it were committed
// to the database, then removes its staging file.  A failed manifest update
// leaves the file intact so a resumed write safely replays it.
func (s *addrStager) markShardWritten(shard int) error {
	if shard != int(s.manifest.writtenShards) {
		return fmt.Errorf("address staging shards were written out of order")
	}

	manifest := *s.manifest
	manifest.writtenShards++
	if err := writeAddrBuildManifest(s.dir, &manifest); err != nil {
		return err
	}
	s.manifest = &manifest

	sh := &s.shards[shard]
	sh.written = true
	path := sh.path
	sh.path = ""
	sh.numRecords = 0
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		log.Warnf("Unable to remove written address staging shard %d: %v",
			shard, err)
	}
	return nil
}

// readAddrStagingShardRecords seeks to the beginning of a staging shard file
// and reads numRecords through a buffered reader.  It is the whole-shard
// wrapper for callers that do not need to preserve a streaming position.
func readAddrStagingShardRecords(f *os.File, numRecords int,
	interrupts ...<-chan struct{}) ([]addrRecord, error) {

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	r := bufio.NewReaderSize(f, 64*1024)
	return readAddrStagingRecords(r, numRecords, interrupts...)
}

// readAddrStagingRecords reads the next numRecords serialized records from the
// current position of r without seeking so callers can consume consecutive
// batches from one buffered stream.
func readAddrStagingRecords(r io.Reader, numRecords int,
	interrupts ...<-chan struct{}) ([]addrRecord, error) {

	records := make([]addrRecord, numRecords)
	var varIntBuf [addrVarIntScratchSize]byte
	for i := range records {
		if i%addrStagingInterruptCheckRecords == 0 &&
			addrBuildInterruptRequested(interrupts...) {

			return nil, errInterruptRequested
		}
		if err := readAddrRecord(r, &records[i], &varIntBuf); err != nil {
			return nil, err
		}
	}
	return records, nil
}

// readAddrRecord deserializes one address index staging record from r.
func readAddrRecord(r io.Reader, record *addrRecord,
	varIntBuf *[addrVarIntScratchSize]byte) error {

	if _, err := io.ReadFull(r, record.addrKey[:]); err != nil {
		return err
	}

	var err error
	record.blockID, err = wire.ReadVarIntBuf(r, 0, varIntBuf[:])
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	if err != nil {
		return err
	}
	record.txStart, err = wire.ReadVarIntBuf(r, 0, varIntBuf[:])
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	if err != nil {
		return err
	}
	record.txLen, err = wire.ReadVarIntBuf(r, 0, varIntBuf[:])
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

// writeAddrRecord serializes one address index staging record to w.
func writeAddrRecord(w io.Writer, record *addrRecord,
	varIntBuf *[addrVarIntScratchSize]byte) error {

	if _, err := w.Write(record.addrKey[:]); err != nil {
		return err
	}
	if err := wire.WriteVarIntBuf(w, 0, record.blockID,
		varIntBuf[:]); err != nil {

		return err
	}
	if err := wire.WriteVarIntBuf(w, 0, record.txStart,
		varIntBuf[:]); err != nil {

		return err
	}
	return wire.WriteVarIntBuf(w, 0, record.txLen, varIntBuf[:])
}

// writeAddrStagingShard serializes records into a newly created path.  It
// removes partial output on failure and, when requested, syncs completed output
// before retaining it.
func writeAddrStagingShard(path string, records []addrRecord,
	syncFile bool, interrupts ...<-chan struct{}) error {

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	// Retain the output only after every record is written, the requested sync
	// completes, and the file is closed.
	remove := true
	defer func() {
		if f != nil {
			f.Close()
		}
		if remove {
			os.Remove(path)
		}
	}()

	w := bufio.NewWriterSize(f, 64*1024)
	var varIntBuf [addrVarIntScratchSize]byte
	for i := range records {
		if i%addrStagingInterruptCheckRecords == 0 &&
			addrBuildInterruptRequested(interrupts...) {

			return errInterruptRequested
		}
		if err := writeAddrRecord(w, &records[i], &varIntBuf); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if syncFile {
		if err := f.Sync(); err != nil {
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	f = nil
	remove = false
	return nil
}

// publishSortedAddrStagingShard publishes synced sort output before removing
// its source.  If replacement is interrupted, the .sorted file is authoritative
// when both files exist.
func publishSortedAddrStagingShard(path, sortingPath, sortedPath string) error {
	if err := os.Remove(sortedPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(sortingPath, sortedPath); err != nil {
		return err
	}
	if err := syncAddrBuildDir(filepath.Dir(sortedPath)); err != nil {
		return err
	}
	return os.Remove(path)
}

// mergeAddrStagingRuns performs a k-way merge of the sorted runs into
// sortedPath.  It keeps only one record from each run in memory.  Input runs
// are temporary and are removed as they are consumed or if the merge aborts.
func mergeAddrStagingRuns(runPaths []string, sortedPath string,
	limiter *addrMergeFileLimiter, interrupts ...<-chan struct{}) error {

	// The first channel is the caller interrupt.  The optional second channel
	// stops sibling workers after another worker fails.
	var interrupt, stop <-chan struct{}
	if len(interrupts) > 0 {
		interrupt = interrupts[0]
	}
	if len(interrupts) > 1 {
		stop = interrupts[1]
	}
	// Reserve every input and the output together so concurrent merges cannot
	// each hold a partial set of descriptors while waiting for the remainder.
	fileCount := len(runPaths) + 1
	if err := limiter.acquire(fileCount, interrupt, stop); err != nil {
		return err
	}
	defer limiter.release(fileCount)

	// runReader owns one input run's path, file, and buffered stream during a
	// merge.
	type runReader struct {
		// path identifies the run file to remove after it is consumed.
		path string

		// f remains open while the run participates in the merge.
		f *os.File

		// r preserves buffered input between records from this run.
		r *bufio.Reader
	}
	runs := make([]runReader, len(runPaths))
	// The original shard remains authoritative until publication, so close and
	// remove any inputs left behind by an aborted merge.
	defer func() {
		for i := range runs {
			if runs[i].f != nil {
				runs[i].f.Close()
			}
			os.Remove(runs[i].path)
		}
	}()

	// Prime the heap with the first record from every run.
	merged := make(addrRecordMergeHeap, 0, len(runs))
	var readVarIntBuf [addrVarIntScratchSize]byte
	for i, path := range runPaths {
		if addrBuildInterruptRequested(interrupts...) {
			return errInterruptRequested
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		runs[i] = runReader{
			path: path,
			f:    f,
			r:    bufio.NewReaderSize(f, 64*1024),
		}
		merged = append(merged, addrRecordMergeItem{run: i})
		item := &merged[len(merged)-1]
		if err := readAddrRecord(runs[i].r, &item.record,
			&readVarIntBuf); err != nil {

			return err
		}
	}
	heap.Init(&merged)

	f, err := os.Create(sortedPath)
	if err != nil {
		return err
	}
	// Retain merged output only after it has been flushed, synced, and closed.
	remove := true
	defer func() {
		if f != nil {
			f.Close()
		}
		if remove {
			os.Remove(sortedPath)
		}
	}()
	w := bufio.NewWriterSize(f, 64*1024)
	var writeVarIntBuf [addrVarIntScratchSize]byte
	var numMerged uint64
	// Repeatedly write the smallest record, then replace it with the next record
	// from the same run.  Exhausted runs are removed from both the heap and disk.
	for merged.Len() > 0 {
		if numMerged%addrStagingInterruptCheckRecords == 0 &&
			addrBuildInterruptRequested(interrupts...) {

			return errInterruptRequested
		}
		item := &merged[0]
		if err := writeAddrRecord(w, &item.record,
			&writeVarIntBuf); err != nil {

			return err
		}

		run := &runs[item.run]
		err := readAddrRecord(run.r, &item.record, &readVarIntBuf)
		switch err {
		case nil:
			// The replacement record remains at the root, so restore the heap
			// ordering.
			heap.Fix(&merged, 0)
		case io.EOF:
			heap.Pop(&merged)
			if err := run.f.Close(); err != nil {
				return err
			}
			run.f = nil
			if err := os.Remove(run.path); err != nil {
				return err
			}
		case io.ErrUnexpectedEOF:
			return fmt.Errorf("address index sort run has a truncated record")
		default:
			return err
		}
		numMerged++
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	f = nil
	remove = false
	return nil
}

// sortAddrStagingShard externally sorts one staging shard using bounded
// in-memory runs and publishes it under sortedPath when complete.
func sortAddrStagingShard(path, sortedPath string, numRecords,
	maxRunRecords int, limiter *addrMergeFileLimiter,
	interrupts ...<-chan struct{}) error {

	if maxRunRecords < 1 {
		return fmt.Errorf("address index sort run size must be positive")
	}
	mergeFanIn := min(addrBuildSortMergeFanIn, limiter.maxFiles-1)
	if mergeFanIn < 2 {
		return fmt.Errorf("address index merge fan-in must be at least two")
	}
	if addrBuildInterruptRequested(interrupts...) {
		return errInterruptRequested
	}
	// Sorting always restarts from the authoritative unsorted shard, so discard
	// artifacts left by an interrupted attempt.
	sortingPath := path + ".sorting"
	stalePaths, err := filepath.Glob(path + ".run-*")
	if err != nil {
		return err
	}
	stalePaths = append(stalePaths, sortingPath, path+".sorted")
	for _, stalePath := range stalePaths {
		if err := os.Remove(stalePath); err != nil && !os.IsNotExist(err) {
			return err
		}
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	// Empty and single-record shards are already sorted, so publish them without
	// creating an intermediate run.
	if numRecords < 2 {
		if err := f.Close(); err != nil {
			return err
		}
		if err := os.Remove(sortedPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return os.Rename(path, sortedPath)
	}
	r := bufio.NewReaderSize(f, 64*1024)

	numRuns := (numRecords + maxRunRecords - 1) / maxRunRecords
	runPaths := make([]string, 0, numRuns)
	// Run files are temporary even when sorting or merging fails.
	defer func() {
		runPaths, _ := filepath.Glob(path + ".run-*")
		for _, runPath := range runPaths {
			os.Remove(runPath)
		}
	}()
	// Read, sort, and write bounded batches so a shard never needs to fit in
	// memory as a whole.
	for first := 0; first < numRecords; first += maxRunRecords {
		if addrBuildInterruptRequested(interrupts...) {
			f.Close()
			return errInterruptRequested
		}
		n := min(numRecords-first, maxRunRecords)
		records, err := readAddrStagingRecords(r, n, interrupts...)
		if err != nil {
			f.Close()
			return err
		}
		sort.Sort(addrRecords(records))

		runPath := fmt.Sprintf("%s.run-%03d", path, len(runPaths))
		runPaths = append(runPaths, runPath)
		if err := writeAddrStagingShard(runPath, records,
			numRuns == 1, interrupts...); err != nil {

			f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}

	// Reduce shards with more runs than one merge can safely open through
	// additional passes.  The limiter reserves every input and output file for
	// each merge as one unit, so concurrent merges never deadlock on partial
	// reservations.
	for pass := 0; len(runPaths) > mergeFanIn; pass++ {
		nextRunPaths := make([]string, 0,
			(len(runPaths)+mergeFanIn-1)/mergeFanIn)
		for first := 0; first < len(runPaths); first += mergeFanIn {
			end := min(first+mergeFanIn, len(runPaths))
			if end-first == 1 {
				nextRunPaths = append(nextRunPaths, runPaths[first])
				continue
			}

			mergedPath := fmt.Sprintf("%s.run-merge-%03d-%03d", path,
				pass, len(nextRunPaths))
			err := mergeAddrStagingRuns(runPaths[first:end], mergedPath,
				limiter, interrupts...)
			if err != nil {
				return err
			}
			nextRunPaths = append(nextRunPaths, mergedPath)
		}
		runPaths = nextRunPaths
	}

	// A lone run was synced when written and only needs renaming.  Multiple runs
	// need one last merge into an output that mergeAddrStagingRuns syncs.
	if numRuns == 1 {
		if err := os.Rename(runPaths[0], sortingPath); err != nil {
			return err
		}
	} else if err := mergeAddrStagingRuns(runPaths, sortingPath,
		limiter, interrupts...); err != nil {

		return err
	}
	if addrBuildInterruptRequested(interrupts...) {
		return errInterruptRequested
	}
	if err := publishSortedAddrStagingShard(path, sortingPath,
		sortedPath); err != nil {

		return err
	}
	return nil
}

// logAddrStagingSize reports physical staging use and average record size.
func logAddrStagingSize(label string, numRecords uint64, physicalBytes int64) {
	if numRecords == 0 {
		return
	}
	const gib = 1024 * 1024 * 1024
	log.Infof("%s: %.1f GiB on disk for %d records (%.1f bytes/record)",
		label, float64(physicalBytes)/gib, numRecords,
		float64(physicalBytes)/float64(numRecords))
}

// sortAddrStagingShards externally sorts staging shards concurrently under a
// shared memory limit.  shardSorted is called once for each sorted shard and
// may be called concurrently.
func sortAddrStagingShards(stager *addrStager,
	shardSorted func(int), interrupt <-chan struct{}) error {

	if interruptRequested(interrupt) {
		return errInterruptRequested
	}
	// Make buffered records visible and close append handles before workers
	// reopen the shard files for sorting.
	for i := range stager.shards {
		buf := stager.shards[i].buf
		if buf != nil {
			if err := buf.Flush(); err != nil {
				return err
			}
		}
	}
	stager.closeShards()

	var (
		shardRecords   [numAddrStagingShards]uint64
		unsortedShards []int
		totalRecords   uint64
		physicalBytes  int64
		writtenShards  int
		sortedShards   uint32
		sortedRecords  uint64
	)
	// Snapshot record counts and file sizes, and report shards that a previous
	// attempt already published instead of scheduling them again.
	for shard := range stager.shards {
		sh := &stager.shards[shard]
		if sh.written {
			writtenShards++
			continue
		}
		info, err := os.Stat(sh.path)
		if err != nil {
			return err
		}
		shardRecords[shard] = sh.numRecords
		totalRecords += shardRecords[shard]
		physicalBytes += info.Size()
		if sh.sorted {
			sortedShards++
			sortedRecords += shardRecords[shard]
			shardSorted(shard)
			continue
		}
		unsortedShards = append(unsortedShards, shard)
	}
	logAddrStagingSize("Address index staging", totalRecords, physicalBytes)

	numSortShards := numAddrStagingShards - writtenShards
	remainingShards := len(unsortedShards)
	if remainingShards == 0 {
		log.Infof("Address index sort: %d/%d remaining shards "+
			"(100.0%%, %d records)", numSortShards, numSortShards,
			totalRecords)
		return nil
	}
	if sortedShards > 0 {
		log.Infof("Resuming address index sort with %d/%d remaining "+
			"shards already sorted", sortedShards, numSortShards)
	}

	numWorkers := min(runtime.NumCPU(), addrBuildSortMaxWorkers,
		remainingShards)
	// Divide the shared memory budget among workers and conservatively charge two
	// maximum serialized record sizes for each in-memory record.
	workerMemory := addrBuildSortMemoryBytes / numWorkers
	maxRunRecords := max(1, workerMemory/(addrRecordMaxSize*2))
	mergeLimiter := newAddrMergeFileLimiter(addrBuildSortMaxMergeFiles)
	log.Infof("Sorting address index staging shards using %d workers",
		numWorkers)

	shards := make(chan int, numWorkers)
	var (
		wg           sync.WaitGroup
		errOnce      sync.Once
		firstErr     error
		progressWg   sync.WaitGroup
		progressDone = make(chan struct{})
		stop         = make(chan struct{})
	)
	// Sorting progress is updated by every worker, so the reporter reads atomic
	// snapshots until the main function shuts it down.
	progressWg.Add(1)
	go func() {
		defer progressWg.Done()
		ticker := time.NewTicker(addrBuildProgressInterval)
		defer ticker.Stop()
		for {
			select {
			case <-progressDone:
				return

			case <-ticker.C:
				shards := atomic.LoadUint32(&sortedShards)
				records := atomic.LoadUint64(&sortedRecords)
				percent := float64(shards) /
					float64(numSortShards) * 100
				if totalRecords > 0 {
					percent = float64(records) /
						float64(totalRecords) * 100
				}
				log.Infof("Address index sort: %d/%d remaining shards "+
					"(%.1f%%, %d/%d records)", shards,
					numSortShards, percent, records,
					totalRecords)
			}
		}
	}()
	defer func() {
		close(progressDone)
		progressWg.Wait()
	}()

	// Preserve the first error and broadcast cancellation to the feeder, workers,
	// and merge-file waiters.
	fail := func(err error) {
		errOnce.Do(func() {
			firstErr = err
			close(stop)
		})
	}
	// Workers sort independent shards but share the memory-derived run size and
	// file-descriptor limiter.
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for shard := range shards {
				if addrBuildInterruptRequested(interrupt, stop) {
					fail(errInterruptRequested)
					return
				}
				path, sortedPath := addrStagingShardPaths(
					stager.dir, shard)
				numRecords := int(shardRecords[shard])
				if uint64(numRecords) != shardRecords[shard] {
					fail(fmt.Errorf("address index staging shard is too large"))
					return
				}
				if err := sortAddrStagingShard(path, sortedPath,
					numRecords, maxRunRecords, mergeLimiter, interrupt,
					stop); err != nil {

					fail(err)
					return
				}
				stager.shards[shard].path = sortedPath
				stager.shards[shard].sorted = true
				atomic.AddUint64(&sortedRecords, shardRecords[shard])
				atomic.AddUint32(&sortedShards, 1)
				shardSorted(shard)
			}
		}()
	}

	// Stop feeding work as soon as the caller interrupts or any worker fails.
feed:
	for _, shard := range unsortedShards {
		select {
		case <-stop:
			break feed
		case <-interrupt:
			fail(errInterruptRequested)
			break feed
		case shards <- shard:
		}
	}
	close(shards)
	wg.Wait()
	if firstErr == nil {
		log.Infof("Address index sort: %d/%d remaining shards "+
			"(100.0%%, %d records)", numSortShards, numSortShards,
			totalRecords)
	}
	return firstErr
}

// syncAddrBuildDir makes published staging names durable.  Windows does not
// support syncing directory handles through os.File.
func syncAddrBuildDir(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}

	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		dir.Close()
		return err
	}
	return dir.Close()
}

// addrBuildShardState identifies the durable prefix of one staging shard.
type addrBuildShardState struct {
	// numRecords is the number of complete records in the durable prefix.
	numRecords uint64

	// fileSize is the byte offset immediately after the durable prefix.
	fileSize uint64
}

// addrBuildManifest is the durable recovery state for an address index build.
type addrBuildManifest struct {
	// completed is the highest block height whose records were synced to the
	// shard files.  A resumed scan starts at the following height.
	completed int32

	// baseHeight is the address index tip height this build extends.  It is -1
	// when building a new index from scratch.
	baseHeight int32

	// targetHeight is the chain height the scan was working toward when this
	// state was recorded.
	targetHeight int32

	// writtenShards is the number of consecutive shards, starting at zero,
	// whose database writes completed.  A resumed write starts with the next
	// shard.
	writtenShards uint16

	// baseHash identifies the block at baseHeight and is zero for a new index.
	// It prevents staging built from a different index tip from being reused.
	baseHash chainhash.Hash

	// targetHash identifies the block at targetHeight.  It prevents staging
	// for a target that is no longer on the main chain from being reused.
	targetHash chainhash.Hash

	// shards identifies the exact durable prefix of every staging shard.  It
	// avoids reparsing the files during recovery and discards complete records
	// written after the scan position stored in the manifest.
	shards [numAddrStagingShards]addrBuildShardState
}

const (
	// addrBuildManifestHeaderSize is the size of the fixed manifest fields.
	addrBuildManifestHeaderSize = 19 + 2*chainhash.HashSize

	// addrBuildManifestSize is the serialized size of a build manifest.  The
	// 19-byte prefix consists of the 4-byte magic, 1-byte version, three 4-byte
	// heights, and a 2-byte written shard count, followed by two block hashes
	// and a 16-byte record count and file size for each of the 256 shards.
	addrBuildManifestSize = addrBuildManifestHeaderSize +
		numAddrStagingShards*16
)

// writeAddrBuildManifest atomically records the provided build state in the
// staging directory.
func writeAddrBuildManifest(stagingDir string,
	manifest *addrBuildManifest) error {
	buf := make([]byte, addrBuildManifestSize)
	copy(buf[0:4], addrBuildManifestMagic[:])
	buf[4] = addrBuildManifestVersion
	byteOrder.PutUint32(buf[5:9], uint32(manifest.completed))
	byteOrder.PutUint32(buf[9:13], uint32(manifest.baseHeight))
	byteOrder.PutUint32(buf[13:17], uint32(manifest.targetHeight))
	byteOrder.PutUint16(buf[17:19], manifest.writtenShards)
	copy(buf[19:19+chainhash.HashSize], manifest.baseHash[:])
	targetHashOffset := 19 + chainhash.HashSize
	copy(buf[targetHashOffset:targetHashOffset+chainhash.HashSize],
		manifest.targetHash[:])

	offset := addrBuildManifestHeaderSize
	for i := range manifest.shards {
		state := &manifest.shards[i]
		byteOrder.PutUint64(buf[offset:offset+8], state.numRecords)
		byteOrder.PutUint64(buf[offset+8:offset+16], state.fileSize)
		offset += 16
	}

	tmpPath := filepath.Join(stagingDir, addrBuildManifestName+".tmp")
	f, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	if _, err := f.Write(buf); err != nil {
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
	manifestPath := filepath.Join(stagingDir, addrBuildManifestName)
	if err := os.Rename(tmpPath, manifestPath); err != nil {
		return err
	}
	return syncAddrBuildDir(stagingDir)
}

// readAddrBuildManifest returns the build state recorded in the staging
// directory and whether a valid manifest was present.
func readAddrBuildManifest(stagingDir string) (addrBuildManifest, bool) {
	var manifest addrBuildManifest
	data, err := os.ReadFile(filepath.Join(stagingDir, addrBuildManifestName))
	if err != nil || len(data) != addrBuildManifestSize {
		return manifest, false
	}
	if !bytes.Equal(data[0:4], addrBuildManifestMagic[:]) ||
		data[4] != addrBuildManifestVersion {
		return manifest, false
	}

	manifest.completed = int32(byteOrder.Uint32(data[5:9]))
	manifest.baseHeight = int32(byteOrder.Uint32(data[9:13]))
	manifest.targetHeight = int32(byteOrder.Uint32(data[13:17]))
	manifest.writtenShards = byteOrder.Uint16(data[17:19])
	if manifest.writtenShards > numAddrStagingShards ||
		(manifest.writtenShards != 0 &&
			manifest.completed < manifest.targetHeight) {

		return addrBuildManifest{}, false
	}
	const hashOffset = 19
	copy(manifest.baseHash[:], data[hashOffset:hashOffset+chainhash.HashSize])
	targetHashOffset := hashOffset + chainhash.HashSize
	copy(manifest.targetHash[:],
		data[targetHashOffset:targetHashOffset+chainhash.HashSize])

	offset := addrBuildManifestHeaderSize
	for i := range manifest.shards {
		state := &manifest.shards[i]
		state.numRecords = byteOrder.Uint64(data[offset : offset+8])
		state.fileSize = byteOrder.Uint64(data[offset+8 : offset+16])
		offset += 16

		const minRecordSize = uint64(addrKeySize + 3)
		const maxFileSize = uint64(1<<63 - 1)
		if state.fileSize > maxFileSize ||
			(state.numRecords == 0) != (state.fileSize == 0) ||
			state.numRecords > state.fileSize/minRecordSize ||
			state.fileSize > state.numRecords*addrRecordMaxSize {

			return addrBuildManifest{}, false
		}
	}
	return manifest, true
}

// memAddrBucket is an in-memory internalBucket used to replay one address
// key's entries through dbPutAddrIndexEntry so the write phase produces the
// same level keys and values the incremental path would.
type memAddrBucket struct {
	levels map[[levelKeySize]byte][]byte
}

// flushAddrIndexDB ensures database writes are durable before recording them in
// the staging manifest when the database supports an explicit flush.
func flushAddrIndexDB(db database.DB) error {
	flusher, ok := db.(database.Flusher)
	if !ok {
		return nil
	}
	return flusher.Flush()
}

// Get returns the value associated with the key.
//
// This is part of the internalBucket interface.
func (b *memAddrBucket) Get(key []byte) []byte {
	var levelKey [levelKeySize]byte
	copy(levelKey[:], key)
	return b.levels[levelKey]
}

// Put stores the provided key/value pair.  The address index helpers pass owned
// values and do not mutate them after a put, so retaining the slice avoids a
// redundant copy for every intermediate level update.
//
// This is part of the internalBucket interface.
func (b *memAddrBucket) Put(key []byte, value []byte) error {
	var levelKey [levelKeySize]byte
	copy(levelKey[:], key)
	b.levels[levelKey] = value
	return nil
}

// Delete removes the provided key.
//
// This is part of the internalBucket interface.
func (b *memAddrBucket) Delete(key []byte) error {
	var levelKey [levelKeySize]byte
	copy(levelKey[:], key)
	delete(b.levels, levelKey)
	return nil
}

// reset clears the bucket so it can be reused for the next address key.
func (b *memAddrBucket) reset() {
	clear(b.levels)
}

// addrLevelEntryCountsInterruptible returns the final number of entries in each
// address index level after inserting numEntries entries.  It mirrors the level
// moves performed by dbPutAddrIndexEntry without constructing intermediate
// values.
func addrLevelEntryCountsInterruptible(numEntries int,
	interrupts ...<-chan struct{}) ([]int, error) {

	if numEntries == 0 {
		return nil, nil
	}

	levels := []int{0}
	for entry := 0; entry < numEntries; entry++ {
		if entry%addrStagingInterruptCheckRecords == 0 &&
			addrBuildInterruptRequested(interrupts...) {

			return nil, errInterruptRequested
		}
		if levels[0] < level0MaxEntries {
			levels[0]++
			continue
		}

		prevLevelEntries := levels[0]
		maxEntries := level0MaxEntries * 2
		level := 1
		for {
			if level == len(levels) {
				levels = append(levels, 0)
			}
			if levels[level] == maxEntries {
				prevLevelEntries = levels[level]
				maxEntries *= 2
				level++
				continue
			}

			levels[level] += prevLevelEntries
			for mergeLevel := level - 1; mergeLevel > 0; mergeLevel-- {
				levels[mergeLevel] = levels[mergeLevel-1]
			}
			levels[0] = 1
			break
		}
	}
	return levels, nil
}

// buildAddrLevelValuesInterruptible constructs the final level values for one
// new address from records in canonical order.  Building each value once avoids
// the repeated allocations and copies incremental level merging would perform.
func buildAddrLevelValuesInterruptible(records []addrRecord,
	interrupts ...<-chan struct{}) ([][]byte, error) {

	levelCounts, err := addrLevelEntryCountsInterruptible(
		len(records), interrupts...,
	)
	if err != nil {
		return nil, err
	}
	levels := make([][]byte, len(levelCounts))
	recordIdx := 0
	for level := len(levelCounts) - 1; level >= 0; level-- {
		value := make([]byte, levelCounts[level]*txEntrySize)
		for offset := 0; offset < len(value); offset += txEntrySize {
			if recordIdx%addrStagingInterruptCheckRecords == 0 &&
				addrBuildInterruptRequested(interrupts...) {

				return nil, errInterruptRequested
			}
			record := &records[recordIdx]
			byteOrder.PutUint32(value[offset:], uint32(record.blockID))
			byteOrder.PutUint32(value[offset+4:], uint32(record.txStart))
			byteOrder.PutUint32(value[offset+8:], uint32(record.txLen))
			recordIdx++
		}
		levels[level] = value
	}
	return levels, nil
}

// emitSortedAddrLevelEntries groups sorted records by address key, rebuilds
// their final level values, and invokes emit for every produced level key in
// ascending level order.  New addresses are built directly, while addresses
// with existing levels are replayed through dbPutAddrIndexEntry against
// memBucket so interrupted and incremental builds preserve their existing
// state.  memBucket is reused across groups and must be non-nil.
//
// A build that extends an existing index provides the level values every
// address already has in the database via existing, along with the block id of
// the base the build extends.  Each group's replay then starts from those
// levels after stripping any entries beyond the base, which an interrupted
// write of the same staging may have merged already.  Level values that end up
// unchanged are not emitted, and a seeded level that no longer exists is
// emitted with a nil value so the caller deletes it.
//
// addrDone is invoked after each address's emissions.  It gives the caller a
// safe point to commit what has been emitted so far, since committing only part
// of an address would leave a mix of old and new level values for a resumed
// build to seed its replay from.
func emitSortedAddrLevelEntries(records []addrRecord,
	existing map[[addrKeySize]byte][][]byte, baseBlockID uint32,
	memBucket *memAddrBucket,
	emit func(key [levelKeySize]byte, value []byte) error,
	addrDone func() error, interrupts ...<-chan struct{}) error {

	for j := 0; j < len(records); {
		if addrBuildInterruptRequested(interrupts...) {
			return errInterruptRequested
		}

		// Gather the contiguous run of records for one address key.
		addrKey := records[j].addrKey
		k := j
		for k < len(records) && records[k].addrKey == addrKey {
			if (k-j)%addrStagingInterruptCheckRecords == 0 &&
				addrBuildInterruptRequested(interrupts...) {

				return errInterruptRequested
			}
			k++
		}

		existingLevels := existing[addrKey]
		if len(existingLevels) == 0 {
			levels, err := buildAddrLevelValuesInterruptible(
				records[j:k], interrupts...,
			)
			if err != nil {
				return err
			}
			for level, value := range levels {
				levelKey := keyForLevel(addrKey, uint8(level))
				if err := emit(levelKey, value); err != nil {
					return err
				}
			}
			if err := addrDone(); err != nil {
				return err
			}
			j = k
			continue
		}

		// Seed the replay with the level values the address already has,
		// counting the entries beyond the base so they can be stripped.
		memBucket.reset()
		numStale := 0
		for level, value := range existingLevels {
			levelKey := keyForLevel(addrKey, uint8(level))
			if err := memBucket.Put(levelKey[:], value); err != nil {
				return err
			}
			for off := 0; off+txEntrySize <= len(value); off += txEntrySize {
				if off%(addrStagingInterruptCheckRecords*txEntrySize) == 0 &&
					addrBuildInterruptRequested(interrupts...) {

					return errInterruptRequested
				}
				if byteOrder.Uint32(value[off:]) > baseBlockID {
					numStale++
				}
			}
		}
		if numStale > 0 {
			err := dbRemoveAddrIndexEntries(memBucket, addrKey, numStale)
			if err != nil {
				return err
			}
		}

		// Reconstruct the on-disk level layout by replaying the entries in
		// order through the same routine the incremental path uses.
		for recordIdx, r := range records[j:k] {
			if recordIdx%addrStagingInterruptCheckRecords == 0 &&
				addrBuildInterruptRequested(interrupts...) {

				return errInterruptRequested
			}
			txLoc := wire.TxLoc{
				TxStart: int(r.txStart),
				TxLen:   int(r.txLen),
			}
			err := dbPutAddrIndexEntry(memBucket, addrKey,
				uint32(r.blockID), txLoc)
			if err != nil {
				return err
			}
		}

		// Emit the produced level keys in ascending level order.  There are no
		// gaps, so the first missing level ends the address.  Seeded levels
		// whose value did not change are already in the database and are
		// skipped.
		numLevels := 0
		for level := uint8(0); ; level++ {
			levelKey := keyForLevel(addrKey, level)
			value := memBucket.levels[levelKey]
			if value == nil {
				break
			}
			numLevels++
			if int(level) < len(existingLevels) &&
				bytes.Equal(value, existingLevels[level]) {
				continue
			}
			if err := emit(levelKey, value); err != nil {
				return err
			}
		}

		// Any seeded level beyond the ones produced no longer exists, so emit
		// a nil value for it to have the caller delete it.
		for level := numLevels; level < len(existingLevels); level++ {
			levelKey := keyForLevel(addrKey, uint8(level))
			if err := emit(levelKey, nil); err != nil {
				return err
			}
		}

		if err := addrDone(); err != nil {
			return err
		}
		j = k
	}
	return nil
}

// fetchExistingAddrLevels returns the level values every address appearing in
// the records already has in the address index bucket, in ascending level
// order.  Addresses with no levels are absent from the returned map.
func fetchExistingAddrLevels(db database.DB,
	records []addrRecord,
	interrupt <-chan struct{}) (map[[addrKeySize]byte][][]byte, error) {

	addrKeys := make(map[[addrKeySize]byte]struct{})
	for i := range records {
		if i%addrStagingInterruptCheckRecords == 0 &&
			interruptRequested(interrupt) {

			return nil, errInterruptRequested
		}
		addrKeys[records[i].addrKey] = struct{}{}
	}

	existing := make(map[[addrKeySize]byte][][]byte)
	err := db.View(func(dbTx database.Tx) error {
		bucket := dbTx.Metadata().Bucket(addrIndexKey)
		for addrKey := range addrKeys {
			if interruptRequested(interrupt) {
				return errInterruptRequested
			}

			// Levels have no gaps, so the first missing level ends the
			// address.  The values are copied since they are only valid for
			// the duration of the transaction.
			var levels [][]byte
			for level := uint8(0); ; level++ {
				levelKey := keyForLevel(addrKey, level)
				value := bucket.Get(levelKey[:])
				if value == nil {
					break
				}
				levels = append(levels, append([]byte(nil), value...))
			}
			if levels != nil {
				existing[addrKey] = levels
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return existing, nil
}

// writeAddrIndexToDB sorts shards concurrently on disk while processing ready
// shards in order and writing their address index levels in batched
// transactions.  The ordered replay gives the database mostly ascending keys.
// It flushes at shard boundaries, marks the completed shard in the manifest,
// and removes its staging file so a resumed write starts with the remaining
// suffix.
// baseBlockID is the block id of the index tip the build extends, or zero for a
// build from scratch.  A nonzero value merges each address's staged entries
// into the level values it already has.
func (idx *AddrIndex) writeAddrIndexToDB(db database.DB, stager *addrStager,
	baseBlockID uint32, interrupt <-chan struct{}) error {

	shardReady := make([]chan struct{}, numAddrStagingShards)
	for shard := range shardReady {
		shardReady[shard] = make(chan struct{})
	}

	// Combine the caller's interrupt with errors from the writer so the sort
	// workers always stop and are joined before this function returns.
	sortInterrupt := make(chan struct{})
	var cancelSortOnce sync.Once
	cancelSort := func() {
		cancelSortOnce.Do(func() {
			close(sortInterrupt)
		})
	}
	relayDone := make(chan struct{})
	go func() {
		select {
		case <-interrupt:
			cancelSort()
		case <-relayDone:
		}
	}()
	defer close(relayDone)

	sortDone := make(chan error, 1)
	go func() {
		sortDone <- sortAddrStagingShards(stager, func(shard int) {
			close(shardReady[shard])
		}, sortInterrupt)
	}()

	sortFinished := false
	waitForShard := func(shard int) error {
		if interruptRequested(sortInterrupt) {
			return errInterruptRequested
		}
		if sortFinished {
			<-shardReady[shard]
			return nil
		}

		select {
		case <-sortInterrupt:
			return errInterruptRequested

		case <-shardReady[shard]:
			if interruptRequested(sortInterrupt) {
				return errInterruptRequested
			}
			return nil

		case err := <-sortDone:
			sortFinished = true
			if err != nil {
				return err
			}
			<-shardReady[shard]
			return nil
		}
	}

	type levelEntry struct {
		key   [levelKeySize]byte
		value []byte
	}
	batch := make([]levelEntry, 0, 4096)
	deletes := make([][levelKeySize]byte, 0)
	var (
		batchBytes     int
		currentShard   int
		lastWriteLog   = time.Now()
		writtenEntries uint64
	)
	if stager.manifest.writtenShards != 0 {
		log.Infof("Resuming address index write with %d/%d shards already "+
			"written", stager.manifest.writtenShards,
			numAddrStagingShards)
	}
	flush := func() error {
		if len(batch) == 0 && len(deletes) == 0 {
			return nil
		}

		err := db.Update(func(dbTx database.Tx) error {
			bucket := dbTx.Metadata().Bucket(addrIndexKey)
			for j := range batch {
				err := bucket.Put(batch[j].key[:], batch[j].value)
				if err != nil {
					return err
				}
			}
			for j := range deletes {
				if err := bucket.Delete(deletes[j][:]); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return err
		}

		writtenEntries += uint64(len(batch))
		if time.Since(lastWriteLog) >= addrBuildProgressInterval {
			log.Infof("Address index write: processing shard %d/%d "+
				"(%d level entries written)", currentShard+1,
				numAddrStagingShards, writtenEntries)
			lastWriteLog = time.Now()
		}

		batch = batch[:0]
		deletes = deletes[:0]
		batchBytes = 0
		return nil
	}

	writeErr := func() error {
		memBucket := &memAddrBucket{
			levels: make(map[[levelKeySize]byte][]byte),
		}
		for i := range stager.shards {
			currentShard = i
			if stager.shards[i].written {
				continue
			}
			if interruptRequested(interrupt) {
				return errInterruptRequested
			}
			if err := waitForShard(i); err != nil {
				return err
			}

			f, err := os.Open(stager.shards[i].path)
			if err != nil {
				return err
			}
			numRecords := int(stager.shards[i].numRecords)
			if uint64(numRecords) != stager.shards[i].numRecords {
				f.Close()
				return fmt.Errorf("address index staging shard is too large")
			}
			records, err := readAddrStagingShardRecords(
				f, numRecords, interrupt,
			)
			closeErr := f.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}

			// When the build extends an existing index, load the level values the
			// shard's addresses already have so the staged entries merge into
			// them.  Addresses never span shards, so each shard can be committed
			// independently.
			var existing map[[addrKeySize]byte][][]byte
			if baseBlockID > 0 {
				existing, err = fetchExistingAddrLevels(
					db, records, interrupt,
				)
				if err != nil {
					return err
				}
			}

			err = emitSortedAddrLevelEntries(records, existing, baseBlockID,
				memBucket,
				func(key [levelKeySize]byte, value []byte) error {
					if value == nil {
						deletes = append(deletes, key)
						return nil
					}
					batch = append(batch, levelEntry{
						key:   key,
						value: value,
					})
					batchBytes += len(value) + levelKeySize
					return nil
				},
				func() error {
					if interruptRequested(interrupt) {
						return errInterruptRequested
					}
					if batchBytes >= addrBuildWriteBatchBytes {
						return flush()
					}
					return nil
				}, interrupt)
			if err != nil {
				return err
			}
			if err := flush(); err != nil {
				return err
			}
			if numRecords > 0 {
				if err := flushAddrIndexDB(db); err != nil {
					return err
				}
			}
			records = nil
			if err := stager.markShardWritten(i); err != nil {
				return err
			}
		}
		return nil
	}()

	if writeErr != nil {
		cancelSort()
	}
	if !sortFinished {
		sortErr := <-sortDone
		if writeErr == nil {
			writeErr = sortErr
		}
	}
	return writeErr
}
