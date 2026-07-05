// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

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

	// numAddrStagingShards is the number of shards used to stage records during
	// a build.  The first byte of the address hash160 selects the shard.  That
	// byte is uniformly distributed for hashed address types, so records spread
	// evenly while every entry for an address remains in the same shard.
	numAddrStagingShards = 256

	// addrStagingInterruptCheckRecords is the number of staged records processed
	// between interrupt checks during long-running staging operations.
	addrStagingInterruptCheckRecords = 65536
)

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
// Records are appended without a length prefix because every record has one
// fixed-width address key followed by exactly three self-delimiting wire
// varints.
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

	// f is the shard's backing file.
	f *os.File

	// buf batches varint-encoded record appends to f.
	buf *bufio.Writer

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
// concurrent appends without a global lock.
type addrStager struct {
	// dir contains the staging shard files.
	dir string

	// shards holds the independently locked staging files.
	shards [numAddrStagingShards]addrStagingShard
}

// addrStagingShardPath returns the temporary path for a shard.
func addrStagingShardPath(dir string, shard int) string {
	return filepath.Join(dir, fmt.Sprintf("shard-%03d.tmp", shard))
}

// newAddrStager creates an address record stager in dir.
func newAddrStager(dir string) (*addrStager, error) {
	s := &addrStager{dir: dir}
	for i := range s.shards {
		path := addrStagingShardPath(dir, i)
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
		}
	}
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
