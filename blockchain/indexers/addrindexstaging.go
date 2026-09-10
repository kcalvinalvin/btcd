// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

const (
	// addrRecordSize is an address key followed by one serialized address
	// index entry.
	addrRecordSize = addrKeySize + txEntrySize

	// numAddrStagingShards is the number of files used to stage records.  The
	// first byte of the address hash selects the shard.
	numAddrStagingShards = 256

	// addrStagingIOBufferSize is the buffer used by each staging shard.
	addrStagingIOBufferSize = 64 * 1024

	// addrStagingInterruptCheckRecords controls interrupt checks in record
	// processing loops.
	addrStagingInterruptCheckRecords = 1 << 16

	addrBuildManifestVersion = 1
	addrBuildManifestName    = "manifest"
)

// addrRecord is the fixed size staging representation of an address index
// entry.  Its trailing bytes use the address index value encoding.
type addrRecord [addrRecordSize]byte

func makeAddrRecord(addrKey *[addrKeySize]byte, blockID uint32,
	txLoc wire.TxLoc) addrRecord {

	var record addrRecord
	copy(record[:addrKeySize], addrKey[:])
	byteOrder.PutUint32(record[addrKeySize:], blockID)
	byteOrder.PutUint32(record[addrKeySize+4:], uint32(txLoc.TxStart))
	byteOrder.PutUint32(record[addrKeySize+8:], uint32(txLoc.TxLen))
	return record
}

func (r *addrRecord) key() [addrKeySize]byte {
	var key [addrKeySize]byte
	copy(key[:], r[:addrKeySize])
	return key
}

func (r *addrRecord) blockID() uint32 {
	return byteOrder.Uint32(r[addrKeySize:])
}

func (r *addrRecord) less(other *addrRecord) bool {
	if cmp := bytes.Compare(r[:addrKeySize], other[:addrKeySize]); cmp != 0 {
		return cmp < 0
	}
	if r.blockID() != other.blockID() {
		return r.blockID() < other.blockID()
	}
	return byteOrder.Uint32(r[addrKeySize+4:]) <
		byteOrder.Uint32(other[addrKeySize+4:])
}

type addrRecords []addrRecord

func (r addrRecords) Len() int           { return len(r) }
func (r addrRecords) Less(i, j int) bool { return r[i].less(&r[j]) }
func (r addrRecords) Swap(i, j int)      { r[i], r[j] = r[j], r[i] }

// addrStagingShard serializes concurrent writes to one staging file.
type addrStagingShard struct {
	mu  sync.Mutex
	f   *os.File
	buf *bufio.Writer
}

// addrStager owns the staging files for one address index build.
type addrStager struct {
	dir    string
	shards [numAddrStagingShards]addrStagingShard
}

func addrStagingShardPath(dir string, shard int) string {
	return filepath.Join(dir, fmt.Sprintf("shard-%03d", shard))
}

func newAddrStager(dir string) (*addrStager, error) {
	stager := &addrStager{dir: dir}
	for i := range stager.shards {
		f, err := os.Create(addrStagingShardPath(dir, i))
		if err != nil {
			stager.close()
			return nil, err
		}
		stager.shards[i].f = f
		stager.shards[i].buf = bufio.NewWriterSize(
			f, addrStagingIOBufferSize,
		)
	}
	return stager, nil
}

func openAddrStager(dir string, manifest *addrBuildManifest,
	interrupt <-chan struct{}) (*addrStager, error) {

	stager := &addrStager{dir: dir}
	for i, expectedSize := range manifest.ShardSizes {
		if interruptRequested(interrupt) {
			stager.close()
			return nil, errInterruptRequested
		}

		path := addrStagingShardPath(dir, i)
		f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0600)
		if err != nil {
			stager.close()
			return nil, err
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			stager.close()
			return nil, err
		}
		if info.Size() < expectedSize {
			f.Close()
			stager.close()
			return nil, fmt.Errorf("address staging shard %d is shorter "+
				"than its checkpoint", i)
		}
		if info.Size() != expectedSize {
			if err := f.Truncate(expectedSize); err != nil {
				f.Close()
				stager.close()
				return nil, err
			}
		}

		stager.shards[i].f = f
		stager.shards[i].buf = bufio.NewWriterSize(
			f, addrStagingIOBufferSize,
		)
	}
	return stager, nil
}

func (s *addrStager) add(addrKey *[addrKeySize]byte, blockID uint32,
	txLoc wire.TxLoc) error {

	shard := &s.shards[addrKey[1]]
	shard.mu.Lock()
	defer shard.mu.Unlock()

	record := makeAddrRecord(addrKey, blockID, txLoc)
	_, err := shard.buf.Write(record[:])
	return err
}

// checkpoint makes all staged records durable, then records their exact file
// sizes with the completed height.
func (s *addrStager) checkpoint(manifest *addrBuildManifest,
	interrupt <-chan struct{}) error {

	if len(manifest.ShardSizes) != numAddrStagingShards {
		manifest.ShardSizes = make([]int64, numAddrStagingShards)
	}
	for i := range s.shards {
		if interruptRequested(interrupt) {
			return errInterruptRequested
		}
		shard := &s.shards[i]
		shard.mu.Lock()
		if err := shard.buf.Flush(); err != nil {
			shard.mu.Unlock()
			return err
		}
		if err := shard.f.Sync(); err != nil {
			shard.mu.Unlock()
			return err
		}
		info, err := shard.f.Stat()
		shard.mu.Unlock()
		if err != nil {
			return err
		}
		manifest.ShardSizes[i] = info.Size()
	}
	return writeAddrBuildManifest(s.dir, manifest)
}

func (s *addrStager) close() {
	for i := range s.shards {
		if s.shards[i].f == nil {
			continue
		}
		s.shards[i].f.Close()
		s.shards[i].f = nil
		s.shards[i].buf = nil
	}
}

func readAddrStagingShard(path string,
	interrupt <-chan struct{}) ([]addrRecord, error) {

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size()%addrRecordSize != 0 {
		return nil, fmt.Errorf("address staging shard has a partial record")
	}
	numRecords := info.Size() / addrRecordSize
	if int64(int(numRecords)) != numRecords {
		return nil, fmt.Errorf("address staging shard is too large")
	}

	records := make([]addrRecord, int(numRecords))
	reader := bufio.NewReaderSize(f, addrStagingIOBufferSize)
	for i := range records {
		if i%addrStagingInterruptCheckRecords == 0 &&
			interruptRequested(interrupt) {

			return nil, errInterruptRequested
		}
		if _, err := io.ReadFull(reader, records[i][:]); err != nil {
			return nil, err
		}
	}
	return records, nil
}

// addrBuildManifest identifies the chain range and durable shard prefixes of
// a resumable scan.
type addrBuildManifest struct {
	Version      uint32         `json:"version"`
	Completed    int32          `json:"completed"`
	BaseHeight   int32          `json:"base_height"`
	TargetHeight int32          `json:"target_height"`
	BaseHash     chainhash.Hash `json:"base_hash"`
	TargetHash   chainhash.Hash `json:"target_hash"`
	ShardSizes   []int64        `json:"shard_sizes"`
}

func writeAddrBuildManifest(stagingDir string,
	manifest *addrBuildManifest) error {

	manifest.Version = addrBuildManifestVersion
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmpPath := filepath.Join(stagingDir, addrBuildManifestName+".tmp")
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		f.Close()
		if remove {
			os.Remove(tmpPath)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	manifestPath := filepath.Join(stagingDir, addrBuildManifestName)
	if err := os.Rename(tmpPath, manifestPath); err != nil {
		return err
	}
	remove = false
	return syncAddrBuildDir(stagingDir)
}

func readAddrBuildManifest(stagingDir string) (addrBuildManifest, bool) {
	var manifest addrBuildManifest
	data, err := os.ReadFile(filepath.Join(stagingDir, addrBuildManifestName))
	if err != nil || json.Unmarshal(data, &manifest) != nil ||
		manifest.Version != addrBuildManifestVersion ||
		manifest.BaseHeight < -1 || manifest.TargetHeight < 0 ||
		manifest.Completed < manifest.BaseHeight ||
		manifest.Completed > manifest.TargetHeight ||
		len(manifest.ShardSizes) != numAddrStagingShards {

		return addrBuildManifest{}, false
	}
	for _, size := range manifest.ShardSizes {
		if size < 0 || size%addrRecordSize != 0 {
			return addrBuildManifest{}, false
		}
	}
	return manifest, true
}

// syncAddrBuildDir makes a published staging entry durable.  Directory handles
// cannot be synced on Windows through os.File.
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
