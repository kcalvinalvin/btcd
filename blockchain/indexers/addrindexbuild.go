// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/database"
)

const (
	addrIndexBuildDirName          = "addrindexbuild"
	addrBuildScanChunkSize         = 50000
	addrBuildDecodedScanMaxWorkers = 8
	addrBuildMinBlocks             = 1000
)

var _ FastBuilder = (*AddrIndex)(nil)
var _ staleBuildDropper = (*AddrIndex)(nil)

func createAddrBuildStager(dataDir string,
	manifest *addrBuildManifest) (*addrStager, error) {

	if err := removeAddrIndexBuildDeleteDir(dataDir); err != nil {
		return nil, err
	}
	buildDir := filepath.Join(dataDir, addrIndexBuildDirName)
	if err := os.MkdirAll(buildDir, 0700); err != nil {
		return nil, err
	}
	if err := syncAddrBuildDir(filepath.Dir(buildDir)); err != nil {
		return nil, err
	}

	stagingDir := filepath.Join(buildDir, "staging")
	tmpDir := stagingDir + ".tmp"
	if err := os.RemoveAll(tmpDir); err != nil {
		return nil, err
	}
	if err := os.Mkdir(tmpDir, 0700); err != nil {
		return nil, err
	}
	stager, err := newAddrStager(tmpDir)
	if err != nil {
		return nil, err
	}
	if err := stager.checkpoint(manifest, nil); err != nil {
		stager.close()
		return nil, err
	}
	stager.close()

	if err := os.Rename(tmpDir, stagingDir); err != nil {
		return nil, err
	}
	if err := syncAddrBuildDir(buildDir); err != nil {
		return nil, err
	}
	stager, err = openAddrStager(stagingDir, manifest, nil)
	if err != nil {
		return nil, err
	}
	return stager, nil
}

func removeAddrIndexBuildDeleteDir(dataDir string) error {
	deleteDir := filepath.Join(dataDir, addrIndexBuildDirName) + ".delete"
	if _, err := os.Stat(deleteDir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := os.RemoveAll(deleteDir); err != nil {
		return err
	}
	return syncAddrBuildDir(dataDir)
}

func removeAddrIndexBuildDir(dataDir string) error {
	buildDir := filepath.Join(dataDir, addrIndexBuildDirName)
	deleteDir := buildDir + ".delete"
	if err := removeAddrIndexBuildDeleteDir(dataDir); err != nil {
		return err
	}
	if err := os.Rename(buildDir, deleteDir); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	} else if err := syncAddrBuildDir(dataDir); err != nil {
		return err
	}
	if err := os.RemoveAll(deleteDir); err != nil {
		return err
	}
	return syncAddrBuildDir(dataDir)
}

func addrBuildOnMainChain(chain *blockchain.BlockChain,
	manifest *addrBuildManifest) bool {

	if manifest.BaseHeight >= 0 {
		baseHash, err := chain.BlockHashByHeight(manifest.BaseHeight)
		if err != nil || !manifest.BaseHash.IsEqual(baseHash) {
			return false
		}
	}
	targetHash, err := chain.BlockHashByHeight(manifest.TargetHeight)
	return err == nil && manifest.TargetHash.IsEqual(targetHash)
}

type addrBuildDBFlusher interface {
	Flush() error
}

func addrBuildFlusher(db database.DB) (addrBuildDBFlusher, error) {
	flusher, ok := db.(addrBuildDBFlusher)
	if !ok {
		return nil, fmt.Errorf("database %T cannot flush pending writes", db)
	}
	return flusher, nil
}

// flushAddrIndexDB makes recovery state durable before its staging files are
// changed or removed.
func flushAddrIndexDB(db database.DB) error {
	flusher, err := addrBuildFlusher(db)
	if err != nil {
		return err
	}
	return flusher.Flush()
}

type addrBuildState struct {
	manifest  addrBuildManifest
	tipHash   *chainhash.Hash
	tipHeight int32
}

func (idx *AddrIndex) loadAddrBuildState() (*addrBuildState, error) {
	if idx.dataDir == "" {
		return nil, nil
	}
	if err := removeAddrIndexBuildDeleteDir(idx.dataDir); err != nil {
		return nil, err
	}
	buildDir, exists, err := addrIndexBuildDirExists(idx.dataDir)
	if err != nil || !exists {
		return nil, err
	}

	stagingDir := filepath.Join(buildDir, "staging")
	if _, err := os.Stat(stagingDir); err != nil {
		if os.IsNotExist(err) {
			return nil, removeAddrIndexBuildDir(idx.dataDir)
		}
		return nil, err
	}
	manifest, ok := readAddrBuildManifest(stagingDir)
	if !ok {
		return nil, fmt.Errorf("address index build checkpoint is invalid, " +
			"drop the address index before restarting the build")
	}

	state := &addrBuildState{manifest: manifest}
	err = idx.db.View(func(dbTx database.Tx) error {
		var err error
		state.tipHash, state.tipHeight, err = dbFetchIndexerTip(
			dbTx, addrIndexKey,
		)
		return err
	})
	if err != nil {
		return nil, err
	}
	return state, nil
}

// Init removes staging after a completed build or index drop is durable.
//
// This is part of the Indexer interface.
func (idx *AddrIndex) Init() error {
	state, err := idx.loadAddrBuildState()
	if err != nil || state == nil {
		return err
	}
	completed := state.tipHeight == state.manifest.TargetHeight &&
		state.tipHash.IsEqual(&state.manifest.TargetHash)
	dropped := state.tipHeight == -1 && state.manifest.BaseHeight >= 0
	if !completed && !dropped {
		return nil
	}

	if err := flushAddrIndexDB(idx.db); err != nil {
		return err
	}
	log.Infof("Removing stale address index build staging")
	return removeAddrIndexBuildDir(idx.dataDir)
}

func (idx *AddrIndex) dropStaleBuild(chain *blockchain.BlockChain,
	interrupt <-chan struct{}) (bool, error) {

	state, err := idx.loadAddrBuildState()
	if err != nil || state == nil {
		return false, err
	}
	if state.tipHeight != state.manifest.BaseHeight ||
		!state.tipHash.IsEqual(&state.manifest.BaseHash) {

		return false, fmt.Errorf(
			"address index build does not extend the current index tip")
	}
	if addrBuildOnMainChain(chain, &state.manifest) {
		return false, nil
	}

	log.Infof("Rebuilding address index after a chain reorganization")
	if err := DropAddrIndexWithDataDir(
		idx.db, idx.dataDir, interrupt,
	); err != nil {

		return false, err
	}
	return true, nil
}

// buildAddrIndexRecords resumes or starts a scan from the index tip to a
// snapshot of the current chain tip.
func (idx *AddrIndex) buildAddrIndexRecords(chain *blockchain.BlockChain,
	baseHeight int32, baseHash chainhash.Hash,
	interrupt <-chan struct{}) (*addrStager, addrBuildManifest, error) {

	best := chain.BestSnapshot()
	targetHeight := best.Height
	targetHash := best.Hash
	stagingDir := filepath.Join(
		idx.dataDir, addrIndexBuildDirName, "staging",
	)

	var (
		stager   *addrStager
		manifest addrBuildManifest
	)
	_, err := os.Stat(stagingDir)
	switch {
	case os.IsNotExist(err):
		manifest = addrBuildManifest{
			Completed:    baseHeight,
			BaseHeight:   baseHeight,
			TargetHeight: targetHeight,
			BaseHash:     baseHash,
			TargetHash:   targetHash,
		}
		stager, err = createAddrBuildStager(idx.dataDir, &manifest)
		if err != nil {
			return nil, addrBuildManifest{}, err
		}

	case err != nil:
		return nil, addrBuildManifest{}, err

	default:
		var ok bool
		manifest, ok = readAddrBuildManifest(stagingDir)
		if !ok {
			return nil, addrBuildManifest{}, fmt.Errorf(
				"address index build checkpoint is invalid")
		}
		if manifest.BaseHeight != baseHeight ||
			!manifest.BaseHash.IsEqual(&baseHash) {

			return nil, addrBuildManifest{}, fmt.Errorf(
				"address index build does not extend the current index tip")
		}
		if !addrBuildOnMainChain(chain, &manifest) {
			return nil, addrBuildManifest{}, fmt.Errorf(
				"address index build range is not on the main chain")
		}
		stager, err = openAddrStager(stagingDir, &manifest, interrupt)
		if err != nil {
			return nil, addrBuildManifest{}, err
		}
	}

	startHeight, _ := addrBuildScanRange(manifest.Completed, targetHeight)
	if startHeight > int64(targetHeight) {
		return stager, manifest, nil
	}

	numWorkers := min(runtime.GOMAXPROCS(0), addrBuildDecodedScanMaxWorkers)
	log.Infof("Scanning blocks %d to %d for address index entries using %d "+
		"workers", startHeight, targetHeight, numWorkers)
	totalBlocks := uint64(int64(targetHeight) - startHeight + 1)
	progress := newAddrScanProgress(totalBlocks)

	for manifest.Completed < targetHeight {
		chunkStart, chunkEnd := addrBuildScanRange(manifest.Completed, targetHeight)
		err := idx.scanAddrHeightRange(chain, stager, chunkStart, chunkEnd,
			numWorkers, progress, interrupt)
		if err != nil {
			stager.close()
			return nil, addrBuildManifest{}, err
		}

		manifest.Completed = int32(chunkEnd)
		manifest.TargetHeight = targetHeight
		manifest.TargetHash = targetHash
		if err := stager.checkpoint(&manifest, interrupt); err != nil {
			stager.close()
			return nil, addrBuildManifest{}, err
		}
	}
	return stager, manifest, nil
}

// buildAddrIndexFromChain extends the address index from its persisted tip.
func (idx *AddrIndex) buildAddrIndexFromChain(chain *blockchain.BlockChain,
	baseHeight int32, baseHash chainhash.Hash,
	interrupt <-chan struct{}) (chainhash.Hash, int32, error) {

	stager, manifest, err := idx.buildAddrIndexRecords(
		chain, baseHeight, baseHash, interrupt,
	)
	if err != nil {
		return chainhash.Hash{}, 0, err
	}
	defer stager.close()

	log.Infof("Writing address index into the database")
	if err := idx.writeAddrIndexToDB(
		stager, addrBuildBlockID(baseHeight), interrupt,
	); err != nil {

		return chainhash.Hash{}, 0, err
	}

	log.Infof("Built address index into the database at height %d (%s)",
		manifest.TargetHeight, manifest.TargetHash)
	return manifest.TargetHash, manifest.TargetHeight, nil
}

// FastBuild bulk-builds the address index from the chain in a single parallel
// pass and persists the index tip.  An index that already has data is extended
// from its current tip, and small gaps are left to ordinary catchup.
func (idx *AddrIndex) FastBuild(chain *blockchain.BlockChain,
	interrupt <-chan struct{}) (err error) {

	defer func() {
		if err == nil || errors.Is(err, errInterruptRequested) {
			return
		}

		log.Errorf("Address index fast build failed: %v", err)
		log.Errorf("Run btcd with --dropaddrindex to remove the failed " +
			"address index, then restart with --addrindex to try again")
	}()

	// An empty data directory disables fast builds.
	if idx.dataDir == "" {
		return nil
	}

	var (
		baseHash   *chainhash.Hash
		baseHeight int32
	)
	err = idx.db.View(func(dbTx database.Tx) error {
		var err error
		baseHash, baseHeight, err = dbFetchIndexerTip(dbTx, addrIndexKey)
		return err
	})
	if err != nil {
		return err
	}

	if baseHeight >= 0 {
		_, buildExists, statErr := addrIndexBuildDirExists(idx.dataDir)
		if statErr != nil {
			return statErr
		}
		behind := chain.BestSnapshot().Height - baseHeight
		if behind < addrBuildMinBlocks && !buildExists {
			return nil
		}
	}
	if err := flushAddrIndexDB(idx.db); err != nil {
		return err
	}

	log.Warnf("Older btcd versions cannot detect a partially built address " +
		"index and will silently corrupt it. If this build is interrupted, " +
		"drop the index with --dropaddrindex before downgrading btcd")

	builtHash, builtHeight, err := idx.buildAddrIndexFromChain(
		chain, baseHeight, *baseHash, interrupt,
	)
	if err != nil {
		return err
	}

	err = idx.db.Update(func(dbTx database.Tx) error {
		return dbPutIndexerTip(dbTx, addrIndexKey, &builtHash, builtHeight)
	})
	if err != nil {
		return err
	}
	if err := flushAddrIndexDB(idx.db); err != nil {
		return err
	}
	return removeAddrIndexBuildDir(idx.dataDir)
}

func addrIndexBuildDirExists(dataDir string) (string, bool, error) {
	dir := filepath.Join(dataDir, addrIndexBuildDirName)
	_, err := os.Stat(dir)
	if err == nil {
		return dir, true, nil
	}
	if os.IsNotExist(err) {
		return dir, false, nil
	}
	return dir, false, err
}

// AddrIndexFastBuildDir returns the build directory and whether it exists.
func AddrIndexFastBuildDir(dataDir string) (string, bool) {
	dir, exists, _ := addrIndexBuildDirExists(dataDir)
	return dir, exists
}

// DropAddrIndexWithDataDir drops the address index and removes fast-build
// staging from dataDir.
func DropAddrIndexWithDataDir(db database.DB, dataDir string,
	interrupt <-chan struct{}) error {

	_, buildExists, err := addrIndexBuildDirExists(dataDir)
	if err != nil {
		return err
	}
	if buildExists {
		if _, err := addrBuildFlusher(db); err != nil {
			return err
		}
	}
	if err := DropAddrIndex(db, interrupt); err != nil {
		return err
	}
	if !buildExists {
		return removeAddrIndexBuildDeleteDir(dataDir)
	}
	return removeAddrIndexBuildStaging(db, dataDir)
}

func removeAddrIndexBuildStaging(db database.DB, dataDir string) error {
	if err := flushAddrIndexDB(db); err != nil {
		return err
	}
	return removeAddrIndexBuildDir(dataDir)
}
