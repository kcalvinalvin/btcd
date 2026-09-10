// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/blockchain"
)

const addrScanProgressInterval = 10 * time.Second

type addrScanProgress struct {
	mu          sync.Mutex
	lastLogTime time.Time
	lastLogged  uint64
	scanned     uint64
	total       uint64
}

func newAddrScanProgress(total uint64) *addrScanProgress {
	return &addrScanProgress{
		lastLogTime: time.Now(),
		total:       total,
	}
}

func (p *addrScanProgress) blockScanned() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.scanned++
	now := time.Now()
	elapsed := now.Sub(p.lastLogTime)
	if elapsed < addrScanProgressInterval {
		return
	}

	recent := p.scanned - p.lastLogged
	blockLabel := "blocks"
	if recent == 1 {
		blockLabel = "block"
	}
	log.Infof("Scanned %d %s for address index entries in the last %s "+
		"(%d of %d blocks)", recent, blockLabel,
		elapsed.Truncate(10*time.Millisecond), p.scanned, p.total)
	p.lastLogged = p.scanned
	p.lastLogTime = now
}

func (idx *AddrIndex) stageAddrBlock(chain *blockchain.BlockChain,
	stager *addrStager, height int32, data writeIndexData) error {

	clear(data)
	block, err := chain.BlockByHeight(height)
	if err != nil {
		return err
	}
	txLocs, err := block.TxLoc()
	if err != nil {
		return err
	}
	stxos, err := chain.FetchSpendJournal(block)
	if err != nil {
		return err
	}
	idx.indexBlock(data, block, stxos)

	// Transaction index block IDs follow chain height from genesis.
	blockID := addrBuildBlockID(height)
	for addrKey, txIdxs := range data {
		for _, txIdx := range txIdxs {
			if err := stager.add(&addrKey, blockID, txLocs[txIdx]); err != nil {
				return err
			}
		}
	}
	return nil
}

// scanAddrHeightRange scans the block heights in [start, end] with a pool of
// workers and stages the derived address index records.  Chain reads are safe
// to do concurrently.
func (idx *AddrIndex) scanAddrHeightRange(chain *blockchain.BlockChain,
	stager *addrStager, start, end int64, numWorkers int,
	progress *addrScanProgress, interrupt <-chan struct{}) error {

	var (
		workers    sync.WaitGroup
		errOnce    sync.Once
		firstErr   error
		stop       = make(chan struct{})
		nextHeight = start
	)
	fail := func(e error) {
		errOnce.Do(func() {
			firstErr = e
			close(stop)
		})
	}

	for i := 0; i < numWorkers; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			data := make(writeIndexData)

			for {
				if interruptRequested(interrupt) || interruptRequested(stop) {
					fail(errInterruptRequested)
					return
				}
				height, ok := addrScanHeight(atomic.AddInt64(&nextHeight, 1)-1, end)
				if !ok {
					return
				}
				if err := idx.stageAddrBlock(
					chain, stager, height, data,
				); err != nil {

					fail(err)
					return
				}
				progress.blockScanned()
			}
		}()
	}
	workers.Wait()
	return firstErr
}
