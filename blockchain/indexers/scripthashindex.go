package indexers

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/database"
	"github.com/btcsuite/btcd/txscript/v2"
)

const (
	scriptHashIndexName = "script hash index"

	// scriptHashIndexFormatVersion is the version of the on disk format of
	// the script hash index.  An index on disk with a different version,
	// including one built before versions were recorded, is dropped and
	// rebuilt on startup.
	scriptHashIndexFormatVersion uint32 = 1
)

var (
	scriptHashIndexKey = []byte("scripthashindex")

	// scriptHashIndexVersionKey is the metadata key the on disk format
	// version of the script hash index is stored under.
	scriptHashIndexVersionKey = []byte("scripthashindexversion")
)

func dbStoreScriptHashEntry(dbTx database.Tx, scriptHash [32]byte, addrKey [addrKeySize]byte) error {
	idx := dbTx.Metadata().Bucket(scriptHashIndexKey)
	return idx.Put(scriptHash[:], addrKey[:])
}

// dbPutScriptHashIndexVersion stores the on disk format version of the script
// hash index.
func dbPutScriptHashIndexVersion(dbTx database.Tx, version uint32) error {
	var serialized [4]byte
	byteOrder.PutUint32(serialized[:], version)
	return dbTx.Metadata().Put(scriptHashIndexVersionKey, serialized[:])
}

// dbFetchScriptHashIndexVersion returns the on disk format version of the
// script hash index.  An index written before versions were recorded reads as
// version 0.
func dbFetchScriptHashIndexVersion(dbTx database.Tx) uint32 {
	serialized := dbTx.Metadata().Get(scriptHashIndexVersionKey)
	if len(serialized) != 4 {
		return 0
	}
	return byteOrder.Uint32(serialized)
}

// maybeDropStaleScriptHashIndex drops the script hash index when the format
// version on disk does not match scriptHashIndexFormatVersion, so an index in
// a format this code does not read is rebuilt on startup instead of being
// served with every lookup missing.
func maybeDropStaleScriptHashIndex(db database.DB, interrupt <-chan struct{}) error {
	var exists bool
	var version uint32
	err := db.View(func(dbTx database.Tx) error {
		indexesBucket := dbTx.Metadata().Bucket(indexTipsBucketName)
		exists = indexesBucket != nil &&
			indexesBucket.Get(scriptHashIndexKey) != nil
		version = dbFetchScriptHashIndexVersion(dbTx)
		return nil
	})
	if err != nil {
		return err
	}
	if !exists || version == scriptHashIndexFormatVersion {
		return nil
	}

	log.Infof("Dropping the script hash index since its on disk format "+
		"version %d is not the version %d this build reads, the index "+
		"is rebuilt afterwards", version, scriptHashIndexFormatVersion)

	err = db.Update(func(dbTx database.Tx) error {
		return dbTx.Metadata().Delete(scriptHashIndexVersionKey)
	})
	if err != nil {
		return err
	}

	return dropIndex(db, scriptHashIndexKey, scriptHashIndexName, interrupt)
}

// dbFetchScriptHashEntry returns the address index key stored for the script
// hash. The bool is false when the script hash is not in the index.
func dbFetchScriptHashEntry(dbTx database.Tx, scriptHash [32]byte) ([addrKeySize]byte, bool) {
	idx := dbTx.Metadata().Bucket(scriptHashIndexKey)
	val := idx.Get(scriptHash[:])
	if len(val) != addrKeySize {
		return [addrKeySize]byte{}, false
	}
	var addrKey [addrKeySize]byte
	copy(addrKey[:], val)
	return addrKey, true
}

// ScriptHashIndex maps the sha256 hash of a pkScript to the address index key
// of the address it pays to.  Useful for an electrum server as the requests are
// not done with bitcoin addresses, rather with the script hashes.  Storing the
// address index key (rather than the address string) is what the read path uses
// to query the address index, so no decode round-trip is needed on lookup.
type ScriptHashIndex struct {
	db          database.DB
	chainParams *chaincfg.Params

	// dataDir is the directory the fast build stages its work in.
	dataDir string

	// Map for checking if the script hash -> address key mapping already
	// exists.  This happens as there are a lot of address reuse in bitcoin.
	exists map[chainhash.Hash]struct{}

	unconfirmedLock      sync.RWMutex
	addrByScriptHash     map[string][addrKeySize]byte
	scriptHashesByTxHash map[chainhash.Hash]map[string]struct{}
}

// Ensure the ScriptHashIndex type implements the Indexer interface.
var _ Indexer = (*ScriptHashIndex)(nil)

func (idx *ScriptHashIndex) Init() error {
	return nil // Nothing to do.
}

// Key returns the database key to use for the index as a byte slice. This is
// part of the Indexer interface.
func (idx *ScriptHashIndex) Key() []byte {
	return scriptHashIndexKey
}

// Name returns the human-readable name of the index. This is part of the
// Indexer interface.
func (idx *ScriptHashIndex) Name() string {
	return scriptHashIndexName
}

// Create is invoked when the indexer manager determines the index needs
// to be created for the first time.
//
// This is part of the Indexer interface.
func (idx *ScriptHashIndex) Create(dbTx database.Tx) error {
	meta := dbTx.Metadata()
	_, err := meta.CreateBucket(scriptHashIndexKey)
	if err != nil {
		return err
	}
	return dbPutScriptHashIndexVersion(dbTx, scriptHashIndexFormatVersion)
}

func (idx *ScriptHashIndex) ConnectBlock(dbTx database.Tx, block *btcutil.Block,
	stxos []blockchain.SpentTxOut) error {

	for _, tx := range block.Transactions() {
		for _, txOut := range tx.MsgTx().TxOut {
			scriptHash := chainhash.HashH(txOut.PkScript)

			// The cache records every script hash already handled, so
			// a reused script is skipped without extracting addresses
			// or reading the database.  Because of the heavy address
			// reuse in bitcoin this avoids most of the work, and a
			// script hash maps to a single pkScript and therefore a
			// single address, so storing it once is enough.
			_, found := idx.exists[scriptHash]
			if found {
				continue
			}

			_, addrs, _, err := txscript.ExtractPkScriptAddrs(
				txOut.PkScript, idx.chainParams)
			if err != nil || len(addrs) != 1 {
				// We skip when there are multiple addresses as
				// that means the pkscript is for a raw multisig
				// output.  Since the address manager isn't
				// keeping track of them anyways, we simply
				// skip.  Cache it so the script isn't extracted
				// again on reuse.
				idx.exists[scriptHash] = struct{}{}
				continue
			}

			addrKey, err := addrToKey(addrs[0])
			if err != nil {
				// The address index does not support this address
				// type either, so there is nothing to map.  Cache
				// it so the script isn't revisited.
				idx.exists[scriptHash] = struct{}{}
				continue
			}

			err = dbStoreScriptHashEntry(dbTx, scriptHash, addrKey)
			if err != nil {
				return err
			}

			// Keep it in the cache so that we don't revisit it in the future.
			idx.exists[scriptHash] = struct{}{}
		}
	}

	return nil
}

func (idx *ScriptHashIndex) DisconnectBlock(dbTx database.Tx, block *btcutil.Block,
	stxos []blockchain.SpentTxOut) error {
	// Do nothing as we may unmap a script hash -> address mapping that
	// exists in previous blocks. Because of address reuse, we must check
	// all previous blocks to ensure that an address can be unmapped. Since
	// this cost is expensive and the storage for a mapping is cheap, we
	// just do nothing.
	return nil
}

// addrKeyForScriptHash resolves the address index key for the script hash using
// the provided view: the in-memory unconfirmed map first, then the database.
func (idx *ScriptHashIndex) addrKeyForScriptHash(dbTx database.Tx,
	scriptHash chainhash.Hash) ([addrKeySize]byte, bool) {

	idx.unconfirmedLock.RLock()
	addrKey, found := idx.addrByScriptHash[scriptHash.String()]
	idx.unconfirmedLock.RUnlock()
	if found {
		return addrKey, true
	}

	return dbFetchScriptHashEntry(dbTx, scriptHash)
}

// AddrKeyForScriptHash returns the address index key for the script hash.  The
// bool is false when the script hash is unknown.
func (idx *ScriptHashIndex) AddrKeyForScriptHash(scriptHash chainhash.Hash) ([addrKeySize]byte, bool) {
	var (
		addrKey [addrKeySize]byte
		found   bool
	)
	idx.db.View(func(dbTx database.Tx) error {
		addrKey, found = idx.addrKeyForScriptHash(dbTx, scriptHash)
		return nil
	})
	return addrKey, found
}

// TxRegionsForScriptHash returns the address index block regions for the address
// behind the script hash by resolving the script hash to its address index key
// and querying the address index directly, all in a single view.
func (idx *ScriptHashIndex) TxRegionsForScriptHash(scriptHash chainhash.Hash,
	numToSkip, numRequested uint32, reverse bool) ([]database.BlockRegion, uint32, error) {

	var (
		regions []database.BlockRegion
		skipped uint32
	)
	err := idx.db.View(func(dbTx database.Tx) error {
		addrKey, found := idx.addrKeyForScriptHash(dbTx, scriptHash)
		if !found {
			return nil
		}

		fetchBlockHash := func(id []byte) (*chainhash.Hash, error) {
			return dbFetchBlockHashBySerializedID(dbTx, id)
		}
		addrIdxBucket := dbTx.Metadata().Bucket(addrIndexKey)

		var err error
		regions, skipped, err = dbFetchAddrIndexEntries(addrIdxBucket, addrKey,
			numToSkip, numRequested, reverse, fetchBlockHash)
		return err
	})
	return regions, skipped, err
}

func (idx *ScriptHashIndex) indexUnconfirmedScriptHash(txHash *chainhash.Hash, pkScript []byte) {
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript,
		idx.chainParams)
	if err != nil || len(addrs) != 1 {
		// We skip when there are multiple addresses as
		// that means the pkscript is for a raw multisig
		// output.  Since the address manager isn't
		// keeping track of them anyways, we simply
		// skip.
		return
	}

	addrKey, err := addrToKey(addrs[0])
	if err != nil {
		// Unsupported address type; nothing to map.
		return
	}

	scriptHash := chainhash.HashH(pkScript)

	// No need to keep this in memory if it is already mapped by the database.
	// This happens because of address re-use.
	var alreadyMapped bool
	idx.db.View(func(dbTx database.Tx) error {
		_, alreadyMapped = dbFetchScriptHashEntry(dbTx, scriptHash)
		return nil
	})
	if alreadyMapped {
		return
	}

	idx.unconfirmedLock.Lock()

	// Add a mapping from the scriptHash to the address key.
	idx.addrByScriptHash[scriptHash.String()] = addrKey

	// Add a mapping from the tx hash to the scriptHash.
	scriptHashesByTxHash := idx.scriptHashesByTxHash[*txHash]
	if scriptHashesByTxHash == nil {
		scriptHashesByTxHash = make(map[string]struct{})
		idx.scriptHashesByTxHash[*txHash] = scriptHashesByTxHash
	}
	scriptHashesByTxHash[scriptHash.String()] = struct{}{}

	idx.unconfirmedLock.Unlock()
}

func (idx *ScriptHashIndex) MapUnconfirmedTx(tx *btcutil.Tx, utxoView *blockchain.UtxoViewpoint) {
	// Index addresses of all referenced previous transaction outputs.
	//
	// The existence checks are elided since this is only called after the
	// transaction has already been validated and thus all inputs are
	// already known to exist.
	for _, txIn := range tx.MsgTx().TxIn {
		entry := utxoView.LookupEntry(txIn.PreviousOutPoint)
		if entry == nil {
			// Ignore missing entries.  This should never happen
			// in practice since the function comments specifically
			// call out all inputs must be available.
			continue
		}

		idx.indexUnconfirmedScriptHash(tx.Hash(), entry.PkScript())
	}

	// Index addresses of all created outputs.
	for _, txOut := range tx.MsgTx().TxOut {
		idx.indexUnconfirmedScriptHash(tx.Hash(), txOut.PkScript)
	}
}

func (idx *ScriptHashIndex) RemoveUnconfirmedTxEntry(hash *chainhash.Hash) {
	idx.unconfirmedLock.Lock()
	defer idx.unconfirmedLock.Unlock()

	scriptHashes := idx.scriptHashesByTxHash[*hash]
	delete(idx.scriptHashesByTxHash, *hash)

	// Because of address reuse, a script hash mapped by this tx may still be
	// referenced by another unconfirmed tx. Gather the script hashes that
	// remain in use so we only unmap the ones no longer referenced.
	stillReferenced := make(map[string]struct{})
	for _, hashes := range idx.scriptHashesByTxHash {
		for scriptHash := range hashes {
			stillReferenced[scriptHash] = struct{}{}
		}
	}

	for scriptHash := range scriptHashes {
		if _, found := stillReferenced[scriptHash]; !found {
			delete(idx.addrByScriptHash, scriptHash)
		}
	}
}

// FastBuild bulk-builds the script hash table from the chain, swaps it in for
// the read path, and persists the index tip.  It implements the FastBuilder
// interface so the index manager can build the index in a single parallel pass
// instead of block by block.
func (idx *ScriptHashIndex) FastBuild(chain *blockchain.BlockChain,
	interrupt <-chan struct{}) error {

	builtHash, builtHeight, err := buildScriptHashBucketFromChain(
		chain, idx.db, idx.chainParams, idx.dataDir, 0, interrupt)
	if err != nil {
		return err
	}

	return idx.db.Update(func(dbTx database.Tx) error {
		return dbPutIndexerTip(dbTx, scriptHashIndexKey, &builtHash, builtHeight)
	})
}

func NewScriptHashIndex(db database.DB, chainParams *chaincfg.Params,
	dataDir string) *ScriptHashIndex {

	return &ScriptHashIndex{
		db:                   db,
		chainParams:          chainParams,
		dataDir:              dataDir,
		exists:               make(map[chainhash.Hash]struct{}),
		addrByScriptHash:     make(map[string][addrKeySize]byte),
		scriptHashesByTxHash: make(map[chainhash.Hash]map[string]struct{}),
	}
}

func DropScriptHashIndex(db database.DB, dataDir string, interrupt <-chan struct{}) error {
	if err := dropIndex(db, scriptHashIndexKey, scriptHashIndexName, interrupt); err != nil {
		return err
	}

	// Remove the standalone table and any build staging kept on disk, which
	// live outside the database.
	return os.RemoveAll(filepath.Join(dataDir, scriptHashIndexDirName))
}
