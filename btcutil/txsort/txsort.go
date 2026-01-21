// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Provides functions for sorting tx inputs and outputs according to BIP 69
// (https://github.com/bitcoin/bips/blob/master/bip-0069.mediawiki)

package txsort

import (
	"bytes"
	"sort"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// InPlaceSort is deprecated with the new immutable MsgTx API.
// It now returns a new sorted transaction instead of modifying in place.
// Use Sort() instead for clearer semantics.
//
// Deprecated: Use Sort() instead.
func InPlaceSort(tx *wire.MsgTx) *wire.MsgTx {
	return Sort(tx)
}

// Sort returns a new transaction with the inputs and outputs sorted based on
// BIP 69.  The passed transaction is not modified and the new transaction
// might have a different hash if any sorting was done.
func Sort(tx *wire.MsgTx) *wire.MsgTx {
	// Extract inputs and outputs into slices.
	txIns := tx.TxIn()
	inputs := make([]*wire.TxIn, len(txIns))
	for i := range txIns {
		inputs[i] = &txIns[i]
	}

	txOuts := tx.TxOut()
	outputs := make([]*wire.TxOut, len(txOuts))
	for i := range txOuts {
		outputs[i] = &txOuts[i]
	}

	// Sort the slices.
	sort.Sort(sortableInputSlice(inputs))
	sort.Sort(sortableOutputSlice(outputs))

	// Create a new transaction with sorted inputs and outputs.
	return wire.NewMsgTx(tx.Version, inputs, outputs, tx.LockTime)
}

// IsSorted checks whether tx has inputs and outputs sorted according to BIP
// 69.
func IsSorted(tx *wire.MsgTx) bool {
	// Check inputs are sorted.
	txIns := tx.TxIn()
	for i := 1; i < len(txIns); i++ {
		prev := &txIns[i-1]
		curr := &txIns[i]
		if !inputLessOrEqual(prev, curr) {
			return false
		}
	}

	// Check outputs are sorted.
	txOuts := tx.TxOut()
	for i := 1; i < len(txOuts); i++ {
		prev := &txOuts[i-1]
		curr := &txOuts[i]
		if !outputLessOrEqual(prev, curr) {
			return false
		}
	}

	return true
}

// inputLessOrEqual returns true if a should come before or equal to b.
func inputLessOrEqual(a, b *wire.TxIn) bool {
	ahash := a.PreviousOutPoint.Hash
	bhash := b.PreviousOutPoint.Hash
	if ahash == bhash {
		return a.PreviousOutPoint.Index <= b.PreviousOutPoint.Index
	}

	// Reverse hashes to big-endian for comparison.
	const hashSize = chainhash.HashSize
	for k := 0; k < hashSize/2; k++ {
		ahash[k], ahash[hashSize-1-k] = ahash[hashSize-1-k], ahash[k]
		bhash[k], bhash[hashSize-1-k] = bhash[hashSize-1-k], bhash[k]
	}
	return bytes.Compare(ahash[:], bhash[:]) <= 0
}

// outputLessOrEqual returns true if a should come before or equal to b.
func outputLessOrEqual(a, b *wire.TxOut) bool {
	if a.Value == b.Value {
		return bytes.Compare(a.PkScript, b.PkScript) <= 0
	}
	return a.Value < b.Value
}

type sortableInputSlice []*wire.TxIn
type sortableOutputSlice []*wire.TxOut

// For SortableInputSlice and SortableOutputSlice, three functions are needed
// to make it sortable with sort.Sort() -- Len, Less, and Swap
// Len and Swap are trivial.  Less is BIP 69 specific.
func (s sortableInputSlice) Len() int       { return len(s) }
func (s sortableOutputSlice) Len() int      { return len(s) }
func (s sortableOutputSlice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s sortableInputSlice) Swap(i, j int)  { s[i], s[j] = s[j], s[i] }

// Input comparison function.
// First sort based on input hash (reversed / rpc-style), then index.
func (s sortableInputSlice) Less(i, j int) bool {
	// Input hashes are the same, so compare the index.
	ihash := s[i].PreviousOutPoint.Hash
	jhash := s[j].PreviousOutPoint.Hash
	if ihash == jhash {
		return s[i].PreviousOutPoint.Index < s[j].PreviousOutPoint.Index
	}

	// At this point, the hashes are not equal, so reverse them to
	// big-endian and return the result of the comparison.
	const hashSize = chainhash.HashSize
	for b := 0; b < hashSize/2; b++ {
		ihash[b], ihash[hashSize-1-b] = ihash[hashSize-1-b], ihash[b]
		jhash[b], jhash[hashSize-1-b] = jhash[hashSize-1-b], jhash[b]
	}
	return bytes.Compare(ihash[:], jhash[:]) == -1
}

// Output comparison function.
// First sort based on amount (smallest first), then PkScript.
func (s sortableOutputSlice) Less(i, j int) bool {
	if s[i].Value == s[j].Value {
		return bytes.Compare(s[i].PkScript, s[j].PkScript) < 0
	}
	return s[i].Value < s[j].Value
}
