// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// TestMerkle tests the BuildMerkleTreeStore API.
func TestMerkle(t *testing.T) {
	block := btcutil.NewBlock(&Block100000)
	calcMerkleRoot := CalcMerkleRoot(block.Transactions(), false)
	merkleStoreTree := BuildMerkleTreeStore(block.Transactions(), false)
	merkleStoreRoot := merkleStoreTree[len(merkleStoreTree)-1]

	require.Equal(t, *merkleStoreRoot, calcMerkleRoot)

	wantMerkle := &Block100000.Header.MerkleRoot
	if !wantMerkle.IsEqual(&calcMerkleRoot) {
		t.Errorf("BuildMerkleTreeStore: merkle root mismatch - "+
			"got %v, want %v", calcMerkleRoot, wantMerkle)
	}
}

func makeHashes(size int) []*chainhash.Hash {
	var hashes = make([]*chainhash.Hash, size)
	for i := range hashes {
		hashes[i] = new(chainhash.Hash)
	}
	return hashes
}

func makeTxs(size int) []*btcutil.Tx {
	var txs = make([]*btcutil.Tx, size)
	for i := range txs {
		tx := btcutil.NewTx(wire.NewMsgTx(2))
		tx.Hash()
		txs[i] = tx
	}
	return txs
}

// BenchmarkRollingMerkle benches the RollingMerkleTree while varying the number
// of leaves pushed to the tree.
func BenchmarkRollingMerkle(b *testing.B) {
	sizes := []int{
		1000,
		2000,
		4000,
		8000,
		16000,
		32000,
	}

	for _, size := range sizes {
		txs := makeTxs(size)
		name := fmt.Sprintf("%d", size)
		b.Run(name, func(b *testing.B) {
			benchmarkRollingMerkle(b, txs)
		})
	}
}

// BenchmarkMerkle benches the BuildMerkleTreeStore while varying the number
// of leaves pushed to the tree.
func BenchmarkMerkle(b *testing.B) {
	sizes := []int{
		1000,
		2000,
		4000,
		8000,
		16000,
		32000,
	}

	for _, size := range sizes {
		txs := makeTxs(size)
		name := fmt.Sprintf("%d", size)
		b.Run(name, func(b *testing.B) {
			benchmarkMerkle(b, txs)
		})
	}
}

func benchmarkRollingMerkle(b *testing.B, txs []*btcutil.Tx) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		CalcMerkleRoot(txs, false)
	}
}

func benchmarkMerkle(b *testing.B, txs []*btcutil.Tx) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		BuildMerkleTreeStore(txs, false)
	}
}

// makeUniqueTxs creates size transactions, each with a distinct hash by varying
// the transaction version.
func makeUniqueTxs(size int) []*btcutil.Tx {
	txs := make([]*btcutil.Tx, size)
	for i := range txs {
		txs[i] = btcutil.NewTx(wire.NewMsgTx(int32(i + 1)))
	}
	return txs
}

// merkleRootFromBranch reconstructs the merkle root from a transaction hash, its
// position in the tree, and the branch returned by ExtractMerkleBranch, using
// Bitcoin's left/right hashing convention.
func merkleRootFromBranch(txHash chainhash.Hash, pos int,
	branch []*chainhash.Hash) chainhash.Hash {

	hash := txHash
	idx := pos
	for _, sibling := range branch {
		if idx&1 == 0 {
			hash = HashMerkleBranches(&hash, sibling)
		} else {
			hash = HashMerkleBranches(sibling, &hash)
		}
		idx >>= 1
	}
	return hash
}

// TestExtractMerkleBranch ensures the branch returned for each transaction hashes
// back up to the block's merkle root across a range of tree shapes, including non
// power of two sizes whose trees contain duplicated padding nodes. For every leaf
// it also locks the branch invariants: its length equals the tree height and it
// has no nil entries. (An odd final leaf is hashed with itself, so its first
// branch element legitimately equals its own hash.)
func TestExtractMerkleBranch(t *testing.T) {
	tests := []struct {
		name   string
		numTxs int
	}{
		{name: "single", numTxs: 1},
		{name: "two", numTxs: 2},
		{name: "three with padding", numTxs: 3},
		{name: "four full", numTxs: 4},
		{name: "five with padding", numTxs: 5},
		{name: "six with padding", numTxs: 6},
		{name: "seven with padding", numTxs: 7},
		{name: "eight full", numTxs: 8},
		{name: "nine with padding", numTxs: 9},
		{name: "fifteen with padding", numTxs: 15},
		{name: "sixteen full", numTxs: 16},
		{name: "seventeen with padding", numTxs: 17},
		{name: "thirty one with padding", numTxs: 31},
		{name: "thirty two full", numTxs: 32},
		{name: "thirty three with padding", numTxs: 33},
		{name: "sixty three with padding", numTxs: 63},
		{name: "sixty four full", numTxs: 64},
		{name: "one hundred with padding", numTxs: 100},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			txs := makeUniqueTxs(test.numTxs)
			merkles := BuildMerkleTreeStore(txs, false)
			root := merkles[len(merkles)-1]

			// The branch holds one sibling per row above the leaves,
			// so its length is the height of the tree.
			numLeaves := (len(merkles) + 1) / 2
			wantLen := int(treeRows(uint64(numLeaves)))

			for i, tx := range txs {
				txHash := *tx.Hash()
				branch := ExtractMerkleBranch(merkles, txHash)

				// The branch is one sibling per row and has no nil
				// entries.
				require.Lenf(t, branch, wantLen,
					"branch length for tx %d", i)
				for j, h := range branch {
					require.NotNilf(t, h,
						"nil branch entry %d for tx %d", j, i)
				}

				// The branch must hash back up to the merkle root
				// from this transaction's position.
				got := merkleRootFromBranch(txHash, i, branch)
				require.Equalf(t, *root, got,
					"reconstructed root mismatch for tx %d", i)
			}

			// A hash that is not in the block has no branch.
			var absent chainhash.Hash
			absent[0] = 0xff
			require.Nil(t, ExtractMerkleBranch(merkles, absent))
		})
	}
}

// TestExtractMerkleBranchEdgeCases covers inputs the size driven test cannot
// reach: hashes present in the store but not as leaves, the zero hash against
// both nil padding and a real zero valued witness leaf, duplicated leaves, and
// degenerate empty and single leaf stores.
func TestExtractMerkleBranchEdgeCases(t *testing.T) {
	// A hash present in the store as an interior node or the root must not
	// be matched, since only the leaf region of the store is searched.
	t.Run("interior and root not matched as leaves", func(t *testing.T) {
		merkles := BuildMerkleTreeStore(makeUniqueTxs(4), false)
		require.Nil(t, ExtractMerkleBranch(merkles, *merkles[4]),
			"parent node should not match")
		require.Nil(t, ExtractMerkleBranch(merkles, *merkles[len(merkles)-1]),
			"root should not match")
	})

	// The all zero hash must not be matched against a nil padding slot.
	t.Run("zero hash not matched as nil padding", func(t *testing.T) {
		// For five leaves, indices 5, 6 and 7 are nil padding.
		merkles := BuildMerkleTreeStore(makeUniqueTxs(5), false)
		require.Nil(t, ExtractMerkleBranch(merkles, chainhash.Hash{}))
	})

	// In a witness tree the coinbase leaf is a real, non nil, zero valued
	// leaf and must be found rather than confused with nil padding.
	t.Run("zero hash coinbase witness leaf found", func(t *testing.T) {
		merkles := BuildMerkleTreeStore(makeUniqueTxs(4), true)
		require.Equal(t, chainhash.Hash{}, *merkles[0],
			"coinbase wtxid is the zero hash")

		branch := ExtractMerkleBranch(merkles, chainhash.Hash{})
		require.NotNil(t, branch)
		got := merkleRootFromBranch(chainhash.Hash{}, 0, branch)
		require.Equal(t, *merkles[len(merkles)-1], got)
	})

	// When a hash is duplicated across leaves, the branch for the first
	// occurrence is returned and reconstructs the root only from that
	// position.
	t.Run("duplicate leaf returns first occurrence", func(t *testing.T) {
		txs := []*btcutil.Tx{
			btcutil.NewTx(wire.NewMsgTx(1)),
			btcutil.NewTx(wire.NewMsgTx(2)),
			btcutil.NewTx(wire.NewMsgTx(2)), // duplicate of index 1
			btcutil.NewTx(wire.NewMsgTx(3)),
		}
		merkles := BuildMerkleTreeStore(txs, false)
		root := *merkles[len(merkles)-1]
		dup := *txs[1].Hash()
		require.Equal(t, dup, *txs[2].Hash(), "leaves 1 and 2 share a hash")

		branch := ExtractMerkleBranch(merkles, dup)
		require.Equal(t, root, merkleRootFromBranch(dup, 1, branch),
			"first occurrence reconstructs the root")
		require.NotEqual(t, root, merkleRootFromBranch(dup, 2, branch),
			"second occurrence does not")
	})

	// Degenerate stores: nil and empty return nil; a single leaf store
	// yields an empty branch for that leaf and nil for anything else.
	t.Run("degenerate stores", func(t *testing.T) {
		var h chainhash.Hash
		h[0] = 0x01

		require.Nil(t, ExtractMerkleBranch(nil, h))
		require.Nil(t, ExtractMerkleBranch([]*chainhash.Hash{}, h))

		single := []*chainhash.Hash{&h}
		branch := ExtractMerkleBranch(single, h)
		require.NotNil(t, branch)
		require.Len(t, branch, 0)
		require.Equal(t, h, merkleRootFromBranch(h, 0, branch))

		var other chainhash.Hash
		other[0] = 0x02
		require.Nil(t, ExtractMerkleBranch(single, other))
	})
}
