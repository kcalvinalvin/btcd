package blockchain

import (
	"crypto/sha256"
	"math/bits"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// parentHash returns the hash of the left and right hashes passed in.
func parentHash(l, r chainhash.Hash) chainhash.Hash {
	h := sha256.New()
	h.Write(l[:])
	h.Write(r[:])

	buf := make([]byte, 0, 32)
	first := h.Sum(buf)
	h.Reset()
	h.Write(first)
	return *((*chainhash.Hash)(h.Sum(buf)))
}

// Stump is bare-minimum data required to validate and update changes in the accumulator.
// This can also be used to calculate merkle roots.
type Stump struct {
	// Roots are the state of the accumulator.
	Roots []chainhash.Hash
	//  NumLeaves is how many leaves the accumulator has allocated for.
	NumLeaves uint64
}

func NewStump(size int) Stump {
	var alloc int
	if size != 0 {
		alloc = bits.Len64(uint64(size) - 1)
	}
	return Stump{Roots: make([]chainhash.Hash, 0, alloc)}
}

func (s *Stump) calcMerkleRoot(adds []*btcutil.Tx, witness bool) chainhash.Hash {
	for i := range adds {
		// If we're computing a witness merkle root, instead of the
		// regular txid, we use the modified wtxid which includes a
		// transaction's witness data within the digest. Additionally,
		// the coinbase's wtxid is all zeroes.
		switch {
		case witness && i == 0:
			var zeroHash chainhash.Hash
			s.add(zeroHash)
		case witness:
			s.add(*adds[i].WitnessHash())
		default:
			s.add(*adds[i].Hash())
		}
	}

	// If we only have one tx, then the hash of that tx is the merkle root.
	if len(adds) == 1 {
		return s.Roots[0]
	}

	// Add on the last tx again if there's an odd number of txs.
	if len(adds) > 0 && len(adds)&1 == 1 {
		switch {
		case witness:
			s.add(*adds[len(adds)-1].WitnessHash())
		default:
			s.add(*adds[len(adds)-1].Hash())
		}
	}

	// If we still have more than 1 root after adding on the last tx again,
	// we need to do the same for the upper rows.
	//
	// For exmaple, the below tree has 6 leaves.  For row 1, you'll need to
	// hash 'F' with itself to create 'C' so you have something to hash with
	// 'B'.  For bigger trees we may need to do the same in rows 2 or 3 as
	// well.
	//
	// row :3        A
	//              /  \
	// row :2     B     C
	//           / \    |
	// row :1   D   E   F
	//         / \ / \ / \
	// row :0  1 2 3 4 5 6
	for len(s.Roots) > 1 {
		// If we have to keep adding the last node in the set, then
		// move the row up to guarantee that the last node isn't added
		// on as another root.
		currentLeaves := s.NumLeaves
		for h := uint8(0); (currentLeaves>>h)&1 == 0; h++ {
			s.NumLeaves >>= 1
		}

		h := s.Roots[len(s.Roots)-1]
		s.add(h)
	}

	return s.Roots[0]
}

func (s *Stump) add(add chainhash.Hash) {
	// We can tell where the roots are by looking at the binary representation
	// of the numLeaves. Wherever there's a 1, there's a root.
	//
	// numLeaves of 8 will be '1000' in binary, so there will be one root at
	// row 3. numLeaves of 3 will be '11' in binary, so there's two roots. One at
	// row 0 and one at row 1.
	//
	// In this loop below, we're looking for these roots by checking if there's
	// a '1'. If there is a '1', we'll hash the root being added with that root
	// until we hit a '0'.
	newRoot := add
	for h := uint8(0); (s.NumLeaves>>h)&1 == 1; h++ {
		// Grab the last root.
		root := s.Roots[len(s.Roots)-1]

		// Pop off the last root.
		s.Roots = s.Roots[:len(s.Roots)-1]

		// Calculate the hash of the new root and append it.
		newRoot = parentHash(root, newRoot)
	}
	s.Roots = append(s.Roots, newRoot)
	s.NumLeaves++
}
