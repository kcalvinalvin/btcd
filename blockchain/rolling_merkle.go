package blockchain

import (
	"crypto/sha256"
	"math/bits"

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

func treeRows(n uint64) int {
	if n == 0 {
		return 0
	}

	return bits.Len64(n - 1)
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
	return Stump{Roots: make([]chainhash.Hash, 0, treeRows(uint64(size)))}
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
		root := s.Roots[len(s.Roots)-1]
		s.Roots = s.Roots[:len(s.Roots)-1]

		// Calculate the hash of the new root and append it.
		newRoot = parentHash(root, newRoot)
	}
	s.Roots = append(s.Roots, newRoot)
	s.NumLeaves++
}
