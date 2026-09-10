// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScanAddrHeightRangeCompleted(t *testing.T) {
	t.Parallel()

	idx := &AddrIndex{}
	for _, end := range []int64{0, math.MaxInt32} {
		require.NoError(t, idx.scanAddrHeightRange(
			nil, nil, end+1, end, addrBuildDecodedScanMaxWorkers,
			nil, nil,
		))
	}
}
