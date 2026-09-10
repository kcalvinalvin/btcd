// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

// addrBuildScanRange keeps the position after the last height representable.
func addrBuildScanRange(completed, target int32) (int64, int64) {
	start := int64(completed) + 1
	end := start + addrBuildScanChunkSize - 1
	if end > int64(target) {
		end = int64(target)
	}
	return start, end
}

// addrBuildBlockID maps the empty index height to zero and genesis to one.
func addrBuildBlockID(height int32) uint32 {
	return uint32(int64(height) + 1)
}

func addrScanHeight(height, end int64) (int32, bool) {
	if height > end {
		return 0, false
	}
	return int32(height), true
}
