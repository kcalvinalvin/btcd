//go:build ignore

// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

const addrBuildScanChunkSize = 50000

// @ requires -1 <= completed && completed <= target
// @ requires 0 <= target && target <= 2147483647
// @ ensures rangeStart == int64(completed) + 1
// @ ensures 0 <= rangeStart && rangeStart <= 2147483648
// @ ensures rangeEnd <= int64(target)
// @ ensures completed == target ==> rangeStart == rangeEnd + 1
// @ ensures completed < target ==>
// @ 	rangeStart <= rangeEnd && rangeEnd - rangeStart + 1 <= addrBuildScanChunkSize &&
// @ 	(rangeEnd == int64(target) || rangeEnd - rangeStart + 1 == addrBuildScanChunkSize)
// @ ensures 0 <= rangeEnd && rangeEnd <= 2147483647
// @ decreases
func addrBuildScanRange(completed, target int32) (rangeStart, rangeEnd int64) {
	start := int64(completed) + 1
	end := start + addrBuildScanChunkSize - 1
	if end > int64(target) {
		end = int64(target)
	}
	return start, end
}

// @ requires -1 <= height && height <= 2147483647
// @ ensures int64(result) == int64(height) + 1
// @ ensures 0 <= result && result <= 2147483648
// @ decreases
func addrBuildBlockID(height int32) (result uint32) {
	return uint32(int64(height) + 1)
}

// @ requires 0 <= height && height <= 9223372036854775807
// @ requires 0 <= end && end <= 2147483647
// @ ensures ok == (height <= end)
// @ ensures ok ==> 0 <= result && int64(result) == height && int64(result) <= end
// @ ensures !ok ==> result == 0
// @ decreases
func addrScanHeight(height, end int64) (result int32, ok bool) {
	if height > end {
		return 0, false
	}
	return int32(height), true
}
