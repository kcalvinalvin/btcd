// Copyright (c) 2023 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
package blockchain

import "testing"

func TestCalculateEntries(t *testing.T) {
	for i := 0; i < 10_000_000; i++ {
		// It's not possible to calculate the exact amount of entries since
		// the map will only allocate for 2^N where N is the amount of buckets.
		//
		// So to see if the calculate entries fucntion is working correctly,
		// we get the rough map size for i entries, then calculate the entries
		// for that map size.  If the size is the same, the function is correct.
		roughMapSize := CalculateRoughMapSize(i, bucketSize)
		entries := CalculateEntries(roughMapSize, bucketSize)
		gotRoughMapSize := CalculateRoughMapSize(entries, bucketSize)

		if roughMapSize != gotRoughMapSize {
			t.Errorf("For hint of %d, expected %v, got %v\n",
				i, roughMapSize, gotRoughMapSize)
		}

		// Test that the entries returned are the maximum for the given map size.
		// If we increment the entries by one, we should get a bigger map.
		gotRoughMapSizeWrong := CalculateRoughMapSize(entries+1, bucketSize)
		if roughMapSize == gotRoughMapSizeWrong {
			t.Errorf("For hint %d incremented by 1, expected %v, got %v\n",
				i, gotRoughMapSizeWrong*2, gotRoughMapSizeWrong)
		}

		minEntries := CalculateMinEntries(roughMapSize, bucketSize)
		gotMinRoughMapSize := CalculateRoughMapSize(minEntries, bucketSize)
		if roughMapSize != gotMinRoughMapSize {
			t.Errorf("For hint of %d, expected %v, got %v\n",
				i, roughMapSize, gotMinRoughMapSize)
		}

		// Can only test if they'll be half the size if the entries aren't 0.
		if minEntries > 0 {
			gotMinRoughMapSizeWrong := CalculateRoughMapSize(minEntries-1, bucketSize)
			if gotMinRoughMapSize == gotMinRoughMapSizeWrong {
				t.Errorf("For hint %d decremented by 1, expected %v, got %v\n",
					i, gotRoughMapSizeWrong/2, gotRoughMapSizeWrong)
			}
		}
	}
}
