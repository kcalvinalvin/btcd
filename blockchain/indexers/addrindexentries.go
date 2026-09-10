// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

func addrEntryBlockID(entry []byte) uint32 {
	return uint32(entry[0]) | uint32(entry[1])<<8 | uint32(entry[2])<<16 | uint32(entry[3])<<24
}

// appendAddrEntry uses the capacity reserved by buildAddrLevelValues.
func appendAddrEntry(entries, entry []byte, offset int) int {
	end := offset + txEntrySize
	copy(entries[offset:end], entry)
	return end
}

// appendAddrLevelEntries retains complete entries at or below the build's
// base block ID so that staged records can be replayed.
func appendAddrLevelEntries(entries, value []byte, offset int, baseBlockID uint32) int {
	for sourceOffset := 0; sourceOffset < len(value); sourceOffset += txEntrySize {
		entry := value[sourceOffset : sourceOffset+txEntrySize]
		blockID := addrEntryBlockID(entry)
		if blockID <= baseBlockID {
			offset = appendAddrEntry(entries, entry, offset)
		}
	}
	return offset
}

func appendAddrRecordEntries(entries []byte, records []addrRecord, offset int) int {
	for i := 0; i < len(records); i += 1 {
		record := (*[addrRecordSize]byte)(&records[i])
		offset = appendAddrEntry(entries, record[addrKeySize:], offset)
	}
	return offset
}
