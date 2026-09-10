//go:build ignore

// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

const txEntrySize = 4 + 4 + 4
const addrKeySize = 1 + 20
const addrRecordSize = addrKeySize + txEntrySize

type addrRecord [addrRecordSize]byte

/*@
ghost
requires len(entry) >= 4
decreases
pure func addrEntryID(entry seq[byte]) uint32 {
    return uint32(entry[0]) | uint32(entry[1])<<8 | uint32(entry[2])<<16 | uint32(entry[3])<<24
}
@*/

// @ requires acc(entry, 1/2)
// @ requires len(entry) >= 4
// @ ensures result == addrEntryID(seq(entry))
// @ decreases
// @ pure
func addrEntryBlockID(entry []byte) (result uint32) {
	return uint32(entry[0]) | uint32(entry[1])<<8 | uint32(entry[2])<<16 | uint32(entry[3])<<24
}

/*@
pred addrEntryBuffer(value []byte, contents seq[byte]) {
    acc(value) && seq(value) == contents
}
@*/

/*@
ghost
requires len(entry) == txEntrySize
requires 0 <= offset && offset + txEntrySize <= len(entries)
ensures len(result) == len(entries)
ensures result[:offset+txEntrySize] == entries[:offset] ++ entry
ensures result[offset+txEntrySize:] == entries[offset+txEntrySize:]
decreases
pure func addrEntryBytes(entries, entry seq[byte], offset int) (result seq[byte]) {
    return entries[:offset] ++ entry ++ entries[offset+txEntrySize:]
}
@*/

// @ requires addrEntryBuffer(entries, originalEntries)
// @ requires acc(addrEntryBuffer(entry, entryValue), 1/2)
// @ requires len(entry) == txEntrySize
// @ requires len(entryValue) == txEntrySize
// @ requires len(originalEntries) == len(entries)
// @ requires len(entries) <= 9223372036854775807
// @ requires 0 <= offset && offset + txEntrySize <= len(entries)
// @ ensures result == offset + txEntrySize
// @ ensures addrEntryBuffer(entries, addrEntryBytes(originalEntries, entryValue, offset))
// @ ensures acc(addrEntryBuffer(entry, entryValue), 1/2)
// @ decreases
func appendAddrEntry(entries, entry []byte, offset int /*@ , ghost originalEntries seq[byte], ghost entryValue seq[byte] @*/) (result int) {
	//@ unfold addrEntryBuffer(entries, originalEntries)
	//@ unfold acc(addrEntryBuffer(entry, entryValue), 1/2)
	end := offset + txEntrySize
	//@ assert forall i int :: {&entries[offset:end][i]} 0 <= i && i < txEntrySize ==> &entries[offset:end][i] == &entries[offset+i]
	//@ assert acc(entries[offset:end])
	copy(entries[offset:end], entry /*@ , perm(1/2) @*/)
	//@ assert acc(entries)
	//@ assert acc(entry, 1/2)
	//@ assert seq(entry) == entryValue
	//@ assert seq(entries[offset:end]) == seq(entry)
	//@ assert forall i int :: {&entries[offset+i]} 0 <= i && i < txEntrySize ==> &entries[offset+i] == &entries[offset:end][i]
	//@ assert forall i int :: {&entries[offset+i]} 0 <= i && i < txEntrySize ==> entries[offset+i] == entry[i]
	//@ assert seq(entries) == originalEntries[:offset] ++ seq(entry) ++ originalEntries[end:]
	//@ fold addrEntryBuffer(entries, addrEntryBytes(originalEntries, entryValue, offset))
	//@ fold acc(addrEntryBuffer(entry, entryValue), 1/2)
	return end
}

/*@
ghost
requires len(value) % txEntrySize == 0
decreases len(value)
ensures len(result) % txEntrySize == 0
ensures len(result) <= len(value)
pure func addrBaseEntries(value seq[byte], baseBlockID uint32) (result seq[byte]) {
    return len(value) == 0 ? seq[byte]{} :
        addrBaseEntries(value[:len(value)-txEntrySize], baseBlockID) ++ (addrEntryID(value[len(value)-txEntrySize:]) <= baseBlockID ? value[len(value)-txEntrySize:] : seq[byte]{})
}
@*/

/*@
ghost
requires 0 <= offset && offset + txEntrySize <= len(value)
requires offset % txEntrySize == 0
ensures prefix ++ addrBaseEntries(value[:offset+txEntrySize], baseBlockID) ==
    (prefix ++ addrBaseEntries(value[:offset], baseBlockID)) ++ (addrEntryID(value[offset:offset+txEntrySize]) <= baseBlockID ? value[offset:offset+txEntrySize] : seq[byte]{})
decreases
func addrBaseEntriesStep(prefix, value seq[byte], offset int, baseBlockID uint32) {
    assert value[:offset+txEntrySize][:offset] == value[:offset]
    assert value[:offset+txEntrySize][offset:] == value[offset:offset+txEntrySize]
}
@*/

// @ requires acc(entries)
// @ requires acc(value)
// @ requires len(value) % txEntrySize == 0
// @ requires len(entries) <= 9223372036854775807
// @ requires 0 <= offset && offset + len(value) <= len(entries)
// @ ensures acc(entries)
// @ ensures acc(value)
// @ ensures seq(value) == old(seq(value))
// @ ensures offset <= result && result <= offset + len(value)
// @ ensures seq(entries) == old(seq(entries))[:offset] ++ addrBaseEntries(seq(value), baseBlockID) ++ old(seq(entries))[result:]
// @ decreases
func appendAddrLevelEntries(entries, value []byte, offset int, baseBlockID uint32) (result int) {
	//@ ghost originalEntries := seq(entries)
	//@ ghost originalValue := seq(value)
	//@ ghost start := offset
	//@ ghost currentEntries := originalEntries
	//@ fold addrEntryBuffer(entries, currentEntries)
	//@ fold addrEntryBuffer(value, originalValue)
	//@ invariant addrEntryBuffer(entries, currentEntries)
	//@ invariant len(currentEntries) == len(entries)
	//@ invariant addrEntryBuffer(value, originalValue)
	//@ invariant 0 <= sourceOffset && sourceOffset <= len(value)
	//@ invariant sourceOffset % txEntrySize == 0
	//@ invariant start <= offset && offset <= start + sourceOffset
	//@ invariant 0 <= offset && offset <= len(entries)
	//@ invariant offset + len(value) - sourceOffset <= len(entries)
	//@ invariant currentEntries[:offset] == originalEntries[:start] ++ addrBaseEntries(originalValue[:sourceOffset], baseBlockID)
	//@ invariant currentEntries[offset:] == originalEntries[offset:]
	//@ decreases len(value) - sourceOffset
	for sourceOffset := 0; sourceOffset < len(value); sourceOffset += txEntrySize {
		//@ unfold addrEntryBuffer(value, originalValue)
		entry := value[sourceOffset : sourceOffset+txEntrySize]
		//@ assert forall i int :: {&entry[i]} 0 <= i && i < len(entry) ==> &entry[i] == &value[sourceOffset+i]
		//@ assert forall i int :: {&entry[i]} 0 <= i && i < len(entry) ==> acc(&value[sourceOffset+i])
		//@ assert acc(entry)
		//@ assert seq(entry) == originalValue[sourceOffset:sourceOffset+txEntrySize]
		//@ ghost entryValue := seq(entry)
		//@ addrBaseEntriesStep(originalEntries[:start], originalValue, sourceOffset, baseBlockID)
		blockID := addrEntryBlockID(entry)
		//@ assert blockID == addrEntryID(entryValue)
		if blockID <= baseBlockID {
			//@ ghost previousOffset := offset
			//@ ghost prefixEntries := currentEntries[:offset]
			//@ ghost nextEntries := addrEntryBytes(currentEntries, entryValue, offset)
			//@ assert len(prefixEntries) == offset
			//@ assert currentEntries[offset+txEntrySize:] == originalEntries[offset+txEntrySize:]
			//@ fold acc(addrEntryBuffer(entry, entryValue), 1/2)
			offset = appendAddrEntry(entries, entry, offset /*@ , currentEntries, entryValue @*/)
			//@ currentEntries = nextEntries
			//@ assert offset == previousOffset + txEntrySize
			//@ assert len(prefixEntries) + len(entryValue) == offset
			//@ assert currentEntries[:offset] == prefixEntries ++ entryValue
			//@ assert currentEntries[offset:] == originalEntries[offset:]
			//@ assert currentEntries[:offset] == originalEntries[:start] ++ addrBaseEntries(originalValue[:sourceOffset+txEntrySize], baseBlockID)
			//@ unfold acc(addrEntryBuffer(entry, entryValue), 1/2)
		}
		//@ assert currentEntries[:offset] == originalEntries[:start] ++ addrBaseEntries(originalValue[:sourceOffset+txEntrySize], baseBlockID)
		//@ fold addrEntryBuffer(value, originalValue)
	}
	//@ unfold addrEntryBuffer(entries, currentEntries)
	//@ unfold addrEntryBuffer(value, originalValue)
	//@ assert originalValue[:len(value)] == originalValue
	//@ assert seq(entries) == seq(entries)[:offset] ++ seq(entries)[offset:]
	return offset
}

/*@
ghost
requires forall i int :: {records[i]} 0 <= i && i < len(records) ==> len(records[i]) == addrRecordSize
ensures len(result) == len(records) * txEntrySize
decreases len(records)
pure func addrRecordEntries(records seq[seq[byte]]) (result seq[byte]) {
    return len(records) == 0 ? seq[byte]{} :
        addrRecordEntries(records[:len(records)-1]) ++ records[len(records)-1][addrKeySize:]
}
@*/

/*@
pred addrRecordAccess(record *addrRecord) {
    record != nil && acc(record)
}
@*/

// @ requires acc(entries)
// @ requires len(recordValues) == len(records)
// @ requires forall i int :: {recordValues[i]} 0 <= i && i < len(records) ==> len(recordValues[i]) == addrRecordSize
// @ requires forall i int :: {&records[i]} 0 <= i && i < len(records) ==> acc(addrRecordAccess(&records[i]), 1/2)
// @ requires forall i int :: {&records[i]} 0 <= i && i < len(records) ==>
// @     unfolding acc(addrRecordAccess(&records[i]), 1/2) in
// @         forall j int :: {records[i][j]} 0 <= j && j < addrRecordSize ==> records[i][j] == recordValues[i][j]
// @ requires len(entries) <= 9223372036854775807
// @ requires 0 <= offset && offset + len(records) * txEntrySize <= len(entries)
// @ ensures acc(entries)
// @ ensures result == offset + len(records) * txEntrySize
// @ ensures forall i int :: {&records[i]} 0 <= i && i < len(records) ==> acc(addrRecordAccess(&records[i]), 1/2)
// @ ensures forall i int :: {&records[i]} 0 <= i && i < len(records) ==>
// @     unfolding acc(addrRecordAccess(&records[i]), 1/2) in
// @         forall j int :: {records[i][j]} 0 <= j && j < addrRecordSize ==> records[i][j] == recordValues[i][j]
// @ ensures seq(entries) == old(seq(entries))[:offset] ++ addrRecordEntries(recordValues) ++ old(seq(entries))[result:]
// @ decreases
func appendAddrRecordEntries(entries []byte, records []addrRecord, offset int /*@ , ghost recordValues seq[seq[byte]] @*/) (result int) {
	//@ ghost originalEntries := seq(entries)
	//@ ghost start := offset
	//@ ghost currentEntries := originalEntries
	//@ fold addrEntryBuffer(entries, currentEntries)
	//@ invariant addrEntryBuffer(entries, currentEntries)
	//@ invariant len(currentEntries) == len(entries)
	//@ invariant len(recordValues) == len(records)
	//@ invariant forall k int :: {recordValues[k]} 0 <= k && k < len(records) ==> len(recordValues[k]) == addrRecordSize
	//@ invariant forall k int :: {&records[k]} 0 <= k && k < len(records) ==> acc(addrRecordAccess(&records[k]), 1/2)
	//@ invariant forall k int :: {&records[k]} 0 <= k && k < len(records) ==>
	//@ unfolding acc(addrRecordAccess(&records[k]), 1/2) in
	//@ forall j int :: {records[k][j]} 0 <= j && j < addrRecordSize ==> records[k][j] == recordValues[k][j]
	//@ invariant 0 <= i && i <= len(records)
	//@ invariant offset == start + i * txEntrySize
	//@ invariant 0 <= offset && offset <= len(entries)
	//@ invariant offset + (len(records)-i) * txEntrySize <= len(entries)
	//@ invariant currentEntries[:offset] == originalEntries[:start] ++ addrRecordEntries(recordValues[:i])
	//@ invariant currentEntries[offset:] == originalEntries[offset:]
	//@ decreases len(records) - i
	for i := 0; i < len(records); i += 1 {
		//@ unfold acc(addrRecordAccess(&records[i]), 1/2)
		record := (*[addrRecordSize]byte)(&records[i])
		//@ assert forall j int :: {&record[j]} 0 <= j && j < addrRecordSize ==> &record[j] == &records[i][j]
		//@ assert seq(record[:]) == recordValues[i]
		//@ ghost previousOffset := offset
		//@ ghost prefixEntries := currentEntries[:offset]
		//@ ghost nextEntries := addrEntryBytes(currentEntries, recordValues[i][addrKeySize:], offset)
		//@ assert len(prefixEntries) == offset
		//@ assert seq(record[addrKeySize:]) == recordValues[i][addrKeySize:]
		//@ assert currentEntries[offset+txEntrySize:] == originalEntries[offset+txEntrySize:]
		//@ fold acc(addrEntryBuffer(record[addrKeySize:], recordValues[i][addrKeySize:]), 1/2)
		offset = appendAddrEntry(entries, record[addrKeySize:], offset /*@ , currentEntries, recordValues[i][addrKeySize:] @*/)
		//@ currentEntries = nextEntries
		//@ assert offset == previousOffset + txEntrySize
		//@ assert len(prefixEntries) + txEntrySize == offset
		//@ assert currentEntries[:offset] == prefixEntries ++ recordValues[i][addrKeySize:]
		//@ assert currentEntries[offset:] == originalEntries[offset:]
		//@ assert recordValues[:i+1][:i] == recordValues[:i]
		//@ assert recordValues[:i+1][i] == recordValues[i]
		//@ assert addrRecordEntries(recordValues[:i+1]) == addrRecordEntries(recordValues[:i]) ++ recordValues[i][addrKeySize:]
		//@ assert currentEntries[:offset] == originalEntries[:start] ++ addrRecordEntries(recordValues[:i+1])
		//@ unfold acc(addrEntryBuffer(record[addrKeySize:], recordValues[i][addrKeySize:]), 1/2)
		//@ fold acc(addrRecordAccess(&records[i]), 1/2)
	}
	//@ unfold addrEntryBuffer(entries, currentEntries)
	//@ assert recordValues[:len(records)] == recordValues
	//@ assert seq(entries) == seq(entries)[:offset] ++ seq(entries)[offset:]
	return offset
}

/*@
ghost
requires len(left) % txEntrySize == 0 && len(right) % txEntrySize == 0
ensures addrBaseEntries(left ++ right, baseBlockID) == addrBaseEntries(left, baseBlockID) ++ addrBaseEntries(right, baseBlockID)
decreases len(right)
func addrBaseEntriesAppend(left, right seq[byte], baseBlockID uint32) {
    if len(right) > 0 {
        ghost prefix := right[:len(right)-txEntrySize]
        ghost entry := right[len(right)-txEntrySize:]
        addrBaseEntriesAppend(left, prefix, baseBlockID)
        assert (left ++ right)[:len(left)+len(prefix)] == left ++ prefix
        assert (left ++ right)[len(left)+len(prefix):] == entry
    }
}
@*/

/*@
ghost
requires len(value) % txEntrySize == 0
ensures addrBaseEntries(addrBaseEntries(value, baseBlockID), baseBlockID) == addrBaseEntries(value, baseBlockID)
decreases len(value)
func addrBaseEntriesIdempotent(value seq[byte], baseBlockID uint32) {
    if len(value) > 0 {
        ghost prefix := value[:len(value)-txEntrySize]
        ghost entry := value[len(value)-txEntrySize:]
        addrBaseEntriesIdempotent(prefix, baseBlockID)
        if addrEntryID(entry) <= baseBlockID {
            addrBaseEntriesAppend(addrBaseEntries(prefix, baseBlockID), entry, baseBlockID)
        }
    }
}
@*/

/*@
ghost
requires len(value) % txEntrySize == 0
decreases len(value)
pure func addrEntriesAfterBase(value seq[byte], baseBlockID uint32) bool {
    return len(value) == 0 ||
        (addrEntriesAfterBase(value[:len(value)-txEntrySize], baseBlockID) && addrEntryID(value[len(value)-txEntrySize:]) > baseBlockID)
}
@*/

/*@
ghost
requires len(value) % txEntrySize == 0
requires addrEntriesAfterBase(value, baseBlockID)
ensures addrBaseEntries(value, baseBlockID) == seq[byte]{}
decreases len(value)
func addrBaseEntriesAfterBase(value seq[byte], baseBlockID uint32) {
    if len(value) > 0 {
        addrBaseEntriesAfterBase(value[:len(value)-txEntrySize], baseBlockID)
    }
}
@*/

/*@
ghost
requires len(existing) % txEntrySize == 0 && len(staged) % txEntrySize == 0
requires addrEntriesAfterBase(staged, baseBlockID)
ensures addrBaseEntries(addrBaseEntries(existing, baseBlockID) ++ staged, baseBlockID) ++ staged ==
    addrBaseEntries(existing, baseBlockID) ++ staged
decreases
func addrReplayEntries(existing, staged seq[byte], baseBlockID uint32) {
    addrBaseEntriesAppend(addrBaseEntries(existing, baseBlockID), staged, baseBlockID)
    addrBaseEntriesIdempotent(existing, baseBlockID)
    addrBaseEntriesAfterBase(staged, baseBlockID)
}
@*/
