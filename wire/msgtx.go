// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unsafe"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

const (
	// TxVersion is the current latest supported transaction version.
	TxVersion = 1

	// MaxTxInSequenceNum is the maximum sequence number the sequence field
	// of a transaction input can be.
	MaxTxInSequenceNum uint32 = 0xffffffff

	// MaxPrevOutIndex is the maximum index the index field of a previous
	// outpoint can be.
	MaxPrevOutIndex uint32 = 0xffffffff

	// SequenceLockTimeDisabled is a flag that if set on a transaction
	// input's sequence number, the sequence number will not be interpreted
	// as a relative locktime.
	SequenceLockTimeDisabled = 1 << 31

	// SequenceLockTimeIsSeconds is a flag that if set on a transaction
	// input's sequence number, the relative locktime has units of 512
	// seconds.
	SequenceLockTimeIsSeconds = 1 << 22

	// SequenceLockTimeMask is a mask that extracts the relative locktime
	// when masked against the transaction input sequence number.
	SequenceLockTimeMask = 0x0000ffff

	// SequenceLockTimeGranularity is the defined time based granularity
	// for seconds-based relative time locks. When converting from seconds
	// to a sequence number, the value is right shifted by this amount,
	// therefore the granularity of relative time locks in 512 or 2^9
	// seconds. Enforced relative lock times are multiples of 512 seconds.
	SequenceLockTimeGranularity = 9

	// minTxInPayload is the minimum payload size for a transaction input.
	// PreviousOutPoint.Hash + PreviousOutPoint.Index 4 bytes + Varint for
	// SignatureScript length 1 byte + Sequence 4 bytes.
	minTxInPayload = 9 + chainhash.HashSize

	// maxTxInPerMessage is the maximum number of transactions inputs that
	// a transaction which fits into a message could possibly have.
	maxTxInPerMessage = (MaxMessagePayload / minTxInPayload) + 1

	// MinTxOutPayload is the minimum payload size for a transaction output.
	// Value 8 bytes + Varint for PkScript length 1 byte.
	MinTxOutPayload = 9

	// maxTxOutPerMessage is the maximum number of transactions outputs that
	// a transaction which fits into a message could possibly have.
	maxTxOutPerMessage = (MaxMessagePayload / MinTxOutPayload) + 1

	// minTxPayload is the minimum payload size for a transaction.  Note
	// that any realistically usable transaction must have at least one
	// input or output, but that is a rule enforced at a higher layer, so
	// it is intentionally not included here.
	// Version 4 bytes + Varint number of transaction inputs 1 byte + Varint
	// number of transaction outputs 1 byte + LockTime 4 bytes + min input
	// payload + min output payload.
	minTxPayload = 10

	// maxWitnessItemsPerInput is the maximum number of witness items to
	// be read for the witness data for a single TxIn. This number is
	// derived using a possible lower bound for the encoding of a witness
	// item: 1 byte for length + 1 byte for the witness item itself, or two
	// bytes. This value is then divided by the currently allowed maximum
	// "cost" for a transaction. We use this for an upper bound for the
	// buffer and consensus makes sure that the weight of a transaction
	// cannot be more than 4000000.
	maxWitnessItemsPerInput = 4_000_000

	// maxWitnessItemSize is the maximum allowed size for an item within
	// an input's witness data. This value is bounded by the largest
	// possible block size, post segwit v1 (taproot).
	maxWitnessItemSize = 4_000_000
)

var (
	// errSuperfluousWitnessRecord is returned during tx deserialization when
	// a tx has the witness marker flag set but has no witnesses.
	errSuperfluousWitnessRecord = fmt.Errorf(
		"witness flag set but tx has no witnesses",
	)
)

// TxFlagMarker is the first byte of the FLAG field in a bitcoin tx
// message. It allows decoders to distinguish a regular serialized
// transaction from one that would require a different parsing logic.
//
// Position of FLAG in a bitcoin tx message:
//
//	┌─────────┬────────────────────┬─────────────┬─────┐
//	│ VERSION │ FLAG               │ TX-IN-COUNT │ ... │
//	│ 4 bytes │ 2 bytes (optional) │ varint      │     │
//	└─────────┴────────────────────┴─────────────┴─────┘
//
// Zooming into the FLAG field:
//
//	┌── FLAG ─────────────┬────────┐
//	│ TxFlagMarker (0x00) │ TxFlag │
//	│ 1 byte              │ 1 byte │
//	└─────────────────────┴────────┘
const TxFlagMarker = 0x00

// TxFlag is the second byte of the FLAG field in a bitcoin tx message.
// It indicates the decoding logic to use in the transaction parser, if
// TxFlagMarker is detected in the tx message.
//
// As of writing this, only the witness flag (0x01) is supported, but may be
// extended in the future to accommodate auxiliary non-committed fields.
type TxFlag = byte

const (
	// WitnessFlag is a flag specific to witness encoding. If the TxFlagMarker
	// is encountered followed by the WitnessFlag, then it indicates a
	// transaction has witness data. This allows decoders to distinguish a
	// serialized transaction with witnesses from a legacy one.
	WitnessFlag TxFlag = 0x01
)

// OutPoint defines a bitcoin data type that is used to track previous
// transaction outputs.
type OutPoint struct {
	Hash  chainhash.Hash
	Index uint32
}

// NewOutPoint returns a new bitcoin transaction outpoint point with the
// provided hash and index.
func NewOutPoint(hash *chainhash.Hash, index uint32) *OutPoint {
	return &OutPoint{
		Hash:  *hash,
		Index: index,
	}
}

// NewOutPointFromString returns a new bitcoin transaction outpoint parsed from
// the provided string, which should be in the format "hash:index".
func NewOutPointFromString(outpoint string) (*OutPoint, error) {
	parts := strings.Split(outpoint, ":")
	if len(parts) != 2 {
		return nil, errors.New("outpoint should be of the form txid:index")
	}

	if len(parts[0]) != chainhash.MaxHashStringSize {
		return nil, errors.New("outpoint txid should be 64 hex chars")
	}

	hash, err := chainhash.NewHashFromStr(parts[0])
	if err != nil {
		return nil, err
	}

	outputIndex, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid output index: %v", err)
	}

	return &OutPoint{
		Hash:  *hash,
		Index: uint32(outputIndex),
	}, nil
}

// String returns the OutPoint in the human-readable form "hash:index".
func (o OutPoint) String() string {
	// Allocate enough for hash string, colon, and 10 digits.  Although
	// at the time of writing, the number of digits can be no greater than
	// the length of the decimal representation of maxTxOutPerMessage, the
	// maximum message payload may increase in the future and this
	// optimization may go unnoticed, so allocate space for 10 decimal
	// digits, which will fit any uint32.
	buf := make([]byte, 2*chainhash.HashSize+1, 2*chainhash.HashSize+1+10)
	copy(buf, o.Hash.String())
	buf[2*chainhash.HashSize] = ':'
	buf = strconv.AppendUint(buf, uint64(o.Index), 10)
	return string(buf)
}

// TxIn defines a bitcoin transaction input.
type TxIn struct {
	PreviousOutPoint OutPoint
	SignatureScript  []byte
	Witness          TxWitness
	Sequence         uint32
}

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction input.
func (t *TxIn) SerializeSize() int {
	// Outpoint Hash 32 bytes + Outpoint Index 4 bytes + Sequence 4 bytes +
	// serialized varint size for the length of SignatureScript +
	// SignatureScript bytes.
	return 40 + VarIntSerializeSize(uint64(len(t.SignatureScript))) +
		len(t.SignatureScript)
}

// NewTxIn returns a new bitcoin transaction input with the provided
// previous outpoint point and signature script with a default sequence of
// MaxTxInSequenceNum.
func NewTxIn(prevOut *OutPoint, signatureScript []byte, witness [][]byte) *TxIn {
	return &TxIn{
		PreviousOutPoint: *prevOut,
		SignatureScript:  signatureScript,
		Witness:          witness,
		Sequence:         MaxTxInSequenceNum,
	}
}

// TxWitness defines the witness for a TxIn. A witness is to be interpreted as
// a slice of byte slices, or a stack with one or many elements.
type TxWitness [][]byte

// SerializeSize returns the number of bytes it would take to serialize the
// transaction input's witness.
func (t TxWitness) SerializeSize() int {
	// A varint to signal the number of elements the witness has.
	n := VarIntSerializeSize(uint64(len(t)))

	// For each element in the witness, we'll need a varint to signal the
	// size of the element, then finally the number of bytes the element
	// itself comprises.
	for _, witItem := range t {
		n += VarIntSerializeSize(uint64(len(witItem)))
		n += len(witItem)
	}

	return n
}

// ToHexStrings formats the witness stack as a slice of hex-encoded strings.
func (t TxWitness) ToHexStrings() []string {
	// Ensure nil is returned when there are no entries versus an empty
	// slice so it can properly be omitted as necessary.
	if len(t) == 0 {
		return nil
	}

	result := make([]string, len(t))
	for idx, wit := range t {
		result[idx] = hex.EncodeToString(wit)
	}

	return result
}

// TxOut defines a bitcoin transaction output.
type TxOut struct {
	Value    int64
	PkScript []byte
}

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction output.
func (t *TxOut) SerializeSize() int {
	// Value 8 bytes + serialized varint size for the length of PkScript +
	// PkScript bytes.
	return 8 + VarIntSerializeSize(uint64(len(t.PkScript))) + len(t.PkScript)
}

// NewTxOut returns a new bitcoin transaction output with the provided
// transaction value and public key script.
func NewTxOut(value int64, pkScript []byte) *TxOut {
	return &TxOut{
		Value:    value,
		PkScript: pkScript,
	}
}

// MsgTx implements the Message interface and represents a bitcoin tx message.
// It is used to deliver transaction information in response to a getdata
// message (MsgGetData) for a given transaction.
//
// MsgTx uses a zero-allocation tokenizer approach: all data is stored as raw
// bytes and parsed on-demand. Use NewMsgTx to create transactions from fields,
// or NewMsgTxFromBytes to parse from serialized bytes.
type MsgTx struct {
	Version  int32
	LockTime uint32

	data         []byte
	hasWitness   bool
	inputCount   int
	outputCount  int
	inputsStart  int
	outputsStart int
	witnessStart int

	// Cached parsed data - lazily initialized on first access.
	// Using slices of structs (not pointers) reduces allocations.
	txInSlice  []TxIn
	txOutSlice []TxOut
}

// InputCount returns the number of inputs.
func (msg *MsgTx) InputCount() int {
	return msg.inputCount
}

// OutputCount returns the number of outputs.
func (msg *MsgTx) OutputCount() int {
	return msg.outputCount
}

// TxIn returns a pointer to the input at the given index.
// The returned pointer points into an internal cache and should not be modified.
// TxIn returns all transaction inputs as a slice.
// The returned slice points into an internal cache and should not be modified.
func (msg *MsgTx) TxIn() []TxIn {
	if msg.txInSlice == nil {
		msg.parseInputs()
	}
	return msg.txInSlice
}

// parseInputs parses all transaction inputs into a contiguous slice.
// This results in a single allocation for all inputs.
func (msg *MsgTx) parseInputs() {
	if msg.txInSlice != nil {
		return
	}

	// Single allocation for all inputs.
	msg.txInSlice = make([]TxIn, msg.inputCount)
	offset := msg.inputsStart

	for i := range msg.inputCount {
		ti := &msg.txInSlice[i]
		copy(ti.PreviousOutPoint.Hash[:], msg.data[offset:offset+32])
		ti.PreviousOutPoint.Index = littleEndian.Uint32(msg.data[offset+32 : offset+36])
		offset += 36

		scriptLen, n := deserializeVarInt(msg.data[offset:])
		offset += n
		ti.SignatureScript = msg.data[offset : offset+int(scriptLen)]
		offset += int(scriptLen)

		ti.Sequence = littleEndian.Uint32(msg.data[offset : offset+4])
		offset += 4
	}

	// Parse witnesses if present.
	if msg.hasWitness {
		offset = msg.witnessStart
		for i := range msg.inputCount {
			witCount, n := deserializeVarInt(msg.data[offset:])
			offset += n

			if witCount > 0 {
				msg.txInSlice[i].Witness = make(TxWitness, witCount)
				for j := range witCount {
					itemLen, n := deserializeVarInt(msg.data[offset:])
					offset += n
					msg.txInSlice[i].Witness[j] = msg.data[offset : offset+int(itemLen)]
					offset += int(itemLen)
				}
			}
		}
	}
}

// TxOut returns a pointer to the output at the given index.
// The returned pointer points into an internal cache and should not be modified.
// TxOut returns all transaction outputs as a slice.
// The returned slice points into an internal cache and should not be modified.
func (msg *MsgTx) TxOut() []TxOut {
	if msg.txOutSlice == nil {
		msg.parseOutputs()
	}
	return msg.txOutSlice
}

// parseOutputs parses all transaction outputs into a contiguous slice.
// This results in a single allocation for all outputs.
func (msg *MsgTx) parseOutputs() {
	if msg.txOutSlice != nil {
		return
	}

	// Single allocation for all outputs.
	msg.txOutSlice = make([]TxOut, msg.outputCount)
	offset := msg.outputsStart

	for i := range msg.outputCount {
		to := &msg.txOutSlice[i]
		to.Value = int64(littleEndian.Uint64(msg.data[offset : offset+8]))
		offset += 8

		scriptLen, n := deserializeVarInt(msg.data[offset:])
		offset += n
		to.PkScript = msg.data[offset : offset+int(scriptLen)]
		offset += int(scriptLen)
	}
}

// Witness returns the witness data for the input at the given index.
func (msg *MsgTx) Witness(inputIndex int) (TxWitness, error) {
	if inputIndex < 0 || inputIndex >= msg.inputCount {
		return nil, fmt.Errorf("input index %d out of range [0, %d)", inputIndex, msg.inputCount)
	}
	if !msg.hasWitness {
		return nil, nil
	}

	txIns := msg.TxIn()
	return txIns[inputIndex].Witness, nil
}

// TxHash generates the Hash for the transaction (without witness data).
func (msg *MsgTx) TxHash() chainhash.Hash {
	if !msg.hasWitness {
		return chainhash.DoubleHashRaw(func(w io.Writer) error {
			_, err := w.Write(msg.data)
			return err
		})
	}

	// Strip witness data for hash computation.
	return chainhash.DoubleHashRaw(func(w io.Writer) error {
		// Version (4 bytes).
		if _, err := w.Write(msg.data[:4]); err != nil {
			return err
		}
		// Skip marker+flag (2 bytes), write from inputs through outputs.
		endOutputs := msg.witnessStart
		if _, err := w.Write(msg.data[6:endOutputs]); err != nil {
			return err
		}
		// LockTime (last 4 bytes).
		_, err := w.Write(msg.data[len(msg.data)-4:])
		return err
	})
}

// TxID generates the transaction ID of the transaction.
func (msg *MsgTx) TxID() string {
	return msg.TxHash().String()
}

// WitnessHash generates the hash of the transaction serialized according to
// the new witness serialization defined in BIP0141 and BIP0144. The final
// output is used within the Segregated Witness commitment of all the witnesses
// within a block. If a transaction has no witness data, then the witness hash,
// is the same as its txid.
func (msg *MsgTx) WitnessHash() chainhash.Hash {
	return chainhash.DoubleHashRaw(func(w io.Writer) error {
		_, err := w.Write(msg.data)
		return err
	})
}

// Copy creates a deep copy of a transaction so that the original does not get
// modified when the copy is manipulated.
func (msg *MsgTx) Copy() *MsgTx {
	dataCopy := make([]byte, len(msg.data))
	copy(dataCopy, msg.data)

	cp := &MsgTx{
		data:         dataCopy,
		Version:      msg.Version,
		LockTime:     msg.LockTime,
		hasWitness:   msg.hasWitness,
		inputCount:   msg.inputCount,
		outputCount:  msg.outputCount,
		inputsStart:  msg.inputsStart,
		outputsStart: msg.outputsStart,
		witnessStart: msg.witnessStart,
	}

	// Copy cached inputs if present, updating byte slice references to new data.
	if msg.txInSlice != nil {
		cp.txInSlice = make([]TxIn, len(msg.txInSlice))
		for i := range msg.txInSlice {
			ti := &msg.txInSlice[i]
			newTi := &cp.txInSlice[i]
			newTi.PreviousOutPoint = ti.PreviousOutPoint
			newTi.Sequence = ti.Sequence

			// Update SignatureScript to point to the new data slice.
			if len(ti.SignatureScript) > 0 {
				offset := int(uintptr(unsafe.Pointer(&ti.SignatureScript[0])) -
					uintptr(unsafe.Pointer(&msg.data[0])))
				newTi.SignatureScript = dataCopy[offset : offset+len(ti.SignatureScript)]
			}

			// Update Witness to point to the new data slice.
			if len(ti.Witness) > 0 {
				newTi.Witness = make(TxWitness, len(ti.Witness))
				for j, wit := range ti.Witness {
					if len(wit) > 0 {
						offset := int(uintptr(unsafe.Pointer(&wit[0])) -
							uintptr(unsafe.Pointer(&msg.data[0])))
						newTi.Witness[j] = dataCopy[offset : offset+len(wit)]
					}
				}
			}
		}
	}

	// Copy cached outputs if present, updating byte slice references to new data.
	if msg.txOutSlice != nil {
		cp.txOutSlice = make([]TxOut, len(msg.txOutSlice))
		for i := range msg.txOutSlice {
			to := &msg.txOutSlice[i]
			newTo := &cp.txOutSlice[i]
			newTo.Value = to.Value

			// Update PkScript to point to the new data slice.
			if len(to.PkScript) > 0 {
				offset := int(uintptr(unsafe.Pointer(&to.PkScript[0])) -
					uintptr(unsafe.Pointer(&msg.data[0])))
				newTo.PkScript = dataCopy[offset : offset+len(to.PkScript)]
			}
		}
	}

	return cp
}

// Bytes returns the raw serialized transaction bytes.
func (msg *MsgTx) Bytes() []byte {
	return msg.data
}


// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
// See Deserialize for decoding transactions stored to disk, such as in a
// database, as opposed to decoding transactions from the wire.
func (msg *MsgTx) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	parsed, err := NewMsgTxFromBytes(data)
	if err != nil {
		return err
	}

	*msg = *parsed
	return nil
}

// Deserialize decodes a transaction from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field in the transaction.  This function differs from BtcDecode
// in that BtcDecode decodes from the bitcoin wire protocol as it was sent
// across the network.  The wire encoding can technically differ depending on
// the protocol version and doesn't even really need to match the format of a
// stored transaction at all.  As of the time this comment was written, the
// encoded transaction is the same in both instances, but there is a distinct
// difference and separating the two allows the API to be flexible enough to
// deal with changes.
func (msg *MsgTx) Deserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of BtcDecode.
	return msg.BtcDecode(r, 0, WitnessEncoding)
}

// DeserializeNoWitness decodes a transaction from r into the receiver, where
// the transaction encoding format within r MUST NOT utilize the new
// serialization format created to encode transaction bearing witness data
// within inputs.
func (msg *MsgTx) DeserializeNoWitness(r io.Reader) error {
	return msg.BtcDecode(r, 0, BaseEncoding)
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
// See Serialize for encoding transactions to be stored to disk, such as in a
// database, as opposed to encoding transactions for the wire.
func (msg *MsgTx) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	// If witness encoding requested or no witness data, write directly.
	if enc == WitnessEncoding || !msg.hasWitness {
		_, err := w.Write(msg.data)
		return err
	}

	// BaseEncoding requested but we have witness data - strip it.
	// Write version.
	if _, err := w.Write(msg.data[:4]); err != nil {
		return err
	}
	// Skip marker+flag (2 bytes), write from inputs through outputs.
	endOutputs := msg.witnessStart
	if _, err := w.Write(msg.data[6:endOutputs]); err != nil {
		return err
	}
	// LockTime (last 4 bytes).
	_, err := w.Write(msg.data[len(msg.data)-4:])
	return err
}

// HasWitness returns true if the transaction has witness data.
func (msg *MsgTx) HasWitness() bool {
	return msg.hasWitness
}

// Serialize encodes the transaction to w using a format that suitable for
// long-term storage such as a database while respecting the Version field in
// the transaction.
func (msg *MsgTx) Serialize(w io.Writer) error {
	return msg.BtcEncode(w, 0, WitnessEncoding)
}

// SerializeNoWitness encodes the transaction to w in an identical manner to
// Serialize, however even if the source transaction has inputs with witness
// data, the old serialization format will still be used.
func (msg *MsgTx) SerializeNoWitness(w io.Writer) error {
	return msg.BtcEncode(w, 0, BaseEncoding)
}

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction.
func (msg *MsgTx) SerializeSize() int {
	return len(msg.data)
}

// SerializeSizeStripped returns the number of bytes it would take to serialize
// the transaction, excluding any included witness data.
func (msg *MsgTx) SerializeSizeStripped() int {
	if !msg.hasWitness {
		return len(msg.data)
	}

	// For witness transactions, calculate the stripped size:
	// Version (4) + inputs + outputs + LockTime (4)
	// Excluding: marker (1) + flag (1) + witness data
	return 4 + // version
		(msg.witnessStart - 6) + // inputs and outputs (skip marker+flag at bytes 4-5)
		4 // locktime
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgTx) Command() string {
	return CmdTx
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgTx) MaxPayloadLength(pver uint32) uint32 {
	return MaxBlockPayload
}

// PkScriptLocs returns a slice containing the start of each public key script
// within the raw serialized transaction.  The caller can easily obtain the
// length of each script by using len on the script available via the
// appropriate transaction output entry.
func (msg *MsgTx) PkScriptLocs() []int {
	if msg.outputCount == 0 {
		return nil
	}

	// Walk through outputs to find PkScript locations.
	pkScriptLocs := make([]int, msg.outputCount)
	offset := msg.outputsStart
	for i := range msg.outputCount {
		// Value is 8 bytes, then varint script length.
		offset += 8
		scriptLen, n := deserializeVarInt(msg.data[offset:])
		offset += n
		pkScriptLocs[i] = offset
		offset += int(scriptLen)
	}

	return pkScriptLocs
}

// NewMsgTx creates a new MsgTx from the given fields by serializing them.
func NewMsgTx(version int32, txIn []*TxIn, txOut []*TxOut, lockTime uint32) *MsgTx {
	// Calculate size.
	hasWitness := false
	for _, ti := range txIn {
		if len(ti.Witness) > 0 {
			hasWitness = true
			break
		}
	}

	size := 4 // version
	if hasWitness {
		size += 2 // marker + flag
	}
	size += VarIntSerializeSize(uint64(len(txIn)))
	for _, ti := range txIn {
		size += ti.SerializeSize()
	}
	size += VarIntSerializeSize(uint64(len(txOut)))
	for _, to := range txOut {
		size += to.SerializeSize()
	}
	if hasWitness {
		for _, ti := range txIn {
			size += ti.Witness.SerializeSize()
		}
	}
	size += 4 // lockTime

	// Serialize.
	data := make([]byte, size)
	offset := 0

	// Version.
	littleEndian.PutUint32(data[offset:], uint32(version))
	offset += 4

	// Witness marker and flag.
	if hasWitness {
		data[offset] = TxFlagMarker
		data[offset+1] = WitnessFlag
		offset += 2
	}

	// Input count.
	offset += putVarInt(data[offset:], uint64(len(txIn)))

	// Inputs.
	inputsStart := offset
	for _, ti := range txIn {
		copy(data[offset:], ti.PreviousOutPoint.Hash[:])
		offset += 32
		littleEndian.PutUint32(data[offset:], ti.PreviousOutPoint.Index)
		offset += 4
		offset += putVarInt(data[offset:], uint64(len(ti.SignatureScript)))
		copy(data[offset:], ti.SignatureScript)
		offset += len(ti.SignatureScript)
		littleEndian.PutUint32(data[offset:], ti.Sequence)
		offset += 4
	}

	// Output count.
	offset += putVarInt(data[offset:], uint64(len(txOut)))
	outputsStart := offset

	// Outputs.
	for _, to := range txOut {
		littleEndian.PutUint64(data[offset:], uint64(to.Value))
		offset += 8
		offset += putVarInt(data[offset:], uint64(len(to.PkScript)))
		copy(data[offset:], to.PkScript)
		offset += len(to.PkScript)
	}

	// Witness data.
	witnessStart := offset
	if hasWitness {
		for _, ti := range txIn {
			offset += putVarInt(data[offset:], uint64(len(ti.Witness)))
			for _, wit := range ti.Witness {
				offset += putVarInt(data[offset:], uint64(len(wit)))
				copy(data[offset:], wit)
				offset += len(wit)
			}
		}
	}

	// LockTime.
	littleEndian.PutUint32(data[offset:], lockTime)

	return &MsgTx{
		data:         data,
		Version:      version,
		LockTime:     lockTime,
		hasWitness:   hasWitness,
		inputCount:   len(txIn),
		outputCount:  len(txOut),
		inputsStart:  inputsStart,
		outputsStart: outputsStart,
		witnessStart: witnessStart,
	}
}

// NewMsgTxFromBytes creates a MsgTx from serialized transaction bytes.
func NewMsgTxFromBytes(data []byte) (*MsgTx, error) {
	if len(data) < 10 {
		return nil, io.EOF
	}

	msg := &MsgTx{data: data}
	offset := 0

	// Version (4 bytes).
	msg.Version = int32(littleEndian.Uint32(data[offset : offset+4]))
	offset += 4

	// Read input count (may be witness flag marker).
	inputCount, n := deserializeVarInt(data[offset:])
	if n == 0 {
		return nil, io.EOF
	}
	if n < 0 {
		return nil, messageError("NewMsgTxFromBytes", "non-canonical varint")
	}
	offset += n

	// Check for witness flag.
	// The marker byte (0x00) is the same as a varint-encoded 0, so we need to
	// check if the next byte is the witness flag (0x01) to determine if this
	// is a witness transaction or just a transaction with 0 inputs.
	if inputCount == TxFlagMarker {
		if len(data) <= offset {
			return nil, io.EOF
		}
		flag := data[offset]

		if flag == WitnessFlag {
			// This is a witness transaction.
			offset++
			msg.hasWitness = true

			// Read actual input count.
			inputCount, n = deserializeVarInt(data[offset:])
			if n == 0 {
				return nil, io.EOF
			}
			if n < 0 {
				return nil, messageError("NewMsgTxFromBytes", "non-canonical varint")
			}
			offset += n
		}
		// Otherwise, inputCount really is 0 (non-witness transaction with 0 inputs).
	}

	// Sanity check input count.
	if inputCount > uint64(maxTxInPerMessage) {
		str := fmt.Sprintf("too many input transactions to fit into "+
			"max message size [count %d, max %d]", inputCount,
			maxTxInPerMessage)
		return nil, messageError("MsgTx.BtcDecode", str)
	}

	msg.inputCount = int(inputCount)
	msg.inputsStart = offset

	// Skip over inputs to find outputs.
	for range msg.inputCount {
		inputLen, err := scanTxIn(data, offset)
		if err != nil {
			return nil, err
		}
		offset += inputLen
	}

	// Read output count.
	outputCount, n := deserializeVarInt(data[offset:])
	if n == 0 {
		return nil, io.EOF
	}
	if n < 0 {
		return nil, messageError("NewMsgTxFromBytes", "non-canonical varint")
	}
	offset += n

	// Sanity check output count.
	if outputCount > uint64(maxTxOutPerMessage) {
		str := fmt.Sprintf("too many output transactions to fit into "+
			"max message size [count %d, max %d]", outputCount,
			maxTxOutPerMessage)
		return nil, messageError("MsgTx.BtcDecode", str)
	}

	msg.outputCount = int(outputCount)
	msg.outputsStart = offset

	// Skip over outputs to find witness/locktime.
	for range msg.outputCount {
		outputLen, err := scanTxOut(data, offset)
		if err != nil {
			return nil, err
		}
		offset += outputLen
	}

	// Record witness start and skip witness data if present.
	if msg.hasWitness {
		msg.witnessStart = offset
		// Track if we have any actual witness data.
		hasAnyWitness := false
		for range msg.inputCount {
			witLen, err := scanWitness(data, offset)
			if err != nil {
				return nil, err
			}
			// Check if this input has any witness items.
			// A witness with 0 items has length 1 (just the count byte).
			if witLen > 1 {
				hasAnyWitness = true
			}
			offset += witLen
		}
		// If witness flag was set but no inputs have witness data, reject.
		if !hasAnyWitness {
			return nil, errSuperfluousWitnessRecord
		}
	}

	// LockTime (4 bytes).
	if len(data) < offset+4 {
		return nil, io.EOF
	}
	msg.LockTime = littleEndian.Uint32(data[offset : offset+4])

	return msg, nil
}

// putVarInt serializes a variable length integer to the given buffer and
// returns the number of bytes written.
func putVarInt(buf []byte, val uint64) int {
	switch {
	case val < 0xfd:
		buf[0] = byte(val)
		return 1
	case val <= 0xffff:
		buf[0] = 0xfd
		littleEndian.PutUint16(buf[1:], uint16(val))
		return 3
	case val <= 0xffffffff:
		buf[0] = 0xfe
		littleEndian.PutUint32(buf[1:], uint32(val))
		return 5
	default:
		buf[0] = 0xff
		littleEndian.PutUint64(buf[1:], val)
		return 9
	}
}

// deserializeVarInt reads a variable length integer from buf and returns it
// along with the number of bytes read. Returns 0 for bytesRead if there's
// an error or not enough data. Returns -1 for bytesRead if the encoding is
// non-canonical (uses more bytes than necessary to encode the value).
func deserializeVarInt(buf []byte) (uint64, int) {
	if len(buf) == 0 {
		return 0, 0
	}

	discriminant := buf[0]
	switch {
	case discriminant < 0xfd:
		return uint64(discriminant), 1

	case discriminant == 0xfd:
		if len(buf) < 3 {
			return 0, 0
		}
		rv := uint64(littleEndian.Uint16(buf[1:3]))
		// The encoding is not canonical if the value could have been
		// encoded using fewer bytes.
		if rv < 0xfd {
			return 0, -1
		}
		return rv, 3

	case discriminant == 0xfe:
		if len(buf) < 5 {
			return 0, 0
		}
		rv := uint64(littleEndian.Uint32(buf[1:5]))
		// The encoding is not canonical if the value could have been
		// encoded using fewer bytes.
		if rv < 0x10000 {
			return 0, -1
		}
		return rv, 5

	default: // 0xff
		if len(buf) < 9 {
			return 0, 0
		}
		rv := littleEndian.Uint64(buf[1:9])
		// The encoding is not canonical if the value could have been
		// encoded using fewer bytes.
		if rv < 0x100000000 {
			return 0, -1
		}
		return rv, 9
	}
}

// scanTxIn returns the length of the TxIn at the given offset.
func scanTxIn(data []byte, offset int) (int, error) {
	start := offset

	// Outpoint (36 bytes).
	if len(data) < offset+36 {
		return 0, io.EOF
	}
	offset += 36

	// Script length + script.
	scriptLen, n := deserializeVarInt(data[offset:])
	if n == 0 {
		return 0, io.EOF
	}
	if n < 0 {
		return 0, messageError("scanTxIn", "non-canonical varint")
	}
	// Check for overflow before the addition. Only check for truly excessive
	// values that would overflow int. For simply truncated data, we'll catch
	// it with the bounds check below.
	if scriptLen > uint64(MaxMessagePayload) {
		str := fmt.Sprintf("transaction input signature script "+
			"is larger than max message size [script size %d]", scriptLen)
		return 0, messageError("MsgTx.BtcDecode", str)
	}
	offset += n + int(scriptLen)

	// Sequence (4 bytes).
	if len(data) < offset+4 {
		return 0, io.EOF
	}
	offset += 4

	return offset - start, nil
}

// scanTxOut returns the length of the TxOut at the given offset.
func scanTxOut(data []byte, offset int) (int, error) {
	start := offset

	// Value (8 bytes).
	if len(data) < offset+8 {
		return 0, io.EOF
	}
	offset += 8

	// Script length + script.
	scriptLen, n := deserializeVarInt(data[offset:])
	if n == 0 {
		return 0, io.EOF
	}
	if n < 0 {
		return 0, messageError("scanTxOut", "non-canonical varint")
	}
	// Check for overflow before the addition. Only check for truly excessive
	// values that would overflow int. For simply truncated data, we'll catch
	// it with the bounds check below.
	if scriptLen > uint64(MaxMessagePayload) {
		str := fmt.Sprintf("transaction output public key script "+
			"is larger than max message size [script size %d]", scriptLen)
		return 0, messageError("MsgTx.BtcDecode", str)
	}
	offset += n + int(scriptLen)

	if len(data) < offset {
		return 0, io.EOF
	}

	return offset - start, nil
}

// scanWitness returns the length of the witness data for one input.
func scanWitness(data []byte, offset int) (int, error) {
	start := offset

	// Number of witness items.
	witCount, n := deserializeVarInt(data[offset:])
	if n == 0 {
		return 0, io.EOF
	}
	if n < 0 {
		return 0, messageError("scanWitness", "non-canonical varint")
	}
	if witCount > maxWitnessItemsPerInput {
		str := fmt.Sprintf("too many witness items to fit "+
			"into max message size [count %d, max %d]",
			witCount, maxWitnessItemsPerInput)
		return 0, messageError("MsgTx.BtcDecode", str)
	}
	offset += n

	// Skip each witness item.
	for range witCount {
		itemLen, n := deserializeVarInt(data[offset:])
		if n == 0 {
			return 0, io.EOF
		}
		if n < 0 {
			return 0, messageError("scanWitness", "non-canonical varint")
		}
		if itemLen > maxWitnessItemSize {
			str := fmt.Sprintf("witness item is larger than the max "+
				"allowed size [size %d, max %d]",
				itemLen, maxWitnessItemSize)
			return 0, messageError("scanWitness", str)
		}
		offset += n + int(itemLen)

		if len(data) < offset {
			return 0, io.EOF
		}
	}

	return offset - start, nil
}

// readOutPointBuf reads the next sequence of bytes from r as an OutPoint.
//
// If b is non-nil, the provided buffer will be used for serializing small
// values.  Otherwise a buffer will be drawn from the binarySerializer's pool
// and return when the method finishes.
//
// NOTE: b MUST either be nil or at least an 8-byte slice.
func readOutPointBuf(r io.Reader, pver uint32, version int32, op *OutPoint,
	buf []byte) error {

	_, err := io.ReadFull(r, op.Hash[:])
	if err != nil {
		return err
	}

	if _, err := io.ReadFull(r, buf[:4]); err != nil {
		return err
	}
	op.Index = littleEndian.Uint32(buf[:4])

	return nil
}

// WriteOutPoint encodes op to the bitcoin protocol encoding for an OutPoint to
// w.
func WriteOutPoint(w io.Writer, pver uint32, version int32, op *OutPoint) error {
	buf := binarySerializer.Borrow()
	defer binarySerializer.Return(buf)

	err := writeOutPointBuf(w, pver, version, op, buf)
	return err
}

// writeOutPointBuf encodes op to the bitcoin protocol encoding for an OutPoint
// to w.
//
// If b is non-nil, the provided buffer will be used for serializing small
// values.  Otherwise a buffer will be drawn from the binarySerializer's pool
// and return when the method finishes.
//
// NOTE: b MUST either be nil or at least an 8-byte slice.
func writeOutPointBuf(w io.Writer, pver uint32, version int32, op *OutPoint,
	buf []byte) error {

	_, err := w.Write(op.Hash[:])
	if err != nil {
		return err
	}

	littleEndian.PutUint32(buf[:4], op.Index)
	_, err = w.Write(buf[:4])
	return err
}

// readScript reads a variable length byte array that represents a transaction
// script. It is encoded as a varInt containing the length of the array
// followed by the bytes themselves. An error is returned if the length is
// greater than the max allowed size which helps protect against memory
// exhaustion attacks and forced panics through malformed messages. The
// fieldName parameter is only used for the error message so it provides more
// context in the error.
func readScript(r io.Reader, pver uint32, buf []byte,
	fieldName string) ([]byte, error) {

	count, err := ReadVarIntBuf(r, pver, buf)
	if err != nil {
		return nil, err
	}

	// Prevent byte array larger than the max message size. It would
	// be possible to cause memory exhaustion and panics without a sane
	// upper bound on this count.
	if count > maxWitnessItemSize {
		str := fmt.Sprintf("%s is larger than the max allowed size "+
			"[count %d, max %d]", fieldName, count, maxWitnessItemSize)
		return nil, messageError("readScript", str)
	}

	script := make([]byte, count)
	_, err = io.ReadFull(r, script)
	if err != nil {
		return nil, err
	}
	return script, nil
}

// readTxIn reads the next sequence of bytes from r as a transaction input
// (TxIn).
func readTxIn(r io.Reader, pver uint32, version int32, ti *TxIn,
	buf []byte) error {

	err := readOutPointBuf(r, pver, version, &ti.PreviousOutPoint, buf)
	if err != nil {
		return err
	}

	ti.SignatureScript, err = readScript(
		r, pver, buf, "transaction input signature script",
	)
	if err != nil {
		return err
	}

	if _, err := io.ReadFull(r, buf[:4]); err != nil {
		return err
	}

	ti.Sequence = littleEndian.Uint32(buf[:4])

	return nil
}

// writeTxInBuf encodes ti to the bitcoin protocol encoding for a transaction
// input (TxIn) to w. If b is non-nil, the provided buffer will be used for
// serializing small values. Otherwise a buffer will be drawn from the
// binarySerializer's pool and return when the method finishes.
func writeTxInBuf(w io.Writer, pver uint32, version int32, ti *TxIn,
	buf []byte) error {

	err := writeOutPointBuf(w, pver, version, &ti.PreviousOutPoint, buf)
	if err != nil {
		return err
	}

	err = WriteVarBytesBuf(w, pver, ti.SignatureScript, buf)
	if err != nil {
		return err
	}

	littleEndian.PutUint32(buf[:4], ti.Sequence)
	_, err = w.Write(buf[:4])

	return err
}

// ReadTxOut reads the next sequence of bytes from r as a transaction output
// (TxOut).
func ReadTxOut(r io.Reader, pver uint32, version int32, to *TxOut) error {
	buf := binarySerializer.Borrow()
	defer binarySerializer.Return(buf)

	return readTxOut(r, pver, version, to, buf)
}

// readTxOut reads the next sequence of bytes from r as a transaction output
// (TxOut).
func readTxOut(r io.Reader, pver uint32, version int32, to *TxOut,
	buf []byte) error {

	_, err := io.ReadFull(r, buf)
	if err != nil {
		return err
	}
	to.Value = int64(littleEndian.Uint64(buf))

	to.PkScript, err = readScript(
		r, pver, buf, "transaction output public key script",
	)
	return err
}

// WriteTxOut encodes to into the bitcoin protocol encoding for a transaction
// output (TxOut) to w.
//
// NOTE: This function is exported in order to allow txscript to compute the
// new sighashes for witness transactions (BIP0143).
func WriteTxOut(w io.Writer, pver uint32, version int32, to *TxOut) error {
	buf := binarySerializer.Borrow()
	defer binarySerializer.Return(buf)

	err := WriteTxOutBuf(w, pver, version, to, buf)
	return err
}

// WriteTxOutBuf encodes to into the bitcoin protocol encoding for a transaction
// output (TxOut) to w. If b is non-nil, the provided buffer will be used for
// serializing small values. Otherwise a buffer will be drawn from the
// binarySerializer's pool and return when the method finishes.
//
// NOTE: This function is exported in order to allow txscript to compute the
// new sighashes for witness transactions (BIP0143).
func WriteTxOutBuf(w io.Writer, pver uint32, version int32, to *TxOut,
	buf []byte) error {

	littleEndian.PutUint64(buf, uint64(to.Value))
	_, err := w.Write(buf)
	if err != nil {
		return err
	}

	return WriteVarBytesBuf(w, pver, to.PkScript, buf)
}
