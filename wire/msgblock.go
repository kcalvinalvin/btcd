// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// defaultTransactionAlloc is the default size used for the backing array
// for transactions.  The transaction array will dynamically grow as needed, but
// this figure is intended to provide enough space for the number of
// transactions in the vast majority of blocks without needing to grow the
// backing array multiple times.
const defaultTransactionAlloc = 2048

// MaxBlocksPerMsg is the maximum number of blocks allowed per message.
const MaxBlocksPerMsg = 500

// MaxBlockPayload is the maximum bytes a block message can be in bytes.
// After Segregated Witness, the max block payload has been raised to 4MB.
const MaxBlockPayload = 4000000

// maxTxPerBlock is the maximum number of transactions that could
// possibly fit into a block.
const maxTxPerBlock = (MaxBlockPayload / minTxPayload) + 1

// TxLoc holds locator data for the offset and length of where a transaction is
// located within a MsgBlock data buffer.
type TxLoc struct {
	TxStart int
	TxLen   int
}

// txOffset stores the location of a transaction within the block data.
type txOffset struct {
	start int
	end   int
}

// MsgBlock implements the Message interface and represents a bitcoin
// block message.  It is used to deliver block and transaction information in
// response to a getdata message (MsgGetData) for a given block hash.
type MsgBlock struct {
	Header       BlockHeader
	Transactions []*MsgTx

	// Internal tokenizer fields for efficient operations.
	// When data is non-nil, we have the raw serialized block.
	data      []byte
	txOffsets []txOffset
}

// Copy creates a deep copy of MsgBlock.
func (msg *MsgBlock) Copy() *MsgBlock {
	block := &MsgBlock{
		Header:       msg.Header,
		Transactions: make([]*MsgTx, len(msg.Transactions)),
	}

	for i, tx := range msg.Transactions {
		block.Transactions[i] = tx.Copy()
	}

	return block
}

// AddTransaction adds a transaction to the message.
func (msg *MsgBlock) AddTransaction(tx *MsgTx) error {
	msg.Transactions = append(msg.Transactions, tx)
	return nil
}

// ClearTransactions removes all transactions from the message.
func (msg *MsgBlock) ClearTransactions() {
	msg.Transactions = make([]*MsgTx, 0, defaultTransactionAlloc)
	msg.data = nil
	msg.txOffsets = nil
}

// TxData returns the raw bytes for the transaction at the given index.
// Only available when the block was deserialized from bytes.
func (msg *MsgBlock) TxData(i int) ([]byte, error) {
	if len(msg.txOffsets) == 0 {
		return nil, fmt.Errorf("TxData not available - block was not deserialized from bytes")
	}
	if i < 0 || i >= len(msg.txOffsets) {
		return nil, fmt.Errorf("tx index %d out of range [0, %d)", i, len(msg.txOffsets))
	}
	off := msg.txOffsets[i]
	return msg.data[off.start:off.end], nil
}

// Bytes returns the raw serialized block bytes if available.
func (msg *MsgBlock) Bytes() []byte {
	return msg.data
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
// See Deserialize for decoding blocks stored to disk, such as in a database, as
// opposed to decoding blocks from the wire.
func (msg *MsgBlock) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	// Read all data from the reader for zero-copy tokenizer mode.
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	parsed, err := NewMsgBlockFromBytes(data)
	if err != nil {
		return err
	}

	*msg = *parsed
	return nil
}

// Deserialize decodes a block from r into the receiver using a format that is
// suitable for long-term storage such as a database while respecting the
// Version field in the block.  This function differs from BtcDecode in that
// BtcDecode decodes from the bitcoin wire protocol as it was sent across the
// network.  The wire encoding can technically differ depending on the protocol
// version and doesn't even really need to match the format of a stored block at
// all.  As of the time this comment was written, the encoded block is the same
// in both instances, but there is a distinct difference and separating the two
// allows the API to be flexible enough to deal with changes.
func (msg *MsgBlock) Deserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of BtcDecode.
	//
	// Passing an encoding type of WitnessEncoding to BtcEncode for the
	// MessageEncoding parameter indicates that the transactions within the
	// block are expected to be serialized according to the new
	// serialization structure defined in BIP0141.
	return msg.BtcDecode(r, 0, WitnessEncoding)
}

// DeserializeNoWitness decodes a block from r into the receiver similar to
// Deserialize, however DeserializeWitness strips all (if any) witness data
// from the transactions within the block before encoding them.
func (msg *MsgBlock) DeserializeNoWitness(r io.Reader) error {
	return msg.BtcDecode(r, 0, BaseEncoding)
}

// DeserializeTxLoc decodes r in the same manner Deserialize does, but it takes
// a byte buffer instead of a generic reader and returns a slice containing the
// start and length of each transaction within the raw data that is being
// deserialized.
func (msg *MsgBlock) DeserializeTxLoc(r *bytes.Buffer) ([]TxLoc, error) {
	// Use the tokenizer approach - just parse from bytes.
	data := r.Bytes()
	parsed, err := NewMsgBlockFromBytes(data)
	if err != nil {
		return nil, err
	}

	*msg = *parsed
	return msg.TxLoc(), nil
}

// TxLoc returns the offsets and lengths of each transaction in the block.
// Only available when the block was deserialized from bytes.
func (msg *MsgBlock) TxLoc() []TxLoc {
	if len(msg.txOffsets) == 0 {
		return nil
	}
	txLocs := make([]TxLoc, len(msg.txOffsets))
	for i, off := range msg.txOffsets {
		txLocs[i] = TxLoc{
			TxStart: off.start,
			TxLen:   off.end - off.start,
		}
	}
	return txLocs
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
// See Serialize for encoding blocks to be stored to disk, such as in a
// database, as opposed to encoding blocks for the wire.
func (msg *MsgBlock) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	// If we have raw bytes and witness encoding is requested, write directly.
	if len(msg.data) > 0 && enc == WitnessEncoding {
		_, err := w.Write(msg.data)
		return err
	}

	// Serialize from fields.
	buf := binarySerializer.Borrow()
	defer binarySerializer.Return(buf)

	err := writeBlockHeaderBuf(w, pver, &msg.Header, buf)
	if err != nil {
		return err
	}

	err = WriteVarIntBuf(w, pver, uint64(len(msg.Transactions)), buf)
	if err != nil {
		return err
	}

	for _, tx := range msg.Transactions {
		err = tx.BtcEncode(w, pver, enc)
		if err != nil {
			return err
		}
	}

	return nil
}

// Serialize encodes the block to w using a format that suitable for long-term
// storage such as a database while respecting the Version field in the block.
// This function differs from BtcEncode in that BtcEncode encodes the block to
// the bitcoin wire protocol in order to be sent across the network.  The wire
// encoding can technically differ depending on the protocol version and doesn't
// even really need to match the format of a stored block at all.  As of the
// time this comment was written, the encoded block is the same in both
// instances, but there is a distinct difference and separating the two allows
// the API to be flexible enough to deal with changes.
func (msg *MsgBlock) Serialize(w io.Writer) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of BtcEncode.
	//
	// Passing WitnessEncoding as the encoding type here indicates that
	// each of the transactions should be serialized using the witness
	// serialization structure defined in BIP0141.
	return msg.BtcEncode(w, 0, WitnessEncoding)
}

// SerializeNoWitness encodes a block to w using an identical format to
// Serialize, with all (if any) witness data stripped from all transactions.
// This method is provided in addition to the regular Serialize, in order to
// allow one to selectively encode transaction witness data to non-upgraded
// peers which are unaware of the new encoding.
func (msg *MsgBlock) SerializeNoWitness(w io.Writer) error {
	return msg.BtcEncode(w, 0, BaseEncoding)
}

// SerializeSize returns the number of bytes it would take to serialize the
// block, factoring in any witness data within transaction.
func (msg *MsgBlock) SerializeSize() int {
	if len(msg.data) > 0 {
		return len(msg.data)
	}

	// Block header bytes + Serialized varint size for the number of
	// transactions.
	n := blockHeaderLen + VarIntSerializeSize(uint64(len(msg.Transactions)))

	for _, tx := range msg.Transactions {
		n += tx.SerializeSize()
	}

	return n
}

// SerializeSizeStripped returns the number of bytes it would take to serialize
// the block, excluding any witness data (if any).
func (msg *MsgBlock) SerializeSizeStripped() int {
	// Block header bytes + Serialized varint size for the number of
	// transactions.
	n := blockHeaderLen + VarIntSerializeSize(uint64(len(msg.Transactions)))

	for _, tx := range msg.Transactions {
		n += tx.SerializeSizeStripped()
	}

	return n
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgBlock) Command() string {
	return CmdBlock
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgBlock) MaxPayloadLength(pver uint32) uint32 {
	// Block header at 80 bytes + transaction count + max transactions
	// which can vary up to the MaxBlockPayload (including the block header
	// and transaction count).
	return MaxBlockPayload
}

// BlockHash computes the block identifier hash for this block.
func (msg *MsgBlock) BlockHash() chainhash.Hash {
	return msg.Header.BlockHash()
}

// TxHashes returns a slice of hashes of all of transactions in this block.
func (msg *MsgBlock) TxHashes() ([]chainhash.Hash, error) {
	hashList := make([]chainhash.Hash, 0, len(msg.Transactions))
	for _, tx := range msg.Transactions {
		hashList = append(hashList, tx.TxHash())
	}
	return hashList, nil
}

// NewMsgBlock returns a new bitcoin block message that conforms to the
// Message interface.  See MsgBlock for details.
func NewMsgBlock(blockHeader *BlockHeader) *MsgBlock {
	return &MsgBlock{
		Header:       *blockHeader,
		Transactions: make([]*MsgTx, 0, defaultTransactionAlloc),
	}
}

// NewMsgBlockFromBytes creates a MsgBlock from serialized block bytes.
// The raw bytes are stored for efficient operations like TxLoc.
func NewMsgBlockFromBytes(data []byte) (*MsgBlock, error) {
	// Minimum block size is header + varint(0 txns).
	if len(data) < blockHeaderLen+1 {
		return nil, io.EOF
	}

	msg := &MsgBlock{data: data}

	// Parse block header (80 bytes).
	// Use a separate scratch buffer, not data[:8], because readBlockHeaderBuf
	// modifies the scratch buffer and we need to preserve the raw data bytes.
	var buf [8]byte
	err := readBlockHeaderBuf(
		newZeroCopyReader(data[:blockHeaderLen]),
		0, &msg.Header, buf[:],
	)
	if err != nil {
		return nil, err
	}
	offset := blockHeaderLen

	// Read transaction count.
	txCount, bytesRead := deserializeVarInt(data[offset:])
	if bytesRead == 0 {
		return nil, io.EOF
	}
	if bytesRead < 0 {
		return nil, messageError("NewMsgBlockFromBytes",
			"non-canonical varint encoding for tx count")
	}
	offset += bytesRead

	// Sanity check.
	if txCount > maxTxPerBlock {
		str := fmt.Sprintf("too many transactions to fit into a block "+
			"[count %d, max %d]", txCount, maxTxPerBlock)
		return nil, messageError("NewMsgBlockFromBytes", str)
	}

	// Parse transactions and record their offsets.
	msg.txOffsets = make([]txOffset, txCount)
	msg.Transactions = make([]*MsgTx, txCount)
	for i := range txCount {
		txStart := offset
		txLen, err := scanTransaction(data, offset)
		if err != nil {
			return nil, fmt.Errorf("tx %d: %w", i, err)
		}
		msg.txOffsets[i] = txOffset{start: txStart, end: txStart + txLen}

		// Parse the transaction.
		tx, err := NewMsgTxFromBytes(data[txStart : txStart+txLen])
		if err != nil {
			return nil, fmt.Errorf("tx %d: %w", i, err)
		}
		msg.Transactions[i] = tx
		offset += txLen
	}

	return msg, nil
}

// zeroCopyReader is a minimal io.Reader implementation for a fixed byte slice.
type zeroCopyReader struct {
	data []byte
	pos  int
}

func newZeroCopyReader(data []byte) *zeroCopyReader {
	return &zeroCopyReader{data: data}
}

func (r *zeroCopyReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// scanTransaction returns the length of the transaction at the given offset.
func scanTransaction(data []byte, offset int) (int, error) {
	start := offset

	if len(data) < offset+4 {
		return 0, io.EOF
	}

	// Version (4 bytes).
	offset += 4

	// Input count.
	inputCount, n := deserializeVarInt(data[offset:])
	if n == 0 {
		return 0, io.EOF
	}
	if n < 0 {
		return 0, messageError("scanTransaction", "non-canonical varint")
	}
	offset += n

	// Check for witness flag.
	// The marker byte (0x00) is the same as a varint-encoded 0, so we need to
	// check if the next byte is the witness flag (0x01) to determine if this
	// is a witness transaction or just a transaction with 0 inputs.
	hasWitness := false
	if inputCount == TxFlagMarker {
		if len(data) <= offset {
			return 0, io.EOF
		}
		flag := data[offset]

		if flag == WitnessFlag {
			// This is a witness transaction.
			offset++ // Skip flag byte
			hasWitness = true

			// Read actual input count.
			inputCount, n = deserializeVarInt(data[offset:])
			if n == 0 {
				return 0, io.EOF
			}
			if n < 0 {
				return 0, messageError("scanTransaction", "non-canonical varint")
			}
			offset += n
		}
		// Otherwise, inputCount really is 0 (non-witness transaction with 0 inputs).
	}

	// Skip inputs.
	for range inputCount {
		inputLen, err := scanTxIn(data, offset)
		if err != nil {
			return 0, err
		}
		offset += inputLen
	}

	// Output count.
	outputCount, n := deserializeVarInt(data[offset:])
	if n == 0 {
		return 0, io.EOF
	}
	if n < 0 {
		return 0, messageError("scanTransaction", "non-canonical varint")
	}
	offset += n

	// Skip outputs.
	for range outputCount {
		outputLen, err := scanTxOut(data, offset)
		if err != nil {
			return 0, err
		}
		offset += outputLen
	}

	// Skip witness data if present.
	if hasWitness {
		for range inputCount {
			witLen, err := scanWitness(data, offset)
			if err != nil {
				return 0, err
			}
			offset += witLen
		}
	}

	// LockTime (4 bytes).
	if len(data) < offset+4 {
		return 0, io.EOF
	}
	offset += 4

	return offset - start, nil
}
