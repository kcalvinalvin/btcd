// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package electrumclient

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// HeaderTip is a chain tip as reported by blockchain.headers.subscribe, both
// in the response and in the notifications that follow. Hex is the serialized
// block header.
type HeaderTip struct {
	Hex    string `json:"hex"`
	Height int32  `json:"height"`
}

// BlockHeaders is the result of blockchain.block.headers. Hex is the
// concatenation of Count serialized block headers and Max is the largest
// number of headers the server returns for a single request.
type BlockHeaders struct {
	Count int    `json:"count"`
	Hex   string `json:"hex"`
	Max   int    `json:"max"`
}

// Balance is the result of blockchain.scripthash.get_balance. Both amounts
// are in satoshis.
type Balance struct {
	Confirmed   int64 `json:"confirmed"`
	Unconfirmed int64 `json:"unconfirmed"`
}

// HistoryItem is one entry of blockchain.scripthash.get_history or
// blockchain.scripthash.get_mempool. For a mempool transaction the height is
// 0 when every input is confirmed and -1 when it spends an unconfirmed
// output, and Fee is the transaction fee in satoshis. For a confirmed
// transaction the height is the block height that confirmed it and Fee is not
// set.
type HistoryItem struct {
	Height int32  `json:"height"`
	TxHash string `json:"tx_hash"`
	Fee    int64  `json:"fee,omitempty"`
}

// Unspent is one entry of blockchain.scripthash.listunspent. Value is in
// satoshis and the height is 0 for a mempool transaction.
type Unspent struct {
	TxPos  uint32 `json:"tx_pos"`
	Value  int64  `json:"value"`
	Height int32  `json:"height"`
	TxHash string `json:"tx_hash"`
}

// TxMerkle is the result of blockchain.transaction.get_merkle. Merkle holds
// the branch of the block's merkle tree that proves the transaction at
// position Pos is included in the block, ordered from the leaf level up.
type TxMerkle struct {
	Merkle      []string `json:"merkle"`
	BlockHeight int32    `json:"block_height"`
	Pos         int      `json:"pos"`
}

// TxIDFromPos is the result of blockchain.transaction.id_from_pos when the
// merkle branch is requested along with the transaction hash.
type TxIDFromPos struct {
	TxHash string   `json:"tx_hash"`
	Merkle []string `json:"merkle"`
}

// HostPorts lists the ports one host of a server can be reached on. A port is
// 0 when the host does not offer that transport.
type HostPorts struct {
	TCPPort int `json:"tcp_port"`
	SSLPort int `json:"ssl_port"`
}

// ServerFeatures is the result of server.features.
type ServerFeatures struct {
	GenesisHash   string               `json:"genesis_hash"`
	Hosts         map[string]HostPorts `json:"hosts"`
	ProtocolMax   string               `json:"protocol_max"`
	ProtocolMin   string               `json:"protocol_min"`
	Pruning       bool                 `json:"pruning"`
	ServerVersion string               `json:"server_version"`
	HashFunction  string               `json:"hash_function"`
}

// FeeHistogramBin is one entry of the mempool fee histogram. FeeRate is in
// satoshis per virtual byte and can carry a fractional part, some server
// implementations send averaged fee rates. VSize is the cumulative virtual
// size of the mempool transactions that fall into the bin.
type FeeHistogramBin struct {
	FeeRate float64
	VSize   int64
}

// UnmarshalJSON decodes the [fee_rate, vsize] pair the histogram entries are
// sent as.
func (b *FeeHistogramBin) UnmarshalJSON(data []byte) error {
	var pair [2]float64
	if err := json.Unmarshal(data, &pair); err != nil {
		return err
	}
	b.FeeRate = pair[0]
	b.VSize = int64(pair[1])
	return nil
}

// ScriptHash returns the key the electrum protocol identifies an output
// script by, which is the hex encoding of the sha256 digest of the script in
// reversed byte order.
func ScriptHash(pkScript []byte) string {
	digest := sha256.Sum256(pkScript)
	slices.Reverse(digest[:])
	return hex.EncodeToString(digest[:])
}

// HistoryStatus computes the status of a script hash from its history, which
// is the hex encoding of the sha256 digest of the concatenated
// "tx_hash:height:" strings of every history entry in order. It returns the
// empty string for an empty history, which the protocol represents as a null
// status.
func HistoryStatus(history []HistoryItem) string {
	if len(history) == 0 {
		return ""
	}

	var sb strings.Builder
	for _, item := range history {
		fmt.Fprintf(&sb, "%s:%d:", item.TxHash, item.Height)
	}
	digest := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(digest[:])
}

// ServerVersion identifies the client to the server with server.version and
// returns the server's software version string along with the protocol
// version it settled on.
func (c *Client) ServerVersion(clientName, protocolVersion string) (string, string, error) {
	var result []string
	err := c.call("server.version",
		[]interface{}{clientName, protocolVersion}, &result)
	if err != nil {
		return "", "", err
	}
	if len(result) != 2 {
		return "", "", fmt.Errorf("server.version: expected 2 "+
			"elements, got %d", len(result))
	}
	return result[0], result[1], nil
}

// ServerBanner fetches the server's banner with server.banner.
func (c *Client) ServerBanner() (string, error) {
	var banner string
	err := c.call("server.banner", nil, &banner)
	return banner, err
}

// ServerDonationAddress fetches the server's donation address with
// server.donation_address.
func (c *Client) ServerDonationAddress() (string, error) {
	var addr string
	err := c.call("server.donation_address", nil, &addr)
	return addr, err
}

// ServerFeatures fetches the features the server advertises with
// server.features.
func (c *Client) ServerFeatures() (*ServerFeatures, error) {
	features := new(ServerFeatures)
	err := c.call("server.features", nil, features)
	if err != nil {
		return nil, err
	}
	return features, nil
}

// ServerPeersSubscribe fetches the list of peer servers with
// server.peers.subscribe. Each peer is a [address, hostname, features] triple
// left in its raw form.
func (c *Client) ServerPeersSubscribe() ([][]interface{}, error) {
	var peers [][]interface{}
	err := c.call("server.peers.subscribe", nil, &peers)
	return peers, err
}

// ServerAddPeer offers this client's server to the connected server as a peer
// with server.add_peer and reports whether it was accepted. The features
// parameter takes the same form as a server.features result.
func (c *Client) ServerAddPeer(features map[string]interface{}) (bool, error) {
	var accepted bool
	err := c.call("server.add_peer", []interface{}{features}, &accepted)
	return accepted, err
}

// Ping keeps the connection alive with server.ping.
func (c *Client) Ping() error {
	return c.call("server.ping", nil, nil)
}

// BlockHeader fetches the serialized block header at the given height with
// blockchain.block.header and returns it hex encoded.
func (c *Client) BlockHeader(height int32) (string, error) {
	var header string
	err := c.call("blockchain.block.header",
		[]interface{}{height}, &header)
	return header, err
}

// BlockHeaders fetches up to count serialized block headers starting at
// startHeight with blockchain.block.headers. The server may return fewer
// headers than requested, the count of the result says how many it holds.
func (c *Client) BlockHeaders(startHeight int32, count int) (*BlockHeaders, error) {
	headers := new(BlockHeaders)
	err := c.call("blockchain.block.headers",
		[]interface{}{startHeight, count}, headers)
	if err != nil {
		return nil, err
	}
	return headers, nil
}

// EstimateFee asks the server with blockchain.estimatefee for the fee rate,
// in coins per kilobyte, needed to confirm within confTarget blocks. It
// returns -1 when the server has no estimate.
func (c *Client) EstimateFee(confTarget int) (float64, error) {
	var fee float64
	err := c.call("blockchain.estimatefee",
		[]interface{}{confTarget}, &fee)
	return fee, err
}

// RelayFee fetches the minimum fee rate, in coins per kilobyte, a transaction
// must pay to be accepted into the server's mempool with
// blockchain.relayfee.
func (c *Client) RelayFee() (float64, error) {
	var fee float64
	err := c.call("blockchain.relayfee", nil, &fee)
	return fee, err
}

// HeadersSubscribe subscribes to chain tip changes with
// blockchain.headers.subscribe. It returns the current tip and a channel that
// carries every tip the server announces afterwards. The channel is closed
// when the connection goes away.
func (c *Client) HeadersSubscribe() (*HeaderTip, <-chan HeaderTip, error) {
	// Register the channel before sending the request so a notification
	// racing the response cannot be missed.
	ch := make(chan HeaderTip, notificationBufferSize)
	c.mtx.Lock()
	if c.closed {
		err := c.closeErr
		c.mtx.Unlock()
		return nil, nil, fmt.Errorf("connection is down: %w", err)
	}
	c.headerSubs = append(c.headerSubs, ch)
	c.mtx.Unlock()

	tip := new(HeaderTip)
	if err := c.call("blockchain.headers.subscribe", nil, tip); err != nil {
		c.mtx.Lock()
		if i := slices.Index(c.headerSubs, ch); i != -1 {
			c.headerSubs = slices.Delete(c.headerSubs, i, i+1)
		}
		c.mtx.Unlock()
		return nil, nil, err
	}

	return tip, ch, nil
}

// ScriptHashSubscribe subscribes to status changes of the given script hash
// with blockchain.scripthash.subscribe. It returns the current status, which
// is nil when the script hash has no history, and a channel that carries
// every status the server announces afterwards. The channel is closed when
// the subscription ends through ScriptHashUnsubscribe or when the connection
// goes away.
func (c *Client) ScriptHashSubscribe(scriptHash string) (*string, <-chan string, error) {
	// Register the channel before sending the request so a notification
	// racing the response cannot be missed.
	ch := make(chan string, notificationBufferSize)
	c.mtx.Lock()
	if c.closed {
		err := c.closeErr
		c.mtx.Unlock()
		return nil, nil, fmt.Errorf("connection is down: %w", err)
	}
	c.scriptHashSubs[scriptHash] = append(c.scriptHashSubs[scriptHash], ch)
	c.mtx.Unlock()

	var status *string
	err := c.call("blockchain.scripthash.subscribe",
		[]interface{}{scriptHash}, &status)
	if err != nil {
		c.mtx.Lock()
		subs := c.scriptHashSubs[scriptHash]
		if i := slices.Index(subs, ch); i != -1 {
			subs = slices.Delete(subs, i, i+1)
			if len(subs) == 0 {
				delete(c.scriptHashSubs, scriptHash)
			} else {
				c.scriptHashSubs[scriptHash] = subs
			}
		}
		c.mtx.Unlock()
		return nil, nil, err
	}

	return status, ch, nil
}

// ScriptHashUnsubscribe drops the subscription to the given script hash with
// blockchain.scripthash.unsubscribe and reports whether a subscription
// existed on the server. The channels handed out for the script hash by
// ScriptHashSubscribe are closed.
func (c *Client) ScriptHashUnsubscribe(scriptHash string) (bool, error) {
	var wasSubscribed bool
	err := c.call("blockchain.scripthash.unsubscribe",
		[]interface{}{scriptHash}, &wasSubscribed)
	if err != nil {
		return false, err
	}

	c.mtx.Lock()
	chans := c.scriptHashSubs[scriptHash]
	delete(c.scriptHashSubs, scriptHash)
	c.mtx.Unlock()
	for _, ch := range chans {
		close(ch)
	}

	return wasSubscribed, nil
}

// ScriptHashGetBalance fetches the balance of the given script hash with
// blockchain.scripthash.get_balance.
func (c *Client) ScriptHashGetBalance(scriptHash string) (*Balance, error) {
	balance := new(Balance)
	err := c.call("blockchain.scripthash.get_balance",
		[]interface{}{scriptHash}, balance)
	if err != nil {
		return nil, err
	}
	return balance, nil
}

// ScriptHashGetHistory fetches the confirmed history of the given script hash
// followed by its mempool transactions with
// blockchain.scripthash.get_history.
func (c *Client) ScriptHashGetHistory(scriptHash string) ([]HistoryItem, error) {
	var history []HistoryItem
	err := c.call("blockchain.scripthash.get_history",
		[]interface{}{scriptHash}, &history)
	return history, err
}

// ScriptHashGetMempool fetches the mempool transactions of the given script
// hash with blockchain.scripthash.get_mempool.
func (c *Client) ScriptHashGetMempool(scriptHash string) ([]HistoryItem, error) {
	var history []HistoryItem
	err := c.call("blockchain.scripthash.get_mempool",
		[]interface{}{scriptHash}, &history)
	return history, err
}

// ScriptHashListUnspent fetches the unspent outputs of the given script hash
// with blockchain.scripthash.listunspent.
func (c *Client) ScriptHashListUnspent(scriptHash string) ([]Unspent, error) {
	var unspents []Unspent
	err := c.call("blockchain.scripthash.listunspent",
		[]interface{}{scriptHash}, &unspents)
	return unspents, err
}

// TransactionBroadcast submits a serialized transaction to the server with
// blockchain.transaction.broadcast and returns its transaction hash.
func (c *Client) TransactionBroadcast(rawTx []byte) (string, error) {
	var txHash string
	err := c.call("blockchain.transaction.broadcast",
		[]interface{}{hex.EncodeToString(rawTx)}, &txHash)
	return txHash, err
}

// TransactionGet fetches the serialized transaction with the given hash with
// blockchain.transaction.get and returns it hex encoded.
func (c *Client) TransactionGet(txHash string) (string, error) {
	var rawTx string
	err := c.call("blockchain.transaction.get",
		[]interface{}{txHash}, &rawTx)
	return rawTx, err
}

// TransactionGetMerkle fetches the merkle branch proving the transaction with
// the given hash is included in the block at the given height with
// blockchain.transaction.get_merkle.
func (c *Client) TransactionGetMerkle(txHash string, height int32) (*TxMerkle, error) {
	merkle := new(TxMerkle)
	err := c.call("blockchain.transaction.get_merkle",
		[]interface{}{txHash, height}, merkle)
	if err != nil {
		return nil, err
	}
	return merkle, nil
}

// TransactionIDFromPos fetches the hash of the transaction at the given
// position in the block at the given height with
// blockchain.transaction.id_from_pos.
func (c *Client) TransactionIDFromPos(height int32, txPos int) (string, error) {
	var txHash string
	err := c.call("blockchain.transaction.id_from_pos",
		[]interface{}{height, txPos}, &txHash)
	return txHash, err
}

// TransactionIDFromPosMerkle fetches the hash of the transaction at the given
// position in the block at the given height along with the merkle branch
// proving its inclusion with blockchain.transaction.id_from_pos.
func (c *Client) TransactionIDFromPosMerkle(height int32, txPos int) (*TxIDFromPos, error) {
	result := new(TxIDFromPos)
	err := c.call("blockchain.transaction.id_from_pos",
		[]interface{}{height, txPos, true}, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// MempoolGetFeeHistogram fetches the histogram of fee rates across the
// server's mempool with mempool.get_fee_histogram, ordered from the highest
// fee rate to the lowest.
func (c *Client) MempoolGetFeeHistogram() ([]FeeHistogramBin, error) {
	var histogram []FeeHistogramBin
	err := c.call("mempool.get_fee_histogram", nil, &histogram)
	return histogram, err
}
