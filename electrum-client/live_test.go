// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package electrumclient_test

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	electrumclient "github.com/btcsuite/btcd/electrum-client"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// liveServers are public mainnet electrum servers, picked from the list at
// https://1209k.com/bitcoin-eye/ele.php to cover the common server
// implementations: electrs behind blockstream.info, Fulcrum, and ElectrumX.
var liveServers = []struct {
	addr   string
	useTLS bool
}{
	{"electrum.blockstream.info:50001", false},
	{"blockstream.info:700", true},
	{"fulcrum-core.1209k.com:50002", true},
	{"electrum.emzy.de:50002", true},
	{"electrum.bitaroo.net:50002", true},
}

// dialLiveServer connects to a public server. Public electrum servers
// commonly use self signed certificates, so certificate verification is
// skipped the same way electrum wallets skip it.
func dialLiveServer(t *testing.T, addr string, useTLS bool) *electrumclient.Client {
	t.Helper()

	var client *electrumclient.Client
	var err error
	if useTLS {
		client, err = electrumclient.DialTLS(
			addr, &tls.Config{InsecureSkipVerify: true})
	} else {
		client, err = electrumclient.Dial(addr)
	}
	require.NoError(t, err)
	t.Cleanup(client.Close)
	client.Timeout = 20 * time.Second
	return client
}

// TestLiveServers drives the read only client methods against public mainnet
// electrum servers. The test is gated behind the ELECTRUM_LIVE environment
// variable so regular test runs stay offline:
//
//	ELECTRUM_LIVE=1 go test ./electrum-client/
//
// A single server can be targeted instead of the built in list with
// ELECTRUM_LIVE_SERVER=tcp://host:port or ELECTRUM_LIVE_SERVER=ssl://host:port.
func TestLiveServers(t *testing.T) {
	if os.Getenv("ELECTRUM_LIVE") == "" {
		t.Skip("set ELECTRUM_LIVE=1 to run against public electrum " +
			"servers")
	}

	servers := liveServers
	if override := os.Getenv("ELECTRUM_LIVE_SERVER"); override != "" {
		addr, found := strings.CutPrefix(override, "ssl://")
		useTLS := true
		if !found {
			addr, found = strings.CutPrefix(override, "tcp://")
			useTLS = false
		}
		require.True(t, found, "ELECTRUM_LIVE_SERVER must start "+
			"with tcp:// or ssl://")
		servers = []struct {
			addr   string
			useTLS bool
		}{{addr, useTLS}}
	}

	for _, server := range servers {
		t.Run(server.addr, func(t *testing.T) {
			t.Parallel()
			testLiveServer(t, server.addr, server.useTLS)
		})
	}
}

// testLiveServer runs the read only methods against one server and checks
// the responses against mainnet facts.
func testLiveServer(t *testing.T, addr string, useTLS bool) {
	client := dialLiveServer(t, addr, useTLS)

	serverVersion, protocolVersion, err := client.ServerVersion(
		"electrumclient-live-test", "1.4")
	require.NoError(t, err)
	require.NotEmpty(t, serverVersion)
	require.True(t, strings.HasPrefix(protocolVersion, "1.4"),
		"unexpected protocol version %q", protocolVersion)
	t.Logf("connected to %s, protocol %s", serverVersion, protocolVersion)

	require.NoError(t, client.Ping())

	_, err = client.ServerBanner()
	require.NoError(t, err)

	features, err := client.ServerFeatures()
	require.NoError(t, err)
	require.Equal(t, chaincfg.MainNetParams.GenesisHash.String(),
		features.GenesisHash)

	// The chain tip must be past the height mainnet had already reached
	// when this test was written and its header must deserialize.
	tip, _, err := client.HeadersSubscribe()
	require.NoError(t, err)
	require.Greater(t, tip.Height, int32(900_000))

	tipHeaderBytes, err := hex.DecodeString(tip.Hex)
	require.NoError(t, err)
	var tipHeader wire.BlockHeader
	require.NoError(t, tipHeader.Deserialize(bytes.NewReader(tipHeaderBytes)))

	var genesisBuf bytes.Buffer
	require.NoError(t,
		chaincfg.MainNetParams.GenesisBlock.Header.Serialize(&genesisBuf))
	genesisHex := hex.EncodeToString(genesisBuf.Bytes())

	headerHex, err := client.BlockHeader(0)
	require.NoError(t, err)
	require.Equal(t, genesisHex, headerHex)

	headers, err := client.BlockHeaders(0, 3)
	require.NoError(t, err)
	require.Equal(t, 3, headers.Count)
	require.Len(t, headers.Hex, 3*160)
	require.True(t, strings.HasPrefix(headers.Hex, genesisHex))

	// The first bitcoin transfer, in block 170 at position 1.
	const (
		famousTxID   = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
		famousHeight = 170
	)

	rawTxHex, err := client.TransactionGet(famousTxID)
	require.NoError(t, err)
	rawTx, err := hex.DecodeString(rawTxHex)
	require.NoError(t, err)
	var msgTx wire.MsgTx
	require.NoError(t, msgTx.Deserialize(bytes.NewReader(rawTx)))
	require.Equal(t, famousTxID, msgTx.TxHash().String())

	// The merkle branch for it must fold up to the merkle root committed
	// to by the header of block 170.
	famousHeaderHex, err := client.BlockHeader(famousHeight)
	require.NoError(t, err)
	famousHeaderBytes, err := hex.DecodeString(famousHeaderHex)
	require.NoError(t, err)
	var famousHeader wire.BlockHeader
	require.NoError(t,
		famousHeader.Deserialize(bytes.NewReader(famousHeaderBytes)))

	txMerkle, err := client.TransactionGetMerkle(famousTxID, famousHeight)
	require.NoError(t, err)
	require.EqualValues(t, famousHeight, txMerkle.BlockHeight)

	current, err := chainhash.NewHashFromStr(famousTxID)
	require.NoError(t, err)
	pos := txMerkle.Pos
	folded := *current
	for _, hashStr := range txMerkle.Merkle {
		sibling, err := chainhash.NewHashFromStr(hashStr)
		require.NoError(t, err)
		if pos&1 == 1 {
			folded = blockchain.HashMerkleBranches(sibling, &folded)
		} else {
			folded = blockchain.HashMerkleBranches(&folded, sibling)
		}
		pos >>= 1
	}
	require.Equal(t, famousHeader.MerkleRoot, folded)

	// A script that provably has no history, so every script hash method
	// must come back empty.
	unusedScript := []byte{0x6a, 0x14} // OP_RETURN with a 20 byte push.
	unusedScript = append(unusedScript,
		[]byte("electrumclient-test\x00")...)
	scriptHash := electrumclient.ScriptHash(unusedScript)

	status, _, err := client.ScriptHashSubscribe(scriptHash)
	require.NoError(t, err)
	require.Nil(t, status)

	balance, err := client.ScriptHashGetBalance(scriptHash)
	require.NoError(t, err)
	require.Equal(t, &electrumclient.Balance{}, balance)

	history, err := client.ScriptHashGetHistory(scriptHash)
	require.NoError(t, err)
	require.Empty(t, history)

	unspents, err := client.ScriptHashListUnspent(scriptHash)
	require.NoError(t, err)
	require.Empty(t, unspents)

	// The fee methods only promise sane shapes, the values move with the
	// mempool.
	estimate, err := client.EstimateFee(6)
	require.NoError(t, err)
	if estimate != -1 {
		require.Greater(t, estimate, 0.0)
	}

	relayFee, err := client.RelayFee()
	require.NoError(t, err)
	require.GreaterOrEqual(t, relayFee, 0.0)

	histogram, err := client.MempoolGetFeeHistogram()
	require.NoError(t, err)
	for _, bin := range histogram {
		require.Greater(t, bin.VSize, int64(0))
	}

	// The remaining methods are not answered by every server
	// implementation in the wild. ElectrumX answers unsubscribe with an
	// unknown method error and the blockstream electrs endpoints drop the
	// connection on get_mempool, so a missing method only ends the test
	// early instead of failing it.
	skipUnsupported := func(method string, err error) bool {
		t.Helper()

		var rpcErr *electrumclient.RPCError
		if errors.As(err, &rpcErr) {
			t.Logf("server does not support %s: %v", method, err)
			return false
		}
		t.Logf("server dropped the connection on %s: %v", method, err)
		return true
	}

	posTxHash, err := client.TransactionIDFromPos(
		famousHeight, txMerkle.Pos)
	if err != nil {
		if skipUnsupported("blockchain.transaction.id_from_pos", err) {
			return
		}
	} else {
		require.Equal(t, famousTxID, posTxHash)
	}

	mempoolHistory, err := client.ScriptHashGetMempool(scriptHash)
	if err != nil {
		if skipUnsupported("blockchain.scripthash.get_mempool", err) {
			return
		}
	} else {
		require.Empty(t, mempoolHistory)
	}

	_, err = client.ScriptHashUnsubscribe(scriptHash)
	if err != nil {
		if skipUnsupported("blockchain.scripthash.unsubscribe", err) {
			return
		}
	}
}
