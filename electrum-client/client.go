// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package electrumclient implements a client for version 1.4 of the electrum
// protocol, which is JSON-RPC 2.0 carried over a plain TCP or TLS connection
// with one newline terminated message per line.
package electrumclient

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	// DefaultTimeout is how long a request waits for its response before
	// giving up when no other timeout is configured on the client.
	DefaultTimeout = 30 * time.Second

	// notificationBufferSize is the buffer size of the channels handed out
	// to subscribers. Notifications for a subscriber that has fallen this
	// far behind are dropped so a slow consumer cannot stall the read loop.
	notificationBufferSize = 64

	// delim terminates every message in both directions.
	delim = byte('\n')
)

// ErrClientClosed is returned by requests made after the connection has been
// closed with Close. Requests that fail because the connection died for any
// other reason wrap the error that killed it instead.
var ErrClientClosed = errors.New("electrum client closed")

// RPCError is an error object from a JSON-RPC response.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Error implements the error interface.
func (e *RPCError) Error() string {
	return fmt.Sprintf("electrum rpc error %d: %s", e.Code, e.Message)
}

// request is the wire form of everything the client sends.
type request struct {
	Jsonrpc string        `json:"jsonrpc"`
	ID      uint64        `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

// message is the wire form of everything the server sends. A response to a
// request carries the id of that request along with a result or an error. A
// notification carries a method and params instead.
type message struct {
	ID     *uint64         `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Result json.RawMessage `json:"result"`
	Error  *RPCError       `json:"error"`
}

// Client is a connection to an electrum server. It may be used from multiple
// goroutines at once and requests may be issued concurrently. Notifications
// for the subscription methods are delivered on the channels returned by
// HeadersSubscribe and ScriptHashSubscribe.
type Client struct {
	// Timeout bounds how long a single request waits for its response.
	// Zero means DefaultTimeout. It must be set before the client is used
	// and not changed afterwards.
	Timeout time.Duration

	conn net.Conn

	// writeMtx serializes writes to conn so concurrent requests cannot
	// interleave their bytes.
	writeMtx sync.Mutex

	// mtx guards everything below.
	mtx            sync.Mutex
	nextID         uint64
	pending        map[uint64]chan *message
	headerSubs     []chan HeaderTip
	scriptHashSubs map[string][]chan string
	closed         bool
	closeErr       error
}

// Dial connects to an electrum server over plain TCP.
func Dial(addr string) (*Client, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return NewClient(conn), nil
}

// DialTLS connects to an electrum server over TLS.
func DialTLS(addr string, config *tls.Config) (*Client, error) {
	conn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		return nil, err
	}
	return NewClient(conn), nil
}

// NewClient returns a client that speaks the electrum protocol over the given
// connection and takes ownership of it. The connection is closed when the
// client is closed or when reading from it fails.
func NewClient(conn net.Conn) *Client {
	c := &Client{
		conn:           conn,
		pending:        make(map[uint64]chan *message),
		scriptHashSubs: make(map[string][]chan string),
	}
	go c.readLoop()
	return c
}

// Close tears down the connection. Any requests waiting for a response fail
// and every subscription channel is closed.
func (c *Client) Close() {
	c.shutdown(ErrClientClosed)
}

// Err returns the error that tore down the connection, or nil while the
// connection is still alive.
func (c *Client) Err() error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.closeErr
}

// shutdown marks the client closed with the given error, closes the
// connection, and unblocks everything waiting on it. Only the first call has
// any effect.
func (c *Client) shutdown(err error) {
	c.mtx.Lock()
	if c.closed {
		c.mtx.Unlock()
		return
	}
	c.closed = true
	c.closeErr = err
	pending := c.pending
	c.pending = nil
	headerSubs := c.headerSubs
	c.headerSubs = nil
	scriptHashSubs := c.scriptHashSubs
	c.scriptHashSubs = nil
	c.mtx.Unlock()

	c.conn.Close()

	for _, ch := range pending {
		close(ch)
	}
	for _, ch := range headerSubs {
		close(ch)
	}
	for _, chans := range scriptHashSubs {
		for _, ch := range chans {
			close(ch)
		}
	}
}

// readLoop reads messages off the connection and routes each one to the
// request waiting on it or to the matching subscription channels.
func (c *Client) readLoop() {
	reader := bufio.NewReader(c.conn)
	for {
		line, err := reader.ReadBytes(delim)
		if err != nil {
			c.shutdown(err)
			return
		}

		var msg message
		if err := json.Unmarshal(line, &msg); err != nil {
			c.shutdown(fmt.Errorf("malformed message %q from "+
				"server: %w", line, err))
			return
		}

		// A method marks the message as a notification for one of the
		// subscription methods.
		if msg.Method != "" {
			c.dispatchNotification(&msg)
			continue
		}

		// A response without an id is one the server could not
		// attribute to a request, which cannot happen for the well
		// formed requests this client sends. Ignore it.
		if msg.ID == nil {
			continue
		}

		c.mtx.Lock()
		ch, ok := c.pending[*msg.ID]
		delete(c.pending, *msg.ID)
		c.mtx.Unlock()
		if ok {
			ch <- &msg
		}
	}
}

// dispatchNotification fans a notification out to the channels subscribed to
// it. Sends never block, a subscriber that has fallen notificationBufferSize
// messages behind misses the notification.
func (c *Client) dispatchNotification(msg *message) {
	switch msg.Method {
	case "blockchain.headers.subscribe":
		// The params carry a single element, the new chain tip.
		var params []HeaderTip
		if err := json.Unmarshal(msg.Params, &params); err != nil ||
			len(params) != 1 {

			return
		}

		c.mtx.Lock()
		for _, ch := range c.headerSubs {
			select {
			case ch <- params[0]:
			default:
			}
		}
		c.mtx.Unlock()

	case "blockchain.scripthash.subscribe":
		// The params carry the script hash and its new status.
		var params []string
		if err := json.Unmarshal(msg.Params, &params); err != nil ||
			len(params) != 2 {

			return
		}

		c.mtx.Lock()
		for _, ch := range c.scriptHashSubs[params[0]] {
			select {
			case ch <- params[1]:
			default:
			}
		}
		c.mtx.Unlock()
	}
}

// forgetPending drops the response channel for the given request id after the
// request failed or timed out so the map does not leak entries.
func (c *Client) forgetPending(id uint64) {
	c.mtx.Lock()
	delete(c.pending, id)
	c.mtx.Unlock()
}

// do sends one request and waits for its response. A response carrying an
// error object is returned as an *RPCError.
func (c *Client) do(method string, params []interface{}) (*message, error) {
	// Always send a params array, even an empty one, since some servers
	// reject requests without a params field.
	if params == nil {
		params = []interface{}{}
	}

	c.mtx.Lock()
	if c.closed {
		err := c.closeErr
		c.mtx.Unlock()
		return nil, fmt.Errorf("%s: connection is down: %w", method, err)
	}
	id := c.nextID
	c.nextID++
	ch := make(chan *message, 1)
	c.pending[id] = ch
	c.mtx.Unlock()

	raw, err := json.Marshal(request{
		Jsonrpc: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	})
	if err != nil {
		c.forgetPending(id)
		return nil, err
	}
	raw = append(raw, delim)

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	c.writeMtx.Lock()
	c.conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = c.conn.Write(raw)
	c.writeMtx.Unlock()
	if err != nil {
		c.forgetPending(id)
		return nil, err
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case msg, ok := <-ch:
		if !ok {
			c.mtx.Lock()
			err := c.closeErr
			c.mtx.Unlock()
			return nil, fmt.Errorf("%s: connection is down: %w",
				method, err)
		}
		if msg.Error != nil {
			return nil, msg.Error
		}
		return msg, nil

	case <-timer.C:
		c.forgetPending(id)
		return nil, fmt.Errorf("%s: no response after %v", method,
			timeout)
	}
}

// Call sends a request for the given method with the given positional params
// and returns the raw result. It is the building block the typed methods wrap
// and is exported so callers can reach methods this package has no wrapper
// for.
func (c *Client) Call(method string, params ...interface{}) (json.RawMessage, error) {
	msg, err := c.do(method, params)
	if err != nil {
		return nil, err
	}
	return msg.Result, nil
}

// call sends a request and unmarshals its result into result when result is
// not nil.
func (c *Client) call(method string, params []interface{}, result interface{}) error {
	msg, err := c.do(method, params)
	if err != nil {
		return err
	}
	if result == nil {
		return nil
	}

	// Treat an absent result field the same as an explicit null.
	raw := msg.Result
	if len(raw) == 0 {
		raw = json.RawMessage("null")
	}
	return json.Unmarshal(raw, result)
}
