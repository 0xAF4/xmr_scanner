package levin

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"time"
)

const DialTimeout = 15 * time.Second

type Client struct {
	conn net.Conn
}

type ClientConfig struct {
	ContextDialer ContextDialer
}

type ClientOption func(*ClientConfig)

type ContextDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

func WithContextDialer(v ContextDialer) func(*ClientConfig) {
	return func(c *ClientConfig) {
		c.ContextDialer = v
	}
}

func NewClient(ctx context.Context, addr string, opts ...ClientOption) (*Client, error) {
	cfg := &ClientConfig{
		ContextDialer: &net.Dialer{},
	}
	for _, opt := range opts {
		opt(cfg)
	}

	conn, err := cfg.ContextDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial ctx: %w", err)
	}

	return &Client{
		conn: conn,
	}, nil
}

func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}

	if err := c.conn.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	return nil
}

func (c *Client) Handshake(ctx context.Context) (*Node, error) {
	payload := (&PortableStorage{
		Entries: []Entry{
			{
				Name: "node_data",
				Serializable: &Section{
					Entries: []Entry{
						{
							Name:         "network_id",
							Serializable: BoostString(string(MainnetNetworkId)),
						},
						{
							Name:         "my_port",
							Serializable: BoostUint32(0),
						},
						{
							Name:         "peer_id",
							Serializable: BoostUint64(uint64(time.Now().Unix())),
						},
						{
							Name:         "support_flags",
							Serializable: BoostUint32(1),
						},
					},
				},
			},
		},
	}).Bytes()

	reqHeaderB := NewRequestHeader(CommandHandshake, uint64(len(payload))).Bytes()

	if _, err := c.conn.Write(reqHeaderB); err != nil {
		return nil, fmt.Errorf("write header: %w", err)
	}

	if _, err := c.conn.Write(payload); err != nil {
		return nil, fmt.Errorf("write payload: %w", err)
	}

again:
	responseHeaderB := make([]byte, LevinHeaderSizeBytes)
	if _, err := io.ReadFull(c.conn, responseHeaderB); err != nil {
		return nil, fmt.Errorf("read full header: %w", err)
	}

	respHeader, err := NewHeaderFromBytesBytes(responseHeaderB)
	if err != nil {
		return nil, fmt.Errorf("new header from resp bytes: %w", err)
	}

	dest := new(bytes.Buffer)

	if respHeader.Length != 0 {
		if _, err := io.CopyN(dest, c.conn, int64(respHeader.Length)); err != nil {
			return nil, fmt.Errorf("copy payload to stdout: %w", err)
		}
	}

	if respHeader.Command != CommandHandshake {
		dest.Reset()
		goto again
	}

	ps, err := NewPortableStorageFromBytes(dest.Bytes())
	if err != nil {
		return nil, fmt.Errorf("new portable storage from bytes: %w", err)
	}

	peerList := NewNodeFromEntries(ps.Entries)
	return &peerList, nil
}

func (c *Client) ReadMessage() (*Header, *PortableStorage, error) {
	responseHeaderB := make([]byte, LevinHeaderSizeBytes)
	if _, err := io.ReadFull(c.conn, responseHeaderB); err != nil {
		return nil, nil, err
	}

	respHeader, err := NewHeaderFromBytesBytes(responseHeaderB)
	if err != nil {
		return nil, nil, err
	}

	if respHeader.Length == 0 {
		return respHeader, nil, nil
	}

	responseBodyB := make([]byte, respHeader.Length)
	if _, err := io.ReadFull(c.conn, responseBodyB); err != nil {
		return nil, nil, err
	}

	ps, err := NewPortableStorageFromBytes(responseBodyB)
	if err != nil {
		return nil, nil, err
	}

	return respHeader, ps, nil
}

// c.SendRequest(levin.CommandPing, c.NilPayload())
func (c *Client) SendRequest(Command uint32, payload []byte) error {
	len := uint64(len(payload))
	reqHeaderB := NewRequestHeader(Command, len)

	if _, err := c.conn.Write(reqHeaderB.Bytes()); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	if len > 0 {
		if _, err := c.conn.Write(payload); err != nil {
			return fmt.Errorf("write payload: %w", err)
		}
	}

	return nil
}

func (c *Client) SendResponse(Command uint32, payload []byte) error {
	len := uint64(len(payload))
	respHeaderB := NewResponseHeader(Command, len).Bytes()

	if _, err := c.conn.Write(respHeaderB); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	if len > 0 {
		if _, err := c.conn.Write(payload); err != nil {
			return fmt.Errorf("write payload: %w", err)
		}
	}

	return nil
}

// ------------------

func (c *Client) NilPayload() []byte {
	return (&PortableStorage{
		Entries: []Entry{},
	}).Bytes()
}
