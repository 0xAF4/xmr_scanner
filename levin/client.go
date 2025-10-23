package levin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
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

func NewClient(addr string, opts ...ClientOption) (*Client, error) {
	cfg := &ClientConfig{
		ContextDialer: &net.Dialer{},
	}
	for _, opt := range opts {
		opt(cfg)
	}

	conn, err := cfg.ContextDialer.DialContext(context.Background(), "tcp", addr)
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

func (c *Client) Handshake(Height uint64, Hash string, peer_id uint64) (*Node, error) {
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
							Serializable: BoostUint32(MyPort),
						},
						{
							Name:         "peer_id",
							Serializable: BoostUint64(peer_id),
						},
						{
							Name:         "support_flags",
							Serializable: BoostUint32(SupportFlags),
						},
					},
				},
			},
			{
				Name: "payload_data",
				Serializable: &Section{
					Entries: []Entry{
						{
							Name:         "cumulative_difficulty",
							Serializable: BoostUint64(CumulativeDifficulty),
						},
						{
							Name:         "cumulative_difficulty_top64",
							Serializable: BoostUint64(CumulativeDifficultyTop64),
						},
						{
							Name:         "current_height",
							Serializable: BoostUint64(Height),
						},
						{
							Name:         "top_id",
							Serializable: BoostHash(Hash),
						},
						{
							Name:         "top_version",
							Serializable: BoostUint8(TopVersion),
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

	// for _, p := range ps.Entries {
	// 	fmt.Println("Name", p.Name)
	// 	if p.Name == "payload_data" {
	// 		for _, e := range p.Entries() {
	// 			fmt.Println("----")
	// 			fmt.Println("Name", e.Name)
	// 			switch e.Name {
	// 			case "cumulative_difficulty":
	// 				fmt.Println("val:", e.Uint64())
	// 			case "cumulative_difficulty_top64":
	// 				fmt.Println("val:", e.Uint64())
	// 			case "current_height":
	// 				fmt.Println("val:", e.Uint64())
	// 			case "top_id":
	// 				fmt.Println("val:", e.String())
	// 			case "top_version":
	// 				fmt.Println("val:", e.Uint8())
	// 			default:
	// 				fmt.Println("def name", e.Name)
	// 			}
	// 		}
	// 	}
	// }

	peerList := NewNodeFromEntries(ps.Entries)
	return &peerList, nil
}

func (c *Client) ReadMessage() (*Header, *PortableStorage, error) {
	responseHeaderB := make([]byte, LevinHeaderSizeBytes)
	if _, err := io.ReadFull(c.conn, responseHeaderB); err != nil {
		return nil, nil, errors.New("1:" + err.Error())
	}

	respHeader, err := NewHeaderFromBytesBytes(responseHeaderB)
	if err != nil {
		return nil, nil, errors.New("2:" + err.Error())
	}

	if respHeader.Length == 0 {
		return respHeader, nil, nil
	}

	responseBodyB := make([]byte, respHeader.Length)
	if _, err := io.ReadFull(c.conn, responseBodyB); err != nil {
		return nil, nil, errors.New("3:" + err.Error())
	}

	if respHeader.Command == NotifyResponseGetObjects {
		fileName := fmt.Sprintf("dump_985_%d.bin", time.Now().Unix())
		if err := os.WriteFile(fileName, responseBodyB, 0644); err != nil {
			fmt.Printf("Ошибка сохранения дампа в %s: %v\n", fileName, err)
		} else {
			fmt.Printf("Дамп сохранён в %s\n", fileName)
		}

		os.Exit(985)
	}

	ps, err := NewPortableStorageFromBytes(responseBodyB)
	if err != nil {
		return nil, nil, errors.New("4:" + err.Error())
	}

	return respHeader, ps, nil
}

// c.SendRequest(levin.CommandPing, c.NilPayload())
func (c *Client) SendRequest(Command uint32, payload []byte) error {
	len := uint64(len(payload))
	reqHeaderB := NewRequestHeader(Command, len)
	if slices.Contains([]uint32{NotifyRequestChain, NotifyRequestGetObjects}, Command) {
		reqHeaderB.ExpectsResponse = false
	}

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

func NilPayload() []byte {
	return (&PortableStorage{
		Entries: []Entry{},
	}).Bytes()
}
