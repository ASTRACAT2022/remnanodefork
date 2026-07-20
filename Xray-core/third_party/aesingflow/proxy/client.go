package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/ASTRACAT2022/aesingflow/pkg/aesingflow"
)

// ClientConfig configures a local SOCKS5 listener backed by an AesingFlow client.
type ClientConfig struct {
	ListenAddress string
	Client        aesingflow.Client
	Logger        *slog.Logger
}

// Client listens for unauthenticated SOCKS5 CONNECT requests and sends them
// through the configured AesingFlow connection. UDP ASSOCIATE is not supported.
type Client struct {
	listenAddress string
	client        aesingflow.Client
	log           *slog.Logger
	connectionMu  sync.Mutex
	connection    aesingflow.Connection
}

func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.ListenAddress == "" {
		return nil, fmt.Errorf("proxy: local SOCKS listen address is required")
	}
	if cfg.Client == nil {
		return nil, fmt.Errorf("proxy: AesingFlow client is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Client{listenAddress: cfg.ListenAddress, client: cfg.Client, log: cfg.Logger}, nil
}

func (c *Client) ListenAndServe(ctx context.Context) error {
	defer c.closeConnection()
	listener, err := net.Listen("tcp", c.listenAddress)
	if err != nil {
		return err
	}
	defer listener.Close()
	c.log.Info("SOCKS5 proxy listening", "address", listener.Addr())
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		local, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go c.handle(ctx, local)
	}
}

func (c *Client) handle(ctx context.Context, local net.Conn) {
	defer local.Close()
	target, err := negotiateSOCKS5(local)
	if err != nil {
		c.log.Debug("SOCKS5 negotiation failed", "remote", local.RemoteAddr(), "error", err)
		return
	}
	conn, err := c.getConnection(ctx)
	if err != nil {
		_ = writeSOCKSReply(local, 0x01)
		c.log.Warn("AesingFlow connection failed", "target", target.Address(), "error", err)
		return
	}
	stream, err := conn.OpenStream(ctx)
	if err != nil {
		c.resetConnection(conn)
	}
	if err == nil {
		err = writeRequest(stream, target)
	}
	if err == nil {
		err = readResponse(stream)
	}
	if err != nil {
		if stream != nil {
			_ = stream.Close()
		}
		_ = writeSOCKSReply(local, 0x01)
		c.log.Debug("tunnel open failed", "target", target.Address(), "error", err)
		return
	}
	if err = writeSOCKSReply(local, 0x00); err != nil {
		return
	}
	c.log.Debug("proxy tunnel opened", "target", target.Address())
	copyBoth(local, stream)
}

// getConnection returns a shared, multiplexed AesingFlow connection. Opening
// a QUIC connection per SOCKS request prevents connection warm-up and severely
// reduces throughput for browsers that make several short-lived connections.
func (c *Client) getConnection(ctx context.Context) (aesingflow.Connection, error) {
	c.connectionMu.Lock()
	defer c.connectionMu.Unlock()
	if c.connection != nil {
		return c.connection, nil
	}
	conn, err := c.client.Connect(ctx)
	if err != nil {
		return nil, err
	}
	c.connection = conn
	return conn, nil
}

func (c *Client) resetConnection(conn aesingflow.Connection) {
	c.connectionMu.Lock()
	if c.connection == conn {
		c.connection = nil
	}
	c.connectionMu.Unlock()
	_ = conn.CloseWithError(0, "proxy reconnecting")
}

func (c *Client) closeConnection() {
	c.connectionMu.Lock()
	conn := c.connection
	c.connection = nil
	c.connectionMu.Unlock()
	if conn != nil {
		_ = conn.CloseWithError(0, "proxy stopped")
	}
}

func negotiateSOCKS5(conn net.Conn) (Target, error) {
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return Target{}, err
	}
	if greeting[0] != 5 || greeting[1] == 0 {
		return Target{}, fmt.Errorf("invalid SOCKS5 greeting")
	}
	methods := make([]byte, greeting[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return Target{}, err
	}
	noAuth := false
	for _, method := range methods {
		noAuth = noAuth || method == 0
	}
	if !noAuth {
		_, _ = conn.Write([]byte{5, 0xff})
		return Target{}, fmt.Errorf("SOCKS5 client did not offer no-auth")
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return Target{}, err
	}
	var request [4]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil {
		return Target{}, err
	}
	if request[0] != 5 || request[1] != 1 || request[2] != 0 {
		_ = writeSOCKSReply(conn, 0x07)
		return Target{}, fmt.Errorf("unsupported SOCKS5 request")
	}
	var host []byte
	switch request[3] {
	case addressIPv4:
		host = make([]byte, net.IPv4len)
	case addressIPv6:
		host = make([]byte, net.IPv6len)
	case addressDomain:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return Target{}, err
		}
		if length[0] == 0 {
			return Target{}, fmt.Errorf("empty SOCKS5 host")
		}
		host = make([]byte, length[0])
	default:
		_ = writeSOCKSReply(conn, 0x08)
		return Target{}, fmt.Errorf("unsupported SOCKS5 address type")
	}
	if _, err := io.ReadFull(conn, host); err != nil {
		return Target{}, err
	}
	var port [2]byte
	if _, err := io.ReadFull(conn, port[:]); err != nil {
		return Target{}, err
	}
	if request[3] == addressIPv4 || request[3] == addressIPv6 {
		host = []byte(net.IP(host).String())
	}
	return Target{Host: string(host), Port: uint16(port[0])<<8 | uint16(port[1])}, nil
}

func writeSOCKSReply(w io.Writer, code byte) error {
	_, err := w.Write([]byte{5, code, 0, addressIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

func copyBoth(a io.ReadWriteCloser, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	done := make(chan struct{})
	var closeOnce sync.Once
	closeAll := func() {
		closeOnce.Do(func() {
			_ = a.Close()
			_ = b.Close()
			close(done)
		})
	}
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(a, b); closeAll() }()
	go func() { defer wg.Done(); _, _ = io.Copy(b, a); closeAll() }()
	<-done
	wg.Wait()
}
