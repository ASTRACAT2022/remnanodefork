package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/ASTRACAT2022/aesingflow/pkg/aesingflow"
)

// DialerConfig configures a reusable TCP outbound for a proxy core or any Go
// application. The supplied AesingFlow client owns TLS, authentication and
// transport configuration.
type DialerConfig struct {
	Client aesingflow.Client
	Logger *slog.Logger
}

// Dialer is a net.Dialer-compatible TCP outbound over multiplexed AesingFlow
// streams. It is suitable as the transport boundary for custom Xray, sing-box,
// or other Go proxy-core adapters. UDP is intentionally not accepted here.
type Dialer struct {
	client aesingflow.Client
	log    *slog.Logger

	connectionMu sync.Mutex
	connection   aesingflow.Connection
}

// NewDialer creates a reusable outbound. Call Close when the hosting core
// stops so the shared QUIC connection is closed promptly.
func NewDialer(cfg DialerConfig) (*Dialer, error) {
	if cfg.Client == nil {
		return nil, fmt.Errorf("proxy: AesingFlow client is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Dialer{client: cfg.Client, log: cfg.Logger}, nil
}

// DialContext implements the standard context-aware TCP dialer contract.
// network must be tcp, tcp4, or tcp6 and address must be host:port.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, &net.OpError{Op: "dial", Net: network, Addr: dialAddr(address), Err: errors.New("AesingFlow Dialer supports TCP only")}
	}
	target, err := targetFromAddress(address)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Addr: dialAddr(address), Err: err}
	}
	return d.DialTarget(ctx, target)
}

// DialTarget opens one TCP CONNECT stream through the shared AesingFlow
// connection. It is exported for adapters that already keep destinations in a
// structured form.
func (d *Dialer) DialTarget(ctx context.Context, target Target) (net.Conn, error) {
	conn, err := d.getConnection(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStream(ctx)
	if err != nil {
		d.resetConnection(conn)
		return nil, err
	}
	if err = writeRequest(stream, target); err == nil {
		err = readResponse(stream)
	}
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	d.log.Debug("AesingFlow tunnel opened", "target", target.Address())
	return &streamConn{stream: stream, local: dialAddr("aesingflow"), remote: dialAddr(target.Address())}, nil
}

func (d *Dialer) getConnection(ctx context.Context) (aesingflow.Connection, error) {
	d.connectionMu.Lock()
	defer d.connectionMu.Unlock()
	if d.connection != nil {
		return d.connection, nil
	}
	conn, err := d.client.Connect(ctx)
	if err != nil {
		return nil, err
	}
	d.connection = conn
	return conn, nil
}

func (d *Dialer) resetConnection(conn aesingflow.Connection) {
	d.connectionMu.Lock()
	if d.connection == conn {
		d.connection = nil
	}
	d.connectionMu.Unlock()
	_ = conn.CloseWithError(0, "dialer reconnecting")
}

// Close shuts down the shared QUIC connection. It is safe to call more than once.
func (d *Dialer) Close() error {
	d.connectionMu.Lock()
	conn := d.connection
	d.connection = nil
	d.connectionMu.Unlock()
	if conn == nil {
		return nil
	}
	return conn.CloseWithError(0, "dialer stopped")
}

func targetFromAddress(address string) (Target, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return Target{}, fmt.Errorf("invalid TCP address %q", address)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return Target{}, fmt.Errorf("invalid TCP port in %q", address)
	}
	return Target{Host: host, Port: uint16(port)}, nil
}

type streamConn struct {
	stream        aesingflow.StreamSession
	local, remote net.Addr
}

func (c *streamConn) Read(p []byte) (int, error)         { return c.stream.Read(p) }
func (c *streamConn) Write(p []byte) (int, error)        { return c.stream.Write(p) }
func (c *streamConn) Close() error                       { return c.stream.Close() }
func (c *streamConn) LocalAddr() net.Addr                { return c.local }
func (c *streamConn) RemoteAddr() net.Addr               { return c.remote }
func (c *streamConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *streamConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

type dialAddr string

func (a dialAddr) Network() string { return "aesingflow" }
func (a dialAddr) String() string  { return string(a) }
