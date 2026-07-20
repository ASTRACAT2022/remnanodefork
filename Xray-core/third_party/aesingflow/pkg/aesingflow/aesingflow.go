// Package aesingflow is the stable public API for the AesingFlow transport core.
package aesingflow

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	coreauth "github.com/ASTRACAT2022/aesingflow/core/auth"
	"github.com/ASTRACAT2022/aesingflow/core/codec"
	coreconn "github.com/ASTRACAT2022/aesingflow/core/connection"
	"github.com/ASTRACAT2022/aesingflow/core/datagram"
	aferrors "github.com/ASTRACAT2022/aesingflow/core/errors"
	"github.com/ASTRACAT2022/aesingflow/core/handshake"
	"github.com/ASTRACAT2022/aesingflow/core/metrics"
	"github.com/ASTRACAT2022/aesingflow/core/padding"
	"github.com/ASTRACAT2022/aesingflow/core/protocol"
	"github.com/ASTRACAT2022/aesingflow/core/scheduler"
	coresession "github.com/ASTRACAT2022/aesingflow/core/session"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
)

type PaddingProfile = padding.Profile

const (
	PaddingDisabled = padding.Disabled
	PaddingMinimal  = padding.Minimal
	PaddingBalanced = padding.Balanced

	// DefaultBrutalSendRate is the default outgoing QUIC rate limit used by
	// AesingFlow's Brutal controller. It is deliberately below a 300 Mbit/s
	// access link to leave room for packet overhead and other traffic.
	DefaultBrutalSendRate uint64 = 250_000_000
)

type Authenticator = coreauth.Authenticator
type AuthRequest = coreauth.Request
type AuthResult = coreauth.Result
type Token = coreauth.Token
type StaticAuthenticator = coreauth.StaticAuthenticator
type ConnectionStats = metrics.Snapshot
type StreamStats struct {
	BytesSent, BytesReceived uint64
	State                    protocol.SessionState
}
type DatagramStats struct {
	Sent, Received, Dropped uint64
	State                   protocol.SessionState
}

type ClientConfig struct {
	Address                                                          string
	TLSConfig                                                        *tls.Config
	Token                                                            string
	ConnectTimeout, HandshakeTimeout, IdleTimeout, KeepAliveInterval time.Duration
	MaxStreams, MaxDatagramSize                                      int
	EnableDatagrams                                                  bool
	PaddingProfile                                                   PaddingProfile
	// BrutalSendRate sets the fixed-rate Brutal controller's outbound rate in
	// bits per second. A zero value uses DefaultBrutalSendRate unless
	// DisableBrutal is set.
	BrutalSendRate uint64
	// DisableBrutal opts out of AesingFlow's default Brutal controller and uses
	// CUBIC instead.
	DisableBrutal bool
	// BrutalDisableLossCompensation disables Brutal's bounded loss compensation.
	BrutalDisableLossCompensation bool
	Logger                        *slog.Logger
}
type ServerConfig struct {
	Address                                                                                          string
	TLSConfig                                                                                        *tls.Config
	Authenticator                                                                                    Authenticator
	IdleTimeout, KeepAliveInterval                                                                   time.Duration
	MaxConnections, MaxStreamsPerClient, MaxDatagramSessions, MaxControlMessageSize, MaxDatagramSize int
	PaddingProfile                                                                                   PaddingProfile
	// BrutalSendRate sets the fixed-rate Brutal controller's outbound rate in
	// bits per second. A zero value uses DefaultBrutalSendRate unless
	// DisableBrutal is set.
	BrutalSendRate uint64
	// DisableBrutal opts out of AesingFlow's default Brutal controller and uses
	// CUBIC instead.
	DisableBrutal bool
	// BrutalDisableLossCompensation disables Brutal's bounded loss compensation.
	BrutalDisableLossCompensation bool
	Logger                        *slog.Logger
}
type Client interface {
	Connect(context.Context) (Connection, error)
}
type Server interface {
	Serve(context.Context) error
	Accept(context.Context) (Connection, error)
	Close() error
	Addr() net.Addr
}
type Connection interface {
	OpenStream(context.Context) (StreamSession, error)
	OpenDatagramSession(context.Context) (DatagramSession, error)
	AcceptStream(context.Context) (StreamSession, error)
	AcceptDatagramSession(context.Context) (DatagramSession, error)
	Stats() ConnectionStats
	CloseWithError(code uint64, reason string) error
}
type StreamSession interface {
	ID() uint64
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	Close() error
	CloseWithError(code uint64, reason string) error
	Stats() StreamStats
}
type DatagramSession interface {
	ID() uint64
	Send(context.Context, []byte) error
	Receive(context.Context) ([]byte, error)
	Close() error
	Stats() DatagramStats
}
type Exporter interface{ Export(ConnectionStats) }

func NewClient(c ClientConfig) (Client, error) {
	if c.Address == "" {
		return nil, fmt.Errorf("aesingflow: client address is required")
	}
	if _, e := clientTLS(c.TLSConfig); e != nil {
		return nil, e
	}
	if c.MaxStreams <= 0 {
		c.MaxStreams = 32
	}
	if c.MaxDatagramSize <= 0 {
		c.MaxDatagramSize = protocol.DefaultMaxDatagramSize
	}
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = 10 * time.Second
	}
	if !c.DisableBrutal && c.BrutalSendRate == 0 {
		c.BrutalSendRate = DefaultBrutalSendRate
	}
	return &client{cfg: c, log: logger(c.Logger)}, nil
}
func NewServer(c ServerConfig) (Server, error) {
	if c.Address == "" {
		return nil, fmt.Errorf("aesingflow: server address is required")
	}
	if c.Authenticator == nil {
		return nil, fmt.Errorf("aesingflow: authenticator is required")
	}
	t, e := serverTLS(c.TLSConfig)
	if e != nil {
		return nil, e
	}
	if c.MaxConnections <= 0 {
		c.MaxConnections = 1024
	}
	if c.MaxStreamsPerClient <= 0 {
		c.MaxStreamsPerClient = 32
	}
	if c.MaxDatagramSessions <= 0 {
		c.MaxDatagramSessions = 32
	}
	if c.MaxControlMessageSize <= 0 {
		c.MaxControlMessageSize = protocol.DefaultMaxControlMessage
	}
	if c.MaxDatagramSize <= 0 {
		c.MaxDatagramSize = protocol.DefaultMaxDatagramSize
	}
	if !c.DisableBrutal && c.BrutalSendRate == 0 {
		c.BrutalSendRate = DefaultBrutalSendRate
	}
	l, e := quic.ListenAddr(c.Address, t, quicConfig(c.IdleTimeout, c.KeepAliveInterval, c.MaxStreamsPerClient, true, c.BrutalSendRate, c.BrutalDisableLossCompensation))
	if e != nil {
		return nil, e
	}
	return &server{cfg: c, listener: l, log: logger(c.Logger)}, nil
}
func logger(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return slog.Default()
}
func clientTLS(in *tls.Config) (*tls.Config, error) {
	if in == nil {
		return nil, fmt.Errorf("aesingflow: TLSConfig is required; certificate verification cannot be disabled by default")
	}
	if in.InsecureSkipVerify {
		return nil, fmt.Errorf("aesingflow: InsecureSkipVerify is not permitted")
	}
	c := in.Clone()
	c.MinVersion = tls.VersionTLS13
	if len(c.NextProtos) == 0 {
		c.NextProtos = []string{"aesingflow/1"}
	}
	return c, nil
}
func serverTLS(in *tls.Config) (*tls.Config, error) {
	if in == nil || len(in.Certificates) == 0 {
		return nil, fmt.Errorf("aesingflow: TLSConfig with certificate is required")
	}
	c := in.Clone()
	c.MinVersion = tls.VersionTLS13
	if len(c.NextProtos) == 0 {
		c.NextProtos = []string{"aesingflow/1"}
	}
	return c, nil
}
func quicConfig(idle, keep time.Duration, maxStreams int, datagrams bool, brutalSendRate uint64, brutalDisableLossCompensation bool) *quic.Config {
	// Proxy traffic commonly has a bandwidth-delay product well above the
	// conservative quic-go defaults. Start with windows large enough for a
	// broadband long-haul link and leave headroom for multiplexed streams.
	return &quic.Config{
		HandshakeIdleTimeout:           10 * time.Second,
		MaxIdleTimeout:                 idle,
		KeepAlivePeriod:                keep,
		InitialStreamReceiveWindow:     4 << 20,
		MaxStreamReceiveWindow:         32 << 20,
		InitialConnectionReceiveWindow: 8 << 20,
		MaxConnectionReceiveWindow:     64 << 20,
		MaxIncomingStreams:             int64(maxStreams + 1),
		EnableDatagrams:                datagrams,
		BrutalSendRate:                 brutalSendRate,
		BrutalDisableLossCompensation:  brutalDisableLossCompensation,
		// This tracer is a no-op until QLOGDIR is set in the environment.
		Tracer: qlog.DefaultConnectionTracer,
	}
}

type client struct {
	cfg ClientConfig
	log *slog.Logger
}

func (c *client) Connect(ctx context.Context) (Connection, error) {
	t, e := clientTLS(c.cfg.TLSConfig)
	if e != nil {
		return nil, e
	}
	if c.cfg.ConnectTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.cfg.ConnectTimeout)
		defer cancel()
	}
	q, e := quic.DialAddr(ctx, c.cfg.Address, t, quicConfig(c.cfg.IdleTimeout, c.cfg.KeepAliveInterval, c.cfg.MaxStreams, c.cfg.EnableDatagrams, c.cfg.BrutalSendRate, c.cfg.BrutalDisableLossCompensation))
	if e != nil {
		return nil, e
	}
	fc, e := clientHandshake(ctx, q, c.cfg, c.log)
	if e != nil {
		_ = q.CloseWithError(quic.ApplicationErrorCode(aferrors.CodeOf(e)), "handshake failed")
		return nil, e
	}
	return fc, nil
}

type server struct {
	cfg      ServerConfig
	listener *quic.Listener
	log      *slog.Logger
	closed   atomic.Bool
	active   atomic.Int64
}

func (s *server) Addr() net.Addr { return s.listener.Addr() }
func (s *server) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	return s.listener.Close()
}
func (s *server) Serve(ctx context.Context) error {
	for {
		c, e := s.Accept(ctx)
		if e != nil {
			if ctx.Err() != nil || s.closed.Load() {
				return nil
			}
			return e
		}
		go func() { <-c.(*flowConn).ctx.Done() }()
	}
}
func (s *server) Accept(ctx context.Context) (Connection, error) {
	if s.closed.Load() {
		return nil, aferrors.New(aferrors.ShuttingDown, "server is shutting down")
	}
	q, e := s.listener.Accept(ctx)
	if e != nil {
		return nil, e
	}
	if s.active.Add(1) > int64(s.cfg.MaxConnections) {
		s.active.Add(-1)
		_ = q.CloseWithError(quic.ApplicationErrorCode(aferrors.ServerBusy), "server busy")
		return nil, aferrors.New(aferrors.ServerBusy, "server busy")
	}
	fc, e := serverHandshake(ctx, q, s.cfg, s.log)
	if e != nil {
		s.active.Add(-1)
		_ = q.CloseWithError(quic.ApplicationErrorCode(aferrors.CodeOf(e)), "handshake failed")
		return nil, e
	}
	go func() { <-fc.ctx.Done(); s.active.Add(-1) }()
	return fc, nil
}

type flowConn struct {
	q               *quic.Conn
	control         *quic.Stream
	client          bool
	cfg             limits
	log             *slog.Logger
	ctx             context.Context
	cancel          context.CancelFunc
	state           *coreconn.StateMachine
	controlMu       sync.Mutex
	streamsMu       sync.Mutex
	streams         map[uint64]*streamSession
	datagramsMu     sync.Mutex
	datagrams       map[uint64]*datagramSession
	acceptStreams   chan StreamSession
	acceptDatagrams chan DatagramSession
	nextID          atomic.Uint64
	metrics         *metrics.Counters
	scheduler       *scheduler.Scheduler
	closeOnce       sync.Once
}
type limits struct {
	maxStreams, maxDatagrams, maxControl, maxDatagram int
	padding                                           PaddingProfile
}

func newFlow(q *quic.Conn, control *quic.Stream, client bool, l limits, log *slog.Logger) *flowConn {
	ctx, cancel := context.WithCancel(q.Context())
	f := &flowConn{q: q, control: control, client: client, cfg: l, log: log, ctx: ctx, cancel: cancel, state: coreconn.NewStateMachine(), streams: map[uint64]*streamSession{}, datagrams: map[uint64]*datagramSession{}, acceptStreams: make(chan StreamSession, l.maxStreams), acceptDatagrams: make(chan DatagramSession, l.maxDatagrams), metrics: metrics.New(), scheduler: scheduler.New(64)}
	f.nextID.Store(uint64(time.Now().UnixNano()))
	return f
}
func (f *flowConn) start() {
	go f.controlLoop()
	go f.streamLoop()
	if supportsDatagrams(f.q) {
		go f.datagramReceiveLoop()
		go f.datagramSendLoop()
	}
	go func() { <-f.q.Context().Done(); f.shutdown() }()
}
func (f *flowConn) shutdown() {
	f.closeOnce.Do(func() {
		_ = f.state.Transition(protocol.ConnectionClosing)
		f.cancel()
		f.scheduler.Close()
		f.streamsMu.Lock()
		streams := make([]*streamSession, 0, len(f.streams))
		for _, s := range f.streams {
			streams = append(streams, s)
		}
		f.streamsMu.Unlock()
		for _, s := range streams {
			_ = s.Close()
		}
		f.datagramsMu.Lock()
		datagrams := make([]*datagramSession, 0, len(f.datagrams))
		for _, d := range f.datagrams {
			datagrams = append(datagrams, d)
		}
		f.datagramsMu.Unlock()
		for _, d := range datagrams {
			_ = d.Close()
		}
		_ = f.state.Transition(protocol.ConnectionClosed)
	})
}
func (f *flowConn) writeControl(fr codec.Frame) error {
	f.controlMu.Lock()
	defer f.controlMu.Unlock()
	if f.cfg.padding != PaddingDisabled {
		fs, e := codec.DecodeFields(fr.Payload, f.cfg.maxControl)
		if e != nil {
			return e
		}
		p, n, e := padding.Add(f.cfg.padding, nil, 64)
		if e != nil {
			return e
		}
		fs = append(fs, codec.Field{Type: 0xffff, Value: p})
		fr.Payload, e = codec.EncodeFields(fs, f.cfg.maxControl)
		if e != nil {
			return e
		}
		f.metrics.SetQueue(f.scheduler.Len())
		f.metrics.AddPadding(n)
	}
	if e := codec.Write(f.control, fr, f.cfg.maxControl); e != nil {
		return e
	}
	return nil
}
func (f *flowConn) controlLoop() {
	for {
		fr, e := codec.Read(f.control, f.cfg.maxControl)
		if e != nil {
			if !errors.Is(e, io.EOF) {
				f.metrics.AddDecodeError()
				f.log.Debug("control stream ended", "error", e)
			}
			f.shutdown()
			return
		}
		switch fr.Type {
		case protocol.OpenDatagramSession:
			id, e := handshake.ParseOpen(fr, f.cfg.maxControl)
			if e == nil {
				_, e = f.ensureDatagram(id, true)
				if e == nil {
					res, _ := handshake.OpenFrame(protocol.DatagramSessionResult, id, f.cfg.maxControl)
					_ = f.writeControl(res)
				}
			}
		case protocol.CloseSession:
			id, e := handshake.ParseOpen(fr, f.cfg.maxControl)
			if e == nil {
				f.closeSession(id)
			}
		case protocol.Ping:
			fr.Type = protocol.Pong
			_ = f.writeControl(fr)
		case protocol.GoAway:
			_ = f.state.Transition(protocol.ConnectionDraining)
		case protocol.ConnectionReady:
		default:
		}
	}
}
func (f *flowConn) streamLoop() {
	for {
		st, e := f.q.AcceptStream(f.ctx)
		if e != nil {
			return
		}
		var idb [8]byte
		if _, e = io.ReadFull(st, idb[:]); e != nil {
			st.CancelRead(quic.StreamErrorCode(aferrors.InvalidMessage))
			continue
		}
		id := binary.BigEndian.Uint64(idb[:])
		ss, e := f.ensureStream(id, st)
		if e != nil {
			st.CancelWrite(quic.StreamErrorCode(aferrors.LimitExceeded))
			st.CancelRead(quic.StreamErrorCode(aferrors.LimitExceeded))
			continue
		}
		res, _ := handshake.OpenFrame(protocol.StreamResult, id, f.cfg.maxControl)
		_ = f.writeControl(res)
		select {
		case f.acceptStreams <- ss:
		case <-f.ctx.Done():
			return
		}
	}
}
func (f *flowConn) datagramReceiveLoop() {
	for {
		b, e := f.q.ReceiveDatagram(f.ctx)
		if e != nil {
			return
		}
		h, p, e := datagram.Decode(b, f.cfg.maxDatagram)
		if e != nil {
			f.metrics.AddDGDropped()
			continue
		}
		f.datagramsMu.Lock()
		d := f.datagrams[h.SessionID]
		f.datagramsMu.Unlock()
		if d == nil {
			f.metrics.AddDGDropped()
			continue
		}
		if !d.deliver(h.Sequence, p) {
			f.metrics.AddDGDropped()
			continue
		}
		f.metrics.AddDGReceived()
	}
}
func (f *flowConn) datagramSendLoop() {
	for {
		i, e := f.scheduler.Next(f.ctx)
		if e != nil {
			return
		}
		if e = f.q.SendDatagram(i.Payload); e != nil {
			f.metrics.AddDGDropped()
		} else {
			f.metrics.AddDGSent()
			f.metrics.AddSent(len(i.Payload))
		}
		f.metrics.SetQueue(f.scheduler.Len())
	}
}
func (f *flowConn) OpenStream(ctx context.Context) (StreamSession, error) {
	if f.state.State() != protocol.ConnectionReadyState {
		return nil, aferrors.New(aferrors.InvalidState, "connection not ready")
	}
	st, e := f.q.OpenStreamSync(ctx)
	if e != nil {
		return nil, e
	}
	id := f.nextID.Add(1)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], id)
	if _, e = st.Write(b[:]); e != nil {
		return nil, e
	}
	ss, e := f.ensureStream(id, st)
	if e != nil {
		return nil, e
	}
	fr, _ := handshake.OpenFrame(protocol.OpenStream, id, f.cfg.maxControl)
	if e = f.writeControl(fr); e != nil {
		return nil, e
	}
	return ss, nil
}
func (f *flowConn) AcceptStream(ctx context.Context) (StreamSession, error) {
	select {
	case s := <-f.acceptStreams:
		return s, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-f.ctx.Done():
		return nil, f.ctx.Err()
	}
}
func (f *flowConn) OpenDatagramSession(ctx context.Context) (DatagramSession, error) {
	if !supportsDatagrams(f.q) {
		return nil, aferrors.New(aferrors.InvalidState, "QUIC datagrams were not negotiated")
	}
	id := f.nextID.Add(1)
	d, e := f.ensureDatagram(id, false)
	if e != nil {
		return nil, e
	}
	fr, _ := handshake.OpenFrame(protocol.OpenDatagramSession, id, f.cfg.maxControl)
	if e = f.writeControl(fr); e != nil {
		return nil, e
	}
	return d, nil
}
func (f *flowConn) AcceptDatagramSession(ctx context.Context) (DatagramSession, error) {
	select {
	case d := <-f.acceptDatagrams:
		return d, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-f.ctx.Done():
		return nil, f.ctx.Err()
	}
}
func (f *flowConn) Stats() ConnectionStats {
	s := f.metrics.Snapshot()
	s.QueueSize = int64(f.scheduler.Len())
	s.SmoothedRTT = f.q.ConnectionStats().SmoothedRTT
	return s
}
func (f *flowConn) CloseWithError(code uint64, reason string) error {
	f.shutdown()
	return f.q.CloseWithError(quic.ApplicationErrorCode(code), safeReason(reason))
}
func safeReason(s string) string {
	if len(s) > 256 {
		return "connection closed"
	}
	return s
}
func (f *flowConn) ensureStream(id uint64, st *quic.Stream) (*streamSession, error) {
	f.streamsMu.Lock()
	defer f.streamsMu.Unlock()
	if x := f.streams[id]; x != nil {
		return nil, aferrors.New(aferrors.InvalidMessage, "duplicate stream session")
	}
	if len(f.streams) >= f.cfg.maxStreams {
		return nil, aferrors.New(aferrors.LimitExceeded, "stream session limit")
	}
	x := &streamSession{id: id, stream: st, conn: f, state: coresession.NewStateMachine()}
	_ = x.state.Transition(protocol.SessionOpening)
	_ = x.state.Transition(protocol.SessionActive)
	f.streams[id] = x
	f.metrics.SetStreams(len(f.streams))
	return x, nil
}
func (f *flowConn) ensureDatagram(id uint64, accept bool) (*datagramSession, error) {
	f.datagramsMu.Lock()
	defer f.datagramsMu.Unlock()
	if x := f.datagrams[id]; x != nil {
		return x, nil
	}
	if len(f.datagrams) >= f.cfg.maxDatagrams {
		return nil, aferrors.New(aferrors.LimitExceeded, "datagram session limit")
	}
	d := &datagramSession{id: id, conn: f, recv: make(chan []byte, 64), state: coresession.NewStateMachine()}
	_ = d.state.Transition(protocol.SessionOpening)
	_ = d.state.Transition(protocol.SessionActive)
	f.datagrams[id] = d
	f.metrics.SetDatagrams(len(f.datagrams))
	if accept {
		select {
		case f.acceptDatagrams <- d:
		default:
			delete(f.datagrams, id)
			return nil, aferrors.New(aferrors.LimitExceeded, "datagram accept queue full")
		}
	}
	return d, nil
}
func (f *flowConn) closeSession(id uint64) {
	f.streamsMu.Lock()
	s := f.streams[id]
	f.streamsMu.Unlock()
	if s != nil {
		_ = s.Close()
	}
	f.datagramsMu.Lock()
	d := f.datagrams[id]
	f.datagramsMu.Unlock()
	if d != nil {
		_ = d.Close()
	}
}

func (f *flowConn) removeStream(id uint64) {
	f.streamsMu.Lock()
	delete(f.streams, id)
	n := len(f.streams)
	f.streamsMu.Unlock()
	f.metrics.SetStreams(n)
}
func (f *flowConn) removeDatagram(id uint64) {
	f.datagramsMu.Lock()
	delete(f.datagrams, id)
	n := len(f.datagrams)
	f.datagramsMu.Unlock()
	f.metrics.SetDatagrams(n)
}

type streamSession struct {
	id             uint64
	stream         *quic.Stream
	conn           *flowConn
	state          *coresession.StateMachine
	once           sync.Once
	sent, received atomic.Uint64
}

func (s *streamSession) ID() uint64 { return s.id }
func (s *streamSession) Read(p []byte) (int, error) {
	n, e := s.stream.Read(p)
	if n > 0 {
		s.received.Add(uint64(n))
		s.conn.metrics.AddReceived(n)
	}
	if errors.Is(e, io.EOF) {
		_ = s.state.Transition(protocol.SessionHalfClosed)
	}
	return n, e
}
func (s *streamSession) Write(p []byte) (int, error) {
	if len(p) > 1<<20 {
		return 0, aferrors.New(aferrors.LimitExceeded, "stream write exceeds buffer limit")
	}
	n, e := s.stream.Write(p)
	if n > 0 {
		s.sent.Add(uint64(n))
		s.conn.metrics.AddSent(n)
	}
	return n, e
}
func (s *streamSession) SetDeadline(t time.Time) error      { return s.stream.SetDeadline(t) }
func (s *streamSession) SetReadDeadline(t time.Time) error  { return s.stream.SetReadDeadline(t) }
func (s *streamSession) SetWriteDeadline(t time.Time) error { return s.stream.SetWriteDeadline(t) }
func (s *streamSession) Close() error {
	var e error
	s.once.Do(func() {
		_ = s.state.Transition(protocol.SessionClosing)
		s.stream.CancelRead(quic.StreamErrorCode(aferrors.NoError))
		s.stream.CancelWrite(quic.StreamErrorCode(aferrors.NoError))
		e = s.stream.Close()
		_ = s.state.Transition(protocol.SessionClosed)
		s.conn.removeStream(s.id)
	})
	return e
}
func (s *streamSession) CloseWithError(code uint64, reason string) error {
	s.stream.CancelRead(quic.StreamErrorCode(code))
	s.stream.CancelWrite(quic.StreamErrorCode(code))
	return s.Close()
}
func (s *streamSession) Stats() StreamStats {
	return StreamStats{s.sent.Load(), s.received.Load(), s.state.State()}
}

type datagramSession struct {
	id                      uint64
	conn                    *flowConn
	recv                    chan []byte
	state                   *coresession.StateMachine
	once                    sync.Once
	next                    atomic.Uint32
	sent, received, dropped atomic.Uint64
	mu                      sync.Mutex
	seen                    map[uint32]struct{}
}

func (d *datagramSession) ID() uint64 { return d.id }
func (d *datagramSession) Send(ctx context.Context, p []byte) error {
	if d.state.State() != protocol.SessionActive {
		return aferrors.New(aferrors.InvalidState, "datagram session closed")
	}
	b, e := datagram.Encode(datagram.Header{Version: 1, SessionID: d.id, Sequence: d.next.Add(1)}, p, d.conn.cfg.maxDatagram)
	if e != nil {
		return e
	}
	e = d.conn.scheduler.Enqueue(ctx, scheduler.Item{Priority: protocol.Realtime, SessionID: d.id, Payload: b})
	if e != nil {
		d.dropped.Add(1)
		d.conn.metrics.AddDGDropped()
		return e
	}
	d.sent.Add(1)
	return nil
}
func (d *datagramSession) Receive(ctx context.Context) ([]byte, error) {
	select {
	case b := <-d.recv:
		d.received.Add(1)
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-d.conn.ctx.Done():
		return nil, d.conn.ctx.Err()
	}
}
func (d *datagramSession) deliver(seq uint32, p []byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seen == nil {
		d.seen = map[uint32]struct{}{}
	}
	if _, ok := d.seen[seq]; ok {
		return false
	}
	if len(d.seen) >= 256 {
		for x := range d.seen {
			delete(d.seen, x)
			break
		}
	}
	d.seen[seq] = struct{}{}
	select {
	case d.recv <- p:
		return true
	default:
		d.dropped.Add(1)
		return false
	}
}
func (d *datagramSession) Close() error {
	d.once.Do(func() {
		_ = d.state.Transition(protocol.SessionClosing)
		_ = d.state.Transition(protocol.SessionClosed)
		d.conn.removeDatagram(d.id)
	})
	return nil
}
func (d *datagramSession) Stats() DatagramStats {
	return DatagramStats{d.sent.Load(), d.received.Load(), d.dropped.Load(), d.state.State()}
}

func clientHandshake(ctx context.Context, q *quic.Conn, c ClientConfig, log *slog.Logger) (*flowConn, error) {
	started := time.Now()
	ctrl, e := q.OpenStreamSync(ctx)
	if e != nil {
		return nil, e
	}
	l := limits{c.MaxStreams, c.MaxStreams, protocol.DefaultMaxControlMessage, c.MaxDatagramSize, c.PaddingProfile}
	f := newFlow(q, ctrl, true, l, log)
	_ = f.state.Transition(protocol.ConnectionConnecting)
	_ = f.state.Transition(protocol.ConnectionQUICReady)
	_ = f.state.Transition(protocol.ConnectionNegotiating)
	var cid, nonce [16]byte
	if _, e = rand.Read(cid[:]); e != nil {
		return nil, e
	}
	if _, e = rand.Read(nonce[:]); e != nil {
		return nil, e
	}
	caps := protocol.Capability(0)
	if c.EnableDatagrams && supportsDatagrams(q) {
		caps |= protocol.CapabilityDatagrams
	}
	h := handshake.ClientHello{Capabilities: caps, ConnectionID: cid, Nonce: nonce, Timestamp: time.Now(), MaxControl: uint32(l.maxControl), MaxDatagram: uint32(l.maxDatagram), Padding: c.PaddingProfile != PaddingDisabled, Implementation: "aesingflow-go/0.1"}
	fr, e := handshake.ClientHelloFrame(h, l.maxControl)
	if e != nil {
		return nil, e
	}
	if e = f.writeControl(fr); e != nil {
		return nil, e
	}
	fr, e = codec.Read(ctrl, l.maxControl)
	if e != nil {
		return nil, e
	}
	sh, e := handshake.ParseServerHello(fr, l.maxControl)
	if e != nil {
		return nil, e
	}
	if sh.Major != protocol.Major || sh.Minor > protocol.Minor || sh.Result != aferrors.NoError {
		return nil, aferrors.New(aferrors.VersionUnsupported, "version negotiation failed")
	}
	if sh.MaxControl == 0 || sh.MaxDatagram == 0 || sh.MaxStreams == 0 {
		return nil, aferrors.New(aferrors.InvalidMessage, "invalid negotiated limits")
	}
	f.cfg.maxControl = minInt(f.cfg.maxControl, int(sh.MaxControl))
	f.cfg.maxDatagram = minInt(f.cfg.maxDatagram, int(sh.MaxDatagram))
	f.cfg.maxStreams = minInt(f.cfg.maxStreams, int(sh.MaxStreams))
	_ = f.state.Transition(protocol.ConnectionAuthenticating)
	ar := coreauth.Request{Token: c.Token, Nonce: nonce, Timestamp: time.Now()}
	fr, e = handshake.AuthRequestFrame(ar, l.maxControl)
	if e != nil {
		return nil, e
	}
	if e = f.writeControl(fr); e != nil {
		return nil, e
	}
	fr, e = codec.Read(ctrl, l.maxControl)
	if e != nil {
		return nil, e
	}
	code, e := handshake.ParseAuthResult(fr, l.maxControl)
	if e != nil {
		return nil, e
	}
	if code != aferrors.NoError {
		return nil, aferrors.New(code, "authentication failed")
	}
	fr = codec.Frame{Major: protocol.Major, Minor: protocol.Minor, Type: protocol.ConnectionReady}
	if e = f.writeControl(fr); e != nil {
		return nil, e
	}
	fr, e = codec.Read(ctrl, l.maxControl)
	if e != nil || fr.Type != protocol.ConnectionReady {
		if e != nil {
			return nil, e
		}
		return nil, aferrors.New(aferrors.InvalidMessage, "expected connection ready")
	}
	_ = f.state.Transition(protocol.ConnectionReadyState)
	f.metrics.SetHandshake(time.Since(started))
	f.start()
	return f, nil
}
func serverHandshake(ctx context.Context, q *quic.Conn, c ServerConfig, log *slog.Logger) (*flowConn, error) {
	started := time.Now()
	ctrl, e := q.AcceptStream(ctx)
	if e != nil {
		return nil, e
	}
	l := limits{c.MaxStreamsPerClient, c.MaxDatagramSessions, c.MaxControlMessageSize, c.MaxDatagramSize, c.PaddingProfile}
	f := newFlow(q, ctrl, false, l, log)
	_ = f.state.Transition(protocol.ConnectionConnecting)
	_ = f.state.Transition(protocol.ConnectionQUICReady)
	_ = f.state.Transition(protocol.ConnectionNegotiating)
	fr, e := codec.Read(ctrl, l.maxControl)
	if e != nil {
		return nil, e
	}
	ch, e := handshake.ParseClientHello(fr, l.maxControl)
	if e != nil {
		return nil, e
	}
	if fr.Major != protocol.Major {
		return nil, aferrors.New(aferrors.VersionUnsupported, "version unsupported")
	}
	if ch.MaxControl == 0 || ch.MaxDatagram == 0 {
		return nil, aferrors.New(aferrors.InvalidMessage, "invalid client limits")
	}
	var id, nonce [16]byte
	_, _ = rand.Read(id[:])
	_, _ = rand.Read(nonce[:])
	caps := ch.Capabilities
	if !supportsDatagrams(q) {
		caps &^= protocol.CapabilityDatagrams
	}
	l.maxControl = minInt(l.maxControl, int(ch.MaxControl))
	l.maxDatagram = minInt(l.maxDatagram, int(ch.MaxDatagram))
	f.cfg = l
	sh := handshake.ServerHello{Major: protocol.Major, Minor: min(protocol.Minor, fr.Minor), Capabilities: caps, ConnectionID: id, Nonce: nonce, MaxStreams: uint32(l.maxStreams), MaxDatagrams: uint32(l.maxDatagrams), MaxDatagram: uint32(l.maxDatagram), IdleTimeout: c.IdleTimeout, KeepAlive: c.KeepAliveInterval, MaxControl: uint32(l.maxControl), Result: aferrors.NoError}
	out, e := handshake.ServerHelloFrame(sh, l.maxControl)
	if e != nil {
		return nil, e
	}
	if e = f.writeControl(out); e != nil {
		return nil, e
	}
	_ = f.state.Transition(protocol.ConnectionAuthenticating)
	fr, e = codec.Read(ctrl, l.maxControl)
	if e != nil {
		return nil, e
	}
	ar, e := handshake.ParseAuthRequest(fr, l.maxControl)
	if e != nil {
		return nil, e
	}
	if ar.Nonce != ch.Nonce {
		return nil, aferrors.New(aferrors.ReplayDetected, "authentication nonce mismatch")
	}
	result, e := c.Authenticator.Authenticate(ctx, ar)
	code := aferrors.NoError
	if e != nil {
		code = aferrors.CodeOf(e)
		f.metrics.AddAuthFailure()
	}
	out, _ = handshake.AuthResultFrame(result, code, l.maxControl)
	_ = f.writeControl(out)
	if e != nil {
		return nil, e
	}
	fr, e = codec.Read(ctrl, l.maxControl)
	if e != nil || fr.Type != protocol.ConnectionReady {
		if e != nil {
			return nil, e
		}
		return nil, aferrors.New(aferrors.InvalidMessage, "expected connection ready")
	}
	out = codec.Frame{Major: protocol.Major, Minor: protocol.Minor, Type: protocol.ConnectionReady}
	if e = f.writeControl(out); e != nil {
		return nil, e
	}
	_ = f.state.Transition(protocol.ConnectionReadyState)
	f.metrics.SetHandshake(time.Since(started))
	f.start()
	return f, nil
}
func min(a, b uint8) uint8 {
	if a < b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func supportsDatagrams(q *quic.Conn) bool {
	s := q.ConnectionState().SupportsDatagrams
	return s.Local && s.Remote
}
