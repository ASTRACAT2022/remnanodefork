// Package metrics supplies dependency-free atomic counters.
package metrics

import (
	"sync/atomic"
	"time"
)

type Snapshot struct {
	Uptime, HandshakeDuration, SmoothedRTT                                                                                                                 time.Duration
	ActiveStreams, ActiveDatagramSessions, QueueSize                                                                                                       int64
	BytesSent, BytesReceived, DatagramsSent, DatagramsReceived, DatagramsDropped, DecodeErrors, AuthenticationFailures, PaddingBytes, ConnectionMigrations uint64
}
type Counters struct {
	started                                                                          time.Time
	handshake                                                                        int64
	rtt                                                                              int64
	activeStreams, activeDatagrams, queue                                            int64
	sent, received, dgSent, dgReceived, dgDropped, decode, auth, padding, migrations atomic.Uint64
}

func New() *Counters { return &Counters{started: time.Now()} }
func (c *Counters) Snapshot() Snapshot {
	return Snapshot{Uptime: time.Since(c.started), HandshakeDuration: time.Duration(atomic.LoadInt64(&c.handshake)), SmoothedRTT: time.Duration(atomic.LoadInt64(&c.rtt)), ActiveStreams: atomic.LoadInt64(&c.activeStreams), ActiveDatagramSessions: atomic.LoadInt64(&c.activeDatagrams), QueueSize: atomic.LoadInt64(&c.queue), BytesSent: c.sent.Load(), BytesReceived: c.received.Load(), DatagramsSent: c.dgSent.Load(), DatagramsReceived: c.dgReceived.Load(), DatagramsDropped: c.dgDropped.Load(), DecodeErrors: c.decode.Load(), AuthenticationFailures: c.auth.Load(), PaddingBytes: c.padding.Load(), ConnectionMigrations: c.migrations.Load()}
}
func (c *Counters) AddSent(n int)                { c.sent.Add(uint64(n)) }
func (c *Counters) AddReceived(n int)            { c.received.Add(uint64(n)) }
func (c *Counters) AddDGSent()                   { c.dgSent.Add(1) }
func (c *Counters) AddDGReceived()               { c.dgReceived.Add(1) }
func (c *Counters) AddDGDropped()                { c.dgDropped.Add(1) }
func (c *Counters) AddDecodeError()              { c.decode.Add(1) }
func (c *Counters) AddAuthFailure()              { c.auth.Add(1) }
func (c *Counters) AddPadding(n int)             { c.padding.Add(uint64(n)) }
func (c *Counters) SetStreams(n int)             { atomic.StoreInt64(&c.activeStreams, int64(n)) }
func (c *Counters) SetDatagrams(n int)           { atomic.StoreInt64(&c.activeDatagrams, int64(n)) }
func (c *Counters) SetQueue(n int)               { atomic.StoreInt64(&c.queue, int64(n)) }
func (c *Counters) SetHandshake(d time.Duration) { atomic.StoreInt64(&c.handshake, int64(d)) }
func (c *Counters) SetRTT(d time.Duration)       { atomic.StoreInt64(&c.rtt, int64(d)) }
