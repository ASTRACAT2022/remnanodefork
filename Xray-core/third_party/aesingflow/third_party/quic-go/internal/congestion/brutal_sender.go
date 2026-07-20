package congestion

import (
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

// brutalSender is adapted from Hysteria's MIT-licensed Brutal controller.
// Unlike loss-based controllers, it paces at a configured rate and maintains
// a congestion window sized to two smoothed RTTs. It deliberately does not
// reduce its target rate after loss; use it only with a conservative explicit
// rate limit.
const (
	brutalPacketInfoSlots = 5
	brutalMinSampleCount  = 50
	brutalMinAckRate      = 0.8
	brutalCWNDMultiplier  = 2
)

var _ SendAlgorithm = &brutalSender{}
var _ SendAlgorithmWithDebugInfos = &brutalSender{}

type brutalSender struct {
	rttStats        *utils.RTTStats
	bps             uint64
	maxDatagramSize protocol.ByteCount
	pacer           *brutalPacer

	packetInfo [brutalPacketInfoSlots]brutalPacketInfo
	ackRate    float64

	disableLossCompensation bool
}

type brutalPacketInfo struct {
	timestamp int64
	acked     uint64
	lost      uint64
}

// NewBrutalSender creates a paced fixed-rate controller. bps is in bits/s.
func NewBrutalSender(bps uint64, rttStats *utils.RTTStats, maxDatagramSize protocol.ByteCount, disableLossCompensation bool) *brutalSender {
	b := &brutalSender{
		rttStats:                rttStats,
		bps:                     bps,
		maxDatagramSize:         maxDatagramSize,
		ackRate:                 1,
		disableLossCompensation: disableLossCompensation,
	}
	b.pacer = newBrutalPacer(func() uint64 {
		return uint64(float64(b.bps) / b.ackRate / 8)
	}, maxDatagramSize)
	return b
}

func (b *brutalSender) TimeUntilSend(_ protocol.ByteCount) monotime.Time {
	return b.pacer.TimeUntilSend()
}

func (b *brutalSender) HasPacingBudget(now monotime.Time) bool {
	return b.pacer.Budget(now) >= b.maxDatagramSize
}

func (b *brutalSender) OnPacketSent(sentTime monotime.Time, _ protocol.ByteCount, _ protocol.PacketNumber, bytes protocol.ByteCount, _ bool) {
	b.pacer.SentPacket(sentTime, bytes)
}

func (b *brutalSender) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight <= b.GetCongestionWindow()
}

func (b *brutalSender) MaybeExitSlowStart() {}

func (b *brutalSender) OnPacketAcked(_ protocol.PacketNumber, _ protocol.ByteCount, _ protocol.ByteCount, eventTime monotime.Time) {
	b.record(eventTime, true)
}

func (b *brutalSender) OnCongestionEvent(_ protocol.PacketNumber, _ protocol.ByteCount, _ protocol.ByteCount) {
	b.record(monotime.Now(), false)
}

func (b *brutalSender) OnRetransmissionTimeout(bool) {}

func (b *brutalSender) SetMaxDatagramSize(size protocol.ByteCount) {
	b.maxDatagramSize = size
	b.pacer.SetMaxDatagramSize(size)
}

func (b *brutalSender) InSlowStart() bool { return false }
func (b *brutalSender) InRecovery() bool  { return false }

func (b *brutalSender) GetCongestionWindow() protocol.ByteCount {
	rtt := b.rttStats.SmoothedRTT()
	if rtt <= 0 {
		return max(protocol.ByteCount(10240), b.maxDatagramSize)
	}
	// bps / 8 converts to bytes/s. ackRate is bounded below, so no division by zero.
	cwnd := protocol.ByteCount(float64(b.bps) * rtt.Seconds() * brutalCWNDMultiplier / b.ackRate / 8)
	return max(cwnd, b.maxDatagramSize)
}

func (b *brutalSender) record(now monotime.Time, acked bool) {
	timestamp := int64(time.Duration(now) / time.Second)
	slot := timestamp % brutalPacketInfoSlots
	if b.packetInfo[slot].timestamp != timestamp {
		b.packetInfo[slot] = brutalPacketInfo{timestamp: timestamp}
	}
	if acked {
		b.packetInfo[slot].acked++
	} else {
		b.packetInfo[slot].lost++
	}
	b.updateAckRate(timestamp)
}

func (b *brutalSender) updateAckRate(timestamp int64) {
	if b.disableLossCompensation {
		b.ackRate = 1
		return
	}
	minTimestamp := timestamp - brutalPacketInfoSlots
	var acked, lost uint64
	for _, info := range b.packetInfo {
		if info.timestamp >= minTimestamp {
			acked += info.acked
			lost += info.lost
		}
	}
	if acked+lost < brutalMinSampleCount {
		b.ackRate = 1
		return
	}
	b.ackRate = max(brutalMinAckRate, float64(acked)/float64(acked+lost))
}

type brutalPacer struct {
	budgetAtLastSent protocol.ByteCount
	maxDatagramSize  protocol.ByteCount
	lastSentTime     monotime.Time
	bandwidth        func() uint64 // bytes/s
}

func newBrutalPacer(bandwidth func() uint64, maxDatagramSize protocol.ByteCount) *brutalPacer {
	return &brutalPacer{budgetAtLastSent: 10 * maxDatagramSize, maxDatagramSize: maxDatagramSize, bandwidth: bandwidth}
}

func (p *brutalPacer) SentPacket(now monotime.Time, size protocol.ByteCount) {
	budget := p.Budget(now)
	if size >= budget {
		p.budgetAtLastSent = 0
	} else {
		p.budgetAtLastSent = budget - size
	}
	p.lastSentTime = now
}

func (p *brutalPacer) Budget(now monotime.Time) protocol.ByteCount {
	if p.lastSentTime.IsZero() {
		return p.maxBurstSize()
	}
	bytesPerSecond := p.bandwidth()
	if bytesPerSecond == 0 {
		return 0
	}
	delta := now.Sub(p.lastSentTime)
	var added protocol.ByteCount
	if delta > 0 {
		added = protocol.ByteCount(bytesPerSecond * uint64(delta.Nanoseconds()) / uint64(time.Second))
	}
	return min(p.maxBurstSize(), p.budgetAtLastSent+added)
}

func (p *brutalPacer) TimeUntilSend() monotime.Time {
	if p.budgetAtLastSent >= p.maxDatagramSize {
		return 0
	}
	bytesPerSecond := p.bandwidth()
	if bytesPerSecond == 0 {
		return monotime.Now().Add(time.Second)
	}
	diff := uint64(p.maxDatagramSize - p.budgetAtLastSent)
	nanoseconds := diff * uint64(time.Second) / bytesPerSecond
	if diff*uint64(time.Second)%bytesPerSecond != 0 {
		nanoseconds++
	}
	return p.lastSentTime.Add(max(protocol.MinPacingDelay, time.Duration(nanoseconds)))
}

func (p *brutalPacer) SetMaxDatagramSize(size protocol.ByteCount) { p.maxDatagramSize = size }

func (p *brutalPacer) maxBurstSize() protocol.ByteCount {
	return max(10*p.maxDatagramSize, protocol.ByteCount(p.bandwidth()*uint64(4*protocol.MinPacingDelay)/uint64(time.Second)))
}
