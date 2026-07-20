package congestion

import (
	"testing"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestBrutalSenderUsesConfiguredRateAndBoundedLossCompensation(t *testing.T) {
	b := NewBrutalSender(300_000_000, utils.NewRTTStats(), protocol.InitialPacketSize, false)
	// 300 Mbit/s * 100 ms * 2 RTTs / 8 = 7.5 MB.
	require.Equal(t, protocol.ByteCount(7_500_000), b.GetCongestionWindow())

	now := monotime.Now()
	for range 80 {
		b.OnPacketAcked(0, 0, 0, now)
	}
	for range 20 {
		b.record(now, false)
	}
	// At an 80% ACK rate, Brutal compensates up to 1 / 0.8 of the configured
	// rate, making the window 9.375 MB. The rate is never unbounded.
	require.Equal(t, protocol.ByteCount(9_375_000), b.GetCongestionWindow())
	require.True(t, b.CanSend(b.GetCongestionWindow()))
	require.False(t, b.CanSend(b.GetCongestionWindow()+1))
}
