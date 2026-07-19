package tcp

import (
	"context"
	gotls "crypto/tls"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

var realityHandshakeLimiter = newRealityHandshakeLimiter()

type realityHandshakeLimiterState struct {
	events []time.Time
	last   time.Time
}

type realityHandshakeLimiterConfig struct {
	maxPerWindow int
	minInterval  time.Duration
	window       time.Duration
}

type realityHandshakeLimiterRegistry struct {
	mu     sync.Mutex
	states map[string]*realityHandshakeLimiterState
}

func newRealityHandshakeLimiter() *realityHandshakeLimiterRegistry {
	return &realityHandshakeLimiterRegistry{
		states: make(map[string]*realityHandshakeLimiterState),
	}
}

func loadRealityHandshakeLimiterConfig() realityHandshakeLimiterConfig {
	return realityHandshakeLimiterConfig{
		maxPerWindow: platform.NewEnvFlag(platform.UseRealityHandshakeMax).GetValueAsInt(0),
		minInterval:  time.Duration(platform.NewEnvFlag(platform.UseRealityHandshakeMinMS).GetValueAsInt(0)) * time.Millisecond,
		window:       time.Duration(platform.NewEnvFlag(platform.UseRealityHandshakeWinMS).GetValueAsInt(0)) * time.Millisecond,
	}
}

func (c realityHandshakeLimiterConfig) enabled() bool {
	return c.minInterval > 0 || (c.maxPerWindow > 0 && c.window > 0)
}

func limitRealityHandshake(ctx context.Context, dest net.Destination, config *reality.Config) error {
	limiterConfig := loadRealityHandshakeLimiterConfig()
	if !limiterConfig.enabled() {
		return nil
	}
	serverName := config.ServerName
	if serverName == "" {
		serverName = dest.Address.String()
	}
	return realityHandshakeLimiter.wait(ctx, dest.String()+"|"+serverName, limiterConfig)
}

func (r *realityHandshakeLimiterRegistry) wait(ctx context.Context, key string, config realityHandshakeLimiterConfig) error {
	for {
		now := time.Now()
		var waitUntil time.Time

		r.mu.Lock()
		state := r.states[key]
		if state == nil {
			state = &realityHandshakeLimiterState{}
			r.states[key] = state
		}

		if config.maxPerWindow > 0 && config.window > 0 {
			cutoff := now.Add(-config.window)
			kept := state.events[:0]
			for _, event := range state.events {
				if event.After(cutoff) {
					kept = append(kept, event)
				}
			}
			state.events = kept
			if len(state.events) >= config.maxPerWindow {
				waitUntil = state.events[0].Add(config.window)
			}
		}
		if config.minInterval > 0 && !state.last.IsZero() {
			minUntil := state.last.Add(config.minInterval)
			if minUntil.After(now) && (waitUntil.IsZero() || minUntil.After(waitUntil)) {
				waitUntil = minUntil
			}
		}
		if waitUntil.IsZero() || !waitUntil.After(now) {
			state.last = now
			state.events = append(state.events, now)
			r.mu.Unlock()
			return nil
		}
		r.mu.Unlock()

		wait := time.Until(waitUntil)
		errors.LogInfo(ctx, "delaying REALITY handshake for ", wait, " to avoid burst fingerprint")
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// Dial dials a new TCP connection to the given destination.
func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	errors.LogInfo(ctx, "dialing TCP to ", dest)
	if config := reality.ConfigFromStreamSettings(streamSettings); config != nil {
		if err := limitRealityHandshake(ctx, dest, config); err != nil {
			return nil, err
		}
	}
	conn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}

	if streamSettings.TcpmaskManager != nil {
		newConn, err := streamSettings.TcpmaskManager.WrapConnClient(conn)
		if err != nil {
			conn.Close()
			return nil, errors.New("mask err").Base(err)
		}
		conn = newConn
	}

	if config := tls.ConfigFromStreamSettings(streamSettings); config != nil {
		mitmServerName := session.MitmServerNameFromContext(ctx)
		mitmAlpn11 := session.MitmAlpn11FromContext(ctx)
		var tlsConfig *gotls.Config
		if tls.IsFromMitm(config.ServerName) {
			tlsConfig = config.GetTLSConfig(tls.WithOverrideName(mitmServerName))
		} else {
			tlsConfig = config.GetTLSConfig(tls.WithDestination(dest))
		}

		isFromMitmVerify := false
		if r, ok := tlsConfig.Rand.(*tls.RandCarrier); ok && len(r.VerifyPeerCertByName) > 0 {
			for i, name := range r.VerifyPeerCertByName {
				if tls.IsFromMitm(name) {
					isFromMitmVerify = true
					r.VerifyPeerCertByName[0], r.VerifyPeerCertByName[i] = r.VerifyPeerCertByName[i], r.VerifyPeerCertByName[0]
					r.VerifyPeerCertByName = r.VerifyPeerCertByName[1:]
					after := mitmServerName
					for {
						if len(after) > 0 {
							r.VerifyPeerCertByName = append(r.VerifyPeerCertByName, after)
						}
						_, after, _ = strings.Cut(after, ".")
						if !strings.Contains(after, ".") {
							break
						}
					}
					slices.Reverse(r.VerifyPeerCertByName)
					break
				}
			}
		}
		isFromMitmAlpn := len(tlsConfig.NextProtos) == 1 && tls.IsFromMitm(tlsConfig.NextProtos[0])
		if isFromMitmAlpn {
			if mitmAlpn11 {
				tlsConfig.NextProtos[0] = "http/1.1"
			} else {
				tlsConfig.NextProtos = []string{"h2", "http/1.1"}
			}
		}
		if fingerprint := tls.GetFingerprint(config.Fingerprint); fingerprint != nil {
			conn = tls.UClient(conn, tlsConfig, fingerprint)
			if len(tlsConfig.NextProtos) == 1 && tlsConfig.NextProtos[0] == "http/1.1" { // allow manually specify
				err = conn.(*tls.UConn).WebsocketHandshakeContext(ctx)
			} else {
				err = conn.(*tls.UConn).HandshakeContext(ctx)
			}
		} else {
			conn = tls.Client(conn, tlsConfig)
			err = conn.(*tls.Conn).HandshakeContext(ctx)
		}
		if err != nil {
			if isFromMitmVerify {
				return nil, errors.New("MITM freedom RAW TLS: failed to verify Domain Fronting certificate from " + mitmServerName).Base(err).AtWarning()
			}
			return nil, err
		}
		negotiatedProtocol := conn.(tls.Interface).NegotiatedProtocol()
		if isFromMitmAlpn && !mitmAlpn11 && negotiatedProtocol != "h2" {
			conn.Close()
			return nil, errors.New("MITM freedom RAW TLS: unexpected Negotiated Protocol (" + negotiatedProtocol + ") with " + mitmServerName).AtWarning()
		}
	} else if config := reality.ConfigFromStreamSettings(streamSettings); config != nil {
		if conn, err = reality.UClient(conn, config, ctx, dest); err != nil {
			return nil, err
		}
	}

	tcpSettings := streamSettings.ProtocolSettings.(*Config)
	if tcpSettings.HeaderSettings != nil {
		headerConfig, err := tcpSettings.HeaderSettings.GetInstance()
		if err != nil {
			return nil, errors.New("failed to get header settings").Base(err).AtError()
		}
		auth, err := internet.CreateConnectionAuthenticator(headerConfig)
		if err != nil {
			return nil, errors.New("failed to create header authenticator").Base(err).AtError()
		}
		conn = auth.Client(conn)
	}
	return stat.Connection(conn), nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
