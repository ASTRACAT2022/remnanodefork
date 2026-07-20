package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/ASTRACAT2022/aesingflow/pkg/aesingflow"
)

// ServerConfig configures the exit side of an AesingFlow TCP proxy.
type ServerConfig struct {
	DialTimeout time.Duration
	Logger      *slog.Logger
}

// Serve accepts AesingFlow connections and proxies each stream to its requested
// TCP endpoint. Access to this service must be protected with a strong token.
func Serve(ctx context.Context, listener aesingflow.Server, cfg ServerConfig) error {
	if listener == nil {
		return fmt.Errorf("proxy: AesingFlow server is required")
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go serveConnection(ctx, conn, cfg)
	}
}

func serveConnection(ctx context.Context, conn aesingflow.Connection, cfg ServerConfig) {
	defer conn.CloseWithError(0, "proxy client disconnected")
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go serveStream(ctx, stream, cfg)
	}
}

func serveStream(ctx context.Context, stream aesingflow.StreamSession, cfg ServerConfig) {
	defer stream.Close()
	target, err := readRequest(stream)
	if err != nil {
		cfg.Logger.Debug("invalid proxy request", "error", err)
		return
	}
	dialCtx, cancel := context.WithTimeout(ctx, cfg.DialTimeout)
	remote, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", target.Address())
	cancel()
	if err != nil {
		_ = writeResponse(stream, statusFailure)
		cfg.Logger.Debug("proxy target connection failed", "target", target.Address(), "error", err)
		return
	}
	defer remote.Close()
	if err = writeResponse(stream, statusOK); err != nil {
		return
	}
	cfg.Logger.Debug("proxy target connection opened", "target", target.Address())
	copyBoth(remote, stream)
}
