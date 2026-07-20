// aesingflow-proxy-server is the AesingFlow TCP proxy exit server.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/ASTRACAT2022/aesingflow/pkg/aesingflow"
	"github.com/ASTRACAT2022/aesingflow/proxy"
)

func main() {
	listen := flag.String("listen", ":4433", "QUIC/UDP listen address")
	certFile := flag.String("cert", "", "TLS certificate PEM")
	keyFile := flag.String("key", "", "TLS private key PEM")
	token := flag.String("token", "", "AesingFlow access token")
	maxStreams := flag.Int("max-streams", 256, "maximum concurrent TCP streams per client")
	cc := flag.String("cc", "brutal", "QUIC congestion controller: brutal (default) or cubic")
	brutalBPS := flag.Uint64("brutal-bps", aesingflow.DefaultBrutalSendRate, "Brutal outbound rate limit in bits/s")
	brutalDisableLossCompensation := flag.Bool("brutal-disable-loss-compensation", false, "disable Brutal loss compensation")
	flag.Parse()
	if *certFile == "" || *keyFile == "" || *token == "" {
		slog.Error("-cert, -key, and -token are required")
		os.Exit(2)
	}
	if *cc != "cubic" && *cc != "brutal" {
		slog.Error("-cc must be cubic or brutal")
		os.Exit(2)
	}
	brutalSendRate := uint64(0)
	if *cc == "brutal" {
		brutalSendRate = *brutalBPS
	}
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		slog.Error("load TLS certificate", "error", err)
		os.Exit(1)
	}
	server, err := aesingflow.NewServer(aesingflow.ServerConfig{Address: *listen, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, Authenticator: &aesingflow.StaticAuthenticator{Tokens: []aesingflow.Token{{Value: *token, Subject: "proxy"}}}, MaxStreamsPerClient: *maxStreams, BrutalSendRate: brutalSendRate, DisableBrutal: *cc == "cubic", BrutalDisableLossCompensation: *brutalDisableLossCompensation})
	if err != nil {
		slog.Error("create AesingFlow server", "error", err)
		os.Exit(1)
	}
	defer server.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	slog.Info("AesingFlow proxy server listening", "address", server.Addr())
	if err = proxy.Serve(ctx, server, proxy.ServerConfig{}); err != nil {
		slog.Error("proxy server stopped", "error", err)
		os.Exit(1)
	}
}
