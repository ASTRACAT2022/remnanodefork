// aesingflow-proxy-client runs a local SOCKS5 proxy on macOS or another OS.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ASTRACAT2022/aesingflow/pkg/aesingflow"
	"github.com/ASTRACAT2022/aesingflow/pkg/link"
	"github.com/ASTRACAT2022/aesingflow/proxy"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8010", "local SOCKS5 listen address")
	shareLink := flag.String("link", "", "aesingflow:// profile link (overrides server, token, SNI, controller, rate, and stream limit)")
	server := flag.String("server", "", "AesingFlow server host:port")
	serverName := flag.String("server-name", "", "TLS certificate name (defaults to server host)")
	caFile := flag.String("ca", "", "optional server CA certificate in PEM format (needed for a private/self-signed certificate)")
	token := flag.String("token", "", "AesingFlow access token")
	maxStreams := flag.Int("max-streams", 256, "maximum concurrent SOCKS5 TCP streams")
	cc := flag.String("cc", "brutal", "QUIC congestion controller: brutal (default) or cubic")
	brutalBPS := flag.Uint64("brutal-bps", aesingflow.DefaultBrutalSendRate, "Brutal outbound rate limit in bits/s")
	brutalDisableLossCompensation := flag.Bool("brutal-disable-loss-compensation", false, "disable Brutal loss compensation")
	flag.Parse()
	if *shareLink != "" {
		profile, err := link.Parse(*shareLink)
		if err != nil {
			slog.Error("parse AesingFlow link", "error", err)
			os.Exit(2)
		}
		*server = profile.Server
		*token = profile.Token
		*serverName = profile.ServerName
		if profile.MaxStreams != 0 {
			*maxStreams = profile.MaxStreams
		}
		if profile.DisableBrutal {
			*cc = "cubic"
			*brutalBPS = 0
		} else {
			*cc = "brutal"
			if profile.BrutalSendRate != 0 {
				*brutalBPS = profile.BrutalSendRate
			}
		}
	}
	if *server == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "-server and -token are required")
		os.Exit(2)
	}
	if *cc != "cubic" && *cc != "brutal" {
		fmt.Fprintln(os.Stderr, "-cc must be cubic or brutal")
		os.Exit(2)
	}
	brutalSendRate := uint64(0)
	if *cc == "brutal" {
		brutalSendRate = *brutalBPS
	}
	name := *serverName
	var err error
	if name == "" {
		name, _, err = net.SplitHostPort(*server)
		if err != nil {
			slog.Error("invalid server address", "error", err)
			os.Exit(2)
		}
	}
	tlsConfig := &tls.Config{ServerName: name}
	if *caFile != "" {
		pem, readErr := os.ReadFile(*caFile)
		if readErr != nil {
			slog.Error("read CA", "error", readErr)
			os.Exit(1)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			slog.Error("invalid CA PEM")
			os.Exit(1)
		}
		tlsConfig.RootCAs = roots
	}
	client, err := aesingflow.NewClient(aesingflow.ClientConfig{Address: *server, TLSConfig: tlsConfig, Token: *token, ConnectTimeout: 15 * time.Second, MaxStreams: *maxStreams, BrutalSendRate: brutalSendRate, DisableBrutal: *cc == "cubic", BrutalDisableLossCompensation: *brutalDisableLossCompensation})
	if err != nil {
		slog.Error("create AesingFlow client", "error", err)
		os.Exit(1)
	}
	service, err := proxy.NewClient(proxy.ClientConfig{ListenAddress: *listen, Client: client})
	if err != nil {
		slog.Error("create SOCKS5 proxy", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err = service.ListenAndServe(ctx); err != nil {
		slog.Error("SOCKS5 proxy stopped", "error", err)
		os.Exit(1)
	}
}
