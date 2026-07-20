package main

import (
	"context"
	"crypto/tls"
	"flag"
	"github.com/ASTRACAT2022/aesingflow/pkg/aesingflow"
	"log/slog"
	"os"
	"time"
)

func main() {
	addr := flag.String("addr", ":4433", "QUIC listen address")
	certFile := flag.String("cert", "", "PEM certificate")
	keyFile := flag.String("key", "", "PEM private key")
	token := flag.String("token", "", "test token")
	flag.Parse()
	if *certFile == "" || *keyFile == "" || *token == "" {
		slog.Error("cert, key and token are required")
		os.Exit(2)
	}
	cert, e := tls.LoadX509KeyPair(*certFile, *keyFile)
	if e != nil {
		slog.Error("load certificate", "error", e)
		os.Exit(1)
	}
	srv, e := aesingflow.NewServer(aesingflow.ServerConfig{Address: *addr, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, Authenticator: &aesingflow.StaticAuthenticator{Tokens: []aesingflow.Token{{Value: *token, Subject: "test"}}}, KeepAliveInterval: 10 * time.Second})
	if e != nil {
		slog.Error("create server", "error", e)
		os.Exit(1)
	}
	slog.Info("AesingFlow test server listening", "address", srv.Addr())
	for {
		c, e := srv.Accept(context.Background())
		if e != nil {
			slog.Error("accept", "error", e)
			return
		}
		go echo(c)
	}
}
func echo(c aesingflow.Connection) {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			slog.Info("connection stats", "stats", c.Stats())
		}
	}()
	go func() {
		for {
			d, e := c.AcceptDatagramSession(context.Background())
			if e != nil {
				return
			}
			go func() {
				for {
					p, e := d.Receive(context.Background())
					if e != nil {
						return
					}
					_ = d.Send(context.Background(), p)
				}
			}()
		}
	}()
	for {
		st, e := c.AcceptStream(context.Background())
		if e != nil {
			return
		}
		go func() {
			b := make([]byte, 32<<10)
			for {
				n, e := st.Read(b)
				if n > 0 {
					_, _ = st.Write(b[:n])
				}
				if e != nil {
					return
				}
			}
		}()
	}
}
