package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/ASTRACAT2022/aesingflow/pkg/aesingflow"
)

func TestSOCKS5Tunnel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		conn, err := echo.Accept()
		if err == nil {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}
	}()

	serverTLS, clientTLS := testTLS(t)
	server, err := aesingflow.NewServer(aesingflow.ServerConfig{
		Address:       "127.0.0.1:0",
		TLSConfig:     serverTLS,
		Authenticator: &aesingflow.StaticAuthenticator{Tokens: []aesingflow.Token{{Value: "test-token", Subject: "test"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	serverDone := make(chan error, 1)
	go func() { serverDone <- Serve(ctx, server, ServerConfig{}) }()

	flowClient, err := aesingflow.NewClient(aesingflow.ClientConfig{Address: server.Addr().String(), TLSConfig: clientTLS, Token: "test-token", ConnectTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service := &Client{client: flowClient, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	local, socks := net.Pipe()
	defer socks.Close()
	handled := make(chan struct{})
	go func() { defer close(handled); service.handle(ctx, local) }()

	if _, err = socks.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err = io.ReadFull(socks, method[:]); err != nil || method != [2]byte{5, 0} {
		t.Fatalf("SOCKS5 method response = %v, %v", method, err)
	}
	host, portText, err := net.SplitHostPort(echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		t.Fatal(err)
	}
	request := append([]byte{5, 1, 0, addressIPv4}, net.ParseIP(host).To4()...)
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err = socks.Write(request); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err = io.ReadFull(socks, reply[:]); err != nil || reply[1] != 0 {
		t.Fatalf("SOCKS5 CONNECT response = %v, %v", reply, err)
	}
	if _, err = socks.Write([]byte("through the tunnel")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("through the tunnel"))
	if _, err = io.ReadFull(socks, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "through the tunnel" {
		t.Fatalf("got %q", got)
	}
	_ = socks.Close()
	select {
	case <-handled:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cancel()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy server did not stop")
	}
}

func TestDialerTunnel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		conn, err := echo.Accept()
		if err == nil {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}
	}()

	serverTLS, clientTLS := testTLS(t)
	server, err := aesingflow.NewServer(aesingflow.ServerConfig{
		Address:       "127.0.0.1:0",
		TLSConfig:     serverTLS,
		Authenticator: &aesingflow.StaticAuthenticator{Tokens: []aesingflow.Token{{Value: "test-token", Subject: "test"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	serverDone := make(chan error, 1)
	go func() { serverDone <- Serve(ctx, server, ServerConfig{}) }()

	flowClient, err := aesingflow.NewClient(aesingflow.ClientConfig{Address: server.Addr().String(), TLSConfig: clientTLS, Token: "test-token", ConnectTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := NewDialer(DialerConfig{Client: flowClient, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.Close()

	conn, err := dialer.DialContext(ctx, "tcp", echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.Write([]byte("core adapter")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("core adapter"))
	if _, err = io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "core adapter" {
		t.Fatalf("got %q", got)
	}
	if _, err = dialer.DialContext(ctx, "udp", "127.0.0.1:53"); err == nil {
		t.Fatal("UDP dial unexpectedly succeeded")
	}

	cancel()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy server did not stop")
	}
}

func testTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	return &tls.Config{Certificates: []tls.Certificate{cert}}, &tls.Config{RootCAs: roots, ServerName: "localhost"}
}
