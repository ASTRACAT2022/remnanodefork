package aesingflow

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"
	"time"
)

func testTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	return &tls.Config{Certificates: []tls.Certificate{cert}}, &tls.Config{RootCAs: roots, ServerName: "localhost"}
}
func testPair(t *testing.T) (Connection, Connection, func()) {
	t.Helper()
	st, ct := testTLS(t)
	srv, e := NewServer(ServerConfig{Address: "127.0.0.1:0", TLSConfig: st, Authenticator: &StaticAuthenticator{Tokens: []Token{{Value: "token", Subject: "test"}}}, MaxStreamsPerClient: 8, MaxDatagramSessions: 8})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	sc := make(chan Connection, 1)
	ec := make(chan error, 1)
	go func() {
		x, e := srv.Accept(ctx)
		if e != nil {
			ec <- e
			return
		}
		sc <- x
	}()
	cl, e := NewClient(ClientConfig{Address: srv.Addr().String(), TLSConfig: ct, Token: "token", EnableDatagrams: true, MaxStreams: 8})
	if e != nil {
		t.Fatal(e)
	}
	cc, e := cl.Connect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var serverConn Connection
	select {
	case serverConn = <-sc:
	case e = <-ec:
		t.Fatal(e)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	return cc, serverConn, func() {
		_ = cc.CloseWithError(0, "done")
		_ = serverConn.CloseWithError(0, "done")
		_ = srv.Close()
		cancel()
	}
}

func TestBrutalDefaultsAndOptOut(t *testing.T) {
	_, clientTLS := testTLS(t)
	defaultClient, err := NewClient(ClientConfig{Address: "127.0.0.1:4433", TLSConfig: clientTLS, Token: "token"})
	if err != nil {
		t.Fatal(err)
	}
	if got := defaultClient.(*client).cfg.BrutalSendRate; got != DefaultBrutalSendRate {
		t.Fatalf("default Brutal rate = %d, want %d", got, DefaultBrutalSendRate)
	}
	cubicClient, err := NewClient(ClientConfig{Address: "127.0.0.1:4433", TLSConfig: clientTLS, Token: "token", DisableBrutal: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := cubicClient.(*client).cfg.BrutalSendRate; got != 0 {
		t.Fatalf("CUBIC opt-out rate = %d, want 0", got)
	}
}

func TestBrutalQUICHandshake(t *testing.T) {
	st, ct := testTLS(t)
	srv, err := NewServer(ServerConfig{
		Address:             "127.0.0.1:0",
		TLSConfig:           st,
		Authenticator:       &StaticAuthenticator{Tokens: []Token{{Value: "token", Subject: "test"}}},
		BrutalSendRate:      100_000_000,
		MaxStreamsPerClient: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	accepted := make(chan Connection, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := srv.Accept(ctx)
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	cl, err := NewClient(ClientConfig{Address: srv.Addr().String(), TLSConfig: ct, Token: "token", BrutalSendRate: 100_000_000})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := cl.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "test complete")
	select {
	case serverConn := <-accepted:
		defer serverConn.CloseWithError(0, "test complete")
	case err = <-acceptErr:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestQUICHandshakeAndStreamEcho(t *testing.T) {
	c, s, done := testPair(t)
	defer done()
	cs, e := c.OpenStream(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	ss, e := s.AcceptStream(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		b := make([]byte, 32)
		n, e := ss.Read(b)
		if e != nil {
			t.Error(e)
			return
		}
		_, e = ss.Write(b[:n])
		if e != nil {
			t.Error(e)
		}
	}()
	if _, e = cs.Write([]byte("stream echo")); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 32)
	n, e := cs.Read(b)
	if e != nil {
		t.Fatal(e)
	}
	if string(b[:n]) != "stream echo" {
		t.Fatalf("got %q", b[:n])
	}
	wg.Wait()
}
func TestQUICDatagramEcho(t *testing.T) {
	c, s, done := testPair(t)
	defer done()
	cd, e := c.OpenDatagramSession(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sd, e := s.AcceptDatagramSession(ctx)
	if e != nil {
		t.Fatal(e)
	}
	go func() {
		p, e := sd.Receive(ctx)
		if e == nil {
			_ = sd.Send(ctx, p)
		}
	}()
	if e = cd.Send(ctx, []byte("datagram echo")); e != nil {
		t.Fatal(e)
	}
	p, e := cd.Receive(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if string(p) != "datagram echo" {
		t.Fatalf("got %q", p)
	}
	if e = cd.Send(ctx, make([]byte, 4096)); e == nil {
		t.Fatal("accepted oversized datagram")
	}
}
func TestInvalidToken(t *testing.T) {
	st, ct := testTLS(t)
	srv, e := NewServer(ServerConfig{Address: "127.0.0.1:0", TLSConfig: st, Authenticator: &StaticAuthenticator{Tokens: []Token{{Value: "token"}}}})
	if e != nil {
		t.Fatal(e)
	}
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _, _ = srv.Accept(ctx) }()
	cl, _ := NewClient(ClientConfig{Address: srv.Addr().String(), TLSConfig: ct, Token: "wrong"})
	_, e = cl.Connect(ctx)
	if e == nil {
		t.Fatal("expected auth failure")
	}
}
func TestContextCancellation(t *testing.T) {
	c, s, done := testPair(t)
	defer done()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := c.AcceptStream(ctx); e == nil {
		t.Fatal("expected context cancellation")
	}
	_ = s
}
