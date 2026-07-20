package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/ASTRACAT2022/aesingflow/pkg/aesingflow"
	"io"
	"os"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:4433", "server address")
	serverName := flag.String("server-name", "localhost", "TLS server name")
	caFile := flag.String("ca", "", "server CA PEM")
	token := flag.String("token", "", "test token")
	streams := flag.Int("streams", 4, "number of stream echo sessions")
	flag.Parse()
	if *caFile == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "-ca and -token are required")
		os.Exit(2)
	}
	pem, e := os.ReadFile(*caFile)
	if e != nil {
		panic(e)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		panic("invalid CA")
	}
	cl, e := aesingflow.NewClient(aesingflow.ClientConfig{Address: *addr, TLSConfig: &tls.Config{RootCAs: roots, ServerName: *serverName}, Token: *token, EnableDatagrams: true})
	if e != nil {
		panic(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, e := cl.Connect(ctx)
	if e != nil {
		panic(e)
	}
	defer c.CloseWithError(0, "test complete")
	for i := 0; i < *streams; i++ {
		s, e := c.OpenStream(ctx)
		if e != nil {
			panic(e)
		}
		msg := []byte(fmt.Sprintf("stream-%d", i))
		if _, e = s.Write(msg); e != nil {
			panic(e)
		}
		b := make([]byte, len(msg))
		if _, e = io.ReadFull(s, b); e != nil {
			panic(e)
		}
		fmt.Printf("stream %d echo: %q\n", i, b)
	}
	d, e := c.OpenDatagramSession(ctx)
	if e != nil {
		panic(e)
	}
	start := time.Now()
	if e = d.Send(ctx, []byte("datagram ping")); e != nil {
		panic(e)
	}
	p, e := d.Receive(ctx)
	if e != nil {
		panic(e)
	}
	rtt := time.Since(start)
	fmt.Printf("datagram echo: %q, application RTT: %s, throughput: %.0f B/s\n", p, rtt.Round(time.Microsecond), float64(len(p))/rtt.Seconds())
	fmt.Printf("stats: %+v; datagram drops observed: %d\n", c.Stats(), d.Stats().Dropped)
}
