package link

import (
	"crypto/tls"
	"testing"

	"github.com/ASTRACAT2022/aesingflow/pkg/aesingflow"
)

func TestParseAndCanonicalURI(t *testing.T) {
	raw := "aesingflow://token%2Fwith%20space@[2001:db8::1]:4433?sni=edge.example&brutal_bps=270000000&max_streams=64#My%20edge"
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Server != "[2001:db8::1]:4433" || p.Token != "token/with space" || p.ServerName != "edge.example" || p.Name != "My edge" || p.BrutalSendRate != 270000000 || p.MaxStreams != 64 {
		t.Fatalf("unexpected profile: %#v", p)
	}
	uri, err := p.URI()
	if err != nil {
		t.Fatal(err)
	}
	const canonical = "aesingflow://token%2Fwith%20space@[2001:db8::1]:4433?brutal_bps=270000000&max_streams=64&sni=edge.example#My%20edge"
	if uri != canonical {
		t.Fatalf("URI = %q, want %q", uri, canonical)
	}
}

func TestProfileDefaultsAndCubicOptOut(t *testing.T) {
	p, err := Parse("aesingflow://token@example.com:4433")
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{ServerName: "original.example"}
	cfg := p.ClientConfig(tlsConfig)
	if cfg.BrutalSendRate != 0 || cfg.DisableBrutal {
		t.Fatalf("default profile config = %#v", cfg)
	}
	if cfg.TLSConfig != tlsConfig {
		t.Fatal("TLS config changed without a profile SNI")
	}
	if aesingflow.DefaultBrutalSendRate != 250000000 {
		t.Fatal("unexpected default Brutal rate")
	}
	cubic, err := Parse("aesingflow://token@example.com:4433?cc=cubic")
	if err != nil || !cubic.DisableBrutal {
		t.Fatalf("CUBIC profile = %#v, %v", cubic, err)
	}
	sni, err := Parse("aesingflow://token@example.com:4433?sni=edge.example")
	if err != nil {
		t.Fatal(err)
	}
	if got := sni.ClientConfig(tlsConfig).TLSConfig.ServerName; got != "edge.example" {
		t.Fatalf("link SNI = %q", got)
	}
}

func TestParseRejectsUnsafeOrAmbiguousLinks(t *testing.T) {
	for _, raw := range []string{
		"https://token@example.com:4433",
		"aesingflow://example.com:4433",
		"aesingflow://token@example.com",
		"aesingflow://token@example.com:4433?cc=cubic&brutal_bps=1",
		"aesingflow://token@example.com:4433?unknown=value",
	} {
		if _, err := Parse(raw); err == nil {
			t.Fatalf("Parse(%q) unexpectedly succeeded", raw)
		}
	}
}
