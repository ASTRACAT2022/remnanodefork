package handshake

import (
	"github.com/ASTRACAT2022/aesingflow/core/protocol"
	"testing"
	"time"
)

func TestClientHelloRoundTrip(t *testing.T) {
	h := ClientHello{Capabilities: protocol.CapabilityDatagrams, Timestamp: time.Now(), MaxControl: 100, MaxDatagram: 90, Implementation: "test"}
	h.Nonce[0] = 1
	f, e := ClientHelloFrame(h, 1024)
	if e != nil {
		t.Fatal(e)
	}
	got, e := ParseClientHello(f, 1024)
	if e != nil {
		t.Fatal(e)
	}
	if got.MaxDatagram != 90 || got.Nonce[0] != 1 {
		t.Fatal("mismatch")
	}
}
