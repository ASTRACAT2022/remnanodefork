package datagram

import "testing"

func TestRoundTrip(t *testing.T) {
	b, e := Encode(Header{Version: 1, SessionID: 9}, []byte("ok"), 16)
	if e != nil {
		t.Fatal(e)
	}
	h, p, e := Decode(b, 16)
	if e != nil || h.SessionID != 9 || string(p) != "ok" {
		t.Fatal(e)
	}
}
