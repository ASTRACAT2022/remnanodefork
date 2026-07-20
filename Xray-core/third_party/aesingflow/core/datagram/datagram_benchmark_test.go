package datagram

import "testing"

func BenchmarkDatagramRoute(b *testing.B) {
	p := make([]byte, 512)
	for i := 0; i < b.N; i++ {
		raw, e := Encode(Header{Version: 1, SessionID: 1, Sequence: uint32(i)}, p, 1024)
		if e != nil {
			b.Fatal(e)
		}
		if _, _, e = Decode(raw, 1024); e != nil {
			b.Fatal(e)
		}
	}
}
