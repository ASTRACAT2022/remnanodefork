package codec

import (
	"github.com/ASTRACAT2022/aesingflow/core/protocol"
	"testing"
)

func BenchmarkControlEncodeDecode(b *testing.B) {
	f := Frame{Major: protocol.Major, Minor: protocol.Minor, Type: protocol.Ping, Payload: make([]byte, 128)}
	for i := 0; i < b.N; i++ {
		raw, e := Encode(f, 1024)
		if e != nil {
			b.Fatal(e)
		}
		_, e = Read(&sliceReader{b: raw}, 1024)
		if e != nil {
			b.Fatal(e)
		}
	}
}

type sliceReader struct{ b []byte }

func (s *sliceReader) Read(p []byte) (int, error) { n := copy(p, s.b); s.b = s.b[n:]; return n, nil }
