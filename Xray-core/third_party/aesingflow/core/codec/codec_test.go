package codec

import (
	"bytes"
	"errors"
	aferrors "github.com/ASTRACAT2022/aesingflow/core/errors"
	"github.com/ASTRACAT2022/aesingflow/core/protocol"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	p, e := EncodeFields([]Field{{1, RequiredField, []byte("x")}}, 1024)
	if e != nil {
		t.Fatal(e)
	}
	b, e := Encode(Frame{protocol.Major, protocol.Minor, protocol.ClientHello, 0, 7, p}, 1024)
	if e != nil {
		t.Fatal(e)
	}
	f, e := Read(bytes.NewReader(b), 1024)
	if e != nil {
		t.Fatal(e)
	}
	if f.RequestID != 7 || f.Type != protocol.ClientHello {
		t.Fatal("mismatch")
	}
	fs, e := DecodeFields(f.Payload, 1024)
	if e != nil || len(fs) != 1 || string(fs[0].Value) != "x" {
		t.Fatal(e, fs)
	}
}
func TestMalformed(t *testing.T) {
	for _, b := range [][]byte{[]byte("bad"), append([]byte("AFLO\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"), make([]byte, 20)...)} {
		_, e := Read(bytes.NewReader(b), 16)
		if e == nil {
			t.Fatal("expected error")
		}
	}
	_, e := DecodeFields([]byte{0, 1, 0, 0, 0, 0, 3, 1}, 16)
	if e == nil || !errors.Is(e, aferrors.New(aferrors.InvalidMessage, "")) {
		t.Log(e)
	}
}
func FuzzFrameDecoder(f *testing.F) {
	f.Add([]byte("AFLO\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Read(bytes.NewReader(b), protocol.DefaultMaxControlMessage)
		_, _ = DecodeFields(b, protocol.DefaultMaxControlMessage)
	})
}
