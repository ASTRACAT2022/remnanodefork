// Package codec implements bounded AesingFlow control frames and TLV fields.
package codec

import (
	"encoding/binary"
	"fmt"
	"github.com/ASTRACAT2022/aesingflow/core/errors"
	"github.com/ASTRACAT2022/aesingflow/core/protocol"
	"io"
)

const HeaderSize = 20
const RequiredField uint8 = 1

type Frame struct {
	Major, Minor uint8
	Type         protocol.MessageType
	Flags        uint8
	RequestID    uint64
	Payload      []byte
}
type Field struct {
	Type  uint16
	Flags uint8
	Value []byte
}

func Encode(f Frame, max int) ([]byte, error) {
	if max <= 0 {
		max = protocol.DefaultMaxControlMessage
	}
	if len(f.Payload) > max {
		return nil, errors.New(errors.MessageTooLarge, "control message exceeds limit")
	}
	b := make([]byte, HeaderSize+len(f.Payload))
	copy(b, protocol.Magic)
	b[4] = f.Major
	b[5] = f.Minor
	b[6] = byte(f.Type)
	b[7] = f.Flags
	binary.BigEndian.PutUint64(b[8:16], f.RequestID)
	binary.BigEndian.PutUint32(b[16:20], uint32(len(f.Payload)))
	copy(b[20:], f.Payload)
	return b, nil
}
func Write(w io.Writer, f Frame, max int) error {
	b, e := Encode(f, max)
	if e != nil {
		return e
	}
	_, e = w.Write(b)
	return e
}
func Read(r io.Reader, max int) (Frame, error) {
	if max <= 0 {
		max = protocol.DefaultMaxControlMessage
	}
	var h [HeaderSize]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return Frame{}, e
	}
	if string(h[:4]) != protocol.Magic {
		return Frame{}, errors.New(errors.InvalidMessage, "invalid control magic")
	}
	n := binary.BigEndian.Uint32(h[16:])
	if n > uint32(max) {
		return Frame{}, errors.New(errors.MessageTooLarge, "control message exceeds limit")
	}
	p := make([]byte, n)
	if _, e := io.ReadFull(r, p); e != nil {
		return Frame{}, e
	}
	return Frame{h[4], h[5], protocol.MessageType(h[6]), h[7], binary.BigEndian.Uint64(h[8:16]), p}, nil
}
func EncodeFields(fields []Field, max int) ([]byte, error) {
	n := 0
	for _, f := range fields {
		if len(f.Value) > max {
			return nil, errors.New(errors.MessageTooLarge, "field exceeds limit")
		}
		n += 7 + len(f.Value)
		if n > max {
			return nil, errors.New(errors.MessageTooLarge, "payload exceeds limit")
		}
	}
	b := make([]byte, n)
	p := 0
	for _, f := range fields {
		binary.BigEndian.PutUint16(b[p:], f.Type)
		b[p+2] = f.Flags
		binary.BigEndian.PutUint32(b[p+3:], uint32(len(f.Value)))
		p += 7
		copy(b[p:], f.Value)
		p += len(f.Value)
	}
	return b, nil
}
func DecodeFields(b []byte, max int) ([]Field, error) {
	if len(b) > max {
		return nil, errors.New(errors.MessageTooLarge, "payload exceeds limit")
	}
	out := make([]Field, 0, 8)
	seen := map[uint16]struct{}{}
	for len(b) > 0 {
		if len(b) < 7 {
			return nil, errors.New(errors.InvalidMessage, "truncated TLV field")
		}
		t := binary.BigEndian.Uint16(b)
		fl := b[2]
		n := binary.BigEndian.Uint32(b[3:])
		b = b[7:]
		if n > uint32(len(b)) {
			return nil, errors.New(errors.InvalidMessage, "invalid TLV length")
		}
		if _, ok := seen[t]; ok {
			return nil, errors.New(errors.InvalidMessage, "duplicate TLV field")
		}
		seen[t] = struct{}{}
		v := append([]byte(nil), b[:n]...)
		out = append(out, Field{t, fl, v})
		b = b[n:]
	}
	return out, nil
}
func Require(fields []Field, types ...uint16) error {
	m := map[uint16]Field{}
	for _, f := range fields {
		m[f.Type] = f
	}
	for _, t := range types {
		if _, ok := m[t]; !ok {
			return fmt.Errorf("%w: missing required field %d", errors.New(errors.InvalidMessage, "missing required field"), t)
		}
	}
	return nil
}
