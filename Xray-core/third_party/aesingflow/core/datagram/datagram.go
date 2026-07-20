// Package datagram implements AesingFlow's bounded datagram envelope.
package datagram

import (
	"encoding/binary"
	"github.com/ASTRACAT2022/aesingflow/core/errors"
)

const HeaderSize = 18

type Header struct {
	Version, Flags      uint8
	SessionID           uint64
	Sequence            uint32
	Fragment, Fragments uint8
}

func Encode(h Header, p []byte, max int) ([]byte, error) {
	if h.Version != 1 {
		return nil, errors.New(errors.InvalidMessage, "unsupported datagram format")
	}
	if len(p) > max || len(p) > 65535 {
		return nil, errors.New(errors.DatagramTooLarge, "datagram exceeds negotiated limit")
	}
	if h.Fragments > 1 {
		return nil, errors.New(errors.InvalidMessage, "datagram fragmentation not enabled")
	}
	b := make([]byte, HeaderSize+len(p))
	b[0] = h.Version
	b[1] = h.Flags
	binary.BigEndian.PutUint64(b[2:10], h.SessionID)
	binary.BigEndian.PutUint32(b[10:14], h.Sequence)
	b[14] = h.Fragment
	b[15] = h.Fragments
	binary.BigEndian.PutUint16(b[16:18], uint16(len(p)))
	copy(b[18:], p)
	return b, nil
}
func Decode(b []byte, max int) (Header, []byte, error) {
	if len(b) < HeaderSize {
		return Header{}, nil, errors.New(errors.InvalidMessage, "truncated datagram")
	}
	h := Header{b[0], b[1], binary.BigEndian.Uint64(b[2:10]), binary.BigEndian.Uint32(b[10:14]), b[14], b[15]}
	n := int(binary.BigEndian.Uint16(b[16:18]))
	if h.Version != 1 || h.Fragments > 1 || n > max || n != len(b)-HeaderSize {
		return Header{}, nil, errors.New(errors.InvalidMessage, "invalid datagram envelope")
	}
	return h, append([]byte(nil), b[HeaderSize:]...), nil
}
