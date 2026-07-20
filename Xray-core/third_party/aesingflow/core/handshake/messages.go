// Package handshake serializes the control-stream handshake messages.
package handshake

import (
	"encoding/binary"
	"fmt"
	"github.com/ASTRACAT2022/aesingflow/core/auth"
	"github.com/ASTRACAT2022/aesingflow/core/codec"
	"github.com/ASTRACAT2022/aesingflow/core/errors"
	"github.com/ASTRACAT2022/aesingflow/core/protocol"
	"time"
)

const (
	fCapabilities uint16 = iota + 1
	fConnectionID
	fTimestamp
	fNonce
	fMaxControl
	fMaxDatagram
	fRecovery
	fPadding
	fImplementation
	fSelectedMajor
	fSelectedMinor
	fLimitStreams
	fLimitDatagrams
	fIdle
	fKeepAlive
	fResult
	fToken
	fAuthCode
	fSubject
	fExpiry
	fSessionID
)

type ClientHello struct {
	Capabilities            protocol.Capability
	ConnectionID            [16]byte
	Timestamp               time.Time
	Nonce                   [16]byte
	MaxControl, MaxDatagram uint32
	Recovery, Padding       bool
	Implementation          string
}
type ServerHello struct {
	Major, Minor                          uint8
	Capabilities                          protocol.Capability
	ConnectionID                          [16]byte
	Nonce                                 [16]byte
	MaxStreams, MaxDatagrams, MaxDatagram uint32
	IdleTimeout, KeepAlive                time.Duration
	MaxControl                            uint32
	Result                                errors.Code
}
type Open struct{ SessionID uint64 }

func u64(v uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, v); return b }
func u32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
func field(t uint16, flags uint8, value []byte) codec.Field {
	return codec.Field{Type: t, Flags: flags, Value: value}
}
func boolean(v bool) []byte {
	if v {
		return []byte{1}
	}
	return []byte{0}
}
func get(fs []codec.Field, t uint16) ([]byte, bool) {
	for _, f := range fs {
		if f.Type == t {
			return f.Value, true
		}
	}
	return nil, false
}
func checkUnknown(fs []codec.Field, known map[uint16]bool) error {
	for _, f := range fs {
		if !known[f.Type] && f.Flags&codec.RequiredField != 0 {
			return errors.New(errors.InvalidMessage, "unknown required field")
		}
	}
	return nil
}
func clientFields(h ClientHello) []codec.Field {
	return []codec.Field{field(fCapabilities, codec.RequiredField, u64(uint64(h.Capabilities))), field(fConnectionID, codec.RequiredField, h.ConnectionID[:]), field(fTimestamp, codec.RequiredField, u64(uint64(h.Timestamp.UnixMilli()))), field(fNonce, codec.RequiredField, h.Nonce[:]), field(fMaxControl, codec.RequiredField, u32(h.MaxControl)), field(fMaxDatagram, codec.RequiredField, u32(h.MaxDatagram)), field(fRecovery, 0, boolean(h.Recovery)), field(fPadding, 0, boolean(h.Padding)), field(fImplementation, 0, []byte(h.Implementation))}
}
func ClientHelloFrame(h ClientHello, max int) (codec.Frame, error) {
	p, e := codec.EncodeFields(clientFields(h), max)
	return codec.Frame{Major: protocol.Major, Minor: protocol.Minor, Type: protocol.ClientHello, Payload: p}, e
}
func ParseClientHello(f codec.Frame, max int) (ClientHello, error) {
	if f.Type != protocol.ClientHello {
		return ClientHello{}, errors.New(errors.InvalidMessage, "expected client hello")
	}
	fs, e := codec.DecodeFields(f.Payload, max)
	if e != nil {
		return ClientHello{}, e
	}
	known := map[uint16]bool{fCapabilities: true, fConnectionID: true, fTimestamp: true, fNonce: true, fMaxControl: true, fMaxDatagram: true, fRecovery: true, fPadding: true, fImplementation: true}
	if e = checkUnknown(fs, known); e != nil {
		return ClientHello{}, e
	}
	if e = codec.Require(fs, fCapabilities, fConnectionID, fTimestamp, fNonce, fMaxControl, fMaxDatagram); e != nil {
		return ClientHello{}, e
	}
	var h ClientHello
	v, _ := get(fs, fCapabilities)
	if len(v) != 8 {
		return h, errors.New(errors.InvalidMessage, "invalid capability length")
	}
	h.Capabilities = protocol.Capability(binary.BigEndian.Uint64(v))
	if protocol.UnknownCapabilities(h.Capabilities) != 0 {
		return h, errors.New(errors.VersionUnsupported, "unknown mandatory capability")
	}
	v, _ = get(fs, fConnectionID)
	if len(v) != 16 {
		return h, errors.New(errors.InvalidMessage, "invalid connection ID")
	}
	copy(h.ConnectionID[:], v)
	v, _ = get(fs, fNonce)
	if len(v) != 16 {
		return h, errors.New(errors.InvalidMessage, "invalid nonce")
	}
	copy(h.Nonce[:], v)
	v, _ = get(fs, fTimestamp)
	if len(v) != 8 {
		return h, errors.New(errors.InvalidMessage, "invalid timestamp")
	}
	h.Timestamp = time.UnixMilli(int64(binary.BigEndian.Uint64(v)))
	v, _ = get(fs, fMaxControl)
	if len(v) != 4 {
		return h, errors.New(errors.InvalidMessage, "invalid control limit")
	}
	h.MaxControl = binary.BigEndian.Uint32(v)
	v, _ = get(fs, fMaxDatagram)
	if len(v) != 4 {
		return h, errors.New(errors.InvalidMessage, "invalid datagram limit")
	}
	h.MaxDatagram = binary.BigEndian.Uint32(v)
	if v, ok := get(fs, fRecovery); ok {
		h.Recovery = len(v) == 1 && v[0] == 1
	}
	if v, ok := get(fs, fPadding); ok {
		h.Padding = len(v) == 1 && v[0] == 1
	}
	if v, ok := get(fs, fImplementation); ok {
		if len(v) > 256 {
			return h, errors.New(errors.MessageTooLarge, "implementation too long")
		}
		h.Implementation = string(v)
	}
	return h, nil
}
func ServerHelloFrame(h ServerHello, max int) (codec.Frame, error) {
	fs := []codec.Field{field(fSelectedMajor, codec.RequiredField, []byte{h.Major}), field(fSelectedMinor, codec.RequiredField, []byte{h.Minor}), field(fCapabilities, codec.RequiredField, u64(uint64(h.Capabilities))), field(fConnectionID, codec.RequiredField, h.ConnectionID[:]), field(fNonce, codec.RequiredField, h.Nonce[:]), field(fLimitStreams, codec.RequiredField, u32(h.MaxStreams)), field(fLimitDatagrams, codec.RequiredField, u32(h.MaxDatagrams)), field(fMaxDatagram, codec.RequiredField, u32(h.MaxDatagram)), field(fIdle, codec.RequiredField, u64(uint64(h.IdleTimeout.Milliseconds()))), field(fKeepAlive, codec.RequiredField, u64(uint64(h.KeepAlive.Milliseconds()))), field(fMaxControl, codec.RequiredField, u32(h.MaxControl)), field(fResult, codec.RequiredField, u64(uint64(h.Result)))}
	p, e := codec.EncodeFields(fs, max)
	return codec.Frame{Major: protocol.Major, Minor: protocol.Minor, Type: protocol.ServerHello, Payload: p}, e
}
func ParseServerHello(f codec.Frame, max int) (ServerHello, error) {
	if f.Type != protocol.ServerHello {
		return ServerHello{}, errors.New(errors.InvalidMessage, "expected server hello")
	}
	fs, e := codec.DecodeFields(f.Payload, max)
	if e != nil {
		return ServerHello{}, e
	}
	if e = checkUnknown(fs, map[uint16]bool{fSelectedMajor: true, fSelectedMinor: true, fCapabilities: true, fConnectionID: true, fNonce: true, fLimitStreams: true, fLimitDatagrams: true, fMaxDatagram: true, fIdle: true, fKeepAlive: true, fMaxControl: true, fResult: true}); e != nil {
		return ServerHello{}, e
	}
	if e = codec.Require(fs, fSelectedMajor, fSelectedMinor, fCapabilities, fConnectionID, fNonce, fLimitStreams, fLimitDatagrams, fMaxDatagram, fIdle, fKeepAlive, fMaxControl, fResult); e != nil {
		return ServerHello{}, e
	}
	var h ServerHello
	one := func(t uint16) ([]byte, error) {
		v, ok := get(fs, t)
		if !ok {
			return nil, fmt.Errorf("missing %d", t)
		}
		return v, nil
	}
	v, _ := one(fSelectedMajor)
	if len(v) != 1 {
		return h, errors.New(errors.InvalidMessage, "invalid major")
	}
	h.Major = v[0]
	v, _ = one(fSelectedMinor)
	if len(v) != 1 {
		return h, errors.New(errors.InvalidMessage, "invalid minor")
	}
	h.Minor = v[0]
	v, _ = one(fCapabilities)
	if len(v) != 8 {
		return h, errors.New(errors.InvalidMessage, "invalid capabilities")
	}
	h.Capabilities = protocol.Capability(binary.BigEndian.Uint64(v))
	v, _ = one(fConnectionID)
	if len(v) != 16 {
		return h, errors.New(errors.InvalidMessage, "invalid connection ID")
	}
	copy(h.ConnectionID[:], v)
	v, _ = one(fNonce)
	if len(v) != 16 {
		return h, errors.New(errors.InvalidMessage, "invalid nonce")
	}
	copy(h.Nonce[:], v)
	u := func(t uint16) (uint64, error) {
		v, e := one(t)
		if e != nil || len(v) != 8 {
			return 0, errors.New(errors.InvalidMessage, "invalid integer")
		}
		return binary.BigEndian.Uint64(v), nil
	}
	v, _ = one(fLimitStreams)
	if len(v) != 4 {
		return h, errors.New(errors.InvalidMessage, "invalid stream limit")
	}
	h.MaxStreams = binary.BigEndian.Uint32(v)
	v, _ = one(fLimitDatagrams)
	if len(v) != 4 {
		return h, errors.New(errors.InvalidMessage, "invalid datagram limit")
	}
	h.MaxDatagrams = binary.BigEndian.Uint32(v)
	v, _ = one(fMaxDatagram)
	if len(v) != 4 {
		return h, errors.New(errors.InvalidMessage, "invalid datagram size")
	}
	h.MaxDatagram = binary.BigEndian.Uint32(v)
	x, e := u(fIdle)
	x, e = u(fIdle)
	if e != nil {
		return h, e
	}
	h.IdleTimeout = time.Duration(x) * time.Millisecond
	x, e = u(fKeepAlive)
	if e != nil {
		return h, e
	}
	h.KeepAlive = time.Duration(x) * time.Millisecond
	x, e = u(fResult)
	if e != nil {
		return h, e
	}
	h.Result = errors.Code(x)
	v, _ = one(fMaxControl)
	if len(v) != 4 {
		return h, errors.New(errors.InvalidMessage, "invalid max control")
	}
	h.MaxControl = binary.BigEndian.Uint32(v)
	return h, nil
}
func AuthRequestFrame(r auth.Request, max int) (codec.Frame, error) {
	p, e := codec.EncodeFields([]codec.Field{field(fToken, codec.RequiredField, []byte(r.Token)), field(fNonce, codec.RequiredField, r.Nonce[:]), field(fTimestamp, codec.RequiredField, u64(uint64(r.Timestamp.UnixMilli())))}, max)
	return codec.Frame{Major: protocol.Major, Minor: protocol.Minor, Type: protocol.AuthRequest, Payload: p}, e
}
func ParseAuthRequest(f codec.Frame, max int) (auth.Request, error) {
	if f.Type != protocol.AuthRequest {
		return auth.Request{}, errors.New(errors.InvalidMessage, "expected authentication request")
	}
	fs, e := codec.DecodeFields(f.Payload, max)
	if e != nil {
		return auth.Request{}, e
	}
	if e = checkUnknown(fs, map[uint16]bool{fToken: true, fNonce: true, fTimestamp: true}); e != nil {
		return auth.Request{}, e
	}
	if e = codec.Require(fs, fToken, fNonce, fTimestamp); e != nil {
		return auth.Request{}, e
	}
	var r auth.Request
	v, _ := get(fs, fToken)
	if len(v) == 0 || len(v) > 4096 {
		return r, errors.New(errors.AuthFailed, "authentication failed")
	}
	r.Token = string(v)
	v, _ = get(fs, fNonce)
	if len(v) != 16 {
		return r, errors.New(errors.InvalidMessage, "invalid nonce")
	}
	copy(r.Nonce[:], v)
	v, _ = get(fs, fTimestamp)
	if len(v) != 8 {
		return r, errors.New(errors.InvalidMessage, "invalid timestamp")
	}
	r.Timestamp = time.UnixMilli(int64(binary.BigEndian.Uint64(v)))
	return r, nil
}
func AuthResultFrame(result auth.Result, code errors.Code, max int) (codec.Frame, error) {
	fs := []codec.Field{field(fAuthCode, codec.RequiredField, u64(uint64(code))), field(fSubject, 0, []byte(result.Subject))}
	if !result.ExpiresAt.IsZero() {
		fs = append(fs, field(fExpiry, 0, u64(uint64(result.ExpiresAt.UnixMilli()))))
	}
	p, e := codec.EncodeFields(fs, max)
	return codec.Frame{Major: protocol.Major, Minor: protocol.Minor, Type: protocol.AuthResult, Payload: p}, e
}
func ParseAuthResult(f codec.Frame, max int) (errors.Code, error) {
	if f.Type != protocol.AuthResult {
		return errors.InvalidMessage, errors.New(errors.InvalidMessage, "expected authentication result")
	}
	fs, e := codec.DecodeFields(f.Payload, max)
	if e != nil {
		return errors.InvalidMessage, e
	}
	if e = checkUnknown(fs, map[uint16]bool{fAuthCode: true, fSubject: true, fExpiry: true}); e != nil {
		return errors.InvalidMessage, e
	}
	if e = codec.Require(fs, fAuthCode); e != nil {
		return errors.InvalidMessage, e
	}
	v, _ := get(fs, fAuthCode)
	if len(v) != 8 {
		return errors.InvalidMessage, errors.New(errors.InvalidMessage, "invalid authentication result")
	}
	return errors.Code(binary.BigEndian.Uint64(v)), nil
}
func OpenFrame(typ protocol.MessageType, id uint64, max int) (codec.Frame, error) {
	p, e := codec.EncodeFields([]codec.Field{field(fSessionID, codec.RequiredField, u64(id))}, max)
	return codec.Frame{Major: protocol.Major, Minor: protocol.Minor, Type: typ, Payload: p}, e
}
func ParseOpen(f codec.Frame, max int) (uint64, error) {
	fs, e := codec.DecodeFields(f.Payload, max)
	if e != nil {
		return 0, e
	}
	if e = codec.Require(fs, fSessionID); e != nil {
		return 0, e
	}
	v, _ := get(fs, fSessionID)
	if len(v) != 8 {
		return 0, errors.New(errors.InvalidMessage, "invalid session ID")
	}
	return binary.BigEndian.Uint64(v), nil
}
