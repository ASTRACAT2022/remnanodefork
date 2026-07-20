// Package errors defines safe wire errors and their QUIC application codes.
package errors

import "fmt"

type Code uint64

const (
	NoError Code = iota
	InternalError
	ProtocolError
	VersionUnsupported
	AuthFailed
	AuthExpired
	ReplayDetected
	LimitExceeded
	MessageTooLarge
	InvalidMessage
	InvalidState
	SessionNotFound
	SessionTimeout
	DatagramTooLarge
	ServerBusy
	ShuttingDown
)

func (c Code) String() string {
	return [...]string{"no error", "internal error", "protocol error", "version unsupported", "authentication failed", "authentication expired", "replay detected", "limit exceeded", "message too large", "invalid message", "invalid state", "session not found", "session timeout", "datagram too large", "server busy", "shutting down"}[c]
}

// Error carries a safe peer-facing code. Internal causes must be logged locally.
type Error struct {
	Code    Code
	Message string
	Cause   error
}

func (e *Error) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return e.Code.String()
}
func (e *Error) Unwrap() error       { return e.Cause }
func New(c Code, msg string) error   { return &Error{Code: c, Message: msg} }
func Wrap(c Code, cause error) error { return &Error{Code: c, Message: c.String(), Cause: cause} }
func CodeOf(err error) Code {
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return InternalError
}
func (c Code) GoString() string { return fmt.Sprintf("AesingFlowCode(%d)", c) }
