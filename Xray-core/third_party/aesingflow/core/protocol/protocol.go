// Package protocol contains AesingFlow's versioned wire-level values.
package protocol

const (
	Magic                          = "AFLO"
	Major                    uint8 = 1
	Minor                    uint8 = 0
	DefaultMaxControlMessage       = 64 << 10
	DefaultMaxDatagramSize         = 1150 // conservative until a negotiated path MTU API exists
)

type MessageType uint8

const (
	ClientHello MessageType = iota + 1
	ServerHello
	AuthRequest
	AuthResult
	ConnectionReady
	OpenStream
	StreamResult
	OpenDatagramSession
	DatagramSessionResult
	CloseSession
	Ping
	Pong
	Stats
	GoAway
	Error
)

type Capability uint64

const (
	CapabilityDatagrams Capability = 1 << iota
	CapabilitySessionRecovery
	CapabilityPadding
)
const knownCapabilities = CapabilityDatagrams | CapabilitySessionRecovery | CapabilityPadding

func UnknownCapabilities(c Capability) Capability { return c &^ knownCapabilities }

type ConnectionState uint8

const (
	ConnectionNew ConnectionState = iota
	ConnectionConnecting
	ConnectionQUICReady
	ConnectionNegotiating
	ConnectionAuthenticating
	ConnectionReadyState
	ConnectionDraining
	ConnectionClosing
	ConnectionClosed
	ConnectionFailed
)

func (s ConnectionState) String() string {
	return [...]string{"NEW", "CONNECTING", "QUIC_READY", "NEGOTIATING", "AUTHENTICATING", "READY", "DRAINING", "CLOSING", "CLOSED", "FAILED"}[s]
}

type SessionState uint8

const (
	SessionCreated SessionState = iota
	SessionOpening
	SessionActive
	SessionHalfClosed
	SessionClosing
	SessionClosed
	SessionFailed
)

func (s SessionState) String() string {
	return [...]string{"CREATED", "OPENING", "ACTIVE", "HALF_CLOSED", "CLOSING", "CLOSED", "FAILED"}[s]
}

type Priority uint8

const (
	Control Priority = iota
	Interactive
	Realtime
	Normal
	Background
	Padding
)
