package connection

import (
	"github.com/ASTRACAT2022/aesingflow/core/errors"
	"github.com/ASTRACAT2022/aesingflow/core/protocol"
	"sync"
)

type StateMachine struct {
	mu    sync.RWMutex
	state protocol.ConnectionState
}

func NewStateMachine() *StateMachine { return &StateMachine{state: protocol.ConnectionNew} }
func (s *StateMachine) State() protocol.ConnectionState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}
func allowed(from, to protocol.ConnectionState) bool {
	if from == to {
		return true
	}
	if to == protocol.ConnectionFailed {
		return from != protocol.ConnectionClosed
	}
	switch from {
	case protocol.ConnectionNew:
		return to == protocol.ConnectionConnecting || to == protocol.ConnectionClosed
	case protocol.ConnectionConnecting:
		return to == protocol.ConnectionQUICReady || to == protocol.ConnectionClosing
	case protocol.ConnectionQUICReady:
		return to == protocol.ConnectionNegotiating || to == protocol.ConnectionClosing
	case protocol.ConnectionNegotiating:
		return to == protocol.ConnectionAuthenticating || to == protocol.ConnectionClosing
	case protocol.ConnectionAuthenticating:
		return to == protocol.ConnectionReadyState || to == protocol.ConnectionClosing
	case protocol.ConnectionReadyState:
		return to == protocol.ConnectionDraining || to == protocol.ConnectionClosing
	case protocol.ConnectionDraining:
		return to == protocol.ConnectionClosing
	case protocol.ConnectionClosing, protocol.ConnectionFailed:
		return to == protocol.ConnectionClosed
	}
	return false
}
func (s *StateMachine) Transition(to protocol.ConnectionState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !allowed(s.state, to) {
		return errors.New(errors.InvalidState, "invalid connection state transition")
	}
	s.state = to
	return nil
}
