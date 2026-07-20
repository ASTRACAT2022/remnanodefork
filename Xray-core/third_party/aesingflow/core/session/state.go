package session

import (
	"github.com/ASTRACAT2022/aesingflow/core/errors"
	"github.com/ASTRACAT2022/aesingflow/core/protocol"
	"sync"
)

type StateMachine struct {
	mu    sync.RWMutex
	state protocol.SessionState
}

func NewStateMachine() *StateMachine { return &StateMachine{state: protocol.SessionCreated} }
func (s *StateMachine) State() protocol.SessionState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}
func (s *StateMachine) Transition(to protocol.SessionState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.state
	ok := f == to || (to == protocol.SessionFailed && f != protocol.SessionClosed) || (f == protocol.SessionCreated && (to == protocol.SessionOpening || to == protocol.SessionClosed)) || (f == protocol.SessionOpening && (to == protocol.SessionActive || to == protocol.SessionClosing)) || (f == protocol.SessionActive && (to == protocol.SessionHalfClosed || to == protocol.SessionClosing)) || (f == protocol.SessionHalfClosed && to == protocol.SessionClosing) || (f == protocol.SessionClosing && to == protocol.SessionClosed) || (f == protocol.SessionFailed && to == protocol.SessionClosed)
	if !ok {
		return errors.New(errors.InvalidState, "invalid session state transition")
	}
	s.state = to
	return nil
}
