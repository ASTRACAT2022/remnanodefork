package session

import (
	"github.com/ASTRACAT2022/aesingflow/core/protocol"
	"testing"
)

func TestSessionStateTransitions(t *testing.T) {
	s := NewStateMachine()
	for _, n := range []protocol.SessionState{protocol.SessionOpening, protocol.SessionActive, protocol.SessionHalfClosed, protocol.SessionClosing, protocol.SessionClosed} {
		if e := s.Transition(n); e != nil {
			t.Fatal(e)
		}
	}
	if e := s.Transition(protocol.SessionActive); e == nil {
		t.Fatal("accepted terminal transition")
	}
}
