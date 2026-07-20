package connection

import (
	"github.com/ASTRACAT2022/aesingflow/core/protocol"
	"testing"
)

func TestStateTransitions(t *testing.T) {
	s := NewStateMachine()
	for _, n := range []protocol.ConnectionState{protocol.ConnectionConnecting, protocol.ConnectionQUICReady, protocol.ConnectionNegotiating, protocol.ConnectionAuthenticating, protocol.ConnectionReadyState, protocol.ConnectionDraining, protocol.ConnectionClosing, protocol.ConnectionClosed} {
		if e := s.Transition(n); e != nil {
			t.Fatal(e)
		}
	}
	if e := s.Transition(protocol.ConnectionReadyState); e == nil {
		t.Fatal("accepted terminal transition")
	}
}
