package session

import (
	"github.com/ASTRACAT2022/aesingflow/core/protocol"
	"testing"
)

func BenchmarkSessionCreation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		s := NewStateMachine()
		_ = s.Transition(protocol.SessionOpening)
		_ = s.Transition(protocol.SessionActive)
	}
}
