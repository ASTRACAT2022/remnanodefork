package scheduler

import (
	"context"
	"github.com/ASTRACAT2022/aesingflow/core/protocol"
	"testing"
)

func TestPriority(t *testing.T) {
	s := New(2)
	_ = s.Enqueue(context.Background(), Item{Priority: protocol.Normal, Payload: []byte("n")})
	_ = s.Enqueue(context.Background(), Item{Priority: protocol.Control, Payload: []byte("c")})
	i, e := s.Next(context.Background())
	if e != nil || string(i.Payload) != "c" {
		t.Fatal(e)
	}
}
