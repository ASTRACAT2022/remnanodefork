package scheduler

import (
	"context"
	"github.com/ASTRACAT2022/aesingflow/core/protocol"
	"testing"
)

func BenchmarkScheduler(b *testing.B) {
	s := New(2)
	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		if e := s.Enqueue(ctx, Item{Priority: protocol.Normal, Payload: []byte{1}}); e != nil {
			b.Fatal(e)
		}
		if _, e := s.Next(ctx); e != nil {
			b.Fatal(e)
		}
	}
}
