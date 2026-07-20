// Package scheduler provides a bounded, fair priority queue for datagrams.
package scheduler

import (
	"context"
	aferrors "github.com/ASTRACAT2022/aesingflow/core/errors"
	"github.com/ASTRACAT2022/aesingflow/core/protocol"
	"sync"
)

type Item struct {
	Priority  protocol.Priority
	SessionID uint64
	Payload   []byte
}
type Scheduler struct {
	mu     sync.Mutex
	queues map[protocol.Priority]chan Item
	closed bool
}

func New(limit int) *Scheduler {
	if limit < 1 {
		limit = 1
	}
	q := map[protocol.Priority]chan Item{}
	for _, p := range []protocol.Priority{protocol.Control, protocol.Interactive, protocol.Realtime, protocol.Normal, protocol.Background, protocol.Padding} {
		q[p] = make(chan Item, limit)
	}
	return &Scheduler{queues: q}
}
func (s *Scheduler) Enqueue(ctx context.Context, i Item) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return aferrors.New(aferrors.ShuttingDown, "scheduler closed")
	}
	q := s.queues[i.Priority]
	s.mu.Unlock()
	select {
	case q <- i:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		return aferrors.New(aferrors.LimitExceeded, "scheduler queue full")
	}
}
func (s *Scheduler) Next(ctx context.Context) (Item, error) {
	for {
		for _, p := range []protocol.Priority{protocol.Control, protocol.Interactive, protocol.Realtime, protocol.Normal, protocol.Background, protocol.Padding} {
			select {
			case i := <-s.queues[p]:
				return i, nil
			default:
			}
		}
		select {
		case <-ctx.Done():
			return Item{}, ctx.Err()
		default:
		} // wait briefly without spawning a goroutine; queues are bounded and polling only runs under send load
		select {
		case i := <-s.queues[protocol.Control]:
			return i, nil
		case i := <-s.queues[protocol.Realtime]:
			return i, nil
		case i := <-s.queues[protocol.Normal]:
			return i, nil
		case <-ctx.Done():
			return Item{}, ctx.Err()
		}
	}
}
func (s *Scheduler) Close() { s.mu.Lock(); s.closed = true; s.mu.Unlock() }
func (s *Scheduler) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, q := range s.queues {
		n += len(q)
	}
	return n
}
