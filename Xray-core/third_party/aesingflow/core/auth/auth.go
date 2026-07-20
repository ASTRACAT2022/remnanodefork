// Package auth provides replaceable authentication implementations.
package auth

import (
	"context"
	"crypto/subtle"
	"github.com/ASTRACAT2022/aesingflow/core/errors"
	"sync"
	"time"
)

type Request struct {
	Token     string
	Nonce     [16]byte
	Timestamp time.Time
}
type Result struct {
	Subject   string
	ExpiresAt time.Time
}
type Authenticator interface {
	Authenticate(context.Context, Request) (Result, error)
}
type Token struct {
	Value     string
	Subject   string
	ExpiresAt time.Time
}

// StaticAuthenticator is intended for small deployments and tests. Token values are never logged.
type StaticAuthenticator struct {
	Tokens          []Token
	Window          time.Duration
	RetryDelay      time.Duration
	MaxNonceEntries int
	mu              sync.Mutex
	used            map[[16]byte]time.Time
}

func (a *StaticAuthenticator) Authenticate(ctx context.Context, r Request) (Result, error) {
	if a.Window <= 0 {
		a.Window = 2 * time.Minute
	}
	if a.MaxNonceEntries <= 0 {
		a.MaxNonceEntries = 4096
	}
	now := time.Now()
	if r.Timestamp.Before(now.Add(-a.Window)) || r.Timestamp.After(now.Add(a.Window)) {
		return Result{}, errors.New(errors.AuthExpired, "authentication timestamp expired")
	}
	a.mu.Lock()
	if a.used == nil {
		a.used = make(map[[16]byte]time.Time)
	}
	for n, t := range a.used {
		if t.Before(now.Add(-a.Window)) {
			delete(a.used, n)
		}
	}
	if _, ok := a.used[r.Nonce]; ok {
		a.mu.Unlock()
		return Result{}, errors.New(errors.ReplayDetected, "authentication replay detected")
	}
	// Reserve before token comparison: concurrent requests cannot consume a nonce twice.
	if len(a.used) >= a.MaxNonceEntries {
		for n := range a.used {
			delete(a.used, n)
			break
		}
	}
	a.used[r.Nonce] = now
	a.mu.Unlock()
	var match *Token
	for i := range a.Tokens {
		equal := subtle.ConstantTimeCompare([]byte(a.Tokens[i].Value), []byte(r.Token))
		if equal == 1 {
			match = &a.Tokens[i]
		}
	}
	if match == nil {
		if a.RetryDelay > 0 {
			timer := time.NewTimer(a.RetryDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return Result{}, ctx.Err()
			case <-timer.C:
			}
		}
		return Result{}, errors.New(errors.AuthFailed, "authentication failed")
	}
	if !match.ExpiresAt.IsZero() && now.After(match.ExpiresAt) {
		return Result{}, errors.New(errors.AuthExpired, "authentication expired")
	}
	return Result{match.Subject, match.ExpiresAt}, nil
}
