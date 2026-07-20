package auth

import (
	"context"
	aferrors "github.com/ASTRACAT2022/aesingflow/core/errors"
	"testing"
	"time"
)

func TestStaticAuthenticator(t *testing.T) {
	a := &StaticAuthenticator{Tokens: []Token{{Value: "secret", Subject: "test"}}}
	var n [16]byte
	n[0] = 1
	r := Request{"secret", n, time.Now()}
	if _, e := a.Authenticate(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	if aferrors.CodeOf(mustErr(a, r)) != aferrors.ReplayDetected {
		t.Fatal("expected replay")
	}
}
func mustErr(a *StaticAuthenticator, r Request) error {
	_, e := a.Authenticate(context.Background(), r)
	return e
}
func TestExpired(t *testing.T) {
	a := &StaticAuthenticator{Tokens: []Token{{Value: "s", ExpiresAt: time.Now().Add(-time.Second)}}}
	_, e := a.Authenticate(context.Background(), Request{"s", [16]byte{2}, time.Now()})
	if aferrors.CodeOf(e) != aferrors.AuthExpired {
		t.Fatal(e)
	}
}
