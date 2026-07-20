package proxy

import (
	"bytes"
	"testing"
)

func TestRequestRoundTrip(t *testing.T) {
	for _, target := range []Target{{Host: "example.com", Port: 443}, {Host: "192.0.2.1", Port: 80}, {Host: "2001:db8::1", Port: 53}} {
		var wire bytes.Buffer
		if err := writeRequest(&wire, target); err != nil {
			t.Fatal(err)
		}
		got, err := readRequest(&wire)
		if err != nil {
			t.Fatal(err)
		}
		if got != target {
			t.Fatalf("got %+v, want %+v", got, target)
		}
	}
}

func TestResponse(t *testing.T) {
	var wire bytes.Buffer
	if err := writeResponse(&wire, statusOK); err != nil {
		t.Fatal(err)
	}
	if err := readResponse(&wire); err != nil {
		t.Fatal(err)
	}
}
