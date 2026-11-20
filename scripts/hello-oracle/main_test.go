package main

import (
	"crypto/tls"
	"testing"
	"time"
)

// A config Go refuses before writing a hello must not leave the reader
// blocked: the pipe closes and the generation error reaches the caller.
func TestReadClientHelloReportsAFailedGeneration(t *testing.T) {
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		readClientHello(&tls.Config{
			ServerName: "example.com",
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS12,
		})
	}()
	select {
	case got := <-done:
		if got == nil {
			t.Fatal("readClientHello returned without reporting the generation error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readClientHello blocked on a ClientHello Go refused to generate")
	}
}
