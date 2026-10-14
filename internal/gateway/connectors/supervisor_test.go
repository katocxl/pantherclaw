// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package connectors

import (
	"io"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/upstream"
)

// TestAConnectorThatKeepsFailingWaitsLonger: the first failure restarts at
// once (a call that timed out should not make the next one wait), then the
// wait doubles up to five minutes.
func TestAConnectorThatKeepsFailingWaitsLonger(t *testing.T) {
	for n, want := range map[int]time.Duration{0: 0, 1: 0, 2: RetryAfter / 8, 3: RetryAfter / 4, 4: RetryAfter / 2, 30: 5 * time.Minute} {
		if got := backoff(n); got != want {
			t.Errorf("backoff(%d) = %s, want %s", n, got, want)
		}
	}
}

// TestHR216_OnlyAUsableConnectorOfTheRevisionTakesACall: the supervisor
// hands out a connector's client only for the connection's revision and
// while its last exchange was not abandoned.
func TestHR216_OnlyAUsableConnectorOfTheRevisionTakesACall(t *testing.T) {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	t.Cleanup(func() { _ = inR.Close(); _ = outW.Close() })
	stdio := NewStdio(inW, outR, 0)
	in := &instance{revision: 3, stdio: stdio, done: make(chan struct{}), client: upstream.New("http://connector.invalid/c", stdio)}
	s := &Supervisor{running: map[string]*instance{"c": in}}
	if c, err := s.Client("c", 3); err != nil || c != in.client {
		t.Fatalf("the running revision: %v", err)
	}
	if _, err := s.Client("c", 2); err == nil {
		t.Error("another revision took a call")
	}
	stdio.Close()
	if _, err := s.Client("c", 3); err == nil {
		t.Error("a broken connector took a call")
	}
}
