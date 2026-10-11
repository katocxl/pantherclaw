// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package anchoring_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/anchor/anchortest"
	"github.com/katocxl/pantherclaw/internal/evidence/anchoring"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

type countingDoer struct{ calls int }

func (c *countingDoer) Do(*http.Request) (*http.Response, error) {
	c.calls++
	return anchortest.Reply(http.StatusOK, nil), nil
}

// TestHR195_AnchoringClientsReachOnlyTheConfiguredHosts: the Rekor and
// timestamp clients send only to their configured https host; any other
// host, port or scheme is refused before it leaves, and the egress client
// beneath refuses private and loopback addresses (HR-071) without a
// configuration to allow them.
func TestHR195_AnchoringClientsReachOnlyTheConfiguredHosts(t *testing.T) {
	next := &countingDoer{}
	h := anchoring.HostOnly{Host: "rekor.test", Next: next}
	for _, u := range []string{"https://elsewhere.test/api/v2/log/entries", "http://rekor.test/api/v2/log/entries", "https://rekor.test:8443/x"} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, u, nil)
		resp, err := h.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if !errors.Is(err, anchoring.ErrHostNotAllowed) {
			t.Errorf("%s: %v, want refused", u, err)
		}
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://REKOR.test/api/v2/log/entries", nil)
	resp, err := h.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err != nil || next.calls != 1 {
		t.Fatalf("the configured host: %v, %d calls", err, next.calls)
	}
	if _, err := anchoring.EgressDoer("http://rekor.test", time.Second); err == nil {
		t.Fatal("a plain-http endpoint was accepted")
	}
	d, err := anchoring.EgressDoer("https://127.0.0.1:1/api/v1/timestamp", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequestWithContext(context.Background(), http.MethodPost, "https://127.0.0.1:1/api/v1/timestamp", nil)
	resp, err = d.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, httpx.ErrDestinationDenied) {
		t.Fatalf("a loopback endpoint: %v, want the egress client's refusal", err)
	}
}

func TestBackoffDoublesUpToThirtyMinutes(t *testing.T) {
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 30 * time.Minute, 30 * time.Minute}
	for i, w := range want {
		if got := anchoring.Backoff(i + 1); got != w {
			t.Errorf("attempt %d: %s, want %s", i+1, got, w)
		}
	}
}
