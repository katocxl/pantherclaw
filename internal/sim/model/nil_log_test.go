// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package model

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestANilLoggerDiscards: a simulator made without a logger answers calls
// instead of panicking on its first log line (G0 M29 D1212).
func TestANilLoggerDiscards(t *testing.T) {
	ts := httptest.NewServer(New("", Faults{}, nil).Handler())
	t.Cleanup(ts.Close)
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, ts.URL+"/v1/chat/completions", strings.NewReader(`{"model":"m","messages":[]}`))
	req.Header.Set("Authorization", "Bearer "+DefaultKey)
	req.Header.Set("Content-Type", "application/json")
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
}
