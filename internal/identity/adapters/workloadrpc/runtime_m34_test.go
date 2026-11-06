// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package workloadrpc

import (
	"bytes"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// TestHR761_RuntimeRequestsAreHashedBeforeParsing verifies the runtime
// service receives the exact body hash used by PAP and rejects oversized
// bodies before the handler runs.
func TestHR761_RuntimeRequestsAreHashedBeforeParsing(t *testing.T) {
	body := []byte(`{"name":"agentcore:run"}`)
	called := false
	handler := RawBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		got, ok := r.Context().Value(rawKey{}).(raw)
		if !ok || got.sum != sha256.Sum256(body) {
			t.Errorf("runtime request body hash missing or incorrect")
		}
		restored, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(restored, body) {
			t.Errorf("restored body %q: %v", restored, err)
		}
	}), nil)
	path := pantherclawv1connect.RuntimeServiceStartRuntimeRunProcedure
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body)))
	if !called || rr.Code != http.StatusOK {
		t.Fatalf("handler called %t status %d", called, rr.Code)
	}
	called = false
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(make([]byte, MaxBody+1))))
	if called || rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: handler called %t status %d", called, rr.Code)
	}
}
