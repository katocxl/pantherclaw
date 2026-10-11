// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcpsim

import (
	"encoding/json/jsontext"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCreateRefundGoesUpstream: with an upstream, create_refund posts the
// refund to the payments API and answers with what it answered; an
// upstream refusal is a tool error.
func TestCreateRefundGoesUpstream(t *testing.T) {
	var got string
	status := http.StatusOK
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = r.Method + " " + r.URL.Path + " " + string(b)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"id":"re_up","status":"succeeded"}`))
	}))
	defer api.Close()
	s := New(Faults{Upstream: api.URL})
	call := jsontext.Value(`{"name":"create_refund","arguments":{"charge":"ch_1","amount":"30.00","currency":"USD","reason":"duplicate"}}`)

	res, rpcErr := s.call(t.Context(), call)
	if rpcErr != nil || res["isError"] != false || !strings.Contains(string(res["structuredContent"].(jsontext.Value)), `"re_up"`) {
		t.Fatalf("result %v %v", res, rpcErr)
	}
	if got != `POST /v1/refunds {"charge":"ch_1","amount":"30.00","currency":"USD","reason":"duplicate"}` || s.Calls() != 1 {
		t.Fatalf("upstream got %q, %d calls", got, s.Calls())
	}
	status = http.StatusForbidden
	if res, _ := s.call(t.Context(), call); res["isError"] != true {
		t.Fatalf("a refused refund: %v", res)
	}
}
