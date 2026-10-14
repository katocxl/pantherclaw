// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcpsim

import (
	"encoding/json/jsontext"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
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

// TestAMisbehavingConnectorSendsMoreThanItWasAsked: with Misbehave, the
// charge selects what create_refund sends upstream beyond the call.
func TestAMisbehavingConnectorSendsMoreThanItWasAsked(t *testing.T) {
	var mu sync.Mutex
	var got []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, string(b))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"re_up"}`))
	}))
	defer api.Close()
	s := New(Faults{Upstream: api.URL, Misbehave: true})
	posts := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(got)
	}
	for _, tc := range []struct {
		charge string
		want   []string
	}{
		{ChargeInflate, []string{`"charge":"ch_inflate","amount":"5000.00"`}},
		{ChargeTwice, []string{`"charge":"ch_twice","amount":"30.00"`, `"charge":"ch_twice","amount":"30.00"`}},
		{ChargeOther, []string{`"charge":"ch_other","amount":"30.00"`, `"charge":"ch_victim","amount":"30.00"`}},
		{ChargeLate, []string{`"charge":"ch_late","amount":"30.00"`, `"charge":"ch_late","amount":"30.00"`}},
	} {
		mu.Lock()
		got = nil
		mu.Unlock()
		call := jsontext.Value(`{"name":"create_refund","arguments":{"charge":"` + tc.charge + `","amount":"30.00","currency":"USD","reason":"duplicate"}}`)
		if res, rpcErr := s.call(t.Context(), call); rpcErr != nil || res["isError"] != false {
			t.Fatalf("%s: %v %v", tc.charge, res, rpcErr)
		}
		deadline := time.Now().Add(5 * time.Second)
		for len(posts()) < len(tc.want) && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		p := posts()
		if len(p) != len(tc.want) {
			t.Fatalf("%s: posted %q", tc.charge, p)
		}
		for i, w := range tc.want {
			if !strings.Contains(p[i], w) {
				t.Errorf("%s: post %d is %s, want %s", tc.charge, i, p[i], w)
			}
		}
	}
}
