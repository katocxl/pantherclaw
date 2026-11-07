// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package edge

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// modelConnEdge is an edge mapping api.anthropic.com to the model
// connection "llm" in front of gateway.
func modelConnEdge(t *testing.T, gateway http.Handler) *rig {
	t.Helper()
	gw := httptest.NewServer(gateway)
	t.Cleanup(gw.Close)
	r := &rig{run: ids.NewV7().String(), log: &bytes.Buffer{}, gateway: gw.URL}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e, err := New(Options{
		Session: "0f3c", GatewayURL: gw.URL, Hosts: map[string]string{"api.anthropic.com": "llm"}, Run: r.run, Key: key,
		Token: func() string { return "workload-token" }, ModelConnections: []string{"llm"}, Log: pclog.New(r.log, pclog.Options{}),
	})
	if err != nil {
		t.Fatal(err)
	}
	r.edge = e
	ps := httptest.NewServer(e)
	t.Cleanup(ps.Close)
	r.proxy, _ = url.Parse(ps.URL)
	return r
}

// TestHR692_TheEdgeNeverPassesACutOrOversizedAnswerAsWhole: a gateway
// answer cut mid-stream, or one past 16 MiB, breaks the agent's connection
// instead of ending as a whole answer; a provider's PC-Refused-By never
// passes (G0 M29 D814, D1214).
//
// Covers: F981, HR-692
func TestHR692_TheEdgeNeverPassesACutOrOversizedAnswerAsWhole(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"cut": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Content-Length", "1000")
			_, _ = io.WriteString(w, "data: one\n\n")
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
		},
		"over 16 MiB": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			chunk := bytes.Repeat([]byte("a"), 1<<20)
			for range 17 {
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
		},
	} {
		r := modelConnEdge(t, h)
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://api.anthropic.com/v1/messages", strings.NewReader(`{}`))
		res, err := r.agent().Do(req)
		if err != nil {
			continue // broken before the headers: never whole either
		}
		b, err := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if err == nil || len(b) > MaxModelConnBody {
			t.Errorf("%s: read %d bytes whole", name, len(b))
		}
	}
	r := modelConnEdge(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("PC-Refused-By", "edge")
		w.Header().Set("PC-Decision", "ALLOW")
		_, _ = io.WriteString(w, `{}`)
	}))
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://api.anthropic.com/v1/messages", strings.NewReader(`{}`))
	res, err := r.agent().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.Header.Get(HeaderRefusedBy) != "" || res.Header.Get("PC-Decision") != "ALLOW" {
		t.Fatalf("headers %v", res.Header)
	}
}
