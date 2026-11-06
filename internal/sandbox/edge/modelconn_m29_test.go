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

// modelPlaceholder is the session's key placeholder (G0 M29 D815).
const modelPlaceholder = "pc-placeholder-ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// newModelConnRig is newRig with api.anthropic.com mapped to the model
// connection "llm".
func newModelConnRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{run: ids.NewV7().String(), log: &bytes.Buffer{}}
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.got = append(r.got, seen{req.Method, req.URL.EscapedPath(), req.URL.RawQuery, req.Header.Clone(), b})
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(gw.Close)
	r.gateway = gw.URL
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e, err := New(Options{
		Session: "0f3c", GatewayURL: gw.URL, Hosts: map[string]string{"api.anthropic.com": "llm", "api.github.com": "github"},
		Run: r.run, Key: key, Token: func() string { return "workload-token" }, ModelConnections: []string{"llm"},
		Placeholder: modelPlaceholder, Log: pclog.New(r.log, pclog.Options{}),
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

func (r *rig) post(t *testing.T, target, body string, hdr map[string]string) int {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := r.agent().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	return res.StatusCode
}

// TestHR690_TheEdgeStripsTheAgentsModelKeyButNotThePlaceholder: on a model
// connection the agent's key never reaches the gateway; the session's
// placeholder is dropped unreported, a real key is reported by its kind,
// and neither is logged (G0 M29 D815, D816).
//
// Covers: F980, F984, HR-690
func TestHR690_TheEdgeStripsTheAgentsModelKeyButNotThePlaceholder(t *testing.T) {
	r := newModelConnRig(t)
	code := r.post(t, "https://api.anthropic.com/v1/messages", `{"model":"m"}`, map[string]string{"x-api-key": modelPlaceholder, "Anthropic-Version": "2023-06-01"})
	if code != http.StatusOK || r.edge.Stripped() != 0 {
		t.Fatalf("placeholder: %d, stripped %d", code, r.edge.Stripped())
	}
	key := "sk-" + "ant-" + "api03-" + strings.Repeat("Zq9_", 10)
	r.post(t, "https://api.anthropic.com/v1/messages", `{"model":"m"}`, map[string]string{"Authorization": "Bearer " + key})
	got := r.requests()
	if len(got) != 2 || got[1].path != "/llm/v1/messages" || got[1].header.Get("x-api-key") != "" ||
		got[0].header.Get("Anthropic-Version") != "2023-06-01" || !strings.HasPrefix(got[1].header.Get("Authorization"), "PAP ") {
		t.Fatalf("gateway got %+v", got)
	}
	logged := r.log.String()
	if r.edge.Stripped() != 1 || !strings.Contains(logged, `"kind":"anthropic"`) || strings.Contains(logged, key) || strings.Contains(logged, modelPlaceholder) {
		t.Fatalf("stripped %d:\n%s", r.edge.Stripped(), logged)
	}
	for token, want := range map[string]string{
		key: "anthropic", "sk-" + "proj-" + strings.Repeat("a", 8): "openai", "sk-" + "svcacct-x": "openai", "sk-" + "admin-x": "openai",
		"sk-" + strings.Repeat("A", 32): "openai", "sk-" + strings.Repeat("A", 31): "", "sk_live_x": "",
	} {
		if got := modelKeyKind(token); got != want {
			t.Errorf("modelKeyKind(%.12s…) = %q, want %q", token, got, want)
		}
	}
}

// TestHR692_OnlyAModelConnectionTakesBodiesPast64KiB: the edge passes a
// 1 MiB prompt on a model connection and refuses one over 16 MiB; another
// connection keeps its 64 KiB cap (G0 M29 D814).
//
// Covers: F981, HR-692
func TestHR692_OnlyAModelConnectionTakesBodiesPast64KiB(t *testing.T) {
	r := newModelConnRig(t)
	big := `{"p":"` + strings.Repeat("a", 1<<20) + `"}`
	if code := r.post(t, "https://api.anthropic.com/v1/messages", big, nil); code != http.StatusOK {
		t.Fatalf("1 MiB on the model connection: %d", code)
	}
	if code := r.post(t, "https://api.anthropic.com/v1/messages", strings.Repeat("a", MaxModelConnBody+1), nil); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over 16 MiB: %d", code)
	}
	if code := r.post(t, "https://api.github.com/repos/a/b/issues", big, nil); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("1 MiB on another connection: %d", code)
	}
	if n := len(r.requests()); n != 1 {
		t.Fatalf("the gateway got %d requests", n)
	}
	if _, err := New(Options{
		GatewayURL: "http://127.0.0.1:1", Hosts: map[string]string{"api.github.com": "github"}, ModelConnections: []string{"llm"},
		Run: r.run, Key: ed25519.NewKeyFromSeed(make([]byte, 32)), Token: func() string { return "t" },
	}); err == nil {
		t.Fatal("a model connection no host maps was accepted")
	}
}
