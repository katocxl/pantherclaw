// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package edge

import (
	"bufio"
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

const (
	modelHost   = "api.anthropic.com"
	placeholder = "pc-campaign-placeholder"
)

// newModelRig is newRig with a campaign's model route; the fake gateway
// streams an answer in two flushed parts, or answer when set.
func newModelRig(t *testing.T, answer []byte) *rig {
	t.Helper()
	r := &rig{run: ids.NewV7().String(), log: &bytes.Buffer{}}
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.got = append(r.got, seen{req.Method, req.URL.EscapedPath(), req.URL.RawQuery, req.Header.Clone(), b})
		r.mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Set-Cookie", "gw=1")
		w.WriteHeader(http.StatusOK)
		if answer != nil {
			_, _ = w.Write(answer)
			return
		}
		_, _ = io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, "data: two\n\n")
	}))
	t.Cleanup(gw.Close)
	r.gateway = gw.URL
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e, err := New(Options{
		Session: "0f3c", GatewayURL: gw.URL, Hosts: hosts, Run: r.run, Key: key, Token: func() string { return "workload-token" },
		ModelHost: modelHost, ModelConnection: "relay-1", Placeholder: placeholder, Log: pclog.New(r.log, pclog.Options{}),
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

// TestHR615_TheEdgeSendsModelCallsToTheModelFaceAndStreams: a call to the
// campaign's model host goes, signed, to the gateway's model face for the
// relay, with no credential; the answer streams back; the placeholder key is
// dropped without a report, a real-looking key is reported, and the edge still
// reaches only the gateway (D313, HR-213).
// Covers: F906
func TestHR615_TheEdgeSendsModelCallsToTheModelFaceAndStreams(t *testing.T) {
	r := newModelRig(t, nil)
	body := `{"model":"m","stream":true}`
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+modelHost+"/v1/messages?beta=true", strings.NewReader(body))
	req.Header.Set("X-Api-Key", placeholder)
	req.Header.Set("Anthropic-Version", "2023-06-01")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "c=1")
	res, err := r.agent().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(res.Body)
	var lines []string
	for sc.Scan() {
		if sc.Text() != "" {
			lines = append(lines, sc.Text())
		}
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || strings.Join(lines, ",") != "data: one,data: two" || res.Header.Get("Set-Cookie") != "" ||
		res.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("agent got %d %v %v", res.StatusCode, lines, res.Header)
	}
	got := r.requests()
	if len(got) != 1 {
		t.Fatalf("gateway got %d requests", len(got))
	}
	g := got[0]
	if g.path != "/model/relay-1/"+modelHost+"/v1/messages" || g.query != "beta=true" || string(g.body) != body {
		t.Fatalf("gateway got %s?%s %s", g.path, g.query, g.body)
	}
	if g.header.Get("Authorization") != "PAP workload-token" || g.header.Get("PAP-Proof") == "" || g.header.Get(headerRunID) != r.run ||
		g.header.Get("X-Api-Key") != "" || g.header.Get("Cookie") != "" || g.header.Get("Anthropic-Version") != "2023-06-01" {
		t.Fatalf("gateway headers %v", g.header)
	}
	if c := claims(t, g.header.Get("PAP-Proof")); c["htu"] != r.gateway+"/model/relay-1/"+modelHost+"/v1/messages" {
		t.Fatalf("proof htu %v", c["htu"])
	}
	// The placeholder is no secret; the cookie is reported.
	if r.edge.Stripped() != 1 || strings.Contains(r.log.String(), placeholder) {
		t.Fatalf("stripped %d:\n%s", r.edge.Stripped(), r.log)
	}
	// A key the agent found is reported, never logged.
	req, _ = http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+modelHost+"/v1/messages", strings.NewReader(body))
	req.Header.Set("X-Api-Key", "sk-ant-api03-planted")
	if res, err = r.agent().Do(req); err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if r.edge.Stripped() != 2 || strings.Contains(r.log.String(), "sk-ant-api03-planted") {
		t.Fatalf("a found key: stripped %d", r.edge.Stripped())
	}
	// Another provider is no route.
	if res, err := r.agent().Get("https://api.openai.com/v1/models"); err == nil {
		_ = res.Body.Close()
		t.Fatal("another model host's tunnel opened")
	}
}

// TestHR615_AModelAnswerPastTheCapIsCut: an answer longer than 8 MiB breaks
// the agent's connection instead of arriving whole.
// Covers: F906
func TestHR615_AModelAnswerPastTheCapIsCut(t *testing.T) {
	r := newModelRig(t, make([]byte, MaxModelBody+1024))
	res, err := r.agent().Post("https://"+modelHost+"/v1/messages", "application/json", strings.NewReader(`{}`))
	if err != nil {
		return // cut before the headers arrived
	}
	defer func() { _ = res.Body.Close() }()
	if n, err := io.Copy(io.Discard, res.Body); err == nil || n > MaxModelBody {
		t.Fatalf("the agent read %d bytes as a whole answer", n)
	}
}

// TestTheModelRouteIsChecked: the model host is no agent host, a connector's
// edge has none, and both fields go together.
func TestTheModelRouteIsChecked(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	base := Options{GatewayURL: "https://gw.example", Hosts: hosts, Run: ids.NewV7().String(), Key: key, Token: func() string { return "t" }}
	for name, edit := range map[string]func(*Options){
		"an agent host":      func(o *Options) { o.ModelHost, o.ModelConnection = "api.github.com", "relay" },
		"no connection":      func(o *Options) { o.ModelHost = modelHost },
		"no host":            func(o *Options) { o.ModelConnection = "relay" },
		"an IP":              func(o *Options) { o.ModelHost, o.ModelConnection = "10.0.0.1", "relay" },
		"a path in the name": func(o *Options) { o.ModelHost, o.ModelConnection = modelHost, "re/lay" },
		"connector mode": func(o *Options) {
			o.ModelHost, o.ModelConnection, o.Binding = modelHost, "relay", func() string { return "b" }
		},
	} {
		o := base
		edit(&o)
		if _, err := New(o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
