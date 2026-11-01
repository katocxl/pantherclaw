// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package edge

import (
	"bytes"
	"crypto/ed25519"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHR584_InspectingEdgeRefusesEverything: an inspection's edge forwards
// nothing and records every destination, and it cannot be given a gateway, a
// host or a key.
// Covers: F871
func TestHR584_InspectingEdgeRefusesEverything(t *testing.T) {
	var log bytes.Buffer
	e, err := New(Options{Session: "s", Inspect: true, Log: slog.New(slog.NewJSONHandler(&log, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.CACertificate()) == 0 {
		t.Fatal("no CA for the ready line")
	}
	for _, r := range []*http.Request{
		httptest.NewRequest(http.MethodConnect, "api.example.test:443", nil),
		httptest.NewRequest(http.MethodGet, "http://collector.example.test/x", nil),
	} {
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s: %d", r.Method, r.Host, w.Code)
		}
	}
	if e.Refused() != 2 || !strings.Contains(log.String(), "api.example.test:443") || !strings.Contains(log.String(), "collector.example.test") {
		t.Errorf("%d refused, log %s", e.Refused(), log.String())
	}
	for name, o := range map[string]Options{
		"gateway": {Inspect: true, GatewayURL: "https://gw.example.test"},
		"hosts":   {Inspect: true, Hosts: map[string]string{"api.example.test": "c"}},
		"key":     {Inspect: true, Key: make(ed25519.PrivateKey, ed25519.PrivateKeySize)},
		"token":   {Inspect: true, Token: func() string { return "t" }},
		"binding": {Inspect: true, Binding: func() string { return "b" }},
	} {
		if _, err := New(o); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// Covers: F871
func TestHR584_InspectConfig(t *testing.T) {
	read := func(body string) error {
		p := filepath.Join(t.TempDir(), "c.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := ReadConfig(p)
		return err
	}
	base := `{"format":"` + ConfigFormat + `","mode":"inspect","session":"s","listen":":3128","subnet":"10.0.0.0/24"`
	if err := read(base + `}`); err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{`,"key_file":"/k"`, `,"token_file":"/t"`, `,"binding_file":"/b"`, `,"gateway_url":"https://g"`, `,"hosts":{"a.test":"c"}`} {
		if err := read(base + extra + `}`); err == nil {
			t.Errorf("%s accepted", extra)
		}
	}
}
