// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package handshake_test

import (
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sim/github"
	"github.com/katocxl/pantherclaw/internal/sim/handshake"
	"github.com/katocxl/pantherclaw/internal/sim/mcpsim"
	"github.com/katocxl/pantherclaw/internal/sim/payments"
)

const nonce = "0123456789abcdef0123456789abcdef"

// TestSimulatorsAnswerTheHandshake (HR-221, D7): every simulator echoes the
// nonce with its kind and the Simulated header, and refuses a malformed
// nonce.
func TestSimulatorsAnswerTheHandshake(t *testing.T) {
	for kind, h := range map[string]http.Handler{
		"payments": payments.New(payments.Faults{}, pclog.Discard()).Handler(),
		"github":   github.New(pclog.Discard()).Handler(),
		"mcp":      mcpsim.New(mcpsim.Faults{}).Handler(),
	} {
		ts := httptest.NewServer(h)
		get := func(q string) (int, http.Header, []byte) {
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+handshake.Path+q, nil)
			res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = res.Body.Close() }()
			b, _ := io.ReadAll(res.Body)
			return res.StatusCode, res.Header, b
		}
		code, hdr, body := get("?nonce=" + nonce)
		var a handshake.Answer
		if err := json.Unmarshal(body, &a); err != nil {
			t.Fatal(err)
		}
		if code != http.StatusOK || hdr.Get("Simulated") != "true" || hdr.Get("Content-Type") != "application/json" ||
			a != (handshake.Answer{Simulator: "pantherclaw-sim", Kind: kind, Nonce: nonce}) {
			t.Errorf("%s: %d %v %+v", kind, code, hdr, a)
		}
		for _, bad := range []string{"", "?nonce=ABCDEF0123456789abcdef0123456789", "?nonce=abc", "?nonce=" + nonce + "00"} {
			if c, _, _ := get(bad); c != http.StatusBadRequest {
				t.Errorf("%s %q: %d", kind, bad, c)
			}
		}
		ts.Close()
	}
}
