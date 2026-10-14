// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package handshake_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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
		get := func(q string) *http.Response {
			res, err := http.Get(ts.URL + handshake.Path + q)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = res.Body.Close() })
			return res
		}
		res := get("?nonce=" + nonce)
		var a handshake.Answer
		if err := json.NewDecoder(res.Body).Decode(&a); err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != 200 || res.Header.Get("Simulated") != "true" || res.Header.Get("Content-Type") != "application/json" ||
			a != (handshake.Answer{Simulator: "pantherclaw-sim", Kind: kind, Nonce: nonce}) {
			t.Errorf("%s: %d %v %+v", kind, res.StatusCode, res.Header, a)
		}
		for _, bad := range []string{"", "?nonce=ABCDEF0123456789abcdef0123456789", "?nonce=abc", "?nonce=" + nonce + "00"} {
			if r := get(bad); r.StatusCode != 400 {
				t.Errorf("%s %q: %d", kind, bad, r.StatusCode)
			}
		}
		ts.Close()
	}
}
