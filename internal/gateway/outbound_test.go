// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/sim/handshake"
)

const fixtureToken = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"

// TestHR221_NoDispatchWithoutTheSimulatorHandshake: a simulated connection
// whose target does not answer the handshake is refused locally,
// simulator_unverified, before the Authority is asked and before anything
// but the credential-free handshake is sent; once the target answers, the
// action runs.
func TestHR221_NoDispatchWithoutTheSimulatorHandshake(t *testing.T) {
	simulated := func(h *harness) { h.conn.GatewayConnection.Simulated = true }
	h := setup(t, simulated)
	r := h.post(t, inbound, nil)
	if r.code < 400 || r.refusal.Error != "simulator_unverified" || r.refusal.ErrorClass != "cannot_authorize" || h.auth.snap().authorize != 0 {
		t.Fatalf("unverified: %d %+v, authorize %d", r.code, r.refusal, h.auth.snap().authorize)
	}
	for i := range h.target.calls() {
		if body, hdr := h.target.req(i); body != "" || hdr.Get("Authorization") != "" {
			t.Fatalf("something besides the handshake reached the target: %q %v", body, hdr)
		}
	}

	h = setup(t, simulated, func(h *harness) {
		ts := httptest.NewServer(handshake.Wrap("payments", h.target))
		t.Cleanup(ts.Close)
		h.targetURL = ts.URL
	})
	if r := h.post(t, inbound, nil); r.code != http.StatusOK || h.auth.snap().authorize != 1 {
		t.Fatalf("verified: %d %+v", r.code, r.refusal)
	}

	// A real connection is never handshaken.
	h = setup(t)
	if r := h.post(t, inbound, nil); r.code != http.StatusOK {
		t.Fatalf("real: %d", r.code)
	}
	if body, _ := h.target.req(0); body != outbound {
		t.Fatalf("the target's first request was %q", body)
	}
}

// TestHR225_AHeldSecretInAPayloadIsRefused: a secret the gateway holds for
// the connection, in any form, in an action's payload refuses it locally,
// secret_in_payload, before the Authority is asked (hook face).
func TestHR225_AHeldSecretInAPayloadIsRefused(t *testing.T) {
	for name, command := range map[string]string{
		"raw":    "curl -H 'Authorization: Bearer " + testSecret + "' x",
		"base64": "echo " + b64(testSecret),
	} {
		h := setup(t, withShell, withCredential(t, []string{"127.0.0.1"}))
		r := h.hook(t, shellInput(command, "/home/dev/proj"), nil)
		if r.answer.Decision != "deny" || r.answer.Code != "secret_in_payload" || h.auth.snap().authorize != 0 || len(h.auth.snap().records) != 0 {
			t.Errorf("%s: %+v, authorize %d", name, r.answer, h.auth.snap().authorize)
		}
		if strings.Contains(r.answer.Reason, testSecret) {
			t.Errorf("%s: the refusal repeats the secret", name)
		}
	}
}

// TestHR225_AFormatIsReportedToTheAuthority: a credential-shaped value is
// not refused by the gateway; it goes to the Authority as a finding that
// names the kind and place, never the value (hook face).
func TestHR225_AFormatIsReportedToTheAuthority(t *testing.T) {
	h := setup(t, withShell)
	r := h.hook(t, shellInput("git commit -m x # "+fixtureToken, "/home/dev/proj"), nil)
	fs := h.auth.findings
	if r.answer.Decision != "allow" || len(fs) != 1 || fs[0].GetKind() != "github_token" || !strings.HasPrefix(fs[0].GetLocation(), "arg:") {
		t.Fatalf("%+v findings %v", r.answer, fs)
	}
	if strings.Contains(fs[0].String(), "abcdefgh") {
		t.Fatal("a finding carries the value")
	}
	h = setup(t, withShell)
	h.hook(t, shellInput("go test ./...", "/home/dev/proj"), nil)
	if len(h.auth.findings) != 0 {
		t.Fatalf("findings for a clean command: %v", h.auth.findings)
	}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// TestHR225_AFileCommittedThroughTheContentsAPIIsScanned: the content of a
// GitHub contents write is base64; a credential inside it is a finding at
// arg:content(base64), and the write is still dispatched (the Authority
// holds it for a person).
func TestHR225_AFileCommittedThroughTheContentsAPIIsScanned(t *testing.T) {
	w := newGitHubWorld(t)
	h := setup(t, withGitHubApp(t, w))
	body := `{"message":"add config","content":"` + b64("token = "+fixtureToken+"\n") + `","branch":"main"}`
	r := h.do(t, http.MethodPut, "/payments/repos/acme/payments/contents/config.txt", body, nil)
	fs := h.auth.findings
	if len(fs) != 1 || fs[0].GetKind() != "github_token" || fs[0].GetLocation() != "arg:content(base64)" {
		t.Fatalf("%d %s %+v: findings %v", r.code, r.body, r.refusal, fs)
	}
}
