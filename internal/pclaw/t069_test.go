// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestT069_TheHookFailsClosedOnAnythingButAPlainAllow: whatever answers at
// the gateway's address, a broken proxy, a gateway in trouble or someone
// impersonating it, the hook allows a command only for a 200 answer whose
// one decision is exactly "allow" (T-069). An allow under an error status,
// a redirect to an allowing endpoint, a decision of "ask" or another
// spelling, two decisions, trailing bytes, an answer cut at the size limit,
// HTML and an empty body all block the command (exit code 2, nothing on
// stdout for Claude Code to act on).
func TestT069_TheHookFailsClosedOnAnythingButAPlainAllow(t *testing.T) {
	allow := `{"decision":"allow","reason":"PantherClaw allowed this call.","mode":"enforce"}`
	allowing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, allow)
	}))
	t.Cleanup(allowing.Close)
	answer := func(status int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}
	}
	dir := t.TempDir()
	for name, tc := range map[string]struct {
		h       http.HandlerFunc
		allowed bool
	}{
		"a plain allow":        {answer(http.StatusOK, allow), true},
		"allow with 500":       {answer(http.StatusInternalServerError, allow), false},
		"allow with 401":       {answer(http.StatusUnauthorized, allow), false},
		"allow with 202":       {answer(http.StatusAccepted, allow), false},
		"ask":                  {answer(http.StatusOK, `{"decision":"ask","reason":"Ask the developer."}`), false},
		"Allow":                {answer(http.StatusOK, `{"decision":"Allow"}`), false},
		"allow and deny":       {answer(http.StatusOK, `{"decision":"allow","decision":"deny"}`), false},
		"trailing bytes":       {answer(http.StatusOK, allow+`{"decision":"deny"}`), false},
		"cut at the limit":     {answer(http.StatusOK, `{"decision":"allow","reason":"`+strings.Repeat("a", 70<<10)+`"}`), false},
		"html":                 {answer(http.StatusOK, `<html><body>allow</body></html>`), false},
		"empty":                {answer(http.StatusOK, ""), false},
		"no decision":          {answer(http.StatusOK, `{"reason":"PantherClaw allowed this call."}`), false},
		"a decision as a list": {answer(http.StatusOK, `{"decision":["allow"]}`), false},
		"a redirect to an allow": {func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, allowing.URL+r.URL.Path, http.StatusTemporaryRedirect)
		}, false},
	} {
		gw := httptest.NewServer(tc.h)
		code, out, errs := runHook(t, hookEnv(t, gw.URL), hookEvent("Bash", "ls", dir, "toolu_t069"))
		gw.Close()
		if allowed := code == 0 && strings.Contains(out, `"permissionDecision":"allow"`); allowed != tc.allowed {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", name, code, out, errs)
		}
		if !tc.allowed && (code != 2 || out != "") {
			t.Errorf("%s: exit %d, stdout %q", name, code, out)
		}
	}
}
