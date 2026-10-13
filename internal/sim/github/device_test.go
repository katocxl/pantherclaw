// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package github

import (
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/log"
)

// TestDeviceFlowAnswersAsGitHubDoes (P2f): the simulator's device flow
// gives a code to the registered App only, says authorization_pending
// until someone signs in, access_denied when they refuse and expired_token
// after 15 minutes, issues one user access token per code, and GET /user
// names the account that token belongs to and refuses any other.
func TestDeviceFlowAnswersAsGitHubDoes(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	s := New(log.Discard()).WithClock(func() time.Time { return now })
	s.RegisterApp(1, "Iv1.app", nil)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	client := &http.Client{Timeout: 5 * time.Second}
	post := func(path string, form url.Values) map[string]any {
		t.Helper()
		res, err := client.PostForm(srv.URL+path, form)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		var out map[string]any
		if err := json.UnmarshalRead(res.Body, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	start := func() (device, user string) {
		t.Helper()
		out := post("/login/device/code", url.Values{"client_id": {"Iv1.app"}})
		return out["device_code"].(string), out["user_code"].(string)
	}
	poll := func(device string) map[string]any {
		return post("/login/oauth/access_token", url.Values{"client_id": {"Iv1.app"}, "device_code": {device}, "grant_type": {deviceGrant}})
	}
	if out := post("/login/device/code", url.Values{"client_id": {"Iv1.other"}}); out["error"] != "incorrect_client_credentials" {
		t.Fatalf("another App: %v", out)
	}
	device, user := start()
	if out := poll(device); out["error"] != "authorization_pending" {
		t.Fatalf("before sign-in: %v", out)
	}
	if err := s.AuthorizeDevice(user, DeviceUser{ID: 77, Login: "bob-gh"}); err != nil {
		t.Fatal(err)
	}
	out := poll(device)
	token, _ := out["access_token"].(string)
	if !strings.HasPrefix(token, "ghu_") {
		t.Fatalf("after sign-in: %v", out)
	}
	if again := poll(device); again["error"] != "bad_verification_code" {
		t.Fatalf("a second token: %v", again)
	}
	who := func(auth string) (int, map[string]any) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/user", nil)
		req.Header.Set("Authorization", auth)
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		var body map[string]any
		_ = json.UnmarshalRead(res.Body, &body)
		return res.StatusCode, body
	}
	if code, body := who("Bearer " + token); code != http.StatusOK || body["login"] != "bob-gh" || body["id"] != float64(77) {
		t.Fatalf("GET /user: %d %v", code, body)
	}
	if code, _ := who("Bearer ghu_forged"); code != http.StatusUnauthorized {
		t.Fatalf("a forged token: %d", code)
	}

	refused, user := start()
	if err := s.DenyDevice(user); err != nil {
		t.Fatal(err)
	}
	if out := poll(refused); out["error"] != "access_denied" {
		t.Fatalf("refused: %v", out)
	}
	late, _ := start()
	now = now.Add(deviceExpiry)
	if out := poll(late); out["error"] != "expired_token" {
		t.Fatalf("expired: %v", out)
	}
	if err := s.AuthorizeDevice("NOPE-0000", DeviceUser{ID: 1, Login: "x"}); err == nil {
		t.Fatal("signed in to a code nobody asked for")
	}
}
