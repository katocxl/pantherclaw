// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package jira

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

var secret = base64.StdEncoding.EncodeToString([]byte("agent@example.com:simulated-api-token"))

func start(t *testing.T) (*Server, string) {
	t.Helper()
	s := New([]Project{
		{Key: "ENG", Name: "Engineering", Type: TypeSoftware},
		{Key: "HELP", Name: "Help desk", Type: TypeServiceDesk},
	}, []Issue{{Key: "ENG-1", Summary: "One", Type: "Task"}, {Key: "ENG-2", Summary: "Two", Type: "Task", Security: "Internal"}},
		Faults{}, pclog.Discard()).WithRequire(Require{Secret: secret})
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return s, srv.URL
}

func call(t *testing.T, method, url, auth, body string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", "Basic "+auth)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.Header.Get("Simulated") != "true" {
		t.Fatalf("%s %s: not marked simulated", method, url)
	}
	var out map[string]any
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, out
}

func TestJiraSimAnswersAsJiraDoes(t *testing.T) {
	s, url := start(t)
	if code, _ := call(t, "GET", url+"/rest/api/3/project/ENG", "", ""); code != http.StatusUnauthorized {
		t.Fatalf("no auth: %d", code)
	}
	other := base64.StdEncoding.EncodeToString([]byte("agent@example.com:other"))
	if code, _ := call(t, "GET", url+"/rest/api/3/project/ENG", other, ""); code != http.StatusUnauthorized {
		t.Fatalf("other secret: %d", code)
	}
	code, p := call(t, "GET", url+"/rest/api/3/project/HELP", secret, "")
	if code != http.StatusOK || p["projectTypeKey"] != TypeServiceDesk {
		t.Fatalf("project: %d %v", code, p)
	}
	if code, _ := call(t, "GET", url+"/rest/api/3/project/NOPE", secret, ""); code != http.StatusNotFound {
		t.Fatalf("missing project: %d", code)
	}
	code, is := call(t, "GET", url+"/rest/api/2/issue/ENG-2", secret, "")
	fields, _ := is["fields"].(map[string]any)
	if code != http.StatusOK || fields["security"].(map[string]any)["name"] != "Internal" ||
		fields["project"].(map[string]any)["projectTypeKey"] != TypeSoftware {
		t.Fatalf("issue: %d %v", code, is)
	}
	code, created := call(t, "POST", url+"/rest/api/2/issue", secret,
		`{"fields":{"project":{"key":"HELP"},"summary":"Refund sent","issuetype":{"name":"Task"},"description":"Done"}}`)
	if code != http.StatusCreated || created["key"] != "HELP-1" {
		t.Fatalf("create: %d %v", code, created)
	}
	if code, _ := call(t, "POST", url+"/rest/api/2/issue", secret, `{"fields":{"project":{"key":"HELP"},"issuetype":{"name":"Task"}}}`); code != http.StatusBadRequest {
		t.Fatalf("no summary: %d", code)
	}
	if code, _ := call(t, "POST", url+"/rest/api/2/issue/HELP-1/comment", secret, `{"body":"Your refund was sent"}`); code != http.StatusCreated {
		t.Fatalf("comment: %d", code)
	}
	if code, _ := call(t, "POST", url+"/rest/api/2/issue/HELP-1/transitions", secret, `{"transition":{"id":"31"}}`); code != http.StatusNoContent {
		t.Fatalf("transition: %d", code)
	}
	if code, _ := call(t, "POST", url+"/rest/api/2/issue/HELP-1/transitions", secret, `{"transition":{"id":"99"}}`); code != http.StatusBadRequest {
		t.Fatalf("bad transition: %d", code)
	}
	got, _ := s.Issue("HELP-1")
	if got.Status != "Done" || len(got.Comments) != 1 || got.Description != "Done" {
		t.Fatalf("issue: %+v", got)
	}
	s.SetFaults(Faults{RateLimit: 1})
	if code, _ := call(t, "GET", url+"/rest/api/3/project/ENG", secret, ""); code != http.StatusTooManyRequests {
		t.Fatalf("rate limit: %d", code)
	}
	s.SetFaults(Faults{InvalidAuth: true})
	if code, _ := call(t, "GET", url+"/rest/api/3/project/ENG", secret, ""); code != http.StatusUnauthorized {
		t.Fatalf("invalid auth: %d", code)
	}
	s.SetFaults(Faults{NotFound: true})
	if code, _ := call(t, "GET", url+"/rest/api/2/issue/ENG-1", secret, ""); code != http.StatusNotFound {
		t.Fatalf("not found: %d", code)
	}
}

func TestJiraSimPostsSignedWebhooks(t *testing.T) {
	s, _ := start(t)
	got := make(chan *http.Request, 4)
	bodies := make(chan []byte, 4)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- r
		bodies <- b
	}))
	t.Cleanup(hook.Close)
	s.SetWebhook(Webhook{URL: hook.URL, Secret: "whsec"})
	if !s.Transition(context.Background(), "ENG-1", "31") {
		t.Fatal("transition")
	}
	r, b := <-got, <-bodies
	mac := hmac.New(sha256.New, []byte("whsec"))
	mac.Write(b)
	if r.Header.Get("X-Hub-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Fatalf("signature %q", r.Header.Get("X-Hub-Signature"))
	}
	var ev map[string]any
	if json.Unmarshal(b, &ev) != nil || ev["webhookEvent"] != "jira:issue_updated" {
		t.Fatalf("event %s", b)
	}
	if s.Transition(context.Background(), "ENG-1", "99") || s.Transition(context.Background(), "ENG-9", "31") {
		t.Fatal("unknown transition or issue accepted")
	}
}
