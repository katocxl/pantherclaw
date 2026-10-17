// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package slack_test

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sim/handshake"
	"github.com/katocxl/pantherclaw/internal/sim/slack"
)

const token = "xoxb-simulated-unit-test-token"

func newSim(t *testing.T) (*slack.Server, *httptest.Server) {
	t.Helper()
	s := slack.New([]slack.Channel{
		{ID: "C0APPROVAL1", Name: "approvals", Member: true},
		{ID: "C0EXTERNAL1", Name: "shared", Member: true, ExtShared: true},
		{ID: "C0OUTSIDE01", Name: "general"},
	}, slack.Faults{}, pclog.Discard()).WithRequire(slack.Require{Token: token})
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

type answer struct {
	OK      bool           `json:"ok"`
	Error   string         `json:"error"`
	TS      string         `json:"ts"`
	TeamID  string         `json:"team_id"`
	BotID   string         `json:"bot_id"`
	Channel jsontext.Value `json:"channel"`
}

func call(t *testing.T, ts *httptest.Server, tok, method string, body any) (int, http.Header, answer) {
	t.Helper()
	var req *http.Request
	if q, ok := body.(url.Values); ok {
		req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/"+method+"?"+q.Encode(), nil)
	} else {
		b, _ := json.Marshal(body)
		req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/"+method, strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var a answer
	if err := json.UnmarshalRead(resp.Body, &a); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, a
}

func TestSlackSim_AuthAndChannels(t *testing.T) {
	_, ts := newSim(t)
	if _, _, a := call(t, ts, "", "auth.test", map[string]any{}); a.OK || a.Error != "not_authed" {
		t.Fatalf("no token: %+v", a)
	}
	if _, _, a := call(t, ts, "xoxb-other-token-000000000000", "auth.test", map[string]any{}); a.OK {
		t.Fatalf("wrong token accepted: %+v", a)
	}
	if _, _, a := call(t, ts, token, "auth.test", map[string]any{}); !a.OK || a.TeamID != slack.TeamID || a.BotID != slack.BotID {
		t.Fatalf("auth.test: %+v", a)
	}
	_, _, a := call(t, ts, token, "conversations.info", url.Values{"channel": {"C0EXTERNAL1"}})
	var ch map[string]any
	_ = json.Unmarshal(a.Channel, &ch)
	if !a.OK || ch["is_ext_shared"] != true || ch["is_shared"] != true || ch["is_member"] != true {
		t.Fatalf("external: %+v", a)
	}
	if _, _, a := call(t, ts, token, "conversations.info", url.Values{"channel": {"C0NOSUCH001"}}); a.Error != "channel_not_found" {
		t.Fatalf("missing: %+v", a)
	}
}

func TestSlackSim_PostUpdateThread(t *testing.T) {
	s, ts := newSim(t)
	if _, _, a := call(t, ts, token, "chat.postMessage", map[string]any{"channel": "C0OUTSIDE01", "text": "x"}); a.Error != "not_in_channel" {
		t.Fatalf("outside: %+v", a)
	}
	_, _, a := call(t, ts, token, "chat.postMessage", map[string]any{"channel": "C0APPROVAL1", "text": "card", "blocks": []any{map[string]any{"type": "divider"}}})
	if !a.OK || a.TS == "" {
		t.Fatalf("post: %+v", a)
	}
	if _, _, u := call(t, ts, token, "chat.update", map[string]any{"channel": "C0APPROVAL1", "ts": a.TS, "text": "closed"}); !u.OK {
		t.Fatalf("update: %+v", u)
	}
	if _, _, u := call(t, ts, token, "chat.update", map[string]any{"channel": "C0APPROVAL1", "ts": "1.000000", "text": "x"}); u.Error != "message_not_found" {
		t.Fatalf("update missing: %+v", u)
	}
	if _, _, r := call(t, ts, token, "chat.postMessage", map[string]any{"channel": "C0APPROVAL1", "text": "reply", "thread_ts": a.TS}); !r.OK {
		t.Fatalf("reply: %+v", r)
	}
	ms := s.Messages()
	if len(ms) != 2 || ms[0].Text != "closed" || ms[0].Updates != 1 || len(ms[0].Blocks) != 0 || ms[1].ThreadTS != a.TS {
		t.Fatalf("messages: %+v", ms)
	}
	if c := s.Calls(); c["chat.postMessage"] != 3 || c["chat.update"] != 2 {
		t.Fatalf("calls: %v", c)
	}
}

func TestSlackSim_Faults(t *testing.T) {
	s, ts := newSim(t)
	s.SetFaults(slack.Faults{RateLimit: 1, RetryAfter: 7})
	st, h, a := call(t, ts, token, "auth.test", map[string]any{})
	if st != http.StatusTooManyRequests || h.Get("Retry-After") != "7" || a.Error != "ratelimited" {
		t.Fatalf("429: %d %v %+v", st, h, a)
	}
	if _, _, a := call(t, ts, token, "auth.test", map[string]any{}); !a.OK {
		t.Fatalf("after 429: %+v", a)
	}
	s.SetFaults(slack.Faults{InvalidAuth: true})
	if _, _, a := call(t, ts, token, "auth.test", map[string]any{}); a.Error != "invalid_auth" {
		t.Fatalf("invalid_auth: %+v", a)
	}
	s.SetFaults(slack.Faults{ChannelNotFound: true})
	if _, _, a := call(t, ts, token, "chat.postMessage", map[string]any{"channel": "C0APPROVAL1", "text": "x"}); a.Error != "channel_not_found" {
		t.Fatalf("channel_not_found: %+v", a)
	}
}

func TestSlackSim_HandshakeAndTestEndpoints(t *testing.T) {
	_, ts := newSim(t)
	resp, err := http.Get(ts.URL + handshake.Path + "?nonce=0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	var h handshake.Answer
	_ = json.UnmarshalRead(resp.Body, &h)
	_ = resp.Body.Close()
	if h.Kind != "slack" {
		t.Fatalf("handshake: %+v", h)
	}
	resp, err = http.Post(ts.URL+"/__sim/faults", "application/json", strings.NewReader(`{"invalid_auth":true}`))
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("faults: %v %v", err, resp)
	}
	_ = resp.Body.Close()
	if _, _, a := call(t, ts, token, "auth.test", map[string]any{}); a.Error != "invalid_auth" {
		t.Fatalf("faults endpoint: %+v", a)
	}
	resp, err = http.Get(ts.URL + "/__sim/messages")
	if err != nil || resp.StatusCode != http.StatusOK || resp.Header.Get("Simulated") != "true" {
		t.Fatalf("messages: %v %v", err, resp)
	}
	_ = resp.Body.Close()
}
