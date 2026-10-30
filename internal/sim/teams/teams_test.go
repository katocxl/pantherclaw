// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package teams

import (
	"encoding/json/v2"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	general = TeamID
	shared  = "19:shared000000000000000000000000@thread.tacv2"
)

func newSim(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	owner := Member{ID: "29:o", Name: "Owner", TenantID: TenantID, UserRole: "user"}
	var many []Member
	for range 120 {
		many = append(many, owner)
	}
	s := New([]Channel{
		{ID: general, Name: "General", Installed: true, Members: many},
		{ID: shared, Name: "shared", Installed: false, Members: []Member{owner}},
	}, Faults{}, slog.New(slog.DiscardHandler)).WithRequire(Require{ClientID: AppID, ClientSecret: "secret"})
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return s, srv
}

func token(t *testing.T, srv *httptest.Server, secret string) (int, string) {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {AppID}, "client_secret": {secret}, "scope": {Scope}}
	res, err := http.Post(srv.URL+"/botframework.com/oauth2/v2.0/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	var a struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.UnmarshalRead(res.Body, &a)
	return res.StatusCode, a.AccessToken
}

func call(t *testing.T, method, u, tok, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), method, u, strings.NewReader(body))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(res.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return res.StatusCode, out
}

func TestTeamsSimIssuesTokensAndPosts(t *testing.T) {
	s, srv := newSim(t)
	if code, _ := token(t, srv, "wrong"); code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: %d", code)
	}
	code, tok := token(t, srv, "secret")
	if code != http.StatusOK || !strings.HasPrefix(tok, "simtok-") {
		t.Fatalf("token: %d %q", code, tok)
	}
	base := srv.URL + "/teams/v3"
	if code, _ := call(t, http.MethodGet, base+"/teams/"+url.PathEscape(TeamID)+"/conversations", "bogus", ""); code != http.StatusUnauthorized {
		t.Fatalf("bogus token: %d", code)
	}
	code, out := call(t, http.MethodPost, base+"/conversations", tok,
		`{"isGroup":true,"channelData":{"channel":{"id":"`+general+`"},"tenant":{"id":"`+TenantID+`"}},"activity":{"type":"message","text":"hi"}}`)
	if code != http.StatusCreated || out["activityId"] == nil {
		t.Fatalf("create: %d %v", code, out)
	}
	code, _ = call(t, http.MethodPost, base+"/conversations/"+general+"/activities", tok, `{"type":"message","text":"again"}`)
	if code != http.StatusCreated {
		t.Fatalf("send: %d", code)
	}
	code, _ = call(t, http.MethodPost, base+"/conversations/"+shared+"/activities", tok, `{"type":"message","text":"x"}`)
	if code != http.StatusForbidden {
		t.Fatalf("not installed: %d", code)
	}
	if m := s.Messages(); len(m) != 2 || m[0].Text != "hi" || m[1].Text != "again" {
		t.Fatalf("messages %+v", m)
	}
	s.SetFaults(Faults{Blocked: true})
	if code, _ := call(t, http.MethodPost, base+"/conversations/"+general+"/activities", tok, `{"type":"message","text":"x"}`); code != http.StatusForbidden {
		t.Fatalf("blocked: %d", code)
	}
	s.SetFaults(Faults{})
	s.SetClock(func() time.Time { return time.Now().Add(2 * TokenLifetime) })
	if code, _ := call(t, http.MethodGet, base+"/conversations/"+general+"/pagedmembers", tok, ""); code != http.StatusUnauthorized {
		t.Fatalf("expired token: %d", code)
	}
}

func TestTeamsSimPagesMembers(t *testing.T) {
	_, srv := newSim(t)
	_, tok := token(t, srv, "secret")
	u := srv.URL + "/teams/v3/conversations/" + general + "/pagedmembers?pageSize=50"
	total, next, pages := 0, "", 0
	for {
		q := u
		if next != "" {
			q += "&continuationToken=" + next
		}
		code, out := call(t, http.MethodGet, q, tok, "")
		if code != http.StatusOK {
			t.Fatalf("page: %d", code)
		}
		total += len(out["members"].([]any))
		pages++
		c, _ := out["continuationToken"].(string)
		if c == "" {
			break
		}
		next = c
	}
	if total != 120 || pages != 3 {
		t.Fatalf("total %d in %d pages", total, pages)
	}
	if code, _ := call(t, http.MethodGet, u[:len(u)-2]+"10", tok, ""); code != http.StatusBadRequest {
		t.Fatalf("page size 10: %d", code)
	}
}

func TestTeamsSimListsTheBotsConversations(t *testing.T) {
	_, srv := newSim(t)
	_, tok := token(t, srv, "secret")
	code, out := call(t, http.MethodGet, srv.URL+"/teams/v3/conversations", tok, "")
	if code != http.StatusOK || len(out["conversations"].([]any)) != 1 {
		t.Fatalf("%d %v", code, out)
	}
}
