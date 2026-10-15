// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package stream_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/operations/stream"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// perm is what the stream checks.
const perm = stream.PermOperations

type fakeFeed struct {
	mu  sync.Mutex
	evs []stream.Event
}

func (f *fakeFeed) add(e stream.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e.Seq = int64(len(f.evs) + 1)
	if e.ID.IsZero() {
		e.ID = ids.NewV7()
	}
	f.evs = append(f.evs, e)
}

func (f *fakeFeed) After(_ context.Context, org ids.OrgID, after int64, limit int) ([]stream.Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []stream.Event
	for _, e := range f.evs {
		if e.Seq > after && e.Org == org && len(out) < limit {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeFeed) Head(_ context.Context, _ ids.OrgID) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return int64(len(f.evs)), nil
}

// fakeAuth maps bearer tokens to callers; revoke removes one.
type fakeAuth struct {
	mu      sync.Mutex
	callers map[string]tenancy.Caller
}

func (a *fakeAuth) Authenticate(_ context.Context, bearer string) (tenancy.Caller, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.callers[bearer]
	if !ok {
		return tenancy.Caller{}, errors.New("unauthenticated")
	}
	return c, nil
}

func (a *fakeAuth) set(bearer string, c tenancy.Caller) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.callers[bearer] = c
}

func (a *fakeAuth) revoke(bearer string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.callers, bearer)
}

// teamScoper gives org-wide viewers every agent and team viewers the
// agents of their team.
type teamScoper struct{ team map[ids.UUID]ids.UUID } // agent → team

func (s teamScoper) Scope(_ context.Context, c tenancy.Caller) (stream.Scope, error) {
	if c.Can(perm, td.OrgPath(c.Org)) {
		return stream.Scope{All: true}, nil
	}
	out := stream.Scope{Agents: map[ids.UUID]bool{}}
	for agent, team := range s.team {
		if c.Can(perm, td.OrgPath(c.Org).Child(td.ScopeTeam, team)) {
			out.Agents[agent] = true
		}
	}
	return out, nil
}

type world struct {
	org          ids.OrgID
	feed         *fakeFeed
	auth         *fakeAuth
	srv          *httptest.Server
	agentA       ids.UUID // in team A
	agentB       ids.UUID // in team B
	teamA, teamB ids.UUID
	expiry       map[string]time.Time
}

func caller(org ids.OrgID, role td.RoleName, scope td.Scope) tenancy.Caller {
	return tenancy.Caller{Subject: td.Subject{
		Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: role, Scope: scope}},
	}}
}

func newWorld(t *testing.T, cfg stream.Config) *world {
	t.Helper()
	w := &world{
		org: ids.New[ids.Org](), feed: &fakeFeed{}, auth: &fakeAuth{callers: map[string]tenancy.Caller{}},
		agentA: ids.NewV7(), agentB: ids.NewV7(), teamA: ids.NewV7(), teamB: ids.NewV7(), expiry: map[string]time.Time{},
	}
	w.auth.set("org-auditor", caller(w.org, td.RoleAuditor, td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}))
	w.auth.set("team-a-dev", caller(w.org, td.RoleResponder, td.Scope{Type: td.ScopeTeam, ID: w.teamA}))
	sc := teamScoper{team: map[ids.UUID]ids.UUID{w.agentA: w.teamA, w.agentB: w.teamB}}
	if cfg.Poll == 0 {
		cfg.Poll = 5 * time.Millisecond
	}
	h, err := stream.New(w.feed, w.auth, sc, func(b string) (time.Time, bool) {
		e, ok := w.expiry[b]
		return e, ok
	}, nil, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.Mount(mux)
	w.srv = httptest.NewServer(mux)
	t.Cleanup(w.srv.Close)
	return w
}

func (w *world) event(kind string, subjects ...stream.Subject) {
	w.feed.add(stream.Event{Org: w.org, Kind: kind, OccurredAt: time.Now(), Subjects: subjects})
}

func agent(id ids.UUID) stream.Subject { return stream.Subject{Type: "agent", ID: id.String()} }

func txn(id ids.UUID) stream.Subject { return stream.Subject{Type: "transaction", ID: id.String()} }

// opened is a stream response; its body closes when the test ends.
type opened struct {
	StatusCode int
	Header     http.Header
	Body       io.Reader
}

func (w *world) open(t *testing.T, ctx context.Context, path, bearer string, hdr map[string]string) opened {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := w.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return opened{StatusCode: resp.StatusCode, Header: resp.Header, Body: resp.Body}
}

// frame is one SSE frame.
type frame struct {
	id, event, data string
	comment         bool
}

// frames reads frames until stop says so or the stream ends.
func frames(t *testing.T, body io.Reader, stop func([]frame) bool) ([]frame, bool) {
	t.Helper()
	r := bufio.NewReader(body)
	var out []frame
	var cur frame
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return out, true // closed
		}
		line = strings.TrimRight(line, "\n")
		switch {
		case line == "":
			out = append(out, cur)
			cur = frame{}
			if stop(out) {
				return out, false
			}
		case strings.HasPrefix(line, ":"):
			cur.comment = true
		case strings.HasPrefix(line, "id: "):
			cur.id = strings.TrimPrefix(line, "id: ")
		case strings.HasPrefix(line, "event: "):
			cur.event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			cur.data = strings.TrimPrefix(line, "data: ")
		}
	}
}

func events(fs []frame) []frame {
	var out []frame
	for _, f := range fs {
		if f.event != "" {
			out = append(out, f)
		}
	}
	return out
}

func untilEvents(n int) func([]frame) bool {
	return func(fs []frame) bool { return len(events(fs)) >= n }
}

func ctxFor(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestHR256_TheBearerTokenComesFromTheAuthorizationHeaderOnly: a token in
// the URL is refused even beside a valid header, a missing header is 401,
// and a bad one never opens the stream.
func TestHR256_TheBearerTokenComesFromTheAuthorizationHeaderOnly(t *testing.T) {
	w := newWorld(t, stream.Config{})
	ctx := ctxFor(t)
	for _, tc := range []struct {
		name, path, bearer string
		want               int
	}{
		{"query access_token", stream.Path + "?access_token=org-auditor", "", http.StatusBadRequest},
		{"query token beside header", stream.Path + "?token=org-auditor", "org-auditor", http.StatusBadRequest},
		{"query Authorization", stream.Path + "?Authorization=Bearer+org-auditor", "", http.StatusBadRequest},
		{"unknown parameter", stream.Path + "?x=1", "org-auditor", http.StatusBadRequest},
		{"no header", stream.Path, "", http.StatusUnauthorized},
		{"bad token", stream.Path, "nope", http.StatusUnauthorized},
		{"header", stream.Path, "org-auditor", http.StatusOK},
	} {
		resp := w.open(t, ctx, tc.path, tc.bearer, nil)
		if resp.StatusCode != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, resp.StatusCode, tc.want)
		}
		if tc.want == http.StatusOK && resp.Header.Get("Content-Type") != "text/event-stream" {
			t.Errorf("%s: content type %q", tc.name, resp.Header.Get("Content-Type"))
		}
	}
	// A viewer without the permission is refused.
	w.auth.set("no-perm", caller(w.org, td.RoleRunLauncher, td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}))
	if resp := w.open(t, ctx, stream.Path, "no-perm", nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("without permission: %d", resp.StatusCode)
	}
}

// TestHR256_EveryEventIsFilteredByTheViewersPermissions: a team viewer
// sees its team's agents' events only; an event naming an agent outside
// its scope, alongside one inside, and an org-wide event stay hidden. The
// org-wide viewer sees all of them. Routine kinds are never streamed.
func TestHR256_EveryEventIsFilteredByTheViewersPermissions(t *testing.T) {
	w := newWorld(t, stream.Config{})
	ctx := ctxFor(t)
	w.event("reflex.alert", agent(w.agentA))                                // 1 visible to team A
	w.event("reflex.alert", agent(w.agentB))                                // 2 hidden from team A
	w.event("reflex.live", agent(w.agentA), agent(w.agentB))                // 3 hidden: names B
	w.event("audit.containment.kill_switch_engaged")                        // 4 org-wide
	w.event("receipt.decision", agent(w.agentA))                            // 5 routine: never streamed
	w.event("reflex.incident", agent(w.agentA))                             // 6 visible to team A
	w.event("reflex.live", stream.Subject{Type: "agent", ID: "not-a-uuid"}) // 7 malformed: org-wide only

	team := w.open(t, ctx, stream.Path, "team-a-dev", map[string]string{"Last-Event-ID": "0"})
	got, _ := frames(t, team.Body, untilEvents(2))
	ev := events(got)
	if len(ev) != 2 || ev[0].id != "1" || ev[1].id != "6" {
		t.Fatalf("team viewer: %+v", ev)
	}
	org := w.open(t, ctx, stream.Path, "org-auditor", map[string]string{"Last-Event-ID": "0"})
	got, _ = frames(t, org.Body, untilEvents(6))
	ids := []string{}
	for _, f := range events(got) {
		ids = append(ids, f.id)
	}
	if strings.Join(ids, ",") != "1,2,3,4,6,7" {
		t.Fatalf("org viewer: %v", ids)
	}
}

// TestHR256_TheStreamResumesBySeq: Last-Event-ID (or after) resumes after
// that sequence number; without one the stream starts at the head.
func TestHR256_TheStreamResumesBySeq(t *testing.T) {
	w := newWorld(t, stream.Config{})
	ctx := ctxFor(t)
	for range 3 {
		w.event("reflex.alert", agent(w.agentA))
	}
	resp := w.open(t, ctx, stream.Path, "org-auditor", map[string]string{"Last-Event-ID": "2"})
	got, _ := frames(t, resp.Body, untilEvents(1))
	if ev := events(got); ev[0].id != "3" {
		t.Fatalf("Last-Event-ID 2: %+v", ev)
	}
	resp = w.open(t, ctx, stream.Path+"?after=1", "org-auditor", nil)
	got, _ = frames(t, resp.Body, untilEvents(2))
	if ev := events(got); ev[0].id != "2" || ev[1].id != "3" {
		t.Fatalf("after=1: %+v", ev)
	}
	resp = w.open(t, ctx, stream.Path, "org-auditor", nil)
	w.event("reflex.alert", agent(w.agentA))
	got, _ = frames(t, resp.Body, untilEvents(1))
	if ev := events(got); ev[0].id != "4" {
		t.Fatalf("from head: %+v", ev)
	}
	if resp := w.open(t, ctx, stream.Path, "org-auditor", map[string]string{"Last-Event-ID": "-1"}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("negative Last-Event-ID: %d", resp.StatusCode)
	}
}

// TestHR256_TheStreamClosesAtTokenExpiry: the stream ends when the access
// token expires, without waiting for a recheck.
func TestHR256_TheStreamClosesAtTokenExpiry(t *testing.T) {
	w := newWorld(t, stream.Config{Recheck: time.Hour, Heartbeat: time.Hour})
	ctx := ctxFor(t)
	w.expiry["org-auditor"] = time.Now().Add(200 * time.Millisecond)
	resp := w.open(t, ctx, stream.Path, "org-auditor", nil)
	if _, closed := frames(t, resp.Body, func([]frame) bool { return false }); !closed {
		t.Fatal("stream still open")
	}
	w.expiry["org-auditor"] = time.Now().Add(-time.Second)
	resp = w.open(t, ctx, stream.Path, "org-auditor", nil)
	if fs, closed := frames(t, resp.Body, func([]frame) bool { return false }); !closed || len(events(fs)) != 0 {
		t.Fatal("an expired token streamed")
	}
}

// TestHR256_TheStreamClosesOnRevocationOrRoleRemoval: the recheck
// authenticates the credential again; a revoked session or a removed role
// ends the stream, and a narrowed scope applies to the next events.
func TestHR256_TheStreamClosesOnRevocationOrRoleRemoval(t *testing.T) {
	w := newWorld(t, stream.Config{Recheck: 20 * time.Millisecond, Heartbeat: time.Hour})
	ctx := ctxFor(t)
	resp := w.open(t, ctx, stream.Path, "org-auditor", nil)
	w.auth.revoke("org-auditor")
	if _, closed := frames(t, resp.Body, func([]frame) bool { return false }); !closed {
		t.Fatal("revoked session: stream still open")
	}

	dev := caller(w.org, td.RoleResponder, td.Scope{Type: td.ScopeTeam, ID: w.teamA})
	w.auth.set("dev", dev)
	resp = w.open(t, ctx, stream.Path, "dev", nil)
	dev.Bindings = []td.Binding{{Role: td.RoleRunLauncher, Scope: td.Scope{Type: td.ScopeTeam, ID: w.teamA}}}
	w.auth.set("dev", dev)
	if _, closed := frames(t, resp.Body, func([]frame) bool { return false }); !closed {
		t.Fatal("role removed: stream still open")
	}
}

// TestStream_RetriesAreGroupedAndHeartbeatsCarryTheCursor: alerts about
// one transaction arrive as one event with a count; heartbeats advance the
// resume point past events the viewer was not shown.
func TestStream_RetriesAreGroupedAndHeartbeatsCarryTheCursor(t *testing.T) {
	w := newWorld(t, stream.Config{Poll: time.Hour, Heartbeat: 20 * time.Millisecond})
	ctx := ctxFor(t)
	tx := ids.NewV7()
	w.event("reflex.live", agent(w.agentA), txn(tx))
	w.event("reflex.live", agent(w.agentA), txn(tx))
	w.event("reflex.alert", agent(w.agentB))
	w.event("reflex.live", agent(w.agentA), txn(tx))
	resp := w.open(t, ctx, stream.Path, "team-a-dev", map[string]string{"Last-Event-ID": "0"})
	got, _ := frames(t, resp.Body, func(fs []frame) bool {
		for _, f := range fs {
			if f.comment && f.id == "4" {
				return true
			}
		}
		return false
	})
	ev := events(got)
	if len(ev) != 1 || ev[0].id != "4" || !strings.Contains(ev[0].data, `"count":3`) {
		t.Fatalf("grouped: %+v", ev)
	}
}

// TestStream_ConcurrentStreamsPerCallerAreBounded: a sixth stream of one
// principal is refused with 429.
func TestStream_ConcurrentStreamsPerCallerAreBounded(t *testing.T) {
	w := newWorld(t, stream.Config{Heartbeat: time.Hour})
	ctx := ctxFor(t)
	for i := range 5 {
		resp := w.open(t, ctx, stream.Path, "org-auditor", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("stream %d: %d", i, resp.StatusCode)
		}
		// Wait for the open comment so the stream is counted.
		frames(t, resp.Body, func(fs []frame) bool { return len(fs) > 0 })
	}
	if resp := w.open(t, ctx, stream.Path, "org-auditor", nil); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("sixth stream: %d", resp.StatusCode)
	}
	if resp := w.open(t, ctx, stream.Path, "team-a-dev", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("another caller: %d", resp.StatusCode)
	}
}
