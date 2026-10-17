// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/a2a/a2astore"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
)

// fakePins records the step-up the confirmation received and refuses
// without one, as the use case does.
type fakePins struct{ got []*stepup.StepUp }

func (f *fakePins) Get(_ context.Context, conn ids.UUID) (a2astore.Proposal, error) {
	pin := func(state string) *a2astore.Pin {
		return &a2astore.Pin{
			ID: ids.NewV7(), Connection: conn, State: state, ProposedBy: "user:x", ProposedAt: time.Now(),
			Config: &pb.A2AConfig{
				CardUrl: "https://peer.example/.well-known/agent-card.json", CardDigest: make([]byte, 32),
				Interface: &pb.A2AInterface{Protocol: "JSONRPC", Url: "https://peer.example/a2a"}, Skills: []string{"refunds"},
				PeerAgentId: ids.NewV7().String(), PeerScope: &pb.A2APeerScope{Bounds: []byte(`{"note":"<script>alert(1)</script>"}`)},
			},
		}
	}
	return a2astore.Proposal{Connection: conn, Name: "peer", Active: pin(a2astore.StateActive), Proposed: pin(a2astore.StateProposed)}, nil
}

func (f *fakePins) Confirm(_ context.Context, conn, _ ids.UUID, su *stepup.StepUp) (a2astore.Pin, error) {
	f.got = append(f.got, su)
	if su == nil {
		return a2astore.Pin{}, stepup.ErrStepUp
	}
	return a2astore.Pin{Connection: conn, State: a2astore.StateActive, Config: &pb.A2AConfig{CardDigest: make([]byte, 32)}}, nil
}

// TestHR322_A2APinConfirmationNeedsThePagesStepUp (G0 M14 D85): confirming
// a proposed card is a session route with the CSRF proof, and the page
// passes the session's step-up (none when the session has not stepped up,
// which the use case refuses as STEP_UP_REQUIRED). The page shows the
// digest, interface, skills and peer scope, the scope escaped.
func TestHR322_A2APinConfirmationNeedsThePagesStepUp(t *testing.T) {
	h, _, mux := newHandler(t, origin)
	fake := &fakePins{}
	m := mux.(*http.ServeMux)
	h.MountA2APins(m, fake)
	for _, want := range []webhttp.Route{
		{Method: http.MethodGet, Path: "/connections/{id}/a2a-pin", Session: true},
		{Method: http.MethodPost, Path: "/connections/{id}/a2a-pin/{pin}/confirm", Session: true, CSRF: true},
	} {
		if !slices.Contains(h.Routes(), want) {
			t.Errorf("route %+v is not mounted", want)
		}
	}
	id := ids.NewV7().String()
	path := "/connections/" + id + "/a2a-pin/" + ids.NewV7().String() + "/confirm"
	r := post(path)
	r.Header.Del(webhttp.CSRFHeader)
	if resp := do(t, m, r); resp.StatusCode != http.StatusForbidden || len(fake.got) != 0 {
		t.Fatalf("without CSRF: %d, %d calls", resp.StatusCode, len(fake.got))
	}
	if resp := do(t, m, post(path)); resp.StatusCode != http.StatusForbidden || !strings.Contains(resp.Body, "step_up_required") || fake.got[0] != nil {
		t.Fatalf("without a step-up: %d %s", resp.StatusCode, resp.Body)
	}
	resp := do(t, m, withCookie(post(path), "responder"))
	if su := fake.got[len(fake.got)-1]; resp.StatusCode != http.StatusOK || su == nil || su.Credential != responderKey || !su.At.Equal(steppedUpAt) {
		t.Fatalf("stepped up: %d %s %+v", resp.StatusCode, resp.Body, su)
	}
	page := httptest.NewRequest(http.MethodGet, origin+"/connections/"+id+"/a2a-pin", nil)
	page.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: "good"})
	got := do(t, m, page)
	if got.StatusCode != http.StatusOK || strings.Contains(got.Body, "<script>alert") || !strings.Contains(got.Body, strings.Repeat("0", 64)) ||
		!strings.Contains(got.Body, "https://peer.example/a2a") || !strings.Contains(got.Body, "refunds") ||
		!strings.Contains(got.Body, "/static/automation_endpoints.js") {
		t.Fatalf("page: %d %s", got.StatusCode, got.Body)
	}
	bad := httptest.NewRequest(http.MethodGet, origin+"/connections/nope/a2a-pin", nil)
	bad.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: "good"})
	if resp := do(t, m, bad); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a bad id: %d", resp.StatusCode)
	}
}
