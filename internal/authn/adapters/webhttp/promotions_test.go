// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/promotions"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
)

// fakePromotions records what the page passed.
type fakePromotions struct {
	err     error
	stepUps []*stepup.StepUp
	ins     []promotions.PromoteInput
}

func (f *fakePromotions) GetReadiness(context.Context, ids.UUID, ids.UUID, []string, string) ([]promotions.Readiness, error) {
	return []promotions.Readiness{{Operation: "payments.refund.create", Checks: []promotions.Check{
		{Name: promotions.CheckCoverage, Detail: `<script>alert(1)</script>`},
	}}}, f.err
}

func (f *fakePromotions) PromoteAgent(_ context.Context, in promotions.PromoteInput, su *stepup.StepUp) (promotions.Result, error) {
	f.ins, f.stepUps = append(f.ins, in), append(f.stepUps, su)
	if f.err != nil {
		return promotions.Result{}, f.err
	}
	return promotions.Result{Readiness: []promotions.Readiness{{Operation: in.Operations[0]}}}, nil
}

func newPromotionsHandler(t *testing.T) (*fakePromotions, http.Handler) {
	t.Helper()
	h, err := webhttp.New(&fakeBrowser{}, origin, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakePromotions{}
	h.WithPromotions(f)
	mux := http.NewServeMux()
	h.Mount(mux)
	return f, mux
}

// TestHR290_ThePromotionsPageCarriesTheSessionsStepUp (D53): the page
// shows readiness per operation with untrusted details escaped and one
// static script; a promotion passes this session's own step-up to the use
// case, needs the CSRF proof and a strict body, and maps a missing step-up
// to step_up_required.
func TestHR290_ThePromotionsPageCarriesTheSessionsStepUp(t *testing.T) {
	f, mux := newPromotionsHandler(t)
	agent, env := ids.NewV7(), ids.NewV7()
	path := webhttp.PromotionsPath + "/" + agent.String() + "/promote"
	r := httptest.NewRequest(http.MethodGet, origin+path+"?environment="+env.String(), nil)
	r.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: "responder"})
	resp := do(t, mux, r)
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, "payments.refund.create") || strings.Contains(resp.Body, "<script>alert") ||
		strings.Count(resp.Body, "<script") != 1 || !strings.Contains(resp.Body, `<script src="/static/promotions.js"></script>`) {
		t.Fatalf("page: %d %s", resp.StatusCode, resp.Body)
	}

	body := `{"environment_id":"` + env.String() + `","operations":["payments.refund.create"],"failure_behavior":"FAIL_CLOSED"}`
	if resp := do(t, mux, postAs(path, "responder", body)); resp.StatusCode != http.StatusOK || len(f.stepUps) != 1 ||
		*f.stepUps[0] != (stepup.StepUp{Credential: responderKey, At: steppedUpAt}) || f.ins[0].Agent != agent || f.ins[0].Environment != env {
		t.Fatalf("promote: %d %s %+v", resp.StatusCode, resp.Body, f.stepUps)
	}
	noCSRF := postAs(path, "responder", body)
	noCSRF.Header.Del(webhttp.CSRFHeader)
	if resp := do(t, mux, noCSRF); resp.StatusCode != http.StatusForbidden || len(f.ins) != 1 {
		t.Fatalf("without the CSRF header: %d", resp.StatusCode)
	}
	if resp := do(t, mux, postAs(path, "responder", strings.Replace(body, "}", `,"skip":true}`, 1))); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown member: %d", resp.StatusCode)
	}
	f.err = stepup.ErrStepUp
	if resp := do(t, mux, postAs(path, "responder", body)); resp.StatusCode != http.StatusForbidden || !strings.Contains(resp.Body, `"error":"step_up_required"`) {
		t.Fatalf("a stale step-up: %d %s", resp.StatusCode, resp.Body)
	}
}
