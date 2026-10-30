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
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
)

// fakeSlack records what the page passed.
type fakeSlack struct {
	err      error
	state    string
	stepUps  []stepup.StepUp
	versions []string
	previews int
	domains  []string
}

func (f *fakeSlack) view(id ids.UUID) napp.ChannelView {
	return napp.ChannelView{ID: id, Name: "approvals", Kind: domain.KindSlackApp, SlackApp: &napp.SlackAppView{
		ChannelID: "C0APPROVAL1", DataLevel: domain.SlackMinimal, State: f.state, DirectMessages: f.domains != nil, AllowedEmailDomains: f.domains,
	}}
}

func (f *fakeSlack) GetChannel(_ context.Context, id ids.UUID) (napp.ChannelView, []napp.DeliveryView, error) {
	return f.view(id), nil, nil
}

func (f *fakeSlack) ActivateSlackApp(_ context.Context, id ids.UUID, version string, su stepup.StepUp) (napp.ChannelView, error) {
	f.stepUps, f.versions = append(f.stepUps, su), append(f.versions, version)
	return f.view(id), f.err
}

func (f *fakeSlack) PreviewSlackApp(context.Context, ids.UUID) (napp.SlackPreview, error) {
	f.previews++
	return napp.SlackPreview{SlackWorkspace: napp.SlackWorkspace{
		TeamID: "T0SIMULATED", TeamName: "<script>alert(1)</script>", BotID: "B0SIMULATED", BotName: "pantherclaw", ChannelName: "approvals",
	}, Version: "v7"}, nil
}

// TestHR315_TheSlackChannelPageCarriesTheSessionsStepUp (D22, D66): the
// page shows what Slack reports for a waiting channel, escaped, with one
// static script and no token field; activating passes this session's own
// step-up to the use case, needs the CSRF proof and an empty strict body
// (no token), and maps a missing step-up to step_up_required.
func TestHR315_TheSlackChannelPageCarriesTheSessionsStepUp(t *testing.T) {
	h, err := webhttp.New(&fakeBrowser{}, origin, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSlack{state: napp.SlackPending}
	h.WithSlackChannels(f)
	mux := http.NewServeMux()
	h.Mount(mux)
	id := ids.NewV7()
	path := napp.SlackConfirmPath(id)
	r := httptest.NewRequest(http.MethodGet, origin+path, nil)
	r.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: "org-admin"})
	resp := do(t, mux, r)
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, "C0APPROVAL1") || !strings.Contains(resp.Body, "#approvals") ||
		f.previews != 1 || strings.Contains(resp.Body, "<script>alert") || strings.Contains(resp.Body, "<input") || strings.Count(resp.Body, "<script") != 1 ||
		!strings.Contains(resp.Body, `<script src="/static/slack_channel.js"></script>`) {
		t.Fatalf("page: %d %s", resp.StatusCode, resp.Body)
	}
	want := stepup.StepUp{Credential: responderKey, At: steppedUpAt}
	if resp := do(t, mux, postAs(path, "org-admin", `{"version":"v7"}`)); resp.StatusCode != http.StatusOK || len(f.stepUps) != 1 || f.stepUps[0] != want {
		t.Fatalf("activate: %d %s %+v", resp.StatusCode, resp.Body, f.stepUps)
	}
	if !strings.Contains(resp.Body, `data-version="v7"`) || f.versions[0] != "v7" {
		t.Fatalf("version: %v", f.versions)
	}
	if resp := do(t, mux, postAs(path, "org-admin", `{}`)); resp.StatusCode != http.StatusBadRequest || len(f.stepUps) != 1 {
		t.Fatalf("no version: %d", resp.StatusCode)
	}
	if resp := do(t, mux, postAs(path, "org-admin", `{"bot_token":"xoxb-new"}`)); resp.StatusCode != http.StatusBadRequest || len(f.stepUps) != 1 {
		t.Fatalf("a token on the page: %d %s", resp.StatusCode, resp.Body)
	}
	noCSRF := postAs(path, "org-admin", `{"version":"v7"}`)
	noCSRF.Header.Del(webhttp.CSRFHeader)
	if resp := do(t, mux, noCSRF); resp.StatusCode != http.StatusForbidden || len(f.stepUps) != 1 {
		t.Fatalf("without the CSRF header: %d", resp.StatusCode)
	}
	if resp := do(t, mux, postAs(path, "org-admin", `{"activate":true}`)); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown member: %d", resp.StatusCode)
	}
	for err, code := range map[error]string{
		stepup.ErrStepUp: "step_up_required", napp.ErrSlackShared: "slack_channel_shared", napp.ErrSlackEdition: "edition_required",
	} {
		f.err = err
		if resp := do(t, mux, postAs(path, "org-admin", `{"version":"v7"}`)); !strings.Contains(resp.Body, `"error":"`+code+`"`) {
			t.Fatalf("%v: %d %s", err, resp.StatusCode, resp.Body)
		}
	}
}

// TestHR315_TheSlackActivationShowsWhatItConfirms (D265): the Org Admin's
// step-up confirms the channel's direct messages and email domains, so the
// page shows both, or that it sends none.
func TestHR315_TheSlackActivationShowsWhatItConfirms(t *testing.T) {
	h, err := webhttp.New(&fakeBrowser{}, origin, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSlack{state: napp.SlackPending, domains: []string{"example.test", "corp.example"}}
	h.WithSlackChannels(f)
	mux := http.NewServeMux()
	h.Mount(mux)
	get := func() string {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, origin+napp.SlackConfirmPath(ids.NewV7()), nil)
		r.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: "org-admin"})
		resp := do(t, mux, r)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("page: %d %s", resp.StatusCode, resp.Body)
		}
		return resp.Body
	}
	if b := get(); !strings.Contains(b, "<code>example.test</code>, <code>corp.example</code>") || !strings.Contains(b, "Direct messages</dt><dd>On") {
		t.Fatalf("the domains are not shown: %s", b)
	}
	f.domains = nil
	if b := get(); !strings.Contains(b, "Direct messages</dt><dd>Off") || strings.Contains(b, "Allowed email domains") {
		t.Fatalf("no DMs: %s", b)
	}
}
