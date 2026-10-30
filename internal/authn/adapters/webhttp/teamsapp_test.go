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

// fakeTeams records what the page passed.
type fakeTeams struct {
	kind    domain.Kind
	state   string
	stepUps []stepup.StepUp
}

func (f *fakeTeams) GetChannel(_ context.Context, id ids.UUID) (napp.ChannelView, []napp.DeliveryView, error) {
	v := napp.ChannelView{ID: id, Name: "approvals", Kind: f.kind}
	if f.kind == domain.KindTeamsApp {
		v.TeamsApp = &napp.TeamsAppView{ChannelID: "19:approvals@thread.tacv2", TeamID: "19:team@thread.tacv2", State: f.state}
	}
	return v, nil, nil
}

func (f *fakeTeams) ActivateTeamsApp(_ context.Context, id ids.UUID, su stepup.StepUp) (napp.ChannelView, error) {
	f.stepUps = append(f.stepUps, su)
	return napp.ChannelView{ID: id}, nil
}

// TestHR529_ATeamsChannelHasAnActivationPage: the page shows the channel a
// waiting teams_app channel names and offers the security-key activation,
// which passes this session's own step-up; another kind of channel has no
// such page (D277).
func TestHR529_ATeamsChannelHasAnActivationPage(t *testing.T) {
	h, err := webhttp.New(&fakeBrowser{}, origin, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeTeams{kind: domain.KindTeamsApp, state: napp.SlackPending}
	h.WithTeamsChannels(f)
	mux := http.NewServeMux()
	h.Mount(mux)
	path := napp.TeamsConfirmPath(ids.NewV7())
	get := func() (int, string) {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, origin+path, nil)
		r.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: "org-admin"})
		resp := do(t, mux, r)
		return resp.StatusCode, resp.Body
	}
	code, body := get()
	if code != http.StatusOK || !strings.Contains(body, "19:approvals@thread.tacv2") || !strings.Contains(body, `id="activate"`) ||
		!strings.Contains(body, `data-path="`+path+`"`) || strings.Count(body, "<script") != 1 {
		t.Fatalf("page: %d %s", code, body)
	}
	want := stepup.StepUp{Credential: responderKey, At: steppedUpAt}
	if resp := do(t, mux, postAs(path, "org-admin", `{}`)); resp.StatusCode != http.StatusOK || len(f.stepUps) != 1 || f.stepUps[0] != want {
		t.Fatalf("activate: %d %s %+v", resp.StatusCode, resp.Body, f.stepUps)
	}
	f.state = napp.SlackActive
	if code, body := get(); code != http.StatusOK || strings.Contains(body, `id="activate"`) {
		t.Fatalf("an active channel: %d %s", code, body)
	}
	f.kind = domain.KindSlackApp
	if code, _ := get(); code != http.StatusNotFound {
		t.Fatalf("a Slack channel: %d", code)
	}
}
