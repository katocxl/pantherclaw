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
	err     error
	state   string
	stepUps []stepup.StepUp
	tokens  []string
}

func (f *fakeSlack) view(id ids.UUID) napp.ChannelView {
	return napp.ChannelView{ID: id, Name: "approvals", Kind: domain.KindSlackApp, SlackApp: &napp.SlackAppView{
		ChannelID: "C0APPROVAL1", DataLevel: domain.SlackMinimal, State: f.state,
	}}
}

func (f *fakeSlack) GetChannel(_ context.Context, id ids.UUID) (napp.ChannelView, []napp.DeliveryView, error) {
	return f.view(id), nil, nil
}

func (f *fakeSlack) ActivateSlackApp(_ context.Context, id ids.UUID, su stepup.StepUp) (napp.ChannelView, error) {
	f.stepUps = append(f.stepUps, su)
	return f.view(id), f.err
}

func (f *fakeSlack) ReplaceSlackToken(_ context.Context, id ids.UUID, token string, su stepup.StepUp) (napp.ChannelView, error) {
	f.stepUps, f.tokens = append(f.stepUps, su), append(f.tokens, token)
	return f.view(id), f.err
}

// TestHR315_TheSlackChannelPageCarriesTheSessionsStepUp (D22): the page
// shows the channel with one static script; activating and replacing the
// token pass this session's own step-up to the use case, need the CSRF
// proof and a strict body, and map a missing step-up to step_up_required.
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
	r.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: "responder"})
	resp := do(t, mux, r)
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, "C0APPROVAL1") || strings.Count(resp.Body, "<script") != 1 ||
		!strings.Contains(resp.Body, `<script src="/static/slack_channel.js"></script>`) {
		t.Fatalf("page: %d %s", resp.StatusCode, resp.Body)
	}
	want := stepup.StepUp{Credential: responderKey, At: steppedUpAt}
	if resp := do(t, mux, postAs(path, "responder", `{}`)); resp.StatusCode != http.StatusOK || len(f.stepUps) != 1 || f.stepUps[0] != want {
		t.Fatalf("activate: %d %s %+v", resp.StatusCode, resp.Body, f.stepUps)
	}
	if resp := do(t, mux, postAs(path, "responder", `{"bot_token":"xoxb-new"}`)); resp.StatusCode != http.StatusOK || len(f.tokens) != 1 ||
		f.tokens[0] != "xoxb-new" || f.stepUps[1] != want {
		t.Fatalf("replace: %d %s", resp.StatusCode, resp.Body)
	}
	noCSRF := postAs(path, "responder", `{}`)
	noCSRF.Header.Del(webhttp.CSRFHeader)
	if resp := do(t, mux, noCSRF); resp.StatusCode != http.StatusForbidden || len(f.stepUps) != 2 {
		t.Fatalf("without the CSRF header: %d", resp.StatusCode)
	}
	if resp := do(t, mux, postAs(path, "responder", `{"activate":true}`)); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown member: %d", resp.StatusCode)
	}
	for err, code := range map[error]string{
		stepup.ErrStepUp: "step_up_required", napp.ErrSlackShared: "slack_channel_shared", napp.ErrSlackEdition: "edition_required",
	} {
		f.err = err
		if resp := do(t, mux, postAs(path, "responder", `{}`)); !strings.Contains(resp.Body, `"error":"`+code+`"`) {
			t.Fatalf("%v: %d %s", err, resp.StatusCode, resp.Body)
		}
	}
}
