// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

type recordSuggestions struct {
	pantherclawv1connect.UnimplementedSuggestionServiceHandler
	list    *pantherclawv1.ListSuggestionsRequest
	get     *pantherclawv1.GetSuggestionRequest
	dismiss *pantherclawv1.DismissSuggestionRequest
	draft   *pantherclawv1.DraftFromSuggestionRequest
}

func (r *recordSuggestions) ListSuggestions(_ context.Context, req *pantherclawv1.ListSuggestionsRequest) (
	*pantherclawv1.ListSuggestionsResponse, error,
) {
	r.list = req
	return &pantherclawv1.ListSuggestionsResponse{}, nil
}

func (r *recordSuggestions) GetSuggestion(_ context.Context, req *pantherclawv1.GetSuggestionRequest) (
	*pantherclawv1.GetSuggestionResponse, error,
) {
	r.get = req
	return &pantherclawv1.GetSuggestionResponse{Suggestion: &pantherclawv1.Suggestion{
		Id: req.GetId(), ExpectedEffect: &pantherclawv1.SuggestionEffect{NotCollected: []string{"RETENTION_SHORTER_THAN_WINDOW"}},
	}}, nil
}

func (r *recordSuggestions) DismissSuggestion(_ context.Context, req *pantherclawv1.DismissSuggestionRequest) (
	*pantherclawv1.DismissSuggestionResponse, error,
) {
	r.dismiss = req
	return &pantherclawv1.DismissSuggestionResponse{}, nil
}

func (r *recordSuggestions) DraftFromSuggestion(_ context.Context, req *pantherclawv1.DraftFromSuggestionRequest) (
	*pantherclawv1.DraftFromSuggestionResponse, error,
) {
	r.draft = req
	return &pantherclawv1.DraftFromSuggestionResponse{PolicyVersionId: "v1", PolicyVersion: 3}, nil
}

// TestSuggestionsCommands: pclaw suggestions list, show, dismiss and draft
// send what was asked; a bad state or kind, or a dismissal without a
// reason of 10 characters, is never sent; draft says the draft is not
// published; show never prints a count that was not collected.
//
// Covers: F185
func TestSuggestionsCommands(t *testing.T) {
	rx := &recordSuggestions{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterSuggestionServiceHandler(cs, rx)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
	const id = "0192aaaa-bbbb-7ccc-8ddd-000000000001"

	for name, args := range map[string][]string{
		"no verb":      {"suggestions"},
		"unknown verb": {"suggestions", "publish", id},
		"show no id":   {"suggestions", "show"},
		"bad state":    {"suggestions", "list", "--state", "active"},
		"bad kind":     {"suggestions", "list", "--kind", "excess"},
		"no reason":    {"suggestions", "dismiss", id},
		"short reason": {"suggestions", "dismiss", id, "--reason", "no"},
		"extra args":   {"suggestions", "draft", id, "more"},
	} {
		if code, _, _ := run(t, env, args...); code == 0 {
			t.Errorf("%s: exit 0", name)
		}
	}
	if rx.list != nil || rx.dismiss != nil || rx.draft != nil {
		t.Fatalf("a refused command was sent: %+v %+v %+v", rx.list, rx.dismiss, rx.draft)
	}

	if code, _, errs := run(t, env, "suggestions", "list", "--state", "open", "--state", "drafted", "--kind", "unused_authority"); code != 0 ||
		len(rx.list.GetStates()) != 2 || rx.list.GetStates()[0] != pantherclawv1.SuggestionState_SUGGESTION_STATE_OPEN ||
		rx.list.GetKind() != pantherclawv1.SuggestionKind_SUGGESTION_KIND_UNUSED_AUTHORITY {
		t.Fatalf("list: %d %+v %s", code, rx.list, errs)
	}
	code, out, errs := run(t, env, "suggestions", "show", id)
	if code != 0 || rx.get.GetId() != id || strings.Contains(out, "matchingActions") || !strings.Contains(out, "RETENTION_SHORTER_THAN_WINDOW") {
		t.Fatalf("show: %d %s %s", code, out, errs)
	}
	if code, _, errs := run(t, env, "suggestions", "dismiss", id, "--reason", "Owner confirmed the grant is needed."); code != 0 ||
		rx.dismiss.GetId() != id || rx.dismiss.GetReason() != "Owner confirmed the grant is needed." {
		t.Fatalf("dismiss: %d %+v %s", code, rx.dismiss, errs)
	}
	code, _, errs = run(t, env, "suggestions", "draft", id)
	if code != 0 || rx.draft.GetId() != id || !strings.Contains(errs, "not published") {
		t.Fatalf("draft: %d %+v %s", code, rx.draft, errs)
	}
}
