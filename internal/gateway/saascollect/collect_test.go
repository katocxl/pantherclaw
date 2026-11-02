// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package saascollect_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/gateway/saascollect"
	"github.com/katocxl/pantherclaw/internal/saasdiscovery/domain"
	"github.com/katocxl/pantherclaw/internal/sim/chatgptenterprise"
	"github.com/katocxl/pantherclaw/internal/sim/copilotstudio"
)

// getter reads srv with a token it fetched from the simulator.
func getter(t *testing.T, srv *httptest.Server, token string) saascollect.Getter {
	t.Helper()
	return func(ctx context.Context, path string) (egress.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
		if err != nil {
			return egress.Response{}, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := srv.Client().Do(req)
		if err != nil {
			return egress.Response{}, err
		}
		defer func() { _ = res.Body.Close() }()
		body, err := io.ReadAll(res.Body)
		return egress.Response{Status: res.StatusCode, Body: body}, err
	}
}

func copilot(t *testing.T, f copilotstudio.Faults) (*copilotstudio.Server, saascollect.Getter) {
	t.Helper()
	sim := copilotstudio.New(f, slog.New(slog.DiscardHandler))
	srv := httptest.NewServer(sim.Handler())
	t.Cleanup(srv.Close)
	res, err := srv.Client().Post(srv.URL+"/tenant/oauth2/v2.0/token", "application/x-www-form-urlencoded", strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	_, rest, _ := strings.Cut(string(body), `"access_token":"`)
	token, _, _ := strings.Cut(rest, `"`)
	return sim, getter(t, srv, token)
}

func chatgpt(t *testing.T, f chatgptenterprise.Faults) (*chatgptenterprise.Server, saascollect.Getter) {
	t.Helper()
	sim := chatgptenterprise.New("", f, slog.New(slog.DiscardHandler))
	srv := httptest.NewServer(sim.Handler())
	t.Cleanup(srv.Close)
	return sim, getter(t, srv, "key")
}

// Covers: F925
func TestHR635_TheCollectorAsksForMetadataColumnsOnly(t *testing.T) {
	sim, get := copilot(t, copilotstudio.Faults{})
	res := saascollect.CopilotStudio(context.Background(), get, copilotstudio.OrganizationID)
	r := res.Report
	if !res.Reached || !r.Complete() || len(r.Findings) != 3 {
		t.Fatalf("report %+v", r)
	}
	if s := sim.Stats(); s.ContentAsked != 0 || s.Unselected != 0 {
		t.Fatalf("asked for content: %+v", s)
	}
	for _, f := range r.Findings {
		for k, v := range f.Attributes {
			if strings.Contains(v, copilotstudio.Instructions) {
				t.Fatalf("%s holds content: %q", k, v)
			}
		}
	}
	first := r.Findings[0].Attributes
	if first["skills"] != "SYNTHETIC look up leave" || first["knowledge_count"] != "1" || first["access_policy"] != "agent_readers" {
		t.Fatalf("attributes across pages: %v", first)
	}
}

// Covers: F925
func TestHR635_NoConversationIsEverRead(t *testing.T) {
	sim, get := chatgpt(t, chatgptenterprise.Faults{})
	res := saascollect.ChatGPTEnterprise(context.Background(), get, chatgptenterprise.WorkspaceID)
	if !res.Reached || !res.Report.Complete() || len(res.Report.Findings) != 3 {
		t.Fatalf("report %+v", res.Report)
	}
	if n := sim.Stats().Conversations; n != 0 {
		t.Fatalf("%d conversation reads", n)
	}
	for _, f := range res.Report.Findings {
		for _, v := range f.Attributes {
			if strings.Contains(v, chatgptenterprise.Instructions) || strings.Contains(v, "/v1/secret") || strings.Contains(v, "token=") {
				t.Fatalf("kept %q", v)
			}
		}
	}
}

// A next link that asks for a content column, or leaves the list, chooses
// nothing: the collector rebuilds it or stops.
func TestHR635_ANextLinkNeverChoosesWhatIsRead(t *testing.T) {
	var asked []string
	get := func(_ context.Context, path string) (egress.Response, error) {
		asked = append(asked, path)
		switch {
		case strings.Contains(path, "WhoAmI"):
			return egress.Response{Status: 200, Body: []byte(`{"OrganizationId":"t1"}`)}, nil
		case strings.Contains(path, "skiptoken"):
			return egress.Response{Status: 200, Body: []byte(`{"value":[]}`)}, nil
		case strings.Contains(path, "/bots"):
			return egress.Response{Status: 200, Body: []byte(`{"value":[],"@odata.nextLink":"https://other.example/api/data/v9.2/bots?$select=configuration&$skiptoken=2"}`)}, nil
		}
		return egress.Response{Status: 200, Body: []byte(`{"value":[],"@odata.nextLink":"https://x.example/api/data/v9.2/conversationtranscripts?$skiptoken=2"}`)}, nil
	}
	res := saascollect.CopilotStudio(context.Background(), get, "t1")
	for _, p := range asked {
		if strings.Contains(p, "configuration") || strings.Contains(p, "conversationtranscripts") || strings.Contains(p, "other.example") {
			t.Fatalf("followed %q", p)
		}
	}
	if res.Report.NotScanned[domain.ReadBotComponents] != "a next-page link left the list" {
		t.Fatalf("report %+v", res.Report.NotScanned)
	}
	if _, read := res.Report.NotScanned[domain.ReadBots]; read {
		t.Fatalf("bots: %+v", res.Report.NotScanned)
	}
}

// Covers: F926
func TestHR637_WhatACollectorCouldNotReadIsNotScanned(t *testing.T) {
	bg := context.Background()
	_, get := copilot(t, copilotstudio.Faults{DenyComponents: true})
	res := saascollect.CopilotStudio(bg, get, copilotstudio.OrganizationID)
	if !res.Reached || res.Report.Complete() || !strings.Contains(res.Report.NotScanned[domain.ReadBotComponents], "403") || len(res.Report.Findings) != 3 {
		t.Fatalf("components denied: %+v", res.Report)
	}
	if _, ok := res.Report.Findings[0].Attributes["skill_count"]; ok {
		t.Fatal("no read of components must not say an agent has no skills")
	}
	res.Report.MarkUnread()
	if res.Report.Findings[0].Attributes[domain.AttrUnread] != domain.ReadBotComponents {
		t.Fatalf("findings: %+v", res.Report.Findings[0])
	}

	_, get = copilot(t, copilotstudio.Faults{DenyBots: true, DenyComponents: true})
	res = saascollect.CopilotStudio(bg, get, copilotstudio.OrganizationID)
	if len(res.Report.Findings) != 0 || res.Report.Complete() || len(res.Report.Scanned) != 0 {
		t.Fatalf("nothing readable reads as none found: %+v", res.Report)
	}

	_, get = copilot(t, copilotstudio.Faults{OtherOrganization: true})
	res = saascollect.CopilotStudio(bg, get, copilotstudio.OrganizationID)
	if res.Reached || res.Report.NotScanned[domain.NoteTenant] == "" {
		t.Fatalf("another organization: %+v", res.Report)
	}

	_, get = chatgpt(t, chatgptenterprise.Faults{SecondPageFails: true})
	res = saascollect.ChatGPTEnterprise(bg, get, chatgptenterprise.WorkspaceID)
	if !res.Reached || len(res.Report.Findings) != 2 || res.Report.NotScanned[domain.ReadGPTs] == "" {
		t.Fatalf("second page failed: %+v", res.Report)
	}

	_, get = chatgpt(t, chatgptenterprise.Faults{Deny: true})
	res = saascollect.ChatGPTEnterprise(bg, get, chatgptenterprise.WorkspaceID)
	if res.Reached || len(res.Report.Findings) != 0 {
		t.Fatalf("denied: %+v", res.Report)
	}

	_, get = chatgpt(t, chatgptenterprise.Faults{UnknownTools: true})
	res = saascollect.ChatGPTEnterprise(bg, get, chatgptenterprise.WorkspaceID)
	if res.Report.NotScanned[domain.ReadGPTConfigs] == "" || res.Report.Findings[0].Attributes["tools_incomplete"] != "true" {
		t.Fatalf("unknown tools: %+v", res.Report)
	}

	ctx, cancel := context.WithCancel(bg)
	cancel()
	_, get = chatgpt(t, chatgptenterprise.Faults{})
	res = saascollect.ChatGPTEnterprise(ctx, get, chatgptenterprise.WorkspaceID)
	if res.Reached || !strings.Contains(res.Report.NotScanned[domain.NoteTenant], "time limit") {
		t.Fatalf("out of time: %+v", res.Report)
	}
}

// Covers: F925
func TestHR638_AHostileNameOnlyEverReadsAsText(t *testing.T) {
	_, get := copilot(t, copilotstudio.Faults{})
	res := saascollect.CopilotStudio(context.Background(), get, copilotstudio.OrganizationID)
	if got := res.Report.Findings[1].Attributes["name"]; got != copilotstudio.HostileName {
		t.Fatalf("name %q", got)
	}
	if len(res.Report.Findings[1].Attributes) > 16 {
		t.Fatalf("attributes %v", res.Report.Findings[1].Attributes)
	}
}
