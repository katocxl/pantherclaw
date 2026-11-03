// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pcchatgptenterprise_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/gateway/saascollect"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/saasdiscovery/domain"
	"github.com/katocxl/pantherclaw/internal/sim/chatgptenterprise"
	pcchatgptenterprise "github.com/katocxl/pantherclaw/packages/pc-chatgpt-enterprise"
)

// TestHR635_TheChatGPTEnterprisePackageStartsAScanOnItsSimulator: the
// package is the collector's (a static connection), says its API shape is
// unconfirmed, reaches no agent, and its connection test and a scan with its
// key placed read the simulator, never a conversation.
// Covers: F925
func TestHR635_TheChatGPTEnterprisePackageStartsAScanOnItsSimulator(t *testing.T) {
	p, err := manifest.Decode(pcchatgptenterprise.Package)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := domain.CollectorOf(domain.SourceChatGPTEnterprise)
	if p.Name != pcchatgptenterprise.Name || p.Name != want.Package || want.CredentialKind != credentials.KindStatic ||
		!strings.Contains(p.Summary, "unconfirmed") || !strings.Contains(string(pcchatgptenterprise.Package), "UNCONFIRMED") {
		t.Fatalf("package %s %q, collector %+v", p.Name, p.Summary, want)
	}
	m, err := mapping.New(p, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if tools := m.Tools(); len(tools) != 0 {
		t.Fatalf("agent-facing tools %v", tools)
	}
	test, ok := p.Definition("chatgpt_enterprise.workspaces.read")
	if !ok || !test.Test || test.Dispatch.HTTP.Method != http.MethodGet {
		t.Fatalf("connection test %+v", test)
	}

	const key = "sk-compliance-synthetic"
	sim := chatgptenterprise.New(key, chatgptenterprise.Faults{}, slog.New(slog.DiscardHandler))
	srv := httptest.NewServer(sim.Handler())
	t.Cleanup(srv.Close)
	client, err := egress.NewClient(srv.URL, 5*time.Second, 0, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(srv.URL)
	get := func(ctx context.Context, path string) (egress.Response, error) {
		target, _ := url.Parse(srv.URL + path)
		req, err := client.HTTPRequest(ctx, egress.Request{Method: http.MethodGet, URL: target})
		if err != nil {
			return egress.Response{}, err
		}
		if err := broker.Place(req, []string{u.Host}, "Authorization", "Bearer", []byte(key)); err != nil {
			return egress.Response{}, err
		}
		return client.Do(req)
	}
	if res, err := get(context.Background(), test.Dispatch.HTTP.Path); err != nil || res.Status != 200 ||
		!strings.Contains(string(res.Body), chatgptenterprise.WorkspaceID) {
		t.Fatalf("connection test %d %v", res.Status, err)
	}
	scan := saascollect.ChatGPTEnterprise(context.Background(), get, chatgptenterprise.WorkspaceID)
	if !scan.Reached || !scan.Report.Complete() || len(scan.Report.Findings) != 3 {
		t.Fatalf("scan %+v", scan.Report)
	}
	if n := sim.Stats().Conversations; n != 0 {
		t.Fatalf("%d conversation reads", n)
	}
}
