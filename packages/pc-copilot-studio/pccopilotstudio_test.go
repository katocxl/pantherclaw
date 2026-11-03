// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pccopilotstudio_test

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
	"github.com/katocxl/pantherclaw/internal/sim/copilotstudio"
	pccopilotstudio "github.com/katocxl/pantherclaw/packages/pc-copilot-studio"
)

// TestHR635_TheCopilotStudioPackageStartsAScanOnItsSimulator: the package is
// the collector's (an oauth_client connection), says its API shape is
// unconfirmed, reaches no agent, and its connection test and a scan through a
// token minted from its credential read the simulator, metadata only.
// Covers: F925
func TestHR635_TheCopilotStudioPackageStartsAScanOnItsSimulator(t *testing.T) {
	p, err := manifest.Decode(pccopilotstudio.Package)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := domain.CollectorOf(domain.SourceCopilotStudio)
	if p.Name != pccopilotstudio.Name || p.Name != want.Package || want.CredentialKind != credentials.KindOAuthClient ||
		!strings.Contains(p.Summary, "unconfirmed") || !strings.Contains(string(pccopilotstudio.Package), "UNCONFIRMED") {
		t.Fatalf("package %s %q, collector %+v", p.Name, p.Summary, want)
	}
	m, err := mapping.New(p, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if tools := m.Tools(); len(tools) != 0 {
		t.Fatalf("agent-facing tools %v", tools)
	}
	test, ok := p.Definition("copilot_studio.whoami.read")
	if !ok || !test.Test || test.Dispatch.HTTP.Method != http.MethodGet {
		t.Fatalf("connection test %+v", test)
	}

	sim := copilotstudio.New(copilotstudio.Faults{}, slog.New(slog.DiscardHandler))
	srv := httptest.NewServer(sim.Handler())
	t.Cleanup(srv.Close)
	client, err := egress.NewClient(srv.URL, 5*time.Second, 0, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(srv.URL)
	tok, err := broker.MintClientToken(context.Background(), client, []string{u.Host}, credentials.OAuthClient{
		V: 1, TokenURL: srv.URL + "/tenant/oauth2/v2.0/token", ClientID: "app", Scope: "https://org.crm.dynamics.com/.default",
		ClientSecret: []byte("app~secret"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tok.Clear()
	get := func(ctx context.Context, path string) (egress.Response, error) {
		target, _ := url.Parse(srv.URL + path)
		req, err := client.HTTPRequest(ctx, egress.Request{Method: http.MethodGet, URL: target})
		if err != nil {
			return egress.Response{}, err
		}
		if err := tok.Place(req); err != nil {
			return egress.Response{}, err
		}
		return client.Do(req)
	}
	if res, err := get(context.Background(), test.Dispatch.HTTP.Path); err != nil || res.Status != 200 ||
		!strings.Contains(string(res.Body), copilotstudio.OrganizationID) {
		t.Fatalf("connection test %d %v", res.Status, err)
	}
	scan := saascollect.CopilotStudio(context.Background(), get, copilotstudio.OrganizationID)
	if !scan.Reached || !scan.Report.Complete() || len(scan.Report.Findings) != 3 {
		t.Fatalf("scan %+v", scan.Report)
	}
	if s := sim.Stats(); s.ContentAsked != 0 || s.Unselected != 0 {
		t.Fatalf("content asked %+v", s)
	}
}
