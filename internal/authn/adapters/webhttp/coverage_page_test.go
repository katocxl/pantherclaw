// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	covapp "github.com/katocxl/pantherclaw/internal/coverage/app"
	covdomain "github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// fakeCoverage serves canned records to callers holding coverage.read.
type fakeCoverage struct{ rec covapp.Record }

func (f *fakeCoverage) allowed(ctx context.Context) error {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return err
	}
	if !c.CanAnywhere(td.PermCoverageRead) {
		return td.ErrPermissionDenied(td.PermCoverageRead)
	}
	return nil
}

func (f *fakeCoverage) ListCoverage(ctx context.Context, _ covapp.Filter, _ int32, _ string) ([]covapp.Record, string, error) {
	return []covapp.Record{f.rec}, "", f.allowed(ctx)
}

func (f *fakeCoverage) GetCoverage(ctx context.Context, sc covdomain.Scope) (covapp.Record, error) {
	if sc != f.rec.Scope {
		return covapp.Record{}, covapp.ErrNotFound
	}
	return f.rec, f.allowed(ctx)
}

func (f *fakeCoverage) ListSnapshots(ctx context.Context, sc covdomain.Scope, _ int32, _ string) ([]covapp.SnapshotRecord, string, error) {
	at := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	snap := func(state, gitSSH string, computed time.Time) covapp.SnapshotRecord {
		return covapp.SnapshotRecord{
			PcCoverageSnapshot: dbq.PcCoverageSnapshot{ID: ids.NewV7(), State: state, ComputedAt: computed},
			Body: covapp.Snapshot{Routes: []covapp.SnapshotRoute{
				{Kind: "channel", Channel: "http", Status: "mediated"}, {Kind: "git_ssh", Status: gitSSH},
			}},
		}
	}
	return []covapp.SnapshotRecord{snap("PARTIAL", "not_observed", at), snap("ENFORCED", "closed", at.Add(-time.Hour))}, "", f.allowed(ctx)
}

func coverageRecord() covapp.Record {
	at := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	kind, user, closure := "browser", ids.NewV7(), ids.NewV7()
	return covapp.Record{
		Scope:    covdomain.Scope{Agent: ids.NewV7(), Connection: ids.NewV7(), Operation: "github.pulls.merge"},
		State:    covdomain.Partial,
		Computed: covdomain.Enforced,
		Reasons:  []string{"invalidated:credential", "route_not_closed:git_ssh"},
		Snapshot: &dbq.PcCoverageSnapshot{ID: ids.NewV7(), ComputedAt: at},
		Body: covapp.Snapshot{Routes: []covapp.SnapshotRoute{
			{Kind: "channel", Channel: "http", Status: "mediated", Closure: &closure},
			{Kind: "git_ssh", Status: "not_observed"},
			{Kind: "direct_api", Locator: `api.example.com"><script>x</script>`, Status: "possible"},
		}},
		LastValid: &dbq.PcCoverageSnapshot{ID: ids.NewV7(), ComputedAt: at.Add(-time.Hour)},
		Lapse:     "invalidated:credential",
		Exclusions: []dbq.PcCoverageExclusion{{
			ID: ids.NewV7(), RouteKind: &kind, CreatedBy: user, ExpiresAt: at.Add(24 * time.Hour),
			Reason: `<img src=x onerror=alert(1)> no browser`,
		}},
	}
}

func coverageGet(t *testing.T, mux http.Handler, path, cookie string) result {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, origin+path, nil)
	r.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: cookie})
	return do(t, mux, r)
}

// TestCoveragePagesShowOnlyWhatTheEvidenceSays: the list and the card need
// coverage.read; the card says what the record reads now and why, lists
// every route (a route no source showed as "not observed"), keeps the last
// valid record, escapes untrusted text, and runs no script under the
// pages' strict CSP. It compares the last two snapshots.
func TestCoveragePagesShowOnlyWhatTheEvidenceSays(t *testing.T) {
	h, err := webhttp.New(&fakeBrowser{}, origin, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	fc := &fakeCoverage{rec: coverageRecord()}
	f, _ := covdomain.NewFreshness(0, 0)
	h.WithCoverage(fc, f)
	mux := http.NewServeMux()
	h.Mount(mux)
	if resp := coverageGet(t, mux, webhttp.CoveragePath, "good"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("no coverage.read: %d", resp.StatusCode)
	}
	sc := fc.rec.Scope
	card := webhttp.CoveragePath + "/" + sc.Agent.String() + "/" + sc.Connection.String() + "/" + sc.Operation
	list := coverageGet(t, mux, webhttp.CoveragePath, "reader")
	if list.StatusCode != http.StatusOK || !strings.Contains(list.Body, `href="`+card+`"`) || !strings.Contains(list.Body, "(computed ENFORCED)") {
		t.Fatalf("list: %d %s", list.StatusCode, list.Body)
	}
	resp := coverageGet(t, mux, card, "reader")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("card: %d %s", resp.StatusCode, resp.Body)
	}
	for _, want := range []string{
		"<strong>PARTIAL</strong>: its snapshot computed ENFORCED, which no longer holds",
		"A change since the evidence invalidated it (credential).", "The git ssh route is not proven closed.",
		"not observed", "Last valid record", fc.rec.LastValid.ID.String(), "the browser route",
		"Any of these drops it to at most PARTIAL at once: connection,",
		"Since the previous snapshot", "<td>ENFORCED</td><td>PARTIAL</td>", "<td>closed</td><td>not observed</td>",
		"closure " + closureOf(fc.rec),
	} {
		if !strings.Contains(resp.Body, want) {
			t.Errorf("the card lacks %q", want)
		}
	}
	for _, page := range []result{list, resp} {
		if strings.Contains(page.Body, "<script") || strings.Contains(page.Body, "<img src=x") {
			t.Fatalf("a script or unescaped text on a coverage page:\n%s", page.Body)
		}
		if page.Header.Get("Content-Security-Policy") != webhttp.PageCSP {
			t.Fatalf("CSP %q", page.Header.Get("Content-Security-Policy"))
		}
	}
	for _, bad := range []string{"/not-an-id/x/y", "/" + ids.NewV7().String() + "/" + sc.Connection.String() + "/" + sc.Operation} {
		if resp := coverageGet(t, mux, webhttp.CoveragePath+bad, "reader"); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d", bad, resp.StatusCode)
		}
	}
}

func closureOf(r covapp.Record) string { return r.Body.Routes[0].Closure.String() }
