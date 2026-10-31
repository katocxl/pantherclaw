// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	exapp "github.com/katocxl/pantherclaw/internal/exposure/app"
	"github.com/katocxl/pantherclaw/internal/exposure/exposuretest"
	"github.com/katocxl/pantherclaw/internal/exposure/recompute"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	poapp "github.com/katocxl/pantherclaw/internal/posture/app"
	"github.com/katocxl/pantherclaw/internal/postureview/adapters/sources"
	pvapp "github.com/katocxl/pantherclaw/internal/postureview/app"
	pvdomain "github.com/katocxl/pantherclaw/internal/postureview/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestE2E_M24_PostureAndSupplyChain is M24's exit journey (G0 M24 D207). The
// stack's server answers the ranked queue and its trends; on the stack's
// database a finding shows with its fix, and a rescan after the fix clears
// it, because a finding clears when its source clears.
func TestE2E_M24_PostureAndSupplyChain(t *testing.T) {
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", billing: true, people: &p})
	activePlan(t, s.pool, s.org)
	t.Run("the queue answers through the server", func(t *testing.T) { s.m24Server(t, p) })
	o := exposuretest.NewIn(t, s.db, s.pool)
	t.Run("a finding, its fix, and a rescan clearing it", func(t *testing.T) { m24FixClears(t, o) })
}

// m24Server: each procedure refuses an anonymous caller, where an unmounted
// one would answer 404, and a signed-in admin reads each one. A day with no
// rollup is NOT_COLLECTED, never zero.
func (s *stack) m24Server(t *testing.T, p idp) {
	for _, path := range []string{
		"/pantherclaw.v1.PostureQueueService/ListRankedFindings",
		"/pantherclaw.v1.PostureQueueService/GetPostureTrends",
	} {
		r, err := http.NewRequest(http.MethodPost, s.apiURL+path, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: %d", path, resp.StatusCode)
		}
	}

	org := s.org.String()
	var out, errb bytes.Buffer
	if code := runServerCmd(&out, &errb, "org", "admin-invite", "--config", s.serverCfg, "--org", org); code != 0 {
		t.Fatalf("org admin-invite: %d %s", code, errb.String())
	}
	people := &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}
	admin := people.user(t, "m24-admin", "m24-admin@example.test")
	admin.login(t, org, pciToken.FindStringSubmatch(out.String())[1])
	rc := connect.NewClient(connecthttp.NewTransport(&http.Client{
		Timeout: 30 * time.Second, Transport: keyBearer{bearerOf(t, admin)},
	}, s.apiURL))
	client := pantherclawv1connect.NewPostureQueueServiceClient(rc)
	ctx := context.Background()

	l, err := client.ListRankedFindings(ctx, &pantherclawv1.ListRankedFindingsRequest{})
	if err != nil {
		t.Fatalf("ranked findings: %v", err)
	}
	if l.GetRestricted() || len(l.GetSources()) == 0 || l.GetAsOf() == nil {
		t.Errorf("an org admin's read: %+v", l)
	}
	tr, err := client.GetPostureTrends(ctx, &pantherclawv1.GetPostureTrendsRequest{Days: 3})
	if err != nil {
		t.Fatalf("trends: %v", err)
	}
	if len(tr.GetDays()) != 3 {
		t.Fatalf("days: %+v", tr)
	}
	if d := tr.GetDays()[0]; d.GetState() != pantherclawv1.PostureDayState_POSTURE_DAY_STATE_NOT_COLLECTED || len(d.GetCounts()) != 0 {
		t.Errorf("a day with no rollup: %+v", d)
	}
}

// m24FixClears: on Team, a recomputation finds an unbounded grant and the
// queue shows it with a fix naming that grant. Revoking the grant is the fix:
// the next recomputation remediates the finding and the queue no longer lists
// it. Nothing in the queue moved it.
func m24FixClears(t *testing.T, o *exposuretest.Org) {
	ctx := context.Background()
	o.Claim(t, o.Agent)
	grant := o.Grant(t, o.Agent, 0, "", "payments.*")
	ents := m21Edition(billing.Team)
	scan := &recompute.Service{Pool: o.P, Ents: ents, Failures: &failures.Sink{}}
	if res, err := scan.Run(ctx, o.Org); err != nil || !res.Recomputed {
		t.Fatalf("first scan: %+v %v", res, err)
	}

	queue := &pvapp.Service{Pool: o.P, Ents: ents, Sources: sources.Builtin(sources.Reader{Pool: o.P, Ents: ents})}
	viewer := m21As(o, td.RoleResponder, m21Org(o))
	root := "grant:" + grant.String()
	find := func() (pvdomain.RankedFinding, bool) {
		t.Helper()
		l, err := queue.List(viewer, pvdomain.Filter{Source: pvdomain.SourcePosture}, 200, "")
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range l.Findings {
			if f.RootCause == root {
				return f, true
			}
		}
		return pvdomain.RankedFinding{}, false
	}
	f, ok := find()
	if !ok {
		t.Fatal("the grant's finding is not in the queue")
	}
	if f.Fix.Kind != pvdomain.FixReviewGrant || f.Fix.TargetID != root || f.Fix.Label == "" {
		t.Errorf("fix: %+v", f.Fix)
	}
	if len(f.OWASP) == 0 || len(f.RankReasons) == 0 {
		t.Errorf("finding: %+v", f)
	}

	o.Revoke(t, grant)
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		head, err := (feed.Reader{}).Head(ctx, tx)
		if err != nil {
			return err
		}
		rec, err := exapp.Recompute(ctx, tx, "manual", head)
		if err != nil {
			return err
		}
		_, err = poapp.ReconcileWith(ctx, tx, rec, nil)
		return err
	})
	if f, ok := find(); ok {
		t.Errorf("the rescan did not clear the finding: %+v", f)
	}
}
