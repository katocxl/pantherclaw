// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sandbox/report"
	"github.com/katocxl/pantherclaw/internal/sandboxes/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// passing is a sandbox run in which every probe is blocked and both edge
// controls hold.
func passing() []report.Result {
	var out []report.Result
	for _, n := range []string{
		"dns_external", "dns_docker_resolver", "ipv6", "icmp", "direct_https", "metadata", "host_gateway", "docker_socket",
		"direct_ssh", "ssh_push", "pat_push",
	} {
		out = append(out, report.Result{Name: n, Role: report.RoleProbe, Expect: report.Blocked, Observed: report.Blocked})
	}
	return append(out,
		report.Result{Name: "edge_unmapped_refused", Role: report.RoleNegative, Expect: report.Blocked, Observed: report.Blocked},
		report.Result{Name: "edge_mediated", Role: report.RolePositive, Expect: report.Reachable, Observed: report.Reachable},
	)
}

// probeRun submits a sandbox and a control report with results and then
// the canary's report with hits for markers; it returns the canary's
// outcome.
func (w *world) probeRun(t *testing.T, s app.Started, n app.Nonces, sandbox []report.Result, markers ...string) (app.CanaryResult, error) {
	t.Helper()
	ctx := w.as(td.RoleAgentOwner)
	if _, err := w.svc.SubmitProbeReport(ctx, s.Session.ID, w.signed(t, s, report.KindSandbox, n.Sandbox, func(r *report.Report) { r.Results = sandbox }), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.SubmitProbeReport(ctx, s.Session.ID, w.signed(t, s, report.KindControl, n.Control, func(r *report.Report) {
		r.Results = []report.Result{{Name: "canary_control", Role: report.RolePositive, Expect: report.Reachable, Observed: report.Reachable}}
	}), nil); err != nil {
		t.Fatal(err)
	}
	return w.svc.SubmitCanaryReport(ctx, s.Session.ID, w.signed(t, s, report.KindCanary, n.Canary, func(r *report.Report) {
		r.Results = []report.Result{}
		for _, m := range markers {
			r.Canary.Hits = append(r.Canary.Hits, report.Hit{Proto: "tcp", Port: 18443, Marker: m, At: time.Now().UTC()})
		}
	}))
}

func TestHR121_APassingProbeRunClosesEveryMappedConnection(t *testing.T) {
	w := newWorld(t)
	second := ids.NewV7()
	w.connection(t, second, "github-uploads", w.gateway, []string{"uploads.github.com"})
	in := w.input()
	in.Connections = append(in.Connections, second)
	s, err := w.svc.StartSession(w.as(td.RoleAgentOwner), in)
	if err != nil {
		t.Fatal(err)
	}
	w.admit(t, s)
	res, err := w.probeRun(t, s, s.Nonces, passing(), report.Marker(s.Nonces.Control))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Closures) != 2 || res.Next.Sandbox == "" || res.Next.Sandbox == s.Nonces.Sandbox {
		t.Fatalf("result %+v", res)
	}
	for _, c := range res.Closures {
		if !c.Passed || len(c.Failed) != 0 || time.Until(c.ExpiresAt) < 23*time.Hour {
			t.Errorf("closure %+v", c)
		}
	}
	if n := w.count(t, "SELECT count(*) FROM pc.coverage_closures WHERE sandbox_session_id = $1 AND result = 'PASSED'", s.Session.ID); n != 2 {
		t.Fatalf("%d passed closures stored", n)
	}
	// A re-probe in the same session uses the next nonces.
	if _, err := w.probeRun(t, s, res.Next, passing(), report.Marker(res.Next.Control)); err != nil {
		t.Fatalf("re-probe: %v", err)
	}
}

// TestHR215_AFailedControlOrALeakGivesAFailedClosureThatDropsEnforced: a
// reached negative control, a leak to the canary or a control run the
// canary never saw makes the closure FAILED, and a closure_failed
// invalidation drops any ENFORCED state at once.
func TestHR215_AFailedControlOrALeakGivesAFailedClosureThatDropsEnforced(t *testing.T) {
	for name, tc := range map[string]struct {
		sandbox func([]report.Result) []report.Result
		markers func(n app.Nonces) []string
		failed  string
	}{
		"the edge let an unmapped host through": {
			sandbox: func(r []report.Result) []report.Result { r[len(r)-2].Observed = report.Reachable; return r },
			markers: func(n app.Nonces) []string { return []string{report.Marker(n.Control)} },
			failed:  "edge_unmapped_refused",
		},
		"the probe reached the canary": {
			sandbox: func(r []report.Result) []report.Result { return r },
			markers: func(n app.Nonces) []string { return []string{report.Marker(n.Control), report.Marker(n.Sandbox)} },
			failed:  "external_canary",
		},
		"the canary never saw the control run": {
			sandbox: func(r []report.Result) []report.Result { return r },
			markers: func(app.Nonces) []string { return nil },
			failed:  "canary_control",
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			s, err := w.svc.StartSession(w.as(td.RoleAgentOwner), w.input())
			if err != nil {
				t.Fatal(err)
			}
			w.admit(t, s)
			res, err := w.probeRun(t, s, s.Nonces, tc.sandbox(passing()), tc.markers(s.Nonces)...)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Closures) != 1 || res.Closures[0].Passed || !contains(res.Closures[0].Failed, tc.failed) {
				t.Fatalf("closures %+v", res.Closures)
			}
			if n := w.count(t, "SELECT count(*) FROM pc.coverage_invalidations WHERE kind = 'closure_failed' AND connection_id = $1", w.gh); n != 1 {
				t.Fatalf("%d closure_failed invalidations", n)
			}
		})
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func TestHR215_ACanaryReportNeedsItsProbeRun(t *testing.T) {
	w := newWorld(t)
	ctx := w.as(td.RoleAgentOwner)
	s, err := w.svc.StartSession(ctx, w.input())
	if err != nil {
		t.Fatal(err)
	}
	w.admit(t, s)
	if _, err := w.svc.SubmitCanaryReport(ctx, s.Session.ID, w.signed(t, s, report.KindCanary, s.Nonces.Canary, nil)); !errors.Is(err, app.ErrReport) {
		t.Fatalf("canary before the probe run: %v", err)
	}
	if _, err := w.svc.SubmitCanaryReport(ctx, s.Session.ID, w.signed(t, s, report.KindSandbox, s.Nonces.Sandbox, nil)); !errors.Is(err, app.ErrReport) {
		t.Fatalf("a sandbox report as the canary's: %v", err)
	}
}

// TestHR211_ANewImageInvalidatesTheLastClosure: a session that runs other
// images than the agent's last closure invalidates its scope at once.
func TestHR211_ANewImageInvalidatesTheLastClosure(t *testing.T) {
	w := newWorld(t)
	ctx := w.as(td.RoleAgentOwner)
	s, err := w.svc.StartSession(ctx, w.input())
	if err != nil {
		t.Fatal(err)
	}
	w.admit(t, s)
	if _, err := w.probeRun(t, s, s.Nonces, passing(), report.Marker(s.Nonces.Control)); err != nil {
		t.Fatal(err)
	}
	in := w.input()
	in.EdgeImage = otherDigest
	s2, err := w.svc.StartSession(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.coverage_invalidations WHERE kind = 'sandbox_image' AND connection_id = $1", w.gh); n != 1 {
		t.Fatalf("%d sandbox_image invalidations", n)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.coverage_invalidations WHERE kind = 'sandbox_config'"); n != 0 {
		t.Fatalf("%d sandbox_config invalidations for the same configuration", n)
	}
	// The new session's own run closes again: what its opening invalidated
	// and its own sandbox instance come before it or inside it.
	w.admit(t, s2)
	res, err := w.probeRun(t, s2, s2.Nonces, passing(), report.Marker(s2.Nonces.Control))
	if err != nil || len(res.Closures) != 1 || !res.Closures[0].Passed {
		t.Fatalf("the new session's run: %+v %v", res, err)
	}
}

// TestHR211_AConnectionChangedDuringTheSessionMakesItsRunStale: a change
// that invalidates closures after the session opened (here its agent
// hosts) refuses the run's closures; a new session probes again.
func TestHR211_AConnectionChangedDuringTheSessionMakesItsRunStale(t *testing.T) {
	w := newWorld(t)
	s, err := w.svc.StartSession(w.as(td.RoleAgentOwner), w.input())
	if err != nil {
		t.Fatal(err)
	}
	w.admit(t, s)
	w.exec(t, "UPDATE pc.connections SET agent_hosts = ARRAY['api.github.com', 'uploads.github.com'] WHERE id = $1", w.gh)
	if _, err := w.probeRun(t, s, s.Nonces, passing(), report.Marker(s.Nonces.Control)); !errors.Is(err, app.ErrStale) {
		t.Fatalf("a run after the connection changed: %v", err)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.coverage_closures WHERE sandbox_session_id = $1", s.Session.ID); n != 0 {
		t.Fatalf("%d closures stored", n)
	}
}

// TestEndingASessionRevokesItsInstance: the instance acts only inside its
// session: ended, it is revoked, the containment epoch moves, and it gets
// no workload token.
func TestEndingASessionRevokesItsInstance(t *testing.T) {
	w := newWorld(t)
	ctx := w.as(td.RoleAgentOwner)
	s, err := w.svc.StartSession(ctx, w.input())
	if err != nil {
		t.Fatal(err)
	}
	inst := w.admit(t, s)
	if _, err := w.svc.SubmitProbeReport(ctx, s.Session.ID, w.signed(t, s, report.KindSandbox, s.Nonces.Sandbox, nil), nil); err != nil {
		t.Fatal(err)
	}
	epoch := w.count(t, "SELECT coalesce((SELECT epoch FROM pc.org_containment), 0)")
	ended, err := w.svc.EndSession(ctx, s.Session.ID)
	if err != nil || ended.State != "ENDED" {
		t.Fatalf("end: %+v, %v", ended, err)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.agent_instances WHERE id = $1 AND state = 'REVOKED'", inst); n != 1 {
		t.Fatal("the instance was not revoked")
	}
	if got := w.count(t, "SELECT coalesce((SELECT epoch FROM pc.org_containment), 0)"); got <= epoch {
		t.Fatalf("epoch %d, was %d", got, epoch)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.sandbox_sessions WHERE enrollment_token_id = $1 AND state = 'OPEN'", s.Session.EnrollmentTokenID); n != 0 {
		t.Fatal("the session is still open for its token")
	}
	if _, err := w.svc.EndSession(ctx, s.Session.ID); err != nil {
		t.Fatalf("ending twice: %v", err)
	}
}
