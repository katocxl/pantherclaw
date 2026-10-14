// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/evidence/packbuild"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"

	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// The M12 exit (G0 M12, D18) through `pclaw redteam run`, the way a person
// runs the range: a range agent on simulated connections, the live driver,
// every result recorded with the server. `task range` runs the same scenarios
// through the harness driver, which also covers what a live run cannot (person
// steps, simulator changes, the sandbox).

// rangeStack is a stack set up as a range's through the product, with a person
// who runs it.
type rangeStack struct {
	d                               *rangeDriver
	agent, instance, keyFile, grant string
	run0                            string // the range instance's run on the range grant
}

// The team's real grant for its real agent: reviewed merges, and writes only to
// its own repository (what RT-009 tests). The range grant is shaped like it.
const (
	exitBounds = `{"operations": ["github.contents.read", "github.contents.write", "github.branch.create", "github.pull.read",
	  "github.pull.create", "github.pull.merge", "github.deployment.trigger", "payments.refund.create", "payments.refund.get"],
	  "targets": {"github.branch": {"prefixes": ["acme/payments@"]}, "github.repository": {"prefixes": ["acme/payments"]},
	  "github.pull_request": {"prefixes": ["acme/payments#"]}, "payments.charge": {"prefixes": ["ch_"]},
	  "payments.refund": {"prefixes": ["re_"]}}}`
	exitRequirements = `[
	  {"operations": ["github.pull.merge"], "reason": "MERGES_NEED_AN_INDEPENDENT_REVIEW",
	   "approval": {"role": "code_reviewer", "count": 1, "independent": true}},
	  {"operations": ["github.deployment.trigger"], "reason": "DEPLOYMENTS_NEED_A_RELEASE",
	   "approval": {"role": "release_approver", "count": 1}}]`
)

func startRangeStack(t *testing.T) *rangeStack {
	t.Helper()
	d := newRangeDriver(t)
	if _, err := d.Setup(context.Background(), domain.Scenario{ID: "RT-000", Requires: []string{"github", "payments", "person"}}); err != nil {
		t.Fatal(err)
	}
	r := &rangeStack{d: d}
	r.buildRangeThroughTheProduct(exitBounds, exitRequirements)
	return r
}

// run runs `pclaw redteam run` over the scenarios in dir, as the person who
// owns the range agent.
func (r *rangeStack) run(t *testing.T, dir string, extra ...string) (int, string, string, string) {
	t.Helper()
	out := t.TempDir()
	args := []string{
		"redteam", "run", "--suite", "coding-agent", "--scenarios", dir, "--workload-file", r.keyFile, "--gateway", r.d.s.gateway,
		"--role", "github=github-range", "--role", "payments=payments-range", "--role", "real=real", "--run", r.run0, "--out", out,
	}
	for _, name := range []string{"owner", "repo", "other_repo", "main", "file_b64"} {
		args = append(args, "--fixture", name+"="+r.d.fix[name])
	}
	code, stdout, stderr := r.d.admin.pclaw(t, append(args, extra...)...)
	return code, stdout, stderr, out
}

// scenarioDir copies the named scenarios into a directory of their own.
func scenarioDir(t *testing.T, ids ...string) string {
	t.Helper()
	dir := t.TempDir()
	files, err := filepath.Glob("../../redteam/scenarios/RT-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if len(ids) > 0 && !slices.Contains(ids, strings.SplitN(filepath.Base(f), "-", 3)[0]+"-"+strings.SplitN(filepath.Base(f), "-", 3)[1]) {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(f)), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

var tableVerdict = regexp.MustCompile(`(?m)^(RT-[0-9]{3})\s+(PASS|FAIL|ERROR|SKIPPED)\s`)

// TestE2E_M12_CodingAgentSuite: the coding-agent suite, run with
// `pclaw redteam run` against the simulators, has no FAIL and no ERROR; the
// scenarios the live driver cannot run (person steps, simulator changes,
// the sandbox, the kill switch) are SKIPPED, not hidden, and `task range`
// runs them.
func TestE2E_M12_CodingAgentSuite(t *testing.T) {
	r := startRangeStack(t)
	code, out, errs, _ := r.run(t, scenarioDir(t))
	if code != 0 {
		t.Fatalf("pclaw redteam run: %d\n%s\n%s", code, out, errs)
	}
	seen := map[string]string{}
	for _, m := range tableVerdict.FindAllStringSubmatch(out, -1) {
		seen[m[1]] = m[2]
	}
	if len(seen) != 23 {
		t.Fatalf("%d scenarios in the table:\n%s", len(seen), out)
	}
	passed := 0
	for _, v := range seen {
		if v == "PASS" {
			passed++
		}
	}
	if passed < 14 {
		t.Fatalf("only %d scenarios passed through the live driver:\n%s", passed, out)
	}
}

// TestE2E_M12_RangeReachesOnlySimulators: after a range run, every
// transaction of the org is simulated, and the one run that was made is the
// range agent's simulated one; nothing of the range is real (HR-220, HR-222).
func TestE2E_M12_RangeReachesOnlySimulators(t *testing.T) {
	r := startRangeStack(t)
	code, out, errs, _ := r.run(t, scenarioDir(t, "RT-001", "RT-002", "RT-020", "RT-023"))
	if code != 0 {
		t.Fatalf("pclaw redteam run: %d\n%s\n%s", code, out, errs)
	}
	s := r.d.s
	var real, total int
	s.query(t, "SELECT count(*) FILTER (WHERE NOT simulated)::int, count(*)::int FROM pc.transactions", nil, &real, &total)
	if total == 0 || real != 0 {
		t.Fatalf("%d of %d transactions are real", real, total)
	}
	var runs, agents int
	s.query(t, "SELECT (SELECT count(*) FROM pc.runs WHERE NOT simulated)::int, (SELECT count(*) FROM pc.agents WHERE NOT range_agent)::int", nil, &runs, &agents)
	if runs != 0 || agents != 0 {
		t.Fatalf("%d real runs and %d real agents in a range org", runs, agents)
	}
	var real2 int
	s.query(t, "SELECT count(*)::int FROM pc.decision_receipts r JOIN pc.transactions t ON t.id = r.transaction_id WHERE NOT t.simulated", nil, &real2)
	if real2 != 0 {
		t.Fatalf("%d decision receipts of real transactions", real2)
	}
}

var rangeIDOf = regexp.MustCompile(`Range ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}) `)

// TestE2E_M12_BaselineCatchesARegression: a range is run and its assurance
// report exported as a signed pack; the pack verifies offline. A second run
// against the pack as its baseline is clean; a third, under a grant that no
// longer holds merges for review, exits 1 naming the scenario that regressed
// (HR-226, HR-224).
func TestE2E_M12_BaselineCatchesARegression(t *testing.T) {
	r := startRangeStack(t)
	s := r.d.s
	dir := scenarioDir(t, "RT-001", "RT-019")
	code, out, errs, _ := r.run(t, dir)
	first := rangeIDOf.FindStringSubmatch(out)
	if code != 0 || first == nil {
		t.Fatalf("the baseline run: %d\n%s\n%s", code, out, errs)
	}

	p := s.proof(t)
	svc := evapp.New(s.pool, p.origin).WithPacks(func(context.Context, db.TenantTx, ids.OrgID, ids.UUID) error { return nil }, teamEdition{})
	builder := &packbuild.Service{
		Pool: s.pool, Keys: p.reg, LogOrigin: p.origin, Explorer: &txapp.Explorer{Pool: s.pool}, Bundles: evapp.New(s.pool, p.origin),
		Log: pclog.Discard(),
	}
	auditor := s.boundAuditor(t, "range-auditor")
	pk, err := svc.CreateEvidencePack(auditor, evapp.PackRequest{
		Kind: pack.ScopeRange, Range: mustUUID(t, first[1]), Include: pack.Include{Receipts: true, Versions: true},
	})
	if err != nil {
		t.Fatalf("create the assurance report: %v", err)
	}
	if err := builder.Build(context.Background(), s.org, pk.ID); err != nil {
		t.Fatal(err)
	}
	d, err := svc.DownloadEvidencePack(auditor, pk.ID)
	if err != nil {
		t.Fatal(err)
	}
	file := writeFile(t, p.dir, "range.zip", d.Content)
	if code, rep := p.verify(t, file); code != 0 {
		t.Fatalf("pclaw verify of the range pack: exit %d\n%+v", code, rep.Checks)
	}

	// The same range again, with the pack as its baseline: no regression.
	code, out, errs, _ = r.run(t, dir, "--baseline", file, "--trust", p.trust)
	if code != 0 {
		t.Fatalf("a run against its own baseline: %d\n%s\n%s", code, out, errs)
	}

	// A grant that no longer holds merges for review: the merge goes through,
	// RT-001 fails, and the gate says so.
	weak := r.d.grantRun(`{"operations": ["github.contents.read", "github.contents.write", "github.branch.create",
	  "github.pull.read", "github.pull.create", "github.pull.merge"]}`, "")
	code, out, errs, _ = r.run(t, dir, "--baseline", file, "--trust", p.trust, "--run", weak)
	if code != 1 || !strings.Contains(out+errs, "RT-001") {
		t.Fatalf("a run under a weakened grant: %d\n%s\n%s", code, out, errs)
	}
}
