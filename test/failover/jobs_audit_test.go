// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package failover_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// twoWorkerAudit is every River job kind with what keeps it correct when
// two or more worker processes run (G0 M19 D202, HR-498). The full audit,
// with file:line facts, is in the M19 S19b notes (S19b-jobs.md).
//   - unique: a per-entity job with UniqueOpts ByArgs over available,
//     pending, retryable, running and scheduled, so one runs at a time;
//   - fan-out: a dispatcher that only inserts unique per-entity jobs;
//   - lock: a row lock, advisory lock, CAS or conditional write in the
//     job's own transaction serializes concurrent runs.
//
// A new job kind fails this test until it is audited and listed here.
var twoWorkerAudit = map[string]string{
	"accounts.deletion_resume":                   "lock: CAS state transitions and the journal lock",
	"approvals.janitor_dispatch":                 "fan-out",
	"approvals.janitor_org":                      "unique",
	"authn.janitor_dispatch":                     "fan-out",
	"authn.janitor_org":                          "unique",
	"authority.sweep_dispatch":                   "fan-out",
	"authority.sweep_org":                        "unique",
	"automation.execute":                         "lock: LockAutomationExecution FOR UPDATE, ceiling lock",
	"automation.wake":                            "unique; inserts unique execute jobs",
	"automation.wake_org":                        "unique",
	"automation_assurance_sweep":                 "unique",
	"automation_assurance_sweep_dispatch":        "fan-out",
	"automation_simulate":                        "unique",
	"automations.ceiling_sweep_dispatch":         "fan-out",
	"automations.ceiling_sweep_org":              "unique; voiding takes the ceiling lock",
	"automations.triggers_dispatch":              "fan-out",
	"automations.triggers_org":                   "unique per org and task; cursor CAS, delivery lock and lease",
	"changes.expire_dispatch":                    "fan-out",
	"changes.expire_org":                         "unique",
	"coverage.reassess_dispatch":                 "fan-out",
	"coverage.reassess_org":                      "unique",
	"data.daily":                                 "fan-out",
	"data.daily_org":                             "unique; LockOrgAdmins, reminder dedupe keys",
	"data.delete_org":                            "unique per request; journal FOR UPDATE",
	"data.export":                                "unique per request; LockDataRequest and BUILDING guard",
	"detection.dispatch":                         "fan-out",
	"detection.evaluate_org":                     "unique; cursor CAS",
	"evidence.anchor_tick":                       "unique (global); InsertAnchor once, attempt CAS",
	"evidence.chain_dispatch":                    "fan-out",
	"evidence.chain_org":                         "unique; LockLedgerHead",
	"evidence.checkpoint_dispatch":               "fan-out",
	"evidence.checkpoint_org":                    "unique; LockLedgerHead",
	"evidence.pack_build":                        "unique per pack; BUILDING guard, ErrLostRace",
	"evidence.pack_expire":                       "lock: conditional ExpireEvidencePacks",
	"evidence.retention_dispatch":                "fan-out",
	"evidence.retention_org":                     "unique; LockRetention",
	"evidence.security_log_dispatch":             "fan-out",
	"evidence.security_log_org":                  "unique; attempt stamped before emitting",
	"evidence.verify_dispatch":                   "fan-out",
	"evidence.verify_org":                        "unique; LockLedgerHead",
	"exposure.recompute_dispatch":                "fan-out",
	"exposure.recompute_org":                     "unique",
	"gateway_mcp_state.purge":                    "fan-out",
	"gateway_mcp_state.purge_org":                "unique; deletes only",
	"gateway_replicas.prune":                     "fan-out",
	"gateway_replicas.prune_org":                 "unique; deletes only",
	"github.daily_scans_dispatch":                "fan-out",
	"github.daily_scans_org":                     "unique",
	"identity.janitor_dispatch":                  "fan-out",
	"identity.janitor_org":                       "unique",
	"notifications.deliver":                      "lock: one job per delivery, state check and attempts CAS",
	"notifications.janitor_dispatch":             "fan-out",
	"notifications.janitor_org":                  "unique; deletes and expiries only",
	"notifications.slack_reconcile_dispatch":     "fan-out",
	"notifications.slack_reconcile_org":          "unique; conditional MarkSlackSharedExternally",
	"operations.metrics_dispatch":                "fan-out",
	"operations.metrics_org":                     "unique",
	"policy.exception_sweep_dispatch":            "fan-out",
	"policy.exception_sweep_org":                 "unique",
	"policy.rollout_sweep_dispatch":              "fan-out",
	"policy.rollout_sweep_org":                   "unique",
	"policy_simulate":                            "unique",
	"promotions.provisional_sweep_dispatch":      "fan-out",
	"promotions.provisional_sweep_org":           "unique",
	"ratelimit.janitor":                          "unique; idempotent delete",
	"redteam.abandon_dispatch":                   "fan-out",
	"redteam.abandon_org":                        "unique",
	"reflex.digest_dispatch":                     "fan-out",
	"reflex.digest_org":                          "unique; InsertDigest once",
	"response.sweep_dispatch":                    "fan-out",
	"response.sweep_org":                         "unique",
	"sandbox.expiry_dispatch":                    "fan-out",
	"sandbox.expiry_org":                         "unique; FOR UPDATE SKIP LOCKED",
	"siem.export_dispatch":                       "fan-out",
	"siem.export_org":                            "unique; FOR UPDATE, cursor CAS, batch lease",
	"signals.janitor_dispatch":                   "fan-out",
	"signals.janitor_org":                        "unique",
	"support.breakglass_sweep":                   "lock: UPDATE where ended_at IS NULL RETURNING",
	"transactions.target_logs_dispatch":          "fan-out",
	"transactions.target_logs_org":               "unique",
	"transactions.verifications_expire_dispatch": "fan-out",
	"transactions.verifications_expire_org":      "unique",
	"usage.meter_daily":                          "fan-out",
	"usage.meter_org":                            "unique; LockUsageMeter (M19 S19b fix)",
	"usage.recount_weekly":                       "unique; LockUsageMeter (M19 S19b fix)",
	"waitlist.observe":                           "unique; in-process metrics only",
	"waitlist.route_dispatch":                    "fan-out",
	"waitlist.route_org":                         "unique; EntryForRouting FOR UPDATE, dedupe keys",
}

// TestHR498_EveryRiverJobIsAuditedForTwoWorkers: every job kind in the
// product code (a Kind method on an ...Args type, test files excepted) is
// in twoWorkerAudit, and every listed kind still exists.
// Covers: PN-010.7
func TestHR498_EveryRiverJobIsAuditedForTwoWorkers(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	var kinds []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch name := d.Name(); {
			case path == root:
			case name == "vendor", name == "testdata", name == "node_modules", name == "sdk", strings.HasPrefix(name, "."):
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, decl := range f.Decls {
			if k, ok := argsKind(decl); ok {
				kinds = append(kinds, k)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(kinds) < 50 {
		t.Fatalf("found %d job kinds; the scan is not reading the product code", len(kinds))
	}
	for _, k := range kinds {
		if _, ok := twoWorkerAudit[k]; !ok {
			t.Errorf("River job %q is not audited for two workers (HR-498): check it and list it in twoWorkerAudit", k)
		}
	}
	for k := range twoWorkerAudit {
		if !slices.Contains(kinds, k) {
			t.Errorf("twoWorkerAudit lists %q, which no longer exists", k)
		}
	}
}

// argsKind returns the literal a Kind() string method on an ...Args type
// returns.
func argsKind(decl ast.Decl) (string, bool) {
	fn, ok := decl.(*ast.FuncDecl)
	if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 || fn.Name.Name != "Kind" || fn.Body == nil || len(fn.Body.List) != 1 {
		return "", false
	}
	typ := fn.Recv.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	id, ok := typ.(*ast.Ident)
	if !ok || !strings.HasSuffix(id.Name, "Args") {
		return "", false
	}
	ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return "", false
	}
	lit, ok := ret.Results[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}

// moduleRoot is the directory of the nearest go.mod above the test's.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test")
		}
		dir = parent
	}
}
