// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package assurance

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	exapp "github.com/katocxl/pantherclaw/internal/exposure/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// caseOf reads a stored case.
func caseOf(r dbq.ListAutomationTestCasesRow) (Case, error) {
	c := Case{Name: r.Name, Kind: CaseKind(r.CaseKind)}
	if err := errors.Join(json.Unmarshal(r.Trigger, &c.Trigger), json.Unmarshal(r.Stubs, &c.Stubs),
		json.Unmarshal(r.Expect, &c.Expect)); err != nil {
		return Case{}, fmt.Errorf("assurance: stored case %s: %w", r.Name, err)
	}
	return c, nil
}

func storedCases(ctx context.Context, q *dbq.Queries, org ids.OrgID, version ids.UUID) ([]Case, error) {
	rows, err := q.ListAutomationTestCases(ctx, org, version)
	if err != nil {
		return nil, err
	}
	out := make([]Case, 0, len(rows))
	for _, r := range rows {
		c, err := caseOf(r)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// irreversibleCeiling reports whether the version's ceiling reaches an
// irreversible operation of any connection (HR-287's PARTIAL|UNKNOWN).
// An operation of a connection whose package cannot be read may be
// irreversible: such a connection counts as irreversible when the ceiling
// names no operations.
func irreversibleCeiling(ctx context.Context, tx db.TenantTx, def *autodomain.Definition) (bool, error) {
	if def.Authority.Ceiling == nil {
		return false, nil
	}
	l, err := exapp.Load(ctx, tx)
	if err != nil {
		return false, err
	}
	if def.Authority.Ceiling.Bounds.Operations == nil {
		for _, c := range l.Inputs.Connections {
			if !c.Known {
				return true, nil
			}
		}
	}
	return Irreversible(def, l.Irreversible), nil
}

// SetTestCases replaces a DRAFT or VALIDATED version's cases and returns
// the required kinds still missing (D34).
func (s *Service) SetTestCases(ctx context.Context, versionID ids.UUID, cases []Case) ([]string, error) {
	c, err := caller(ctx, td.PermAutomationManage)
	if err != nil {
		return nil, err
	}
	if err := s.edition(ctx, false); err != nil {
		return nil, err
	}
	var missing []string
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		lv, err := q.LockAssuranceVersion(ctx, c.Org, versionID)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if lv.State != string(autodomain.VersionDraft) && lv.State != string(autodomain.VersionValidated) {
			return ErrVersionState
		}
		_, def, err := version(ctx, q, c.Org, versionID)
		if err != nil {
			return err
		}
		if err := Check(def, cases); err != nil {
			return pcerr.Wrap(err, pcerr.InvalidArgument, "TEST_CASES_INVALID", err.Error())
		}
		if _, err := q.DeleteAutomationTestCases(ctx, c.Org, versionID); err != nil {
			return err
		}
		for i, x := range cases {
			trig, err1 := json.Marshal(x.Trigger, json.Deterministic(true))
			stubs, err2 := json.Marshal(x.Stubs, json.Deterministic(true))
			exp, err3 := json.Marshal(x.Expect, json.Deterministic(true))
			if err := errors.Join(err1, err2, err3); err != nil {
				return err
			}
			if err := q.InsertAutomationTestCase(ctx, dbq.InsertAutomationTestCaseParams{
				OrgID: c.Org, ID: ids.NewV7(), VersionID: versionID, Name: x.Name, CaseKind: string(x.Kind), Trigger: trig,
				Stubs: stubs, Expect: exp, Seq: int32(i + 1), CreatedBy: c.Principal.ID, //nolint:gosec // G115: ≤ MaxCases
			}); err != nil {
				return err
			}
		}
		irr, err := irreversibleCeiling(ctx, tx, def)
		if err != nil {
			return err
		}
		missing = Missing(cases, irr)
		return record(ctx, tx, c, "automation.tests_set", versionID, map[string]string{
			"automation": lv.AutomationID.String(), "cases": strconv.Itoa(len(cases)),
		})
	})
	return missing, err
}

// ListTestCases lists a version's cases and the required kinds missing.
func (s *Service) ListTestCases(ctx context.Context, versionID ids.UUID) ([]Case, []string, error) {
	c, err := caller(ctx, td.PermAutomationRead)
	if err != nil {
		return nil, nil, err
	}
	if err := s.edition(ctx, false); err != nil {
		return nil, nil, err
	}
	var cases []Case
	var missing []string
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		_, def, err := version(ctx, q, c.Org, versionID)
		if err != nil {
			return err
		}
		if cases, err = storedCases(ctx, q, c.Org, versionID); err != nil {
			return err
		}
		irr, err := irreversibleCeiling(ctx, tx, def)
		if err != nil {
			return err
		}
		missing = Missing(cases, irr)
		return nil
	}, db.ReadOnly())
	return cases, missing, err
}

func record(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name string, version ids.UUID, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "automation_version", ID: version.String()},
		Details: details,
	})
	return err
}

// TestGate implements autoports.TestGate (D34, HR-287): a version passed
// when its newest run for this definition digest passed and ran exactly
// the cases it has now.
type TestGate struct{}

var _ autoports.TestGate = TestGate{}

// Passed implements autoports.TestGate.
func (TestGate) Passed(ctx context.Context, tx pgx.Tx, version ids.UUID, digest []byte) (ids.UUID, bool, error) {
	q := dbq.New(tx)
	org, err := q.AssuranceVersionOrg(ctx, version)
	if db.IsNoRows(err) {
		return ids.UUID{}, false, nil
	} else if err != nil {
		return ids.UUID{}, false, err
	}
	run, err := q.LatestAutomationTestRun(ctx, org, version, digest)
	if db.IsNoRows(err) {
		return ids.UUID{}, false, nil
	} else if err != nil {
		return ids.UUID{}, false, err
	}
	if !run.Passed {
		return run.ID, false, nil
	}
	cases, err := storedCases(ctx, q, org, version)
	if err != nil {
		return ids.UUID{}, false, err
	}
	cur, err := Digest(cases)
	if err != nil {
		return ids.UUID{}, false, err
	}
	return run.ID, bytes.Equal(cur, run.TestsDigest), nil
}

// TestRun is a stored run.
type TestRun struct {
	ID, Version      ids.UUID
	DefinitionDigest []byte
	TestsDigest      []byte
	Passed           bool
	Result           RunResult
	RunBy            ids.UUID
	CreatedAt        time.Time
	// VersionState is the version's state after the run.
	VersionState string
}

// RunTests runs a VALIDATED or TESTED version's cases against its current
// digest and stores the run; a passing run makes a VALIDATED version
// TESTED (D34, HR-287). Nothing outside the run's own row is written
// (HR-288).
func (s *Service) RunTests(ctx context.Context, versionID ids.UUID) (TestRun, error) {
	c, err := caller(ctx, td.PermAutomationManage)
	if err != nil {
		return TestRun{}, err
	}
	if err := s.edition(ctx, false); err != nil {
		return TestRun{}, err
	}
	var out TestRun
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		lv, err := q.LockAssuranceVersion(ctx, c.Org, versionID)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if lv.State != string(autodomain.VersionValidated) && lv.State != string(autodomain.VersionTested) {
			return ErrVersionState
		}
		_, def, err := version(ctx, q, c.Org, versionID)
		if err != nil {
			return err
		}
		cases, err := storedCases(ctx, q, c.Org, versionID)
		if err != nil {
			return err
		}
		irr, err := irreversibleCeiling(ctx, tx, def)
		if err != nil {
			return err
		}
		res, err := Run(ctx, def, c.Org, lv.AutomationID, versionID, cases, irr, s.now().Now())
		if err != nil {
			return err
		}
		tests, err := Digest(cases)
		if err != nil {
			return err
		}
		body, err := json.Marshal(res, json.Deterministic(true))
		if err != nil {
			return err
		}
		out = TestRun{
			ID: ids.NewV7(), Version: versionID, DefinitionDigest: lv.Digest, TestsDigest: tests, Passed: res.Passed(), Result: res,
			RunBy: c.Principal.ID, VersionState: lv.State,
		}
		if out.CreatedAt, err = q.InsertAutomationTestRun(ctx, dbq.InsertAutomationTestRunParams{
			OrgID: c.Org, ID: out.ID, VersionID: versionID, DefinitionDigest: lv.Digest, TestsDigest: tests, Passed: out.Passed,
			Results: body, RunBy: c.Principal.ID,
		}); err != nil {
			return err
		}
		if out.Passed && lv.State == string(autodomain.VersionValidated) {
			n, err := q.MarkAutomationVersionTested(ctx, dbq.MarkAutomationVersionTestedParams{
				RunID: &out.ID, OrgID: c.Org, ID: versionID, Digest: lv.Digest,
			})
			if err != nil {
				return err
			}
			if n == 1 {
				out.VersionState = string(autodomain.VersionTested)
			}
		}
		outcome := "failed"
		if out.Passed {
			outcome = "passed"
		}
		return record(ctx, tx, c, "automation.tests_run", versionID, map[string]string{
			"automation": lv.AutomationID.String(), "run": out.ID.String(), "result": outcome,
			"cases": strconv.Itoa(len(res.Cases)),
		})
	})
	return out, err
}

// GetTestRun returns a stored run.
func (s *Service) GetTestRun(ctx context.Context, id ids.UUID) (TestRun, error) {
	c, err := caller(ctx, td.PermAutomationRead)
	if err != nil {
		return TestRun{}, err
	}
	if err := s.edition(ctx, false); err != nil {
		return TestRun{}, err
	}
	var out TestRun
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.GetAutomationTestRun(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		out = TestRun{
			ID: r.ID, Version: r.VersionID, DefinitionDigest: r.DefinitionDigest, TestsDigest: r.TestsDigest, Passed: r.Passed,
			RunBy: r.RunBy, CreatedAt: r.CreatedAt,
		}
		if err := json.Unmarshal(r.Results, &out.Result); err != nil {
			return fmt.Errorf("assurance: stored run %s: %w", r.ID, err)
		}
		v, err := q.AssuranceVersion(ctx, c.Org, r.VersionID)
		if err != nil {
			return err
		}
		out.VersionState = v.State
		return nil
	}, db.ReadOnly())
	return out, err
}
