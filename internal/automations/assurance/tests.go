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
