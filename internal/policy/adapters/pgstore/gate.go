// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgstore

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
)

// The publish gate's records (G0 M11.1 design decisions 1 and 6, HR-230):
// validations and test runs of a version's content, the conditional state
// steps, and the one publication path.

// Bounds of the recorded results (00110).
const (
	maxFindingsBytes = 256 << 10
	maxResultsBytes  = 1 << 20
)

var _ app.GateStore = (*Store)(nil)

// RecordValidation implements app.GateStore.
func (s *Store) RecordValidation(ctx context.Context, org ids.OrgID, version ids.UUID, digest [32]byte, r domain.ValidationResult, runBy string) (ids.UUID, error) {
	findings := r.Findings
	if findings == nil {
		findings = []domain.Finding{}
	}
	raw, err := bounded(findings, maxFindingsBytes, "validation findings")
	if err != nil {
		return ids.UUID{}, err
	}
	id := ids.NewV7()
	err = s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.InsertPolicyValidation(ctx, dbq.InsertPolicyValidationParams{
			OrgID: org, ID: id, VersionID: version, ContentDigest: digest[:], DefinitionsDigest: r.DefinitionsDigest[:],
			CatalogDigest: r.CatalogDigest[:], Passed: r.Passed, Findings: raw, RunBy: runBy,
		}); err != nil {
			return err
		}
		if !r.Passed {
			return nil
		}
		_, err := q.AdvancePolicyVersion(ctx, dbq.AdvancePolicyVersionParams{
			ToState: app.StateValidated, OrgID: org, ID: version, FromState: app.StateDraft, ContentDigest: digest[:],
		})
		return err
	})
	return id, err
}

// testResults is the stored form of a test run's results.
type testResults struct {
	Cases     []domain.CaseResult   `json:"cases"`
	Surviving []domain.MutantResult `json:"surviving"`
	Error     string                `json:"error,omitzero"`
}

// RecordTestRun implements app.GateStore.
func (s *Store) RecordTestRun(ctx context.Context, org ids.OrgID, version ids.UUID, digest [32]byte, r domain.TestResult, runBy string) (ids.UUID, error) {
	res := testResults{Cases: r.Cases, Surviving: r.Surviving, Error: r.Error}
	if res.Cases == nil {
		res.Cases = []domain.CaseResult{}
	}
	if res.Surviving == nil {
		res.Surviving = []domain.MutantResult{}
	}
	raw, err := bounded(res, maxResultsBytes, "test results")
	if err != nil {
		return ids.UUID{}, err
	}
	id := ids.NewV7()
	err = s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.InsertPolicyTestRun(ctx, dbq.InsertPolicyTestRunParams{
			OrgID: org, ID: id, VersionID: version, ContentDigest: digest[:], DefinitionsDigest: r.DefinitionsDigest[:],
			CatalogDigest: r.CatalogDigest[:], Passed: r.Passed, Cases: int32(len(r.Cases)), //nolint:gosec // ≤ 200 cases
			Mutants: int32(max(r.Mutants, 0)), Survivors: int32(max(r.Survivors, 0)), //nolint:gosec // bounded runs
			Results: raw, RunBy: runBy,
		}); err != nil {
			return err
		}
		if !r.Passed {
			return nil
		}
		_, err := q.AdvancePolicyVersion(ctx, dbq.AdvancePolicyVersionParams{
			ToState: app.StateTested, OrgID: org, ID: version, FromState: app.StateValidated, ContentDigest: digest[:],
		})
		return err
	})
	return id, err
}

// PublishTested implements app.GateStore.
func (s *Store) PublishTested(ctx context.Context, org ids.OrgID, p app.PublishRequest) error {
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		return s.PublishTestedInTx(ctx, tx, org, p)
	})
	// Two publishes that both expected none: the second meets the first's
	// row at the one-published index.
	if db.IsUniqueViolation(err) {
		return app.ErrPublishedChanged
	}
	return err
}

// PublishTestedInTx implements app.GateStore: the published version is
// locked first, so a concurrent publish is seen; then the base is
// superseded and the version published by the gate's conditional UPDATE
// (HR-230, HR-004), the event recorded and the hook run, all in tx.
func (s *Store) PublishTestedInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, p app.PublishRequest) error {
	q := dbq.New(tx)
	cur, err := s.PublishedIDInTx(ctx, tx, org)
	if err != nil {
		return err
	}
	if cur != p.Base {
		return ErrPublishedChanged
	}
	if _, err := q.SupersedePublishedPolicy(ctx, org, p.Version); err != nil {
		return err
	}
	by := p.PublishedBy
	err = db.ExpectOneRow(q.PublishPolicyVersion(ctx, dbq.PublishPolicyVersionParams{
		PublishedBy: &by, OrgID: org, ID: p.Version, ContentDigest: p.Digest[:], TestRunID: p.TestRun,
	}))
	if errors.Is(err, db.ErrLostRace) {
		return ErrNotDraft
	}
	if err != nil {
		return err
	}
	details := map[string]string{"version_id": p.Version.String(), "test_run": p.TestRun.String()}
	if !p.Base.IsZero() {
		details["superseded"] = p.Base.String()
	}
	if p.Event != nil {
		maps.Copy(details, p.Event.Details)
	}
	if err := record(ctx, tx, p.Event, details); err != nil {
		return err
	}
	if p.Hook == nil {
		return nil
	}
	return p.Hook(ctx, tx, org, p.Version, p.Base)
}

// PublishedIDInTx implements app.GateStore.
func (s *Store) PublishedIDInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID) (ids.UUID, error) {
	cur, err := dbq.New(tx).LockPublishedPolicyVersion(ctx, org)
	if db.IsNoRows(err) {
		return ids.UUID{}, nil
	}
	return cur, err
}

// LatestTestRunInTx implements app.GateStore.
func (s *Store) LatestTestRunInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, version ids.UUID) (app.TestRun, error) {
	r, err := dbq.New(tx).LatestPassedTestRun(ctx, org, version)
	if db.IsNoRows(err) {
		return app.TestRun{}, ErrNotDraft
	}
	if err != nil {
		return app.TestRun{}, err
	}
	out := app.TestRun{ID: r.ID}
	copy(out.DefinitionsDigest[:], r.DefinitionsDigest)
	copy(out.CatalogDigest[:], r.CatalogDigest)
	return out, nil
}

func bounded(v any, limit int, what string) ([]byte, error) {
	raw, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	if len(raw) > limit {
		return nil, fmt.Errorf("policy: the %s are larger than %d bytes", what, limit)
	}
	return raw, nil
}
