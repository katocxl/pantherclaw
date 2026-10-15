// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The publish gate (G0 M11.1 design decisions 1, 6 and 9; HR-230, HR-236).
// A version is published only after it validated and its scenario tests
// passed against the org's current definitions and fact catalog, both re-run
// in the publish call, and only through one conditional UPDATE that names a
// passing test run of exactly its content. A version that is not provably
// tighter than the published one (D3) waits as a PUBLISH change request
// (change.go) for confirmations with security keys (F1).

// Validator validates a bundle against the org's active definitions and
// fact catalog (D8; implemented by internal/policy/validate).
type Validator interface {
	Validate(ctx context.Context, org ids.OrgID, b *domain.Bundle) (domain.ValidationResult, error)
}

// TestRunner runs a bundle's scenario tests and the HR-044 mutants (D7;
// implemented by internal/policy/scenario).
type TestRunner interface {
	Run(ctx context.Context, org ids.OrgID, b *domain.Bundle) (domain.TestResult, error)
}

// PublishedHook runs inside the transaction that makes version the
// published one, after base (zero: none) was superseded (D6; S2's rollout
// record). An error rolls the publication back.
type PublishedHook func(ctx context.Context, tx db.TenantTx, org ids.OrgID, version, base ids.UUID) error

// Gate errors.
var (
	ErrValidationFailed = pcerr.New(pcerr.FailedPrecondition, "POLICY_VALIDATION_FAILED",
		"the policy version did not validate; its findings are in the error details")
	ErrTestsFailed = pcerr.New(pcerr.FailedPrecondition, "POLICY_TESTS_FAILED",
		"the policy version's scenario tests did not pass; the failing cases are in the error details")
	// ErrGateUnavailable: the server has no validator, test runner or change
	// requests, so nothing is published (fail closed).
	ErrGateUnavailable = pcerr.New(pcerr.Unavailable, "POLICY_GATE_UNAVAILABLE",
		"the policy publish gate is not available on this server; nothing was published")
	// ErrLegacyVersion: a version stored before the gate has no content
	// digest, so it can never be validated, tested or published again.
	ErrLegacyVersion = pcerr.New(pcerr.FailedPrecondition, "POLICY_VERSION_LEGACY",
		"this version was stored before the publish gate; create a new version from its bundle")
	// ErrEmergencyRule: the version drops or changes an emergency rule of
	// the published version (HR-236).
	ErrEmergencyRule = pcerr.New(pcerr.PermissionDenied, "INCIDENT_RESPOND_REQUIRED",
		"this version drops or changes an emergency rule of the published policy; that also needs incident.respond")
	// ErrSeedLoosens: a seeded version would loosen the published policy,
	// which only people can confirm.
	ErrSeedLoosens = pcerr.New(pcerr.FailedPrecondition, "POLICY_SEED_LOOSENS",
		"the seeded policy would loosen the published one; publish it as a person")
)

// GateError is a refused publish, validation or test with its results: the
// RPC adapter returns them as error details.
type GateError struct {
	Err        error
	Validation *domain.ValidationResult
	Tests      *domain.TestResult
}

func (e *GateError) Error() string { return e.Err.Error() }
func (e *GateError) Unwrap() error { return e.Err }

// Content states.
const (
	StateDraft      = "DRAFT"
	StateValidated  = "VALIDATED"
	StateTested     = "TESTED"
	StatePublished  = "PUBLISHED"
	StateSuperseded = "SUPERSEDED"
)

// unpublished reports whether a version may still move towards publication.
func unpublished(state string) bool {
	return state == StateDraft || state == StateValidated || state == StateTested
}

// PublishRequest is the gate's last step: the conditional publication of a
// TESTED version of Digest with the passing TestRun, while Base (zero:
// none) is the published version. Hook runs in the same transaction.
type PublishRequest struct {
	Version     ids.UUID
	Digest      [32]byte
	TestRun     ids.UUID
	Base        ids.UUID
	PublishedBy string
	Event       *audit.Event
	Hook        PublishedHook
}

// GateStore is the part of VersionStore the gate writes through.
type GateStore interface {
	// RecordValidation stores a validation of the version's content and,
	// when it passed, moves a DRAFT to VALIDATED.
	RecordValidation(ctx context.Context, org ids.OrgID, version ids.UUID, digest [32]byte, r domain.ValidationResult, runBy string) (ids.UUID, error)
	// RecordTestRun stores a test run of the version's content and, when it
	// passed, moves a VALIDATED version to TESTED.
	RecordTestRun(ctx context.Context, org ids.OrgID, version ids.UUID, digest [32]byte, r domain.TestResult, runBy string) (ids.UUID, error)
	// PublishTested publishes in its own transaction (PublishTestedInTx).
	PublishTested(ctx context.Context, org ids.OrgID, p PublishRequest) error
	// PublishTestedInTx supersedes p.Base and publishes p.Version in tx, or
	// returns ErrPublishedChanged (another version is published) or
	// ErrNotDraft (the version is not TESTED with that content and run).
	PublishTestedInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, p PublishRequest) error
	// VersionInTx is Version inside tx.
	VersionInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, id ids.UUID) (VersionInfo, error)
	// PublishedIDInTx is the published version's id (zero: none), locked.
	PublishedIDInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID) (ids.UUID, error)
	// LatestTestRunInTx is the newest passing test run of the version's
	// content, with the digests it ran against.
	LatestTestRunInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, version ids.UUID) (TestRun, error)
}

// TestRun is a recorded passing test run.
type TestRun struct {
	ID                               ids.UUID
	DefinitionsDigest, CatalogDigest [32]byte
}

// PublishOutcome is what a publish or rollback did: published the version,
// or created a change request that waits for confirmations.
type PublishOutcome struct {
	Version       VersionInfo
	ChangeRequest *ChangeRequest
	Diff          domain.Diff
	Validation    domain.ValidationResult
	Tests         domain.TestResult
	// Carried lists the emergency rules a rollback carried forward (D4).
	Carried []string
}

// publisher is who publishes: a person, or the dev seed.
type publisher struct {
	org   ids.OrgID
	id    string
	actor evdomain.Actor
	// caller is set for a person; the dev seed has none.
	caller *tapp.Caller
}

func (v *Versions) gateReady() error {
	if v.Validator == nil || v.Tests == nil {
		return ErrGateUnavailable
	}
	return nil
}

func storedVersion(info VersionInfo) (*domain.Bundle, [32]byte, error) {
	var digest [32]byte
	if len(info.ContentDigest) != len(digest) {
		return nil, digest, ErrLegacyVersion
	}
	copy(digest[:], info.ContentDigest)
	b, err := decodeStored(info.Bundle)
	if err != nil {
		return nil, digest, err
	}
	if domain.ContentDigest(b) != digest {
		return nil, digest, fmt.Errorf("policy: version %s: the stored bundle does not match its content digest", info.ID)
	}
	return b, digest, nil
}

// validate runs the Validator and records the result (advancing a DRAFT).
func (v *Versions) validate(ctx context.Context, org ids.OrgID, info VersionInfo, b *domain.Bundle, digest [32]byte, runBy string) (domain.ValidationResult, error) {
	r, err := v.Validator.Validate(ctx, org, b)
	if err != nil {
		return r, err
	}
	if _, err := v.Store.RecordValidation(ctx, org, info.ID, digest, r, runBy); err != nil {
		return r, err
	}
	if !r.Passed {
		return r, &GateError{Err: ErrValidationFailed, Validation: &r}
	}
	return r, nil
}

// test runs the TestRunner and records the run (advancing a VALIDATED).
func (v *Versions) test(ctx context.Context, org ids.OrgID, info VersionInfo, b *domain.Bundle, digest [32]byte, runBy string) (domain.TestResult, ids.UUID, error) {
	r, err := v.Tests.Run(ctx, org, b)
	if err != nil {
		return r, ids.UUID{}, err
	}
	run, err := v.Store.RecordTestRun(ctx, org, info.ID, digest, r, runBy)
	if err != nil {
		return r, ids.UUID{}, err
	}
	if !r.Passed {
		return r, run, &GateError{Err: ErrTestsFailed, Tests: &r}
	}
	return r, run, nil
}

// Validate validates a version now and records the result (policy.author
// at the org); a DRAFT that passed becomes VALIDATED.
func (v *Versions) Validate(ctx context.Context, id ids.UUID) (VersionInfo, domain.ValidationResult, error) {
	c, err := v.caller(ctx, PermPolicyAuthor)
	if err != nil {
		return VersionInfo{}, domain.ValidationResult{}, err
	}
	if err := v.gateReady(); err != nil {
		return VersionInfo{}, domain.ValidationResult{}, err
	}
	info, err := v.Store.Version(ctx, c.Org, id)
	if err != nil {
		return VersionInfo{}, domain.ValidationResult{}, err
	}
	b, digest, err := storedVersion(info)
	if err != nil {
		return VersionInfo{}, domain.ValidationResult{}, err
	}
	r, err := v.validate(ctx, c.Org, info, b, digest, c.Principal.String())
	var ge *GateError
	if err != nil && !errors.As(err, &ge) {
		return VersionInfo{}, r, err
	}
	info, verr := v.Store.Version(ctx, c.Org, id)
	if verr != nil {
		return VersionInfo{}, r, verr
	}
	return info, r, nil
}

// Test runs a version's scenario tests now and records the run
// (policy.author at the org); a VALIDATED version that passed becomes
// TESTED.
func (v *Versions) Test(ctx context.Context, id ids.UUID) (VersionInfo, domain.TestResult, error) {
	c, err := v.caller(ctx, PermPolicyAuthor)
	if err != nil {
		return VersionInfo{}, domain.TestResult{}, err
	}
	if err := v.gateReady(); err != nil {
		return VersionInfo{}, domain.TestResult{}, err
	}
	info, err := v.Store.Version(ctx, c.Org, id)
	if err != nil {
		return VersionInfo{}, domain.TestResult{}, err
	}
	b, digest, err := storedVersion(info)
	if err != nil {
		return VersionInfo{}, domain.TestResult{}, err
	}
	r, _, err := v.test(ctx, c.Org, info, b, digest, c.Principal.String())
	var ge *GateError
	if err != nil && !errors.As(err, &ge) {
		return VersionInfo{}, r, err
	}
	info, verr := v.Store.Version(ctx, c.Org, id)
	if verr != nil {
		return VersionInfo{}, r, verr
	}
	return info, r, nil
}

// emergencyChanged reports whether next drops or changes an emergency rule
// of published (HR-236).
func emergencyChanged(published, next *domain.Bundle) bool {
	if published == nil {
		return false
	}
	for _, r := range published.Rules {
		if !r.IsEmergency() {
			continue
		}
		i := slices.IndexFunc(next.Rules, func(x domain.Rule) bool { return x.ID == r.ID })
		if i < 0 || domain.RuleDigest(next.Rules[i]) != domain.RuleDigest(r) {
			return true
		}
	}
	return false
}

// gate runs D6 for a stored version: validate and test again (recording
// both), classify against the published version, then publish a version
// that does not loosen it, or ask for confirmations. expected, when set, is
// the published version the caller expects (C4).
func (v *Versions) gate(ctx context.Context, p publisher, id ids.UUID, expected *ids.UUID, carried []string) (PublishOutcome, error) {
	if err := v.gateReady(); err != nil {
		return PublishOutcome{}, err
	}
	info, err := v.Store.Version(ctx, p.org, id)
	if err != nil {
		return PublishOutcome{}, err
	}
	if !unpublished(info.State) {
		return PublishOutcome{}, ErrNotDraft
	}
	b, digest, err := storedVersion(info)
	if err != nil {
		return PublishOutcome{}, err
	}
	if err := v.compile(ctx, p.org, b); err != nil {
		return PublishOutcome{}, err
	}
	out := PublishOutcome{Carried: carried}
	if out.Validation, err = v.validate(ctx, p.org, info, b, digest, p.id); err != nil {
		return out, err
	}
	var run ids.UUID
	if out.Tests, run, err = v.test(ctx, p.org, info, b, digest, p.id); err != nil {
		return out, err
	}
	cur, err := v.Store.PublishedVersion(ctx, p.org)
	if err != nil {
		return out, err
	}
	var base ids.UUID
	var published *domain.Bundle
	if cur != nil {
		base = cur.ID
		if published, err = decodeStored(cur.Bundle); err != nil {
			return out, err
		}
	}
	if expected != nil && *expected != base {
		return out, ErrPublishedChanged
	}
	if emergencyChanged(published, b) {
		if p.caller == nil {
			return out, ErrSeedLoosens
		}
		if err := v.Authz.Require(*p.caller, tdomain.PermIncidentRespond, tdomain.OrgPath(p.org)); err != nil {
			return out, ErrEmergencyRule
		}
	}
	out.Diff = domain.Compare(published, b)
	if !out.Diff.Loosens() {
		ev := &audit.Event{
			Name: "policy.published", Actor: p.actor, Outcome: audit.Success,
			Object: &audit.Object{Type: "policy", ID: info.BundleID},
		}
		if err := v.Store.PublishTested(ctx, p.org, PublishRequest{
			Version: id, Digest: digest, TestRun: run, Base: base, PublishedBy: p.id, Event: ev, Hook: v.OnPublished,
		}); err != nil {
			return out, err
		}
		out.Version, err = v.Store.Version(ctx, p.org, id)
		return out, err
	}
	if p.caller == nil {
		return out, ErrSeedLoosens
	}
	if v.Changes == nil {
		return out, ErrGateUnavailable
	}
	summary := PublishSummary{
		VersionID: id.String(), BundleID: info.BundleID, Version: info.Version, Direction: string(out.Diff.Direction),
		Carried: carried, Changes: changeRows(out.Diff),
	}
	if !base.IsZero() {
		summary.BaseVersionID = base.String()
	}
	binding, err := ChangeBinding(ChangePublish, p.org, id, base, digest, summary)
	if err != nil {
		return out, err
	}
	req, err := v.Changes.Request(ctx, ChangePublish, id, base, binding, summary)
	if err != nil {
		return out, err
	}
	out.ChangeRequest = &req
	out.Version, err = v.Store.Version(ctx, p.org, id)
	return out, err
}

// PublishSummary is what a PUBLISH change request shows its confirmers:
// the version and every classified change (D3).
type PublishSummary struct {
	VersionID     string      `json:"version_id"`
	BundleID      string      `json:"bundle_id"`
	Version       int         `json:"version"`
	BaseVersionID string      `json:"base_version_id,omitzero"`
	Direction     string      `json:"direction"`
	Carried       []string    `json:"carried_emergency_rules,omitzero"`
	Changes       []ChangeRow `json:"changes"`
}

// ChangeRow is one classified change of a summary.
type ChangeRow struct {
	RuleID    string `json:"rule_id"`
	Kind      string `json:"kind"`
	Field     string `json:"field,omitzero"`
	Before    string `json:"before,omitzero"`
	After     string `json:"after,omitzero"`
	Direction string `json:"direction"`
	Sentence  string `json:"sentence"`
}

func changeRows(d domain.Diff) []ChangeRow {
	out := make([]ChangeRow, 0, len(d.Changes))
	for _, c := range d.Changes {
		out = append(out, ChangeRow{
			RuleID: c.RuleID, Kind: c.Kind, Field: c.Field, Before: c.Before, After: c.After,
			Direction: string(c.Direction), Sentence: c.Sentence,
		})
	}
	return out
}

func (v *Versions) person(ctx context.Context) (publisher, error) {
	c, err := v.caller(ctx, PermPolicyPublish)
	if err != nil {
		return publisher{}, err
	}
	if !c.Human() {
		return publisher{}, ErrHumanOnly
	}
	return publisher{org: c.Org, id: c.Principal.String(), actor: c.Actor(), caller: &c}, nil
}

// Publish publishes a version through the gate (policy.publish at the org,
// human only).
func (v *Versions) Publish(ctx context.Context, id ids.UUID) (PublishOutcome, error) {
	return v.PublishExpecting(ctx, id, nil)
}

// PublishExpecting publishes as Publish does, and with expected set only
// while the published version is *expected (the zero id: none); else
// ErrPublishedChanged. A version that loosens the published policy is not
// published: the outcome carries the change request that waits for
// confirmations.
func (v *Versions) PublishExpecting(ctx context.Context, id ids.UUID, expected *ids.UUID) (PublishOutcome, error) {
	p, err := v.person(ctx)
	if err != nil {
		return PublishOutcome{}, err
	}
	return v.gate(ctx, p, id, expected, nil)
}

// Rollback makes a new version from to's rules and tests, carries every
// emergency rule of the published version forward (D4, HR-236) and runs it
// through the gate (policy.publish at the org, human only; D9). Rolling
// back to a looser version waits for confirmations like any loosening.
// Containment, grants and guardrails are separate records and are never
// touched.
func (v *Versions) Rollback(ctx context.Context, to ids.UUID, expected *ids.UUID) (PublishOutcome, error) {
	p, err := v.person(ctx)
	if err != nil {
		return PublishOutcome{}, err
	}
	target, err := v.Store.Version(ctx, p.org, to)
	if err != nil {
		return PublishOutcome{}, err
	}
	tb, err := decodeStored(target.Bundle)
	if err != nil {
		return PublishOutcome{}, err
	}
	var current *domain.Bundle
	cur, err := v.Store.PublishedVersion(ctx, p.org)
	if err != nil {
		return PublishOutcome{}, err
	}
	if cur != nil {
		if current, err = decodeStored(cur.Bundle); err != nil {
			return PublishOutcome{}, err
		}
		if expected != nil && *expected != cur.ID {
			return PublishOutcome{}, ErrPublishedChanged
		}
	} else if expected != nil && !expected.IsZero() {
		return PublishOutcome{}, ErrPublishedChanged
	}
	next, carried := tb, []string(nil)
	if current != nil {
		next, carried = domain.CarryEmergency(current, tb)
	}
	if err := v.compile(ctx, p.org, next); err != nil {
		return PublishOutcome{}, err
	}
	ev := &audit.Event{
		Name: "policy.version_created", Actor: p.actor, Outcome: audit.Success, ReasonCode: "ROLLBACK",
		Object: &audit.Object{Type: "policy", ID: next.ID},
	}
	id, _, err := v.Store.CreateVersion(ctx, p.org, next, p.id, ev)
	if errors.Is(err, domain.ErrInvalid) {
		return PublishOutcome{}, invalidBundle(err)
	}
	if err != nil {
		return PublishOutcome{}, err
	}
	var exp *ids.UUID
	if cur != nil {
		exp = &cur.ID
	} else {
		exp = &ids.UUID{}
	}
	return v.gate(ctx, p, id, exp, carried)
}

// Seed creates b as a version and publishes it through the gate for the
// dev seed, which is its author and publisher of record (D10). A seed that
// would loosen the published policy is refused: only people confirm that.
func (v *Versions) Seed(ctx context.Context, org ids.OrgID, b *domain.Bundle, actor evdomain.Actor) (ids.UUID, error) {
	if err := v.gateReady(); err != nil {
		return ids.UUID{}, err
	}
	if err := v.compile(ctx, org, b); err != nil {
		return ids.UUID{}, err
	}
	id, _, err := v.Store.CreateVersion(ctx, org, b, actor.ID, &audit.Event{
		Name: "policy.version_created", Actor: actor, Outcome: audit.Success, Object: &audit.Object{Type: "policy", ID: b.ID},
	})
	if err != nil {
		return ids.UUID{}, err
	}
	out, err := v.gate(ctx, publisher{org: org, id: actor.ID, actor: actor}, id, nil, nil)
	if err != nil {
		return id, err
	}
	if out.Version.State != StatePublished {
		return id, ErrSeedLoosens
	}
	return id, nil
}

// Diff compares two versions (policy.read at the org): from (nil: the
// published version, or none) to to, rule by rule (D3), with the outcome
// changes over validation's samples when the server has them.
func (v *Versions) Diff(ctx context.Context, from *ids.UUID, to ids.UUID) (domain.Diff, []byte, error) {
	c, err := v.caller(ctx, PermPolicyRead)
	if err != nil {
		return domain.Diff{}, nil, err
	}
	target, err := v.Store.Version(ctx, c.Org, to)
	if err != nil {
		return domain.Diff{}, nil, err
	}
	next, err := decodeStored(target.Bundle)
	if err != nil {
		return domain.Diff{}, nil, err
	}
	var base *domain.Bundle
	switch {
	case from != nil:
		f, err := v.Store.Version(ctx, c.Org, *from)
		if err != nil {
			return domain.Diff{}, nil, err
		}
		if base, err = decodeStored(f.Bundle); err != nil {
			return domain.Diff{}, nil, err
		}
	default:
		cur, err := v.Store.PublishedVersion(ctx, c.Org)
		if err != nil {
			return domain.Diff{}, nil, err
		}
		if cur != nil {
			if base, err = decodeStored(cur.Bundle); err != nil {
				return domain.Diff{}, nil, err
			}
		}
	}
	d := domain.Compare(base, next)
	if v.Outcomes == nil {
		return d, nil, nil
	}
	outcomes, err := v.Outcomes.OutcomeDiff(ctx, c.Org, base, next)
	return d, outcomes, err
}

// OutcomeDiffer returns, as JSON, the decisions that change between two
// bundles over validation's samples (D8).
type OutcomeDiffer interface {
	OutcomeDiff(ctx context.Context, org ids.OrgID, base, next *domain.Bundle) ([]byte, error)
}

// ApplyPublish is the PUBLISH change requests' apply callback: on the last
// confirmation, the version is published in the approving transaction if
// its newest passing test run ran against the org's current definitions
// and catalog (else the request is voided, STALE_TESTS), superseding the
// request's base (D6, D11).
func (v *Versions) ApplyPublish(ctx context.Context, tx db.TenantTx, req ChangeRequest) error {
	caller, err := tapp.CallerFrom(ctx)
	if err != nil {
		return err
	}
	info, err := v.Store.VersionInTx(ctx, tx, caller.Org, req.Subject)
	if err != nil {
		return err
	}
	var digest [32]byte
	if len(info.ContentDigest) != len(digest) {
		return ErrLegacyVersion
	}
	copy(digest[:], info.ContentDigest)
	run, err := CheckTestsCurrent(ctx, tx, caller.Org, req.Subject, req)
	if err != nil {
		return err
	}
	ev := &audit.Event{
		Name: "policy.published", Actor: caller.Actor(), Outcome: audit.Success,
		Object:  &audit.Object{Type: "policy", ID: info.BundleID},
		Details: map[string]string{"change_request": req.ID.String(), "requested_by": req.RequestedBy},
	}
	err = v.Store.PublishTestedInTx(ctx, tx, caller.Org, PublishRequest{
		Version: req.Subject, Digest: digest, TestRun: run, Base: req.Base, PublishedBy: req.RequestedBy, Event: ev,
		Hook: v.OnPublished,
	})
	if errors.Is(err, ErrPublishedChanged) {
		return &VoidError{Reason: VoidBaseChanged}
	}
	return err
}
