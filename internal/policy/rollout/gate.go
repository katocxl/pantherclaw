// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rollout

import (
	"context"
	"encoding/json/v2"
	"errors"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// VersionsGate is the publish gate (D6) and the change requests (D11) of
// the policy versions, as rollouts use them (D12): a pilot runs the gate
// without publishing and, when its version loosens the published one,
// waits for a ROLLOUT change request; a completion publishes through the
// gate. Connect wires its hooks into the versions.
type VersionsGate struct {
	Versions *papp.Versions
	Service  *Service
}

var _ Gate = VersionsGate{}

// Void reason of a ROLLOUT change request whose rollout left SHADOW.
const voidRolloutStage = "ROLLOUT_NOT_IN_SHADOW"

// PilotSummary is what a ROLLOUT change request shows its confirmers and
// what its apply enters: the rollout, its version, the cohorts the version
// would be enforced for, and every classified change against the base.
type PilotSummary struct {
	RolloutID     string           `json:"rollout_id"`
	VersionID     string           `json:"version_id"`
	BundleID      string           `json:"bundle_id"`
	Version       int              `json:"version"`
	BaseVersionID string           `json:"base_version_id,omitzero"`
	Cohorts       []PilotCohort    `json:"cohorts"`
	Direction     string           `json:"direction"`
	Changes       []papp.ChangeRow `json:"changes"`
}

// PilotCohort is one cohort a pilot enforces its version for.
type PilotCohort struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Connect makes the rollouts part of the versions' gate: every publication
// records its rollout (OnPublished) and an approved ROLLOUT change request
// enters its pilot. It returns the gate for the service.
func Connect(v *papp.Versions, svc *Service) VersionsGate {
	g := VersionsGate{Versions: v, Service: svc}
	v.OnPublished = func(ctx context.Context, tx db.TenantTx, org ids.OrgID, version, base ids.UUID) error {
		return svc.Published(ctx, tx, org, version, optional(base))
	}
	if v.Changes != nil {
		v.Changes.Register(papp.ChangeRollout, g.ApplyPilot)
	}
	return g
}

func optional(id ids.UUID) *ids.UUID {
	if id.IsZero() {
		return nil
	}
	return &id
}

// CheckPilot implements Gate.
func (g VersionsGate) CheckPilot(ctx context.Context, rollout, version ids.UUID, base *ids.UUID, cohorts []RolloutCohort) (*ChangeRequest, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	chk, err := g.Versions.CheckForRollout(ctx, version)
	if err != nil {
		return nil, err
	}
	if !sameVersion(optional(chk.Base), base) {
		return nil, ErrBaseChanged
	}
	if !chk.Diff.Loosens() {
		return nil, nil //nolint:nilnil // the pilot starts now
	}
	if g.Versions.Changes == nil {
		return nil, ErrGateMissing
	}
	summary := PilotSummary{
		RolloutID: rollout.String(), VersionID: version.String(), BundleID: chk.Version.BundleID, Version: chk.Version.Version,
		Cohorts: make([]PilotCohort, 0, len(cohorts)), Direction: string(chk.Diff.Direction), Changes: papp.ChangeRows(chk.Diff),
	}
	if !chk.Base.IsZero() {
		summary.BaseVersionID = chk.Base.String()
	}
	for _, co := range cohorts {
		summary.Cohorts = append(summary.Cohorts, PilotCohort{ID: co.ID.String(), Name: co.Name})
	}
	binding, err := papp.ChangeBinding(papp.ChangeRollout, c.Org, rollout, chk.Base, chk.Digest, summary)
	if err != nil {
		return nil, err
	}
	req, err := g.Versions.Changes.Request(ctx, papp.ChangeRollout, rollout, chk.Base, binding, summary)
	if err != nil {
		return nil, err
	}
	return &ChangeRequest{ID: req.ID, URL: req.URL}, nil
}

// ApplyPilot is the ROLLOUT change requests' apply callback (D11): on the
// last confirmation, in the approving transaction, the version's newest
// passing test run must have run against the org's current definitions and
// catalog (else STALE_TESTS), the request's base must still be published
// and the rollout's (else BASE_CHANGED), and the rollout must still be in
// SHADOW; then the pilot starts for the confirmed cohorts.
func (g VersionsGate) ApplyPilot(ctx context.Context, tx db.TenantTx, req papp.ChangeRequest) error {
	caller, err := tapp.CallerFrom(ctx)
	if err != nil {
		return err
	}
	var s PilotSummary
	if err := json.Unmarshal(req.Summary, &s); err != nil {
		return err
	}
	version, err := ids.ParseUUID(s.VersionID)
	if err != nil {
		return err
	}
	if _, err := papp.CheckTestsCurrent(ctx, tx, caller.Org, version, req); err != nil {
		return err
	}
	cohorts := make([]ids.UUID, 0, len(s.Cohorts))
	for _, co := range s.Cohorts {
		id, err := ids.ParseUUID(co.ID)
		if err != nil {
			return err
		}
		cohorts = append(cohorts, id)
	}
	err = g.Service.EnterPilot(ctx, tx, caller.Actor(), req.Subject, optional(req.Base), cohorts)
	switch {
	case errors.Is(err, ErrBaseChanged):
		return &papp.VoidError{Reason: papp.VoidBaseChanged}
	case errors.Is(err, ErrStage):
		return &papp.VoidError{Reason: voidRolloutStage}
	}
	return err
}

// Publish implements Gate.
func (g VersionsGate) Publish(ctx context.Context, version ids.UUID, base *ids.UUID) (*ChangeRequest, error) {
	var expected ids.UUID
	if base != nil {
		expected = *base
	}
	out, err := g.Versions.PublishExpecting(ctx, version, &expected)
	if errors.Is(err, papp.ErrPublishedChanged) {
		return nil, ErrBaseChanged
	}
	if err != nil || out.ChangeRequest == nil {
		return nil, err
	}
	return &ChangeRequest{ID: out.ChangeRequest.ID, URL: out.ChangeRequest.URL}, nil
}
