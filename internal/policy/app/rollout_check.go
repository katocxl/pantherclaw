// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// RolloutCheck is the publish gate's verdict on a version a pilot would
// enforce (G0 M11.1, D12): it validated and its tests passed now (both
// recorded), and Diff classifies it against Base, the published version
// (zero: none).
type RolloutCheck struct {
	Version    VersionInfo
	Digest     [32]byte
	Base       ids.UUID
	Diff       domain.Diff
	Validation domain.ValidationResult
	Tests      domain.TestResult
}

// CheckForRollout runs the publish gate's steps 1 to 4 (D6) on a version
// without publishing it, for a pilot (policy.publish at the org, human
// only): validation and tests again with the current definitions and
// catalog, recorded and advancing the version's state as they pass, then
// the classification against the published version. A version that drops
// or changes an emergency rule of the published one needs incident.respond
// too (D4). A failed validation or test run refuses with a *GateError.
func (v *Versions) CheckForRollout(ctx context.Context, id ids.UUID) (RolloutCheck, error) {
	p, err := v.person(ctx)
	if err != nil {
		return RolloutCheck{}, err
	}
	if err := v.gateReady(); err != nil {
		return RolloutCheck{}, err
	}
	info, err := v.Store.Version(ctx, p.org, id)
	if err != nil {
		return RolloutCheck{}, err
	}
	if !unpublished(info.State) {
		return RolloutCheck{}, ErrNotDraft
	}
	b, digest, err := storedVersion(info)
	if err != nil {
		return RolloutCheck{}, err
	}
	if err := v.compile(ctx, p.org, b); err != nil {
		return RolloutCheck{}, err
	}
	out := RolloutCheck{Digest: digest}
	if out.Validation, err = v.validate(ctx, p.org, info, b, digest, p.id); err != nil {
		return out, err
	}
	if out.Tests, _, err = v.test(ctx, p.org, info, b, digest, p.id); err != nil {
		return out, err
	}
	cur, err := v.Store.PublishedVersion(ctx, p.org)
	if err != nil {
		return out, err
	}
	var published *domain.Bundle
	if cur != nil {
		out.Base = cur.ID
		if published, err = decodeStored(cur.Bundle); err != nil {
			return out, err
		}
	}
	if emergencyChanged(published, b) {
		if err := v.Authz.Require(*p.caller, tdomain.PermIncidentRespond, tdomain.OrgPath(p.org)); err != nil {
			return out, ErrEmergencyRule
		}
	}
	out.Diff = domain.Compare(published, b)
	out.Version, err = v.Store.Version(ctx, p.org, id)
	return out, err
}

// ChangeRows are a diff's changes as a change request's summary shows them.
func ChangeRows(d domain.Diff) []ChangeRow { return changeRows(d) }
