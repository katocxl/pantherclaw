// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgauthority

import (
	"context"
	"errors"

	"github.com/katocxl/pantherclaw/internal/authority/consequences"
	"github.com/katocxl/pantherclaw/internal/authority/replay"
	"github.com/katocxl/pantherclaw/internal/consequencerules"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// CustomerRules implements pipeline.Reader.
func (r *Reader) CustomerRules(ctx context.Context, org ids.OrgID) ([]consequences.Rule, error) {
	return read(ctx, r, org, func(ctx context.Context, s *snapshot) ([]consequences.Rule, error) {
		return s.CustomerRules(ctx, org)
	})
}

// CustomerRules implements pipeline.Reader: the org's ACTIVE customer
// consequence rules, each with the ACTIVE definition of its consequence
// operation (G0 M17 D106, D108).
func (s *snapshot) CustomerRules(ctx context.Context, org ids.OrgID) ([]consequences.Rule, error) {
	opened, err := consequencerules.Active(ctx, s.tx, org, s.r.Definitions)
	if err != nil {
		return nil, err
	}
	out := make([]consequences.Rule, 0, len(opened))
	for _, o := range opened {
		out = append(out, customerRule(o.Rule, o.Definition, consequences.CustomerRef{Version: o.Version, Digest: o.Digest, Pin: o.Pin}))
	}
	return out, nil
}

// customerRule is a stored customer rule version as step 6 evaluates it.
func customerRule(r defs.ConsequenceRule, d *defs.Definition, ref consequences.CustomerRef) consequences.Rule {
	return consequences.Rule{ConsequenceRule: r, Definition: d, Source: consequences.SourceCustomer, Customer: &ref}
}

// CustomerRule implements replay.Source: one recorded customer rule
// version, by id and version, whose digest must be the recorded one.
func (s *ReplaySource) CustomerRule(ctx context.Context, org ids.OrgID, ruleID string, version int, digest [32]byte) (
	defs.ConsequenceRule, error,
) {
	var out defs.ConsequenceRule
	err := s.read(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		o, err := consequencerules.OpenVersion(ctx, tx, org, s.Definitions, ruleID, version, digest)
		if errors.Is(err, consequencerules.ErrNotFound) || errors.Is(err, consequencerules.ErrInvalid) {
			return replay.ErrNotFound // not as recorded: a gap
		}
		out = o.Rule
		return err
	})
	return out, err
}
