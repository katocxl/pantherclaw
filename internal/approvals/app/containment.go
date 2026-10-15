// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"slices"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// ErrNotContainmentHold refuses deciding, through the response service, a
// request that a HOLD_WRITES containment control did not hold.
var ErrNotContainmentHold = pcerr.New(pcerr.FailedPrecondition, "NOT_A_CONTAINMENT_HOLD",
	"the transaction's waiting request is not held by a containment control")

// containmentDecline is the decline reason the response service records.
const containmentDecline = "TOO_RISKY"

// ContainmentHold returns the live approval request of a transaction held
// by a HOLD_WRITES containment control (G0 M10 D44): one with a
// containment requirement. Any other request is ErrNotContainmentHold.
func (s *Service) ContainmentHold(ctx context.Context, org ids.OrgID, transaction ids.UUID) (ids.UUID, error) {
	var id ids.UUID
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).LiveRequestOfTransaction(ctx, org, &transaction)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		var reqs []apdomain.Requirement
		if err := json.Unmarshal(row.Requirements, &reqs); err != nil {
			return err
		}
		if !slices.ContainsFunc(reqs, func(r apdomain.Requirement) bool { return r.Kind == apdomain.KindContainment }) {
			return ErrNotContainmentHold
		}
		id = row.ID
		return nil
	})
	return id, err
}

// DeclineContainmentHold declines a write held by a containment control
// (G0 M10 D44): the caller must be a person who may decide its containment
// requirement (incident.respond, independent of the run, the agent's owners
// and the grant's issuers), which approval.respond alone does not give. The
// held action ends as DENY (APPROVAL_DECLINED) at its next resubmission.
// Approving needs a security-key binding ceremony, so it happens on the
// approval page, which checks the same eligibility.
func (s *Service) DeclineContainmentHold(ctx context.Context, transaction ids.UUID, note string) (Request, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Request{}, err
	}
	if len([]rune(note)) > apdomain.MaxNote {
		return Request{}, ErrInvalidCode
	}
	id, err := s.ContainmentHold(ctx, c.Org, transaction)
	if err != nil {
		return Request{}, err
	}
	reason := containmentDecline
	return s.end(ctx, id, dbq.InsertApprovalResponseParams{Kind: "DECLINE", ReasonCode: &reason, Note: note},
		apdomain.EndDeclined, "approval.declined", reason)
}
