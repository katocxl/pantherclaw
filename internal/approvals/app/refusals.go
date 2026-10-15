// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// refusedError is ErrNotEligible with the eligibility reason, so the
// refusal can be audited after its transaction rolled back (G0 M10 D59
// H2: an excluded responder, such as the action's launcher, trying to
// approve is what pc.authority.self_approve detects).
type refusedError struct {
	reason  string
	request ids.UUID
}

func (e refusedError) Error() string { return ErrNotEligible.Error() }

func (e refusedError) Unwrap() error { return ErrNotEligible }

// notEligible returns ErrNotEligible carrying the reason the person fails
// the first requirement they could not meet.
func notEligible(request ids.UUID, reqs []apdomain.Requirement, me apdomain.Person, c apdomain.Context, cred ids.UUID) error {
	for _, r := range reqs {
		if ok, reason := apdomain.Check(r, me, c, cred); !ok && reason != "" {
			return refusedError{reason: reason, request: request}
		}
	}
	return ErrNotEligible
}

// recordRefusal audits an ineligible response as
// approval.response_refused with its reason code, in a transaction of its
// own, and returns err unchanged.
func (s *Service) recordRefusal(ctx context.Context, org ids.OrgID, user ids.UUID, err error) error {
	var r refusedError
	if !errors.As(err, &r) || s.Pool == nil {
		return err
	}
	request := r.request
	// Once per (org, responder, request) per minute (D74).
	if !refusalsOnce.First(org.String() + "|" + user.String() + "|" + request.String()) {
		return err
	}
	if aerr := s.Pool.InTenantTx(context.WithoutCancel(ctx), org, func(ctx context.Context, tx db.TenantTx) error {
		details := map[string]string{"user": user.String()}
		if row, err := dbq.New(tx).GetApprovalRequest(ctx, org, request); err == nil {
			details["agent"], details["operation"] = row.AgentID.String(), row.Operation
		}
		_, err := audit.Record(ctx, tx, audit.Event{
			Name: "approval.response_refused", Actor: userActor(user), Outcome: audit.Denied, ReasonCode: r.reason,
			Object: &audit.Object{Type: "approval_request", ID: request.String()}, Details: details,
		})
		return err
	}); aerr != nil {
		return errors.Join(err, aerr)
	}
	return err
}

// refusalsOnce deduplicates refused-response audits across the process.
var refusalsOnce audit.Once
