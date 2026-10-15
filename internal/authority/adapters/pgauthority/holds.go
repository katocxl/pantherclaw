// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgauthority

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Hold implements pipeline.Reader.
func (r *Reader) Hold(ctx context.Context, org ids.OrgID, run, action ids.UUID) (*pipeline.HoldRequest, error) {
	return read(ctx, r, org, func(ctx context.Context, s *snapshot) (*pipeline.HoldRequest, error) {
		return s.Hold(ctx, org, run, action)
	})
}

// Variants implements pipeline.Reader.
func (r *Reader) Variants(ctx context.Context, org ids.OrgID, key [32]byte, operation string, target actionir.Target, now time.Time) (
	[]apdomain.VariantLine, []apdomain.ContextLine, error,
) {
	type pair struct {
		v []apdomain.VariantLine
		c []apdomain.ContextLine
	}
	p, err := read(ctx, r, org, func(ctx context.Context, s *snapshot) (pair, error) {
		v, c, err := s.Variants(ctx, org, key, operation, target, now)
		return pair{v, c}, err
	})
	return p.v, p.c, err
}

// HoldSettings implements pipeline.Reader.
func (r *Reader) HoldSettings(ctx context.Context, org ids.OrgID) (pipeline.HoldSettings, error) {
	return read(ctx, r, org, func(ctx context.Context, s *snapshot) (pipeline.HoldSettings, error) {
		return s.HoldSettings(ctx, org)
	})
}

// storedDisplay is the part of a stored display a resubmission renders
// again: the variants and context it was rendered with.
type storedDisplay struct {
	Variants []apdomain.VariantLine `json:"variants"`
	Context  []apdomain.ContextLine `json:"context_not_precedent"`
}

// Hold implements pipeline.Reader: the latest request of the transaction
// for (run, action).
func (s *snapshot) Hold(ctx context.Context, org ids.OrgID, run, action ids.UUID) (*pipeline.HoldRequest, error) {
	row, err := dbq.New(s.tx).LatestApprovalRequest(ctx, org, run, action)
	if db.IsNoRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(row.Binding) != 32 {
		return nil, fmt.Errorf("authority: approval request %s has a malformed binding", row.ID)
	}
	var d storedDisplay
	if err := json.Unmarshal(row.Display, &d); err != nil {
		return nil, fmt.Errorf("authority: approval request %s: display: %w", row.ID, err)
	}
	out := &pipeline.HoldRequest{
		ID: row.ID, State: apdomain.State(row.State), Deadline: row.DeadlineAt, EvidenceDeadline: row.EvidenceDeadlineAt,
		ConsumeBy: row.ConsumeBy, Variants: d.Variants, Context: d.Context, Question: row.Question, ProposedParams: row.Proposed,
	}
	copy(out.Binding[:], row.Binding)
	if row.EndReason != nil {
		out.EndReason = *row.EndReason
	}
	return out, nil
}

// Variants implements pipeline.Reader.
func (s *snapshot) Variants(ctx context.Context, org ids.OrgID, key [32]byte, operation string, target actionir.Target, now time.Time) (
	[]apdomain.VariantLine, []apdomain.ContextLine, error,
) {
	q := dbq.New(s.tx)
	vs, err := q.ApprovalVariants(ctx, org, key[:])
	if err != nil {
		return nil, nil, err
	}
	out := make([]apdomain.VariantLine, 0, len(vs))
	for _, v := range vs {
		out = append(out, apdomain.VariantLine{Request: v.ID.String(), Created: v.CreatedAt.UTC().Format(time.RFC3339), State: v.State})
	}
	approved, err := q.ApprovedForTarget(ctx, dbq.ApprovedForTargetParams{
		OrgID: org, Operation: operation, TargetType: &target.Type, TargetID: &target.ID, Now: now,
	})
	if err != nil {
		return nil, nil, err
	}
	ctxLines := make([]apdomain.ContextLine, 0, len(approved))
	for _, a := range approved {
		ctxLines = append(ctxLines, apdomain.ContextLine{Request: a.ID.String(), Approved: a.ApprovedAt.UTC().Format(time.RFC3339)})
	}
	return out, ctxLines, nil
}

// HoldSettings implements pipeline.Reader.
func (s *snapshot) HoldSettings(ctx context.Context, org ids.OrgID) (pipeline.HoldSettings, error) {
	return holdSettings(ctx, s.tx, org)
}

// holdSettings reads the org's hold settings in tx (defaults when it has
// none).
func holdSettings(ctx context.Context, tx db.TenantTx, org ids.OrgID) (pipeline.HoldSettings, error) {
	row, err := dbq.New(tx).GetWaitlistSettings(ctx, org)
	if db.IsNoRows(err) {
		return pipeline.HoldSettings{}, nil
	}
	if err != nil {
		return pipeline.HoldSettings{}, err
	}
	var out pipeline.HoldSettings
	if row.HoldDeadlineS != nil {
		out.HoldDeadline = time.Duration(*row.HoldDeadlineS) * time.Second
	}
	return out, nil
}
