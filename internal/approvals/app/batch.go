// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"slices"
	"strconv"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// Batch review (HR-175, decision 9) is a Team feature.
var (
	ErrEditionRequired = pcerr.New(pcerr.PermissionDenied, "EDITION_REQUIRED", "batch review needs the Team edition or above")
	ErrBatchInvalid    = pcerr.New(pcerr.InvalidArgument, "BATCH_INVALID",
		"a batch names 1 to 25 different waiting requests for one operation")
)

// Entitlements reports the current edition (billing.Service).
type Entitlements interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// teamWaitlist fails closed without entitlements wired.
func (s *Service) teamWaitlist(ctx context.Context) error {
	if s.Ents == nil {
		return ErrEditionRequired
	}
	e, err := s.Ents.Current(ctx)
	if err != nil {
		return err
	}
	if !e.TeamWaitlist() {
		return ErrEditionRequired
	}
	return nil
}

// DeclineBatch declines up to 25 waiting requests for one operation at once
// (HR-175, Team edition). Each request gets its own DECLINE response, audit
// event and outcome notice, in one transaction, and the batch is recorded
// with the hash of its bindings. Every request must be one the caller may
// decline now; otherwise nothing is declined.
func (s *Service) DeclineBatch(ctx context.Context, requests []ids.UUID, reason, note string) (ids.UUID, []Request, error) {
	if err := s.teamWaitlist(ctx); err != nil {
		return ids.UUID{}, nil, err
	}
	sorted, err := sortedBatch(requests)
	if err != nil {
		return ids.UUID{}, nil, err
	}
	if !slices.Contains(apdomain.DeclineReasons, reason) || len([]rune(note)) > apdomain.MaxNote {
		return ids.UUID{}, nil, ErrInvalidCode
	}
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return ids.UUID{}, nil, err
	}
	r, err := ResponderFrom(c)
	if err != nil {
		return ids.UUID{}, nil, err
	}
	batch := ids.NewV7()
	var out []Request
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		bindings := make([][32]byte, 0, len(sorted))
		operation := ""
		// Lock in id order, so concurrent batches never wait in a cycle.
		for _, id := range sorted {
			row, err := q.GetApprovalRequestForUpdate(ctx, c.Org, id)
			if db.IsNoRows(err) {
				return ErrNotFound
			} else if err != nil {
				return err
			}
			if operation == "" {
				operation = row.Operation
			} else if row.Operation != operation {
				return ErrBatchInvalid
			}
			var b [32]byte
			copy(b[:], row.Binding)
			bindings = append(bindings, b)
		}
		hash, err := apdomain.BatchChallenge(bindings)
		if err != nil {
			return err
		}
		browser, cli := r.sessions()
		if err := q.InsertApprovalBatch(ctx, dbq.InsertApprovalBatchParams{
			OrgID: c.Org, ID: batch, Kind: "DECLINE", UserID: r.User, SessionID: browser, CliSessionID: cli,
			BatchHash: hash.Hash[:], RequestIds: sorted, State: "COMPLETED",
		}); err != nil {
			return err
		}
		for _, id := range sorted {
			row, err := s.endIn(ctx, tx, c, r, id, dbq.InsertApprovalResponseParams{
				Kind: "DECLINE", ReasonCode: &reason, Note: note, BatchID: &batch,
			}, apdomain.EndDeclined, "approval.declined", reason)
			if err != nil {
				return err
			}
			out = append(out, row)
		}
		return event(ctx, tx, "approval.batch_declined", userActor(r.User), reason, batch,
			map[string]string{"requests": strconv.Itoa(len(sorted)), "operation": operation})
	})
	if err != nil {
		return ids.UUID{}, nil, err
	}
	return batch, out, nil
}
