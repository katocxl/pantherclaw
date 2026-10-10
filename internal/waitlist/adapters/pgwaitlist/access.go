// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgwaitlist

import (
	"context"
	"errors"
	"strconv"

	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	wdomain "github.com/katocxl/pantherclaw/internal/waitlist/domain"
)

// ErrAccessRequestNotOpen: the entry is not an open access request (for
// this grant).
var ErrAccessRequestNotOpen = errors.New("waitlist: not an open access request")

// AccessRequest is an access request to open (decision 10, F051).
type AccessRequest struct {
	Run, Agent, Grant ids.UUID
	GrantRevision     int
	// Transaction is the denied transaction it is about, if any, and
	// Reason that denial's decisive reason.
	Transaction *ids.UUID
	Reason      string
	// RequestedBy is "user:<id>" or "instance:<id>".
	RequestedBy string
	// Note is UNTRUSTED: shown only to people, in the untrusted block.
	Note string
}

// OpenAccessRequest opens the ACCESS_REQUEST entry of a run's grant, or
// returns the grant's open one. It grants nothing (F051): a grant revision
// citing the entry settles it, or a grant.issue holder dismisses it, within
// 7 days.
func OpenAccessRequest(ctx context.Context, tx db.TenantTx, org ids.OrgID, a AccessRequest, actor evdomain.Actor) (ids.UUID, error) {
	trusted := map[string]string{"grant": a.Grant.String(), "grant_revision": strconv.Itoa(a.GrantRevision)}
	if a.Transaction != nil {
		trusted["transaction"], trusted["reason"] = a.Transaction.String(), a.Reason
	}
	return open(ctx, tx, org, entry{
		kind: wdomain.KindAccessRequest, subjectType: "grant", subject: a.Grant, agent: &a.Agent, run: &a.Run,
		txn: a.Transaction, requestedBy: &a.RequestedBy, trusted: trusted, untrusted: map[string]string{"note": a.Note},
	}, actor)
}

// SettleAccessRequest closes an open access request of grant as APPROVED,
// in the transaction of the grant revision that cites it (HR-176), or
// returns ErrAccessRequestNotOpen.
func SettleAccessRequest(ctx context.Context, tx db.TenantTx, org ids.OrgID, entry, grant ids.UUID, by string, revision int) error {
	return settle(ctx, tx, org, entry, grant, wdomain.StateApproved, by, "revision "+strconv.Itoa(revision))
}

// DismissAccessRequest closes an open access request of grant as REJECTED
// without changing the grant, or returns ErrAccessRequestNotOpen.
func DismissAccessRequest(ctx context.Context, tx db.TenantTx, org ids.OrgID, entry, grant ids.UUID, by, reason string) error {
	return settle(ctx, tx, org, entry, grant, wdomain.StateRejected, by, reason)
}

func settle(ctx context.Context, tx db.TenantTx, org ids.OrgID, entry, grant ids.UUID, state, by, reason string) error {
	n, err := dbq.New(tx).SettleAccessRequest(ctx, dbq.SettleAccessRequestParams{
		State: state, DecidedBy: &by, Reason: reason, OrgID: org, ID: entry, GrantID: grant,
	})
	if err == nil && n == 0 {
		return ErrAccessRequestNotOpen
	}
	return err
}
