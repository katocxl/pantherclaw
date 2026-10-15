// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"context"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	rdomain "github.com/katocxl/pantherclaw/internal/response/domain"
)

// SOAR results (D26, HR-251): PARTIAL and REQUESTED are UNKNOWN, with the
// paths.
const (
	SOARConfirmed   = "CONFIRMED"
	SOARFailed      = "FAILED"
	SOARUnsupported = "UNSUPPORTED"
	SOARUnknown     = "UNKNOWN"
)

// Errors of SOAR requests.
var (
	ErrSOARScope = pcerr.New(pcerr.InvalidArgument, "SOAR_SCOPE",
		"a SOAR request contains one run, agent, grant or connection; wider scopes, the kill switch and restoration are for people")
	ErrSOARKey = pcerr.New(pcerr.InvalidArgument, "IDEMPOTENCY_KEY_REQUIRED", "an idempotency key of 1 to 128 characters is required")
)

// SOARRequest is RequestControl's input (D26).
type SOARRequest struct {
	Key       string
	Scope     reflexdomain.Subject
	Control   string
	Operation string
	Reason    string
	// Requester is the caller ("service_account:<id>" or "user:<id>").
	Requester reflexdomain.Subject
}

// SOARResult is the action a request created and its SOAR result.
type SOARResult struct {
	ActionID ids.UUID
	Result   string
	// Replayed is set when the key was used before for the same request.
	Replayed bool
}

// SOARResultOf maps an action status to a SOAR result.
func SOARResultOf(s rdomain.Status) string {
	switch s {
	case rdomain.StatusConfirmed:
		return SOARConfirmed
	case rdomain.StatusFailed:
		return SOARFailed
	case rdomain.StatusUnsupported:
		return SOARUnsupported
	case rdomain.StatusRequested, rdomain.StatusPartial:
	}
	return SOARUnknown
}

// RequestControlIn adds a narrow control for a SOAR integration in tx (D26,
// HR-251): one run, agent, grant or connection, never the kill switch and
// never a lift. It is idempotent on the key: the same canonical request
// returns its action again; a different one is refused ALREADY_EXISTS.
// The action records source SOAR, its scope and its reason, and is audited.
func (s *Containment) RequestControlIn(ctx context.Context, tx db.TenantTx, r SOARRequest) (SOARResult, error) {
	org := tx.OrgID()
	if n := utf8.RuneCountInString(r.Key); n < 1 || n > 128 || !utf8.ValidString(r.Key) {
		return SOARResult{}, ErrSOARKey
	}
	scopeType, scopeID, err := scopeOf(r.Scope)
	if err != nil {
		return SOARResult{}, ErrSOARScope
	}
	switch scopeType {
	case rdomain.ScopeRun, rdomain.ScopeAgent, rdomain.ScopeGrant, rdomain.ScopeConnection:
	default:
		return SOARResult{}, ErrSOARScope
	}
	c := rdomain.Control{ScopeType: scopeType, ScopeID: scopeID, Control: r.Control, Operation: r.Operation, Reason: r.Reason}
	if err := c.Validate(); err != nil {
		return SOARResult{}, err
	}
	actor, _, evActor, err := actorOf(r.Requester)
	if err != nil {
		return SOARResult{}, err
	}
	q := dbq.New(tx)
	digest := requestDigest(c, nil, nil)
	prev, err := q.GetSOARRequest(ctx, org, r.Key)
	switch {
	case err == nil:
		if !bytes.Equal(prev.RequestDigest, digest) {
			return SOARResult{}, ErrIdempotency
		}
		a, err := q.GetResponseAction(ctx, org, prev.ActionID)
		if err != nil {
			return SOARResult{}, err
		}
		return SOARResult{ActionID: a.ID, Result: SOARResultOf(rdomain.Status(a.Status)), Replayed: true}, nil
	case !db.IsNoRows(err):
		return SOARResult{}, err
	}
	res, err := s.contain(ctx, tx, org, c, containOpts{
		actor: actor, source: rdomain.SourceSOAR, evActor: evActor, idempotency: "soar:" + r.Key,
	})
	if err != nil {
		return SOARResult{}, err
	}
	if err := q.InsertSOARRequest(ctx, dbq.InsertSOARRequestParams{
		OrgID: org, IdempotencyKey: r.Key, RequestDigest: digest, ActionID: res.ActionID, RequestedBy: actor,
	}); err != nil {
		return SOARResult{}, err
	}
	return SOARResult{ActionID: res.ActionID, Result: SOARResultOf(rdomain.Status(res.Status))}, nil
}
