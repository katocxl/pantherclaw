// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"regexp"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/extension"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Billing authority and audit for the extension (G0 UI D70): the
// extension's routes check a permission of their session principal with
// the core's own evaluation, and record billing outcomes in the org's
// evidence ledger.

// extAuthorizer is extension.Authorizer.
type extAuthorizer struct{ pool *db.Pool }

// Require reports whether the request's session principal holds permission
// somewhere in its org, as the API checks a Connect procedure's declared
// permission. An account session (no org), a disabled user or an unknown
// permission is refused.
func (a extAuthorizer) Require(ctx context.Context, permission string) error {
	perm := td.Permission(permission)
	denied := td.ErrPermissionDenied(perm)
	if !perm.Known() {
		return denied
	}
	// A session route puts the session's caller in the context, with the
	// bindings its authentication loaded.
	if c, err := tapp.CallerFrom(ctx); err == nil {
		if !c.CanAnywhere(perm) {
			return denied
		}
		return nil
	}
	p, ok := extension.PrincipalFrom(ctx)
	if !ok || p.OrgID == "" || p.UserID == "" || !perm.Known() {
		return denied
	}
	org, err := ids.Parse[ids.Org](p.OrgID)
	if err != nil {
		return denied
	}
	user, err := ids.ParseUUID(p.UserID)
	if err != nil {
		return denied
	}
	var subj td.Subject
	err = a.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		u, err := q.GetUser(ctx, org, user)
		if db.IsNoRows(err) || (err == nil && td.AccountState(u.State) != td.Enabled) {
			return denied
		} else if err != nil {
			return err
		}
		ref := td.PrincipalRef{Kind: td.KindUser, ID: user}
		bs, err := tapp.Bindings(ctx, q, org, ref)
		subj = td.Subject{Org: org, Principal: ref, Bindings: bs}
		return err
	}, db.ReadOnly())
	if err != nil {
		return err
	}
	if !subj.CanAnywhere(perm) {
		return denied
	}
	return nil
}

// errBillingAudit refuses an audit record the extension may not write.
var errBillingAudit = pcerr.New(pcerr.InvalidArgument, "INVALID_AUDIT", "billing audit records need a billing. kind and small, non-secret fields")

// billingKind is the shape of an extension audit kind (D88): "billing."
// then dotted lowercase segments, each starting with a letter.
var billingKind = regexp.MustCompile(`^billing\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)

// maxBillingKind bounds an extension audit kind in bytes (D88).
const maxBillingKind = 64

func validBillingKind(kind string) bool {
	return len(kind) <= maxBillingKind && billingKind.MatchString(kind)
}

// extAudit is extension.AuditRecorder.
type extAudit struct{ pool *db.Pool }

// Record writes a billing outcome into org's evidence ledger: kinds start
// with "billing." (validBillingKind), fields are checked like every audit detail (at most 16
// lowercase keys, none naming a secret, bounded values). The actor is the
// session principal when there is one, else the billing extension.
func (a extAudit) Record(ctx context.Context, orgID, kind string, fields map[string]string) error {
	org, err := ids.Parse[ids.Org](orgID)
	if err != nil || org == ids.PlatformOrg || !validBillingKind(kind) {
		return errBillingAudit
	}
	actor := evdomain.Actor{Type: "system", ID: "billing-extension"}
	if p, ok := extension.PrincipalFrom(ctx); ok && p.OrgID == orgID && p.UserID != "" {
		actor = evdomain.Actor{Type: string(td.KindUser), ID: p.UserID}
	}
	if fields == nil {
		fields = map[string]string{}
	}
	if err := audit.ValidateDetails(fields); err != nil {
		return errBillingAudit
	}
	return a.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := audit.Record(ctx, tx, audit.Event{
			Name: kind, Actor: actor, Outcome: audit.Success,
			Object: &audit.Object{Type: "org", ID: org.String()}, Details: fields,
		})
		if err != nil {
			return pcerr.Wrap(err, pcerr.InvalidArgument, "INVALID_AUDIT", "invalid billing audit record")
		}
		return nil
	})
}
