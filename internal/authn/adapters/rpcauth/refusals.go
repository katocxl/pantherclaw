// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rpcauth

import (
	"context"
	"log/slog"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// RefusalName is the audit event of a human-only refusal (G0 M10 D67).
const RefusalName = "rpc.human_only_refused"

// AuditRefusals writes rpc.human_only_refused in a small tenant
// transaction of its own, once per (org, actor, procedure) per minute, so a
// flood of refused calls cannot fill the ledger. A failed write is logged;
// the caller is refused either way.
type AuditRefusals struct {
	Pool *db.Pool
	Log  *slog.Logger

	once audit.Once
}

var _ RefusalRecorder = (*AuditRefusals)(nil)

// HumanOnlyRefused implements RefusalRecorder.
func (r *AuditRefusals) HumanOnlyRefused(ctx context.Context, c tapp.Caller, procedure string, perm td.Permission) {
	if r == nil || r.Pool == nil {
		return
	}
	actor := c.Actor()
	if !r.once.First(c.Org.String() + "|" + actor.Type + ":" + actor.ID + "|" + procedure) {
		return
	}
	err := r.Pool.InTenantTx(context.WithoutCancel(ctx), c.Org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := audit.Record(ctx, tx, audit.Event{
			Name: RefusalName, Actor: actor, Outcome: audit.Denied, ReasonCode: "HUMAN_ONLY",
			Details: map[string]string{"procedure": procedure, "permission": string(perm), "auth_kind": string(c.Credential)},
		})
		return err
	})
	if err != nil {
		log := r.Log
		if log == nil {
			log = pclog.Discard()
		}
		log.WarnContext(ctx, "rpc.human_only_refusal_not_audited", slog.String("procedure", procedure), pclog.Err(err))
	}
}
