// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rpcauth

import (
	"container/list"
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// RefusalName is the audit event of a human-only refusal (G0 M10 D67).
const RefusalName = "rpc.human_only_refused"

// Dedupe bounds: one audit entry per (org, actor, procedure) per window,
// remembering at most dedupeEntries keys.
const (
	dedupeWindow  = time.Minute
	dedupeEntries = 10_000
)

// AuditRefusals writes rpc.human_only_refused in a small tenant
// transaction of its own, once per (org, actor, procedure) per minute, so a
// flood of refused calls cannot fill the ledger. A failed write is logged;
// the caller is refused either way.
type AuditRefusals struct {
	Pool *db.Pool
	Log  *slog.Logger
	Now  func() time.Time

	mu    sync.Mutex
	order *list.List
	seen  map[string]*list.Element
}

type seenEntry struct {
	key string
	at  time.Time
}

var _ RefusalRecorder = (*AuditRefusals)(nil)

// HumanOnlyRefused implements RefusalRecorder.
func (r *AuditRefusals) HumanOnlyRefused(ctx context.Context, c tapp.Caller, procedure string, perm td.Permission) {
	if r == nil || r.Pool == nil {
		return
	}
	actor := c.Actor()
	if !r.first(c.Org.String() + "|" + actor.Type + ":" + actor.ID + "|" + procedure) {
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

// first reports whether key was not recorded within the window, and
// remembers it, evicting the least recently recorded key beyond the bound.
func (r *AuditRefusals) first(key string) bool {
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen == nil {
		r.seen, r.order = map[string]*list.Element{}, list.New()
	}
	if el, ok := r.seen[key]; ok {
		e := el.Value.(*seenEntry) //nolint:forcetypeassert // only seenEntry is stored
		if now.Sub(e.at) < dedupeWindow {
			return false
		}
		e.at = now
		r.order.MoveToFront(el)
		return true
	}
	r.seen[key] = r.order.PushFront(&seenEntry{key: key, at: now})
	for r.order.Len() > dedupeEntries {
		last := r.order.Back()
		r.order.Remove(last)
		delete(r.seen, last.Value.(*seenEntry).key) //nolint:forcetypeassert // only seenEntry is stored
	}
	return true
}
