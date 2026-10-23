// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package restore re-applies the closed tightening security set under the
// maintenance hold (G0 M13 D31, D41, D48; HR-384).
package restore

import (
	"bufio"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/securityevent"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Event is the machine-only security log contract.
type Event = securityevent.Event

// Handler applies one tightening change in its organization's transaction.
type Handler func(context.Context, db.TenantTx, Event) error

// ScopedHandler is restricted to D41 deletion kinds. It explicitly owns
// the target tenant/account transactions and audits their completed work.
// Multi-org account changes resume after a failure; they are not atomic.
type ScopedHandler func(context.Context, *db.Pool, Event, domain.Actor) error

// Registry is assembled before replay. It has no ambient global state.
type Registry struct {
	handlers map[string]Handler
	scoped   map[string]ScopedHandler
}

// NewRegistry installs the core security handlers. Data deletion supplies
// the two D41 scoped handlers before a command starts replaying.
func NewRegistry() *Registry {
	r := &Registry{handlers: map[string]Handler{}, scoped: map[string]ScopedHandler{}}
	registerCore(r)
	return r
}

// Register adds a handler only for an ordinary closed tightening kind.
func (r *Registry) Register(kind string, h Handler) error {
	dir, _, ok := securityevent.Rule(kind)
	if !ok || dir != "tighten" || deletion(kind) || h == nil {
		return fmt.Errorf("restore: invalid handler kind %q", kind)
	}
	if _, exists := r.handlers[kind]; exists {
		return fmt.Errorf("restore: duplicate handler %q", kind)
	}
	r.handlers[kind] = h
	return nil
}

// RegisterScoped adds only org.deletion_started, org.deleted or account.deleted. No extension
// can introduce another cross-tenant operation through this registry.
func (r *Registry) RegisterScoped(kind string, h ScopedHandler) error {
	if !deletion(kind) || h == nil {
		return fmt.Errorf("restore: invalid scoped kind %q", kind)
	}
	if _, exists := r.scoped[kind]; exists {
		return fmt.Errorf("restore: duplicate scoped handler %q", kind)
	}
	r.scoped[kind] = h
	return nil
}

func deletion(kind string) bool {
	return kind == "org.deleted" || kind == "account.deleted" || kind == "org.deletion_started"
}

// Parse validates the entire bounded input before any state changes. Input
// may be extracted security lines or full operational logs: a line with
// an explicit event other than security_event is ignored. Unknown security
// kinds and malformed records fail, even when --since would omit them.
func (r *Registry) Parse(input io.Reader, since time.Time) ([]Event, error) {
	const maxInput = 64 << 20
	limited := &io.LimitedReader{R: input, N: maxInput + 1}
	scan := bufio.NewScanner(limited)
	scan.Buffer(make([]byte, 4096), 16<<10)
	var events []Event
	seen := map[string]Event{}
	for line := 1; scan.Scan(); line++ {
		if len(strings.TrimSpace(scan.Text())) == 0 {
			continue
		}
		var header struct {
			Event string `json:"event"`
		}
		if err := json.Unmarshal(scan.Bytes(), &header); err != nil {
			return nil, fmt.Errorf("restore: line %d: invalid JSON", line)
		}
		if header.Event != "" && header.Event != "security_event" {
			continue
		}
		var e Event
		if err := json.Unmarshal(scan.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("restore: line %d: invalid security event", line)
		}
		if err := r.validate(e); err != nil {
			return nil, fmt.Errorf("restore: line %d: %w", line, err)
		}
		key := e.Org.String() + "/" + strconv.FormatInt(e.LedgerSeq, 10)
		if previous, exists := seen[key]; exists {
			p, _ := json.Marshal(previous)
			b, _ := json.Marshal(e)
			if string(p) != string(b) {
				return nil, fmt.Errorf("restore: conflicting entry at %s", key)
			}
			continue
		}
		seen[key] = e
		if len(seen) > 100000 {
			return nil, errors.New("restore: input exceeds 100000 security events")
		}
		if e.Direction == "tighten" && !e.Timestamp.Before(since) {
			events = append(events, e)
		}
	}
	if err := scan.Err(); err != nil {
		return nil, fmt.Errorf("restore: read input: %w", err)
	}
	if limited.N <= 0 {
		return nil, errors.New("restore: input exceeds 64 MiB")
	}
	slices.SortStableFunc(events, func(a, b Event) int {
		if c := strings.Compare(a.Org.String(), b.Org.String()); c != 0 {
			return c
		}
		if a.LedgerSeq < b.LedgerSeq {
			return -1
		}
		if a.LedgerSeq > b.LedgerSeq {
			return 1
		}
		return 0
	})
	return events, nil
}

func (r *Registry) validate(e Event) error {
	if err := securityevent.Validate(e); err != nil {
		return err
	}
	if err := validateContainment(e); err != nil {
		return err
	}
	if e.Direction == "tighten" {
		if deletion(e.Kind) {
			if r.scoped[e.Kind] == nil {
				return fmt.Errorf("restore: no scoped handler for %s", e.Kind)
			}
		} else if r.handlers[e.Kind] == nil {
			return fmt.Errorf("restore: no handler for %s", e.Kind)
		}
	}
	return nil
}

// Reapply validates every record again, then applies ordinary changes in
// one tenant transaction per org, with the operator audit in that same tx.
// A failed scoped deletion is returned to the operator; the hold stays on.
func (r *Registry) Reapply(ctx context.Context, pool *db.Pool, events []Event, hold bool, operator domain.Actor) error {
	if !hold {
		return errors.New("restore: maintenance.hold must be on")
	}
	if operator.Type != "operator" || operator.ID == "" {
		return errors.New("restore: an operator actor is required")
	}
	for _, e := range events {
		if err := r.validate(e); err != nil {
			return err
		}
	}
	groups := map[ids.OrgID][]Event{}
	var order []ids.OrgID
	for _, e := range events {
		if e.Direction != "tighten" || deletion(e.Kind) {
			continue
		}
		if _, exists := groups[e.Org]; !exists {
			order = append(order, e.Org)
		}
		groups[e.Org] = append(groups[e.Org], e)
	}
	for _, org := range order {
		entries := groups[org]
		if err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			for _, e := range entries {
				if err := r.handlers[e.Kind](ctx, tx, e); err != nil {
					return fmt.Errorf("restore: %s sequence %d: %w", e.Kind, e.LedgerSeq, err)
				}
			}
			return Audit(ctx, tx, entries, operator)
		}); err != nil {
			return err
		}
	}
	for _, e := range events {
		if e.Direction == "tighten" && deletion(e.Kind) {
			if err := r.scoped[e.Kind](ctx, pool, e, operator); err != nil {
				return fmt.Errorf("restore: %s sequence %d: %w", e.Kind, e.LedgerSeq, err)
			}
		}
	}
	return nil
}

// Audit records completed replay work. Scoped handlers may reuse it in
// their target tenant tx only after their required mutations complete.
func Audit(ctx context.Context, tx db.TenantTx, entries []Event, operator domain.Actor) error {
	if len(entries) == 0 {
		return nil
	}
	first, last := entries[0].LedgerSeq, entries[0].LedgerSeq
	for _, e := range entries {
		first = min(first, e.LedgerSeq)
		last = max(last, e.LedgerSeq)
	}
	details := map[string]string{"count": strconv.Itoa(len(entries)), "first_seq": strconv.FormatInt(first, 10), "last_seq": strconv.FormatInt(last, 10)}
	local, noLocal := 0, 0
	for _, e := range entries {
		if e.Kind != "response.credential_revoked" {
			continue
		}
		connection, version, _ := strings.Cut(e.Object.ID, "/")
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pc.credentials WHERE org_id=$1 AND connection_id=$2::uuid AND version=$3::integer)`, tx.OrgID(), connection, version).Scan(&exists); err != nil {
			return err
		}
		if exists {
			local++
		} else {
			noLocal++
		}
	}
	if local+noLocal > 0 {
		details["credential_local"] = strconv.Itoa(local)
		details["credential_no_local_material"] = strconv.Itoa(noLocal)
	}
	_, err := audit.Record(ctx, tx, audit.Event{Name: "restore.reapplied", Actor: operator, Outcome: audit.Success, Object: &audit.Object{Type: "org", ID: tx.OrgID().String()}, Details: details})
	return err
}
