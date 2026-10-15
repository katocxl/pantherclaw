// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package feed

import (
	"context"
	"fmt"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// MaxBatch is the most events one After call returns (HR-240).
const MaxBatch = 500

// Reader reads chained ledger entries as events, in chain order, inside
// the caller's tenant transaction.
type Reader struct{}

// After returns up to limit events with seq > after, ascending. Events
// about a transaction gain its run, agent, instance, grant, principal,
// environment, operation, connection, mode and destination class. An entry
// whose body was removed (retention) or does not parse passes through with
// its kind and actor only, so one bad entry never stalls a cursor.
func (Reader) After(ctx context.Context, tx db.TenantTx, after int64, limit int) ([]Event, error) {
	if limit < 1 || limit > MaxBatch {
		return nil, fmt.Errorf("feed: limit must be 1..%d", MaxBatch)
	}
	if after < 0 {
		after = 0
	}
	org := tx.OrgID()
	q := dbq.New(tx)
	rows, err := q.ChainedLedgerEntries(ctx, org, after, int32(limit)) //nolint:gosec // G115: limit ≤ 500
	if err != nil {
		return nil, fmt.Errorf("feed: read: %w", err)
	}
	out := make([]Event, 0, len(rows))
	var txns []ids.UUID
	for _, r := range rows {
		body := r.Body
		if r.BodyRemovedAt != nil {
			body = nil
		}
		e, err := Normalize(r.Kind, r.ActorType, r.ActorID, r.OccurredAt, body)
		if err != nil {
			e.Attrs = map[string]string{"malformed": "true"}
		}
		e.Seq, e.ID, e.Org = r.Seq, r.ID, org
		if t, ok := e.Subject(reflexdomain.SubjectTransaction); ok {
			if id, err := ids.ParseUUID(t); err == nil {
				txns = append(txns, id)
			}
		}
		out = append(out, e)
	}
	if len(txns) == 0 {
		return out, nil
	}
	ctxRows, err := q.FeedTransactions(ctx, org, txns)
	if err != nil {
		return nil, fmt.Errorf("feed: transactions: %w", err)
	}
	byID := make(map[string]dbq.FeedTransactionsRow, len(ctxRows))
	for _, r := range ctxRows {
		byID[r.ID.String()] = r
	}
	for i := range out {
		t, ok := out[i].Subject(reflexdomain.SubjectTransaction)
		if !ok {
			continue
		}
		if r, ok := byID[t]; ok {
			enrich(&out[i], r)
		}
	}
	return out, nil
}

// Head returns the seq of the org's last chained entry, 0 when none.
func (Reader) Head(ctx context.Context, tx db.TenantTx) (int64, error) {
	seq, err := dbq.New(tx).FeedHead(ctx, tx.OrgID())
	if err != nil {
		return 0, fmt.Errorf("feed: head: %w", err)
	}
	return seq, nil
}

func enrich(e *Event, r dbq.FeedTransactionsRow) {
	add := func(t reflexdomain.SubjectType, id *ids.UUID) {
		if id != nil && !id.IsZero() {
			e.Subjects = appendID(e.Subjects, t, id.String())
		}
	}
	add(reflexdomain.SubjectRun, &r.RunID)
	add(reflexdomain.SubjectAgent, &r.AgentID)
	add(reflexdomain.SubjectInstance, r.InstanceID)
	add(reflexdomain.SubjectGrant, r.GrantID)
	add(reflexdomain.SubjectUser, r.PrincipalUserID)
	add(reflexdomain.SubjectServiceAccount, r.PrincipalSaID)
	add(reflexdomain.SubjectConnection, r.ConnectionID)
	e.Subjects = dedupe(e.Subjects)
	e.Operation, e.Environment, e.DestinationClass = r.Operation, r.EnvironmentID.String(), r.DestinationClass
	if e.Mode == "" {
		e.Mode = upper(r.Mode)
	}
	if e.Attrs == nil {
		e.Attrs = map[string]string{}
	}
	e.Attrs["depth"] = strconv.Itoa(int(r.Depth))
	if r.ParentRunID != nil {
		e.Attrs["parent_run"] = r.ParentRunID.String()
	}
	e.Attrs = clamp(e.Attrs)
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}
