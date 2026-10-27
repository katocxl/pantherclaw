// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package securityevent

import (
	"context"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"

	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// OutboxBatch bounds each transaction, log burst and operator export.
const OutboxBatch = 500

// Store writes only the machine projection beside the ledger link. Any
// malformed closed event fails the whole linking transaction for retry.
func Store(ctx context.Context, tx db.TenantTx, entry domain.Entry, seq int64) error {
	e, ok, err := FromEntry(entry, seq)
	if err != nil || !ok {
		return err
	}
	payload, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return dbq.New(tx).InsertSecurityEvent(ctx, tx.OrgID(), seq, payload)
}

// Attempt commits an attempt timestamp before touching the log sink. A
// crash after this commit causes a retry after five minutes. A successful
// slog call still leaves every row unacknowledged for at-least-once delivery.
func Attempt(ctx context.Context, pool *db.Pool, org ids.OrgID) ([]Event, error) {
	var events []Event
	err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		payloads, err := dbq.New(tx).AttemptSecurityEvents(ctx, org, OutboxBatch)
		if err != nil {
			return err
		}
		for _, raw := range payloads {
			var e Event
			if err := json.Unmarshal(raw, &e); err != nil {
				return fmt.Errorf("security outbox: invalid stored event: %w", err)
			}
			if err := Validate(e); err != nil {
				return fmt.Errorf("security outbox: invalid projection for org %s: %w", org, err)
			}
			if e.Org != org {
				return fmt.Errorf("security outbox: projection of org %s stored under org %s", e.Org, org)
			}
			events = append(events, e)
		}
		return nil
	})
	return events, err
}

// Export copies a bounded page in stable ledger order. It never changes
// attempt or acknowledgement state. The caller must fsync its durable file.
func Export(ctx context.Context, pool *db.Pool, org ids.OrgID, after int64, limit int, dst io.Writer) (int, int64, error) {
	if after < 0 || limit < 1 || limit > OutboxBatch {
		return 0, 0, errors.New("security-log: invalid page; limit must be 1..500")
	}
	var n int
	var through int64
	err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ExportSecurityEvents(ctx, org, after, int32(limit)) //nolint:gosec // limit <= 500
		if err != nil {
			return err
		}
		for _, row := range rows {
			if _, err := dst.Write(append(row.Payload, '\n')); err != nil {
				return err
			}
			n++
			through = row.LedgerSeq
		}
		return nil
	}, db.ReadOnly())
	return n, through, err
}

// AcknowledgeIn verifies an exact stored sequence and marks the prefix in
// the caller's tenant transaction. The operator audit must share this tx.
func AcknowledgeIn(ctx context.Context, tx db.TenantTx, through int64) (int64, error) {
	if through < 1 {
		return 0, errors.New("security-log: positive --through required")
	}
	q := dbq.New(tx)
	exists, err := q.SecurityEventExists(ctx, tx.OrgID(), through)
	if err != nil {
		return 0, err
	}
	if !exists {
		return 0, errors.New("security-log: --through must identify a stored security event")
	}
	return q.AcknowledgeSecurityEvents(ctx, tx.OrgID(), through)
}

// IntentAcknowledged permits the irreversible deletion phase only after
// an operator has verified and ACKed this exact intent in the durable
// external security log (F19). Missing, unchained and merely emitted or
// exported intents all return false. It never writes or creates an ACK.
func IntentAcknowledged(ctx context.Context, pool *db.Pool, kind string, target ids.UUID, digest string) (bool, error) {
	typ := "org"
	switch kind {
	case "org.deletion_started":
	case "account.deletion_started":
		typ = "account"
	default:
		return false, errors.New("security outbox: closed deletion intent kind required")
	}
	raw, err := hex.DecodeString(digest)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != digest || target.IsZero() {
		return false, errors.New("security outbox: invalid intent target or digest")
	}
	var ready bool
	err = pool.InTenantTx(ctx, ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		ready, err = dbq.New(tx).SecurityIntentAcknowledged(ctx, dbq.SecurityIntentAcknowledgedParams{OrgID: ids.PlatformOrg, EventKind: kind, ObjectType: typ, ObjectID: target.String(), JournalDigest: digest})
		return err
	}, db.ReadOnly())
	return ready, err
}
