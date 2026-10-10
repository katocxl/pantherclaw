// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package capture keeps restricted payload captures (G0 M7 track B slice
// B9, design decision 10, founder decision 7; HR-199, HR-062, HR-076,
// T-076, T-043).
//
// Capture is off unless a person holding evidence.capture.manage creates a
// capture profile: a purpose, the connections and operations it covers,
// the request and/or the response, a byte cap (at most 64 KiB per body), a
// retention (at most 30 days) and an expiry (at most 90 days). Creating and
// disabling are audited and notified to the org's admins and auditors, and
// the profile reaches the gateways serving those connections in their
// configuration.
//
// The gateway captures the outbound body it built (never headers, so never
// the credential) and the target's response after secret-echo redaction,
// truncated to the cap, and sends them with RecordExecution. The server
// trusts none of it blindly (Recorder): it keeps a capture only for an
// attempt the reporting gateway dispatched in enforce mode, under a profile
// that is active, unexpired and covers that connection, operation and
// direction, cuts it to the profile's cap again, seals it per row with the
// org's payload_captures key (AES-256-GCM, AAD org|payload_captures|
// content|id) and keeps it for the profile's retention. Monitor-mode and
// delegated outcomes capture nothing.
//
// A capture is read only by a person holding evidence.read_restricted
// where the transaction's agent lives, with a reason, and the read is
// written to the audit ledger (evidence.payload_read) and committed before
// the content is opened and returned. Captures never appear in logs, job
// arguments, receipts, notifications or explorer responses.
package capture

import (
	"context"
	"log/slog"
	"slices"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Where captures are sealed: the DEK purpose and the column the AAD binds
// with the org and the capture id (HR-062).
const (
	Purpose = "payload_captures"
	table   = "payload_captures"
	column  = "content"
)

// Limits of design decision 10.
const (
	MaxBytes         = 64 << 10
	MaxRetentionDays = 30
	MaxExpiryDays    = 90
	MaxPurpose       = 500
	// MaxReason is the longest reason for a read, in bytes: it is recorded
	// in the audit entry.
	MaxReason      = 500
	maxConnections = 32
	maxOperations  = 64
)

// Direction is which body of a dispatch a capture holds.
type Direction string

// Directions.
const (
	Request  Direction = "request"
	Response Direction = "response"
)

// Body is one body as the gateway reported it.
type Body struct {
	Profile   ids.UUID
	Direction Direction
	Content   []byte
	// Size is the body's size before the gateway truncated it.
	Size      int64
	Truncated bool
}

func field(org ids.OrgID, id ids.UUID) pccrypto.FieldContext {
	return pccrypto.FieldContext{Org: org, Table: table, Column: column, RowID: id.String()}
}

// Recorder keeps the captures of recorded executions as pc_app.
type Recorder struct {
	Pool *db.Pool
	// Env seals with the org's payload_captures key.
	Env *pccrypto.Envelope
	Log *slog.Logger
}

// Drop reasons, logged with ids only (never content).
const (
	dropNoAttempt  = "NO_ATTEMPT"
	dropGateway    = "OTHER_GATEWAY"
	dropNotCapture = "NOT_CAPTURED_OUTCOME"
	dropProfile    = "NO_ACTIVE_PROFILE"
	dropDuplicate  = "DUPLICATE_DIRECTION"
	dropEmpty      = "EMPTY"
)

// covers reports whether a profile covers the connection, operation and
// direction.
func covers(p dbq.ActiveCaptureProfileRow, conn ids.UUID, op string, d Direction) bool {
	switch {
	case !slices.Contains(p.Connections, conn), !slices.Contains(p.Operations, op):
		return false
	case d == Request:
		return p.CaptureRequest
	case d == Response:
		return p.CaptureResponse
	}
	return false
}

// Record keeps the bodies the gateway reported with the outcome of permit
// and returns how many it kept. It keeps nothing for an attempt this
// gateway did not dispatch in enforce mode, a delegated or swept outcome,
// or a body no active profile covers; a repeated report keeps the first.
// Errors never reach the gateway's outcome: the execution is recorded
// already.
func (r *Recorder) Record(ctx context.Context, org ids.OrgID, gateway string, permit ids.UUID, bodies []Body) (int, error) {
	if len(bodies) == 0 {
		return 0, nil
	}
	kept := 0
	err := r.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		t, err := q.CaptureTarget(ctx, org, permit)
		if db.IsNoRows(err) {
			r.drop(ctx, org, permit, dropNoAttempt)
			return nil
		} else if err != nil {
			return err
		}
		switch {
		case t.GatewayID != gateway:
			r.drop(ctx, org, permit, dropGateway)
			return nil
		case t.Mode != "enforce" || t.Outcome == "delegated" || t.RecordedBy != "gateway" || t.ConnectionID == nil:
			r.drop(ctx, org, permit, dropNotCapture)
			return nil
		}
		seen := map[Direction]bool{}
		for _, b := range bodies {
			if seen[b.Direction] {
				r.drop(ctx, org, permit, dropDuplicate)
				continue
			}
			seen[b.Direction] = true
			if len(b.Content) == 0 {
				r.drop(ctx, org, permit, dropEmpty)
				continue
			}
			p, err := q.ActiveCaptureProfile(ctx, org, b.Profile)
			if db.IsNoRows(err) || (err == nil && !covers(p, *t.ConnectionID, t.Operation, b.Direction)) {
				r.drop(ctx, org, permit, dropProfile)
				continue
			} else if err != nil {
				return err
			}
			content, truncated := b.Content, b.Truncated
			if len(content) > int(p.ByteCap) {
				content, truncated = content[:p.ByteCap], true
			}
			size := max(b.Size, int64(len(b.Content)))
			id := ids.NewV7()
			sealed, err := r.Env.Encrypt(ctx, field(org, id), Purpose, content)
			if err != nil {
				return err
			}
			n, err := q.InsertPayloadCapture(ctx, dbq.InsertPayloadCaptureParams{
				OrgID: org, ID: id, AttemptID: t.AttemptID, TransactionID: t.TransactionID, ProfileID: p.ID,
				Direction: string(b.Direction), Content: sealed, Size: int32(min(size, 1<<30)), Truncated: truncated, //nolint:gosec // G115: clamped
				RetentionDays: p.RetentionDays,
			})
			if err != nil {
				return err
			}
			kept += int(n)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return kept, nil
}

func (r *Recorder) drop(ctx context.Context, org ids.OrgID, permit ids.UUID, reason string) {
	if r.Log != nil {
		r.Log.InfoContext(ctx, "evidence.capture_dropped", slog.String("org", org.String()),
			slog.String("permit_id", permit.String()), slog.String("reason", reason))
	}
}

// validText reports a UTF-8 text of 1 to n characters.
func validText(s string, n int) bool {
	return utf8.ValidString(s) && s != "" && utf8.RuneCountInString(s) <= n
}
