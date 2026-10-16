// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package endpoints

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/inbound"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Delivery parameters (D22).
const (
	// MaxDeliveryBody bounds a delivery's JSON body.
	MaxDeliveryBody = 64 << 10
	// MaxAttempts is the most attempts of one delivery.
	MaxAttempts = 8
	// BackoffMin and BackoffMax bound the delay between attempts.
	BackoffMin = 30 * time.Second
	BackoffMax = time.Hour
	// userAgent names the sender.
	userAgent = "PantherClaw-Automations/1"
	// FailureDelivery is the owned failure of a delivery that gave up.
	FailureDelivery = "automation.delivery_failed"
)

// Deliverer errors.
var (
	ErrDestinationInactive = pcerr.New(pcerr.FailedPrecondition, autodomain.ReasonDestinationInactive,
		"the destination is not ACTIVE")
	ErrPurpose = pcerr.New(pcerr.FailedPrecondition, "DESTINATION_PURPOSE",
		"the destination does not accept deliveries of this kind")
	ErrDeliveryBody = pcerr.New(pcerr.InvalidArgument, "DELIVERY_BODY",
		"a delivery body is a JSON object of at most 64 KiB")
	ErrDeliveryNotFound = pcerr.New(pcerr.NotFound, "DELIVERY_NOT_FOUND", "delivery not found")
)

// Deliverer implements autoports.Deliverer (D11, D22).
type Deliverer struct{ s *Service }

var _ autoports.Deliverer = Deliverer{}

// Deliverer returns the service's Deliverer.
func (s *Service) Deliverer() Deliverer { return Deliverer{s: s} }

// Deliver records one webhook to an ACTIVE destination whose purposes
// include d.Kind, in tx. The sender posts it with Standard Webhooks
// signatures; DELIVERED (a 2xx answer) is the step's DELIVERY_CONFIRMED
// evidence.
func (dl Deliverer) Deliver(ctx context.Context, tx pgx.Tx, d autodomain.Delivery) (ids.UUID, error) {
	if d.Execution.IsZero() || d.Destination.IsZero() {
		return ids.UUID{}, ErrDeliveryBody
	}
	if len(d.Body) == 0 || len(d.Body) > MaxDeliveryBody || !jsontext.Value(d.Body).IsValid() || jsontext.Value(d.Body).Kind() != '{' {
		return ids.UUID{}, ErrDeliveryBody
	}
	q := dbq.New(tx)
	dest, err := q.GetAutomationDestination(ctx, d.Org, d.Destination)
	if db.IsNoRows(err) {
		return ids.UUID{}, ErrDestinationInactive
	} else if err != nil {
		return ids.UUID{}, err
	}
	if dest.State != StateActive {
		return ids.UUID{}, ErrDestinationInactive
	}
	if !slices.Contains(dest.Purposes, string(d.Kind)) {
		return ids.UUID{}, ErrPurpose
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return ids.UUID{}, err
	}
	id := ids.NewV7()
	if err := q.InsertAutomationDelivery(ctx, dbq.InsertAutomationDeliveryParams{
		OrgID: d.Org, ID: id, DestinationID: d.Destination, ExecutionID: d.Execution, Kind: string(d.Kind),
		MsgID: "msg_" + hex.EncodeToString(raw[:]), Body: d.Body,
	}); err != nil {
		return ids.UUID{}, err
	}
	return id, nil
}

// Status reports a delivery's state.
func (dl Deliverer) Status(ctx context.Context, tx pgx.Tx, id ids.UUID) (autodomain.DeliveryStatus, error) {
	t, org, err := adopt(ctx, tx)
	if err != nil {
		return autodomain.DeliveryStatus{}, err
	}
	r, err := dbq.New(t).GetAutomationDelivery(ctx, org, id)
	if db.IsNoRows(err) {
		return autodomain.DeliveryStatus{}, ErrDeliveryNotFound
	} else if err != nil {
		return autodomain.DeliveryStatus{}, err
	}
	st := autodomain.DeliveryStatus{ID: r.ID, State: autodomain.DeliveryState(r.State), Attempts: int(r.Attempts)}
	if r.LastStatus != nil {
		st.LastStatus = int(*r.LastStatus)
	}
	if r.LastError != nil {
		st.LastError = *r.LastError
	}
	if r.DeliveredAt != nil {
		st.DeliveredAt = *r.DeliveredAt
	}
	return st, nil
}

func adopt(ctx context.Context, tx pgx.Tx) (db.TenantTx, ids.OrgID, error) {
	var org string
	if err := tx.QueryRow(ctx, "SELECT coalesce(current_setting('app.org_id', true), '')").Scan(&org); err != nil {
		return db.TenantTx{}, ids.OrgID{}, err
	}
	o, err := ids.Parse[ids.Org](org)
	if err != nil {
		return db.TenantTx{}, ids.OrgID{}, db.ErrNoTenant
	}
	t, err := db.AdoptTenantTx(ctx, tx, o)
	return t, o, err
}

// Backoff is the delay after attempt n (1-based) failed: 30 s doubling up
// to an hour.
func Backoff(n int) time.Duration {
	d := BackoffMin
	for i := 1; i < n && d < BackoffMax; i++ {
		d *= 2
	}
	return min(d, BackoffMax)
}

// SendDue posts org's due deliveries, one at a time (D22). It returns how
// many were delivered.
func (s *Service) SendDue(ctx context.Context, org ids.OrgID) (int, error) {
	var due []ids.UUID
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		due, err = dbq.New(tx).DueAutomationDeliveries(ctx, org)
		return err
	}, db.ReadOnly())
	if err != nil {
		return 0, err
	}
	delivered := 0
	for _, id := range due {
		ok, err := s.sendOne(ctx, org, id)
		if err != nil {
			s.log.WarnContext(ctx, "automations.delivery_error", slog.String("delivery", id.String()), pclog.Err(err))
			continue
		}
		if ok {
			delivered++
		}
	}
	return delivered, nil
}

type attempt struct {
	url      string
	internal bool
	msgID    string
	body     []byte
	secrets  [][]byte
	attempts int
	dest     ids.UUID
	exec     ids.UUID
}

func (s *Service) sendOne(ctx context.Context, org ids.OrgID, id ids.UUID) (bool, error) {
	var a attempt
	skip, fail := false, ""
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.LockAutomationDelivery(ctx, org, id)
		if db.IsNoRows(err) {
			skip = true
			return nil
		} else if err != nil {
			return err
		}
		a = attempt{msgID: r.MsgID, body: r.Body, attempts: int(r.Attempts), dest: r.DestinationID, exec: r.ExecutionID}
		d, err := q.LoadAutomationDestinationSecrets(ctx, org, r.DestinationID)
		if err != nil {
			return err
		}
		switch d.State {
		case StateActive:
		case StatePaused:
			// A paused destination keeps its deliveries waiting.
			skip = true
			_, err := q.PostponeAutomationDelivery(ctx, s.clock.Now().Add(BackoffMin), org, id)
			return err
		default:
			fail = "destination_disabled"
			return nil
		}
		a.url, a.internal = d.Url, d.Internal
		if err := CheckURL(a.url, s.ownHost, a.internal, s.cfg.AllowedPrivateRanges); err != nil {
			fail = "destination_url"
			return nil
		}
		if a.attempts >= MaxAttempts {
			// A sender died after leasing the last attempt: it is not tried again.
			fail = "attempts_exhausted"
			return nil
		}
		// The send is leased before the POST and the lease counts the attempt:
		// a sender that dies after posting and before recording leaves it
		// alone for the lease (D87 L11), and Cancel sees it may have been
		// sent (D97 N1).
		n, err := q.LeaseAutomationDelivery(ctx, org, id)
		if err != nil {
			return err
		}
		a.attempts = int(n)
		cur, err := s.envelope.Decrypt(ctx, field(org, destinationsTable, r.DestinationID, secretColumn), SecretPurpose, d.Secret)
		if err != nil {
			return fmt.Errorf("endpoints: decrypt secret: %w", err)
		}
		a.secrets = [][]byte{cur}
		if d.PrevSecret != nil && d.PrevUntil != nil && d.PrevUntil.After(s.clock.Now()) {
			prev, err := s.envelope.Decrypt(ctx, field(org, destinationsTable, r.DestinationID, prevSecretColumn), SecretPurpose, d.PrevSecret)
			if err != nil {
				return fmt.Errorf("endpoints: decrypt previous secret: %w", err)
			}
			a.secrets = append(a.secrets, prev)
		}
		return nil
	})
	if err != nil || skip {
		return false, err
	}
	if fail != "" {
		return false, s.finish(ctx, org, id, a, nil, fail, true)
	}
	status, code := s.post(ctx, a)
	if status >= 200 && status < 300 {
		return true, s.finish(ctx, org, id, a, &status, "", false)
	}
	var st *int
	if status > 0 {
		st = &status
	}
	return false, s.finish(ctx, org, id, a, st, code, a.attempts >= MaxAttempts)
}

// post sends one attempt with Standard Webhooks headers: one signature per
// valid secret (current first) during a rotation overlap.
func (s *Service) post(ctx context.Context, a attempt) (int, string) {
	ts := s.clock.Now().Unix()
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.url, bytes.NewReader(a.body))
	if err != nil {
		return 0, "request"
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set(inbound.HeaderID, a.msgID)
	req.Header.Set(inbound.HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(inbound.HeaderSignature, ndomain.Signatures(a.secrets, a.msgID, ts, a.body))
	client := s.public
	if a.internal {
		client = s.internal
	}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return 0, "timeout"
		}
		return 0, "transport"
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp.StatusCode, ""
	}
	return resp.StatusCode, "http_" + strconv.Itoa(resp.StatusCode)
}

// finish records an attempt's outcome. The attempt was counted by its
// lease (D97 N1); a guarded update that matches nothing (the delivery left
// PENDING meanwhile) is logged.
func (s *Service) finish(ctx context.Context, org ids.OrgID, id ids.UUID, a attempt, status *int, code string, final bool) error {
	return s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var st *int32
		if status != nil {
			v := int32(*status) //nolint:gosec // an HTTP status code
			st = &v
		}
		unmatched := func(n int64) {
			if n == 0 {
				s.log.WarnContext(ctx, "automations.delivery_not_pending", slog.String("delivery", id.String()),
					slog.String("outcome", code))
			}
		}
		switch {
		case code == "":
			n, err := q.MarkAutomationDeliveryDelivered(ctx, st, org, id)
			unmatched(n)
			return err
		case final:
			n, err := q.MarkAutomationDeliveryFailed(ctx, dbq.MarkAutomationDeliveryFailedParams{
				Status: st, Error: &code, OrgID: org, ID: id,
			})
			if err != nil {
				return err
			}
			unmatched(n)
			if n == 0 || s.failures == nil {
				return nil
			}
			_, err = s.failures.Report(ctx, tx.Pgx(), reflexdomain.Failure{
				Org: org, Kind: FailureDelivery, DedupeKey: FailureDelivery + ":" + a.dest.String() + ":" + a.exec.String(),
				Summary:  fmt.Sprintf("A webhook to automation destination %s failed (%s) and will not be sent again.", hostOf(a.url), code),
				NextStep: "Check the destination is reachable and accepts the signature; the execution that sent it sees the delivery as FAILED.",
				Scope: []reflexdomain.Subject{
					{Type: reflexdomain.SubjectAutomationExecution, ID: a.exec.String()},
				},
			})
			return err
		default:
			n, err := q.MarkAutomationDeliveryAttempt(ctx, dbq.MarkAutomationDeliveryAttemptParams{
				Status: st, Error: &code, NextAttemptAt: s.clock.Now().Add(Backoff(a.attempts)), OrgID: org, ID: id,
			})
			unmatched(n)
			return err
		}
	})
}

// DestinationChecker answers core's validation lookup (D4
// DESTINATION_INVALID): whether a destination is ACTIVE and serves the
// purpose.
type DestinationChecker struct{}

// Active implements core's Destinations port.
func (DestinationChecker) Active(ctx context.Context, tx pgx.Tx, org ids.OrgID, destination ids.UUID, purpose string) (bool, error) {
	d, err := dbq.New(tx).GetAutomationDestination(ctx, org, destination)
	if db.IsNoRows(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return d.State == StateActive && slices.Contains(d.Purposes, purpose), nil
}

// CancelCode is the last_error of a delivery Cancel stopped.
const CancelCode = "cancelled" //nolint:misspell // the stored value D89 names

// Cancel errors.
var (
	// ErrDeliveryNotPending reports a delivery that was already failed (a
	// cancel included) without an attempt: Cancel changes nothing.
	ErrDeliveryNotPending = pcerr.New(pcerr.FailedPrecondition, "DELIVERY_NOT_PENDING", "the delivery is no longer pending")
	// ErrDeliveryMayHaveBeenSent reports a delivery with an attempt (a
	// leased send included): it may have reached its destination, so it is
	// never reported as cancelled (D97 N1).
	ErrDeliveryMayHaveBeenSent = pcerr.New(pcerr.FailedPrecondition, "DELIVERY_MAY_HAVE_BEEN_SENT",
		"the delivery may have been sent")
)

// Cancel stops a delivery that has not been sent (D89, the engine's
// cleanup): PENDING with no attempt becomes FAILED with last_error
// CancelCode and its body is dropped. A delivery with an attempt is left
// as it is (ErrDeliveryMayHaveBeenSent, D97 N1), as is one already failed
// without one (ErrDeliveryNotPending); an unknown one is
// ErrDeliveryNotFound.
func (dl Deliverer) Cancel(ctx context.Context, tx pgx.Tx, id ids.UUID) error {
	t, org, err := adopt(ctx, tx)
	if err != nil {
		return err
	}
	q := dbq.New(t)
	code := CancelCode
	n, err := q.CancelAutomationDelivery(ctx, &code, org, id)
	if err != nil {
		return err
	}
	if n == 1 {
		return nil
	}
	r, err := q.GetAutomationDelivery(ctx, org, id)
	if db.IsNoRows(err) {
		return ErrDeliveryNotFound
	} else if err != nil {
		return err
	}
	if r.Attempts > 0 {
		return ErrDeliveryMayHaveBeenSent
	}
	return ErrDeliveryNotPending
}
