// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package siem

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/siem/ocsf"
)

// Export parameters (D36, HR-260).
const (
	// ScanLimit is how many feed entries one batch looks at: a batch covers
	// at most this many sequence numbers, so re-reading its range is one
	// feed read.
	ScanLimit = 500
	// MaxAttempts is the retry schedule's length (5 s … 10 h, 8 attempts);
	// a batch is FAILED after it and is still retried at the last
	// interval: the cursor never skips events.
	MaxAttempts = ndomain.MaxAttempts
	// maxResponseRead bounds what is read of a receiver's answer.
	maxResponseRead = 4 << 10
	// leaseSeconds is how long a worker holds the batch it sends: past the
	// request timeout, so an attempt is recorded before anyone re-sends.
	leaseSeconds = int32(4 * RequestTimeout / time.Second)
	userAgent    = "PantherClaw-SIEM-Export/1"
)

// HealthSink is told when a destination's delivery starts FAILING (D36):
// it records an owned failure and raises a siem signal for Operations.
type HealthSink interface {
	DeliveryFailing(ctx context.Context, tx db.TenantTx, f DeliveryFailure) error
}

// DeliveryFailure describes a destination whose delivery is failing.
type DeliveryFailure struct {
	Org         ids.OrgID
	Destination ids.UUID
	Name        string
	Code        string
	Failures    int
	// HeldAt is the cursor: the feed sequence export is held at.
	HeldAt int64
	Since  time.Time
}

// Step is the outcome of one export step.
type Step struct {
	// Sent: a batch was attempted; Delivered: it got a 2xx.
	Sent, Delivered bool
	// More: the feed may have more for this destination now.
	More bool
	// RetryAt: the open batch's next attempt (zero when none waits).
	RetryAt time.Time
	// Code is the failure code of a failed attempt.
	Code string
}

// batchPlan is the batch one step sends.
type batchPlan struct {
	id       ids.UUID
	from, to int64
	attempts int
	body     []byte
	internal bool
	url      string
	secrets  [][]byte
}

// ExportOnce runs one export step of a destination: it re-sends the open
// batch when it is due, or builds the next batch from the feed after the
// cursor, sends it, and records the outcome. The cursor moves only by
// compare-and-set, after a 2xx, to the end of the delivered batch.
func (s *Service) ExportOnce(ctx context.Context, org ids.OrgID, id ids.UUID) (Step, error) {
	var plan *batchPlan
	var step Step
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		plan, step, err = s.plan(ctx, tx, org, id)
		return err
	})
	if err != nil || plan == nil {
		return step, err
	}
	out := s.send(ctx, plan)
	step.Sent, step.Delivered, step.Code = true, out.ok, out.code
	err = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		return s.record(ctx, tx, org, id, plan, out, &step)
	})
	return step, err
}

// plan reads the destination and decides what to send, inserting a new
// batch when there is none open.
func (s *Service) plan(ctx context.Context, tx db.TenantTx, org ids.OrgID, id ids.UUID) (*batchPlan, Step, error) {
	q := dbq.New(tx)
	row, err := q.LoadSIEMExport(ctx, org, id)
	if db.IsNoRows(err) {
		return nil, Step{}, nil // not activated (no cursor) or gone
	} else if err != nil {
		return nil, Step{}, err
	}
	if row.State != StateActive {
		return nil, Step{}, nil
	}
	classes := make([]ocsf.DataClass, 0, len(row.DataClasses))
	for _, c := range row.DataClasses {
		classes = append(classes, ocsf.DataClass(c))
	}
	p := &batchPlan{url: row.Url, internal: row.Internal}
	if row.BatchID != nil {
		if !row.BatchDue {
			return nil, Step{}, nil
		}
		p.id, p.from, p.to = *row.BatchID, row.BatchFrom, row.BatchTo
		if n, err := q.LeaseSIEMBatch(ctx, leaseSeconds, org, p.id); err != nil || n == 0 {
			return nil, Step{}, err // another worker holds it
		}
		if row.BatchAttempts != nil {
			p.attempts = int(*row.BatchAttempts)
		}
		var b ocsf.Builder
		if _, _, err := s.fill(ctx, tx, &b, p.from, p.to, classes); err != nil {
			return nil, Step{}, err
		}
		if p.body, err = b.Body(p.id.String(), p.from, p.to); err != nil {
			return nil, Step{}, err
		}
	} else {
		var b ocsf.Builder
		to, skipped, err := s.fill(ctx, tx, &b, row.CursorSeq, 0, classes)
		if err != nil {
			return nil, Step{}, err
		}
		if len(skipped) > 0 {
			if err := s.skippedFailure(ctx, tx, org, id, row.CursorSeq, to, skipped); err != nil {
				return nil, Step{}, err
			}
		}
		switch {
		case to == row.CursorSeq:
			return nil, Step{}, nil // nothing new
		case b.Len() == 0:
			// Nothing in the range is for this destination: move past it.
			n, err := q.AdvanceSIEMCursor(ctx, dbq.AdvanceSIEMCursorParams{Seq: to, OrgID: org, DestinationID: id, Expected: row.CursorSeq})
			return nil, Step{More: n == 1}, err
		}
		p.id, p.from, p.to = ids.NewV7(), row.CursorSeq, to
		if p.body, err = b.Body(p.id.String(), p.from, p.to); err != nil {
			return nil, Step{}, err
		}
		if err := q.InsertSIEMBatch(ctx, dbq.InsertSIEMBatchParams{
			OrgID: org, ID: p.id, DestinationID: id, FromSeq: p.from, ToSeq: p.to, EventCount: int32(b.Len()), //nolint:gosec // G115: ≤ 100
			BodyBytes: int32(len(p.body)), SkippedUids: skipped, LeaseSeconds: leaseSeconds, //nolint:gosec // G115: ≤ 1 MiB
		}); err != nil {
			return nil, Step{}, err
		}
	}
	if p.secrets, err = s.secrets(ctx, org, id, row.Secret, row.PrevSecret, row.PrevSecretLive); err != nil {
		return nil, Step{}, err
	}
	return p, Step{}, nil
}

// fill reads the feed after from and adds the destination's events to b.
// With to > 0 it re-reads exactly (from, to]; otherwise it returns where
// the new batch ends: the last event added when the batch filled up,
// else the last entry read. skipped lists the entries too large for any
// batch (never expected: feed bodies are ≤ 8 KiB), which the caller
// records on the batch and as an owned failure (D64 L5).
func (s *Service) fill(ctx context.Context, tx db.TenantTx, b *ocsf.Builder, from, to int64, classes []ocsf.DataClass) (
	end int64, skipped []ids.UUID, err error,
) {
	evs, err := s.feed.After(ctx, tx, from, ScanLimit)
	if err != nil {
		return 0, nil, err
	}
	end = from
	for _, e := range evs {
		if to > 0 && e.Seq > to {
			break
		}
		if !ocsf.Selected(e, classes) {
			end = e.Seq
			continue
		}
		enc, err := ocsf.Encode(ocsf.Map(e, s.cfg.ProductVersion))
		if err != nil {
			return 0, nil, err
		}
		ok, err := b.Add(enc)
		if errors.Is(err, ocsf.ErrEventTooLarge) {
			s.log.ErrorContext(ctx, "siem.event_too_large", slog.String("entry", e.ID.String()), slog.Int64("seq", e.Seq))
			skipped = append(skipped, e.ID)
			end = e.Seq
			continue
		} else if err != nil {
			return 0, nil, err
		}
		if !ok {
			return end, skipped, nil
		}
		end = e.Seq
	}
	return end, skipped, nil
}

// skippedFailure records entries no batch could carry as an owned failure
// naming them (D64 L5): export moves on, and the gap is never silent.
func (s *Service) skippedFailure(ctx context.Context, tx db.TenantTx, org ids.OrgID, id ids.UUID, from, to int64, skipped []ids.UUID) error {
	s.log.ErrorContext(ctx, "siem.events_skipped", slog.String("destination", id.String()), slog.Int("entries", len(skipped)))
	if s.failures == nil {
		return nil
	}
	list := ""
	for i, u := range skipped {
		if i == 8 {
			list += ", …"
			break
		}
		if i > 0 {
			list += ", "
		}
		list += u.String()
	}
	_, err := s.failures.Report(ctx, tx.Pgx(), reflexdomain.Failure{
		Org: org, Kind: "siem.event_skipped",
		Summary: strconv.Itoa(len(skipped)) + " evidence entries between sequence " + strconv.FormatInt(from, 10) + " and " +
			strconv.FormatInt(to, 10) + " were too large to export to destination " + id.String() + ": " + list + ".",
		NextStep:  "Export these entries from the evidence ledger by hand; the destination's batch lists them.",
		Scope:     []reflexdomain.Subject{{Type: reflexdomain.SubjectResource, ID: "siem_destination:" + id.String()}},
		DedupeKey: "siem.event_skipped:" + id.String() + ":" + skipped[0].String(),
	})
	return err
}

func (s *Service) secrets(ctx context.Context, org ids.OrgID, id ids.UUID, cur, prev []byte, prevLive bool) ([][]byte, error) {
	secret, err := s.envelope.Decrypt(ctx, s.field(org, id, secretColumn), SecretPurpose, cur)
	if err != nil {
		return nil, err
	}
	out := [][]byte{secret}
	if prevLive && len(prev) > 0 {
		if p, err := s.envelope.Decrypt(ctx, s.field(org, id, prevSecretColumn), SecretPurpose, prev); err == nil {
			out = append(out, p) // both signatures while a rotation overlaps
		}
	}
	return out, nil
}

// outcome is one attempt's result.
type outcome struct {
	ok         bool
	status     int
	code       string
	retryAfter time.Duration
}

// send POSTs the batch with Standard Webhooks headers through the egress
// client of the destination's kind. webhook-id is the batch id: the same
// on every retry. Redirects are never followed.
func (s *Service) send(ctx context.Context, p *batchPlan) outcome {
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(p.body))
	if err != nil {
		return outcome{code: "bad_url"}
	}
	msgID := p.id.String()
	ts := s.clock.Now().Unix()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("webhook-id", msgID)
	req.Header.Set("webhook-timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("webhook-signature", ndomain.Signatures(p.secrets, msgID, ts, p.body))
	client := s.public
	if p.internal {
		client = s.internal
	}
	resp, err := client.Do(req)
	if err != nil {
		switch {
		case errors.Is(err, httpx.ErrDestinationDenied):
			return outcome{code: "destination_denied"}
		case errors.Is(err, context.DeadlineExceeded):
			return outcome{code: "timeout"}
		}
		s.log.WarnContext(ctx, "siem.send_failed", slog.String("batch", msgID), pclog.Err(err))
		return outcome{code: "connection_failed"}
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseRead))
	out := outcome{status: resp.StatusCode}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		out.ok = true
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		out.code = "redirect_refused"
	case resp.StatusCode == http.StatusTooManyRequests:
		out.code = "rate_limited"
		if secs, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && secs > 0 {
			out.retryAfter = min(time.Duration(secs)*time.Second, ndomain.MaxRetryAfter)
		}
	default:
		out.code = "http_" + strconv.Itoa(resp.StatusCode)
	}
	return out
}

// record stores an attempt's outcome and the destination's health.
func (s *Service) record(ctx context.Context, tx db.TenantTx, org ids.OrgID, id ids.UUID, p *batchPlan, out outcome, step *Step) error {
	q := dbq.New(tx)
	status := int32(out.status) //nolint:gosec // G115: an HTTP status
	var last *int32
	if out.status != 0 {
		last = &status
	}
	if out.ok {
		if _, err := q.DeliveredSIEMBatch(ctx, last, org, p.id); err != nil {
			return err
		}
		n, err := q.AdvanceSIEMCursor(ctx, dbq.AdvanceSIEMCursorParams{Seq: p.to, OrgID: org, DestinationID: id, Expected: p.from})
		if err != nil {
			return err
		}
		if n == 0 {
			// Another worker moved the cursor; the batch is delivered
			// anyway and the receiver drops duplicates by metadata.uid.
			s.log.WarnContext(ctx, "siem.cursor_moved", slog.String("destination", id.String()), slog.String("batch", p.id.String()))
		}
		step.More = true
		return q.SIEMDelivered(ctx, dbq.SIEMDeliveredParams{Seq: p.to, Retries: retried(p.attempts), OrgID: org, ID: id})
	}
	attempt := p.attempts + 1
	state, failedNow := "PENDING", int64(0)
	if attempt >= MaxAttempts {
		state = "FAILED"
		if attempt == MaxAttempts {
			failedNow = 1
		}
	}
	delay := ndomain.RetryDelay(attempt)
	if out.retryAfter > delay {
		delay = out.retryAfter
	}
	code := out.code
	if _, err := q.FailedSIEMBatchAttempt(ctx, dbq.FailedSIEMBatchAttemptParams{
		State: state, LastStatus: last, LastError: &code, DelaySeconds: int32(delay / time.Second), OrgID: org, ID: p.id, //nolint:gosec // G115: ≤ 10 h
	}); err != nil {
		return err
	}
	failures, err := q.SIEMFailed(ctx, dbq.SIEMFailedParams{Code: &code, FailedBatch: failedNow, Retries: retried(p.attempts), OrgID: org, ID: id})
	if err != nil {
		return err
	}
	step.RetryAt = s.clock.Now().Add(delay)
	if int(failures) == ndomain.FailingAfter && s.signals != nil {
		d, err := get(ctx, q, org, id)
		if err != nil {
			return err
		}
		since := s.clock.Now()
		if d.FailingSince != nil {
			since = *d.FailingSince
		}
		return s.signals.DeliveryFailing(ctx, tx, DeliveryFailure{
			Org: org, Destination: id, Name: d.Name, Code: code, Failures: int(failures), Since: since, HeldAt: d.CursorSeq,
		})
	}
	return nil
}

// retried counts an attempt as a retry when the batch was tried before.
func retried(priorAttempts int) int64 {
	if priorAttempts > 0 {
		return 1
	}
	return 0
}
