// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package otlpexport

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	tracev1 "github.com/katocxl/pantherclaw/internal/gen/opentelemetry/proto/trace/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Export parameters (D1061, HR-788).
const (
	// ScanLimit is how many feed entries one batch looks at.
	ScanLimit = 500
	// maxResponseRead bounds what is read of a collector's answer.
	maxResponseRead = 4 << 10
	// leaseSeconds is how long a worker holds the destination it sends to:
	// past the request timeout, so an attempt is recorded before anyone
	// sends again.
	leaseSeconds = int32(4 * RequestTimeout / time.Second)
	// firstBackoff and maxBackoff bound the wait after a failed attempt:
	// it doubles from the first up to the last.
	firstBackoff = 30 * time.Second
	maxBackoff   = 15 * time.Minute
	userAgent    = "PantherClaw-OTLP-Export/1"
)

// The feed kinds whose transactions give spans.
var spanKinds = map[string]bool{"receipt.decision": true, "receipt.execution": true, "receipt.effect": true}

// exporter is the actor of the exporter's own audit entries.
var exporter = evdomain.Actor{Type: "system", ID: "otlp_exporter"}

// Step is the outcome of one export step.
type Step struct {
	// Sent: a batch was attempted; Delivered: it got a 2xx.
	Sent, Delivered bool
	// More: the feed may have more for this destination now.
	More bool
	// Code is the failure code of a failed attempt.
	Code string
}

// batch is what one step sends.
type batch struct {
	from, to int64
	url      string
	headers  []sealedHeader
	traces   *tracev1.TracesData
	// failures is the destination's failure streak before this attempt.
	failures int
}

// ExportOnce runs one export step of a destination: it reads the feed
// after the cursor, builds the spans of the transactions it names, sends
// them, and records the outcome. The cursor moves only by compare-and-set,
// after a 2xx, to the end of the batch; a failing destination keeps its
// cursor and waits its backoff.
func (s *Service) ExportOnce(ctx context.Context, org ids.OrgID, id ids.UUID) (Step, error) {
	var b *batch
	var step Step
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		b, step, err = s.plan(ctx, tx, org, id)
		return err
	})
	if err != nil || b == nil {
		return step, err
	}
	out := s.post(ctx, b.url, b.headers, b.traces)
	step.Sent, step.Delivered, step.Code = true, out.ok, out.code
	err = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		return s.record(ctx, tx, org, id, b, out, &step)
	})
	return step, err
}

// plan reads the destination and the feed after its cursor and decides
// what to send; it leases the destination when it sends.
func (s *Service) plan(ctx context.Context, tx db.TenantTx, org ids.OrgID, id ids.UUID) (*batch, Step, error) {
	q := dbq.New(tx)
	row, err := q.LoadOTLPExport(ctx, org, id)
	if db.IsNoRows(err) {
		return nil, Step{}, nil
	} else if err != nil {
		return nil, Step{}, err
	}
	if row.State != StateActive || !row.Due {
		return nil, Step{}, nil
	}
	evs, err := s.feed.After(ctx, tx, row.CursorSeq, ScanLimit)
	if err != nil || len(evs) == 0 {
		return nil, Step{}, err
	}
	end := evs[len(evs)-1].Seq
	more := len(evs) == ScanLimit
	var txns []ids.UUID
	seen := map[ids.UUID]bool{}
	for _, e := range evs {
		if !spanKinds[e.Kind] {
			continue
		}
		t, ok := e.Subject(reflexdomain.SubjectTransaction)
		if !ok {
			continue
		}
		u, err := ids.ParseUUID(t)
		if err != nil || seen[u] {
			continue
		}
		seen[u] = true
		txns = append(txns, u)
	}
	if len(txns) == 0 {
		// Nothing in the range gives a span: move past it.
		n, err := q.OTLPSkipped(ctx, dbq.OTLPSkippedParams{CursorSeq: end, OrgID: org, ID: id, Expected: row.CursorSeq})
		return nil, Step{More: more && n == 1}, err
	}
	rows, err := q.OTLPSpanTransactions(ctx, org, txns)
	if err != nil {
		return nil, Step{}, err
	}
	effs, err := q.OTLPSpanEffects(ctx, org, txns)
	if err != nil {
		return nil, Step{}, err
	}
	effects := map[ids.UUID][]spanEffect{}
	for _, e := range effs {
		effects[e.TransactionID] = append(effects[e.TransactionID], spanEffect{State: e.State, At: e.CreatedAt})
	}
	if n, err := q.LeaseOTLPExport(ctx, leaseSeconds, org, id); err != nil || n == 0 {
		return nil, Step{}, err // another worker holds it
	}
	headers, err := s.open(ctx, org, id, row.HeaderSecretRef)
	if err != nil {
		return nil, Step{}, err
	}
	return &batch{
		from: row.CursorSeq, to: end, url: row.Url, headers: headers, failures: int(row.FailureCount),
		traces: buildTraces(org, s.cfg.ConsoleURL, rows, effects),
	}, Step{More: more}, nil
}

// outcome is one attempt's result.
type outcome struct {
	ok         bool
	status     int
	code       string
	retryAfter time.Duration
}

// post sends a TracesData message as OTLP/HTTP protobuf, gzip, through the
// egress client, never following a redirect. It never logs a body or a
// header value.
func (s *Service) post(ctx context.Context, target string, headers []sealedHeader, m *tracev1.TracesData) outcome {
	raw, err := proto.Marshal(m)
	if err != nil {
		return outcome{code: "encode_failed"}
	}
	var body bytes.Buffer
	zw := gzip.NewWriter(&body)
	if _, err := zw.Write(raw); err != nil {
		return outcome{code: "encode_failed"}
	}
	if err := zw.Close(); err != nil {
		return outcome{code: "encode_failed"}
	}
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, &body)
	if err != nil {
		return outcome{code: "bad_url"}
	}
	for _, h := range headers {
		req.Header.Set(h.Name, h.Value)
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("User-Agent", userAgent)
	resp, err := s.http.Do(req)
	if err != nil {
		switch {
		case errors.Is(err, httpx.ErrDestinationDenied):
			return outcome{code: "destination_denied"}
		case errors.Is(err, context.DeadlineExceeded):
			return outcome{code: "timeout"}
		}
		s.log.WarnContext(ctx, "otlp.send_failed", pclog.Err(err))
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
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable:
		out.code = "http_" + strconv.Itoa(resp.StatusCode)
		if secs, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && secs > 0 {
			out.retryAfter = min(time.Duration(secs)*time.Second, maxBackoff)
		}
	default:
		out.code = "http_" + strconv.Itoa(resp.StatusCode)
	}
	return out
}

// record stores an attempt's outcome. After 24 hours of failures the
// destination is disabled, audited (D1061).
func (s *Service) record(ctx context.Context, tx db.TenantTx, org ids.OrgID, id ids.UUID, b *batch, out outcome, step *Step) error {
	q := dbq.New(tx)
	if out.ok {
		n, err := q.OTLPExported(ctx, dbq.OTLPExportedParams{CursorSeq: b.to, OrgID: org, ID: id, Expected: b.from})
		if err != nil {
			return err
		}
		if n == 0 {
			// Another worker moved the cursor; the spans are the same
			// either way (HR-788).
			s.log.WarnContext(ctx, "otlp.cursor_moved", slog.String("destination", id.String()))
			step.More = false
		}
		return nil
	}
	step.More = false
	code := out.code
	delay := backoff(b.failures+1, out.retryAfter)
	f, err := q.OTLPExportFailed(ctx, dbq.OTLPExportFailedParams{
		Code: &code, DelaySeconds: int32(delay / time.Second), OrgID: org, ID: id, //nolint:gosec // G115: ≤ 15 min
	})
	if err != nil {
		return err
	}
	if !f.FailingADay {
		return nil
	}
	n, err := q.DisableFailingOTLPDestination(ctx, org, id)
	if err != nil || n == 0 {
		return err
	}
	s.log.WarnContext(ctx, "otlp.destination_disabled", slog.String("destination", id.String()), slog.String("code", code))
	return record(ctx, tx, exporter, auditkind.OtlpDestinationDisabled, id, map[string]string{
		"from": StateActive, "reason": "failing_24h", "code": code, "failures": strconv.Itoa(int(f.FailureCount)),
	})
}

// backoff is the wait after the n-th failure in a row (n ≥ 1): 30 s,
// doubling up to 15 minutes, never shorter than a collector's Retry-After.
func backoff(n int, retryAfter time.Duration) time.Duration {
	d := firstBackoff
	for i := 1; i < n && d < maxBackoff; i++ {
		d *= 2
	}
	return max(min(d, maxBackoff), retryAfter)
}
