// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Delivery limits (HR-159).
const (
	// RequestTimeout bounds one HTTP delivery.
	RequestTimeout = 10 * time.Second
	// maxResponseRead is how much of a response is read (and discarded).
	maxResponseRead = 4 << 10
	// userAgent identifies PantherClaw's outbound requests.
	userAgent = "PantherClaw-Notifications/1"
)

// Mail is one email.
type Mail struct {
	To, Subject, Body string
	// MessageID is unique per delivery (retries reuse it).
	MessageID string
}

// Mailer sends email (adapters/smtpmail). A nil Mailer means email is not
// configured: email deliveries are SKIPPED.
type Mailer interface {
	Send(ctx context.Context, m Mail) error
}

// ErrPermanent marks a mail error that retrying cannot fix (a refused
// recipient, for example).
var ErrPermanent = errors.New("notifications: permanent delivery failure")

// SetMailer sets the mailer (nil: email not configured).
func (s *Service) SetMailer(m Mailer) { s.mailer = m }

// SetHTTPClient replaces the egress client used for Slack and webhooks.
// Tests use it to reach in-process receivers; production keeps the
// egress-guarded default (HR-070..072, HR-157).
func (s *Service) SetHTTPClient(c *http.Client) { s.http = c }

// outcome is the result of one send.
type outcome struct {
	ok     bool
	status int    // HTTP status, 0 when there was no response
	code   string // a stable error code, never a raw error message
	// gone: the destination says it no longer exists (pause the channel).
	gone bool
	// permanent: retrying cannot help (fail now).
	permanent bool
	// retryAfter: the destination asked to wait (429).
	retryAfter time.Duration
	// skip: nothing was sent and nothing will be (email not configured,
	// recipient without an address).
	skip bool
	// contended: another delivery holds what this one needs (a Slack
	// escalation claim, G0 M14 D127): retried, never a channel failure.
	contended bool
}

// errRetry is returned to River when the attempt failed and another one
// is due: River then waits RetryDelay (the worker's NextRetry).
var errRetry = errors.New("notifications: delivery failed, will retry")

// RetryAfterError asks River to wait the destination's Retry-After.
type RetryAfterError struct{ Wait time.Duration }

func (e RetryAfterError) Error() string {
	return "notifications: destination asked to wait " + e.Wait.String()
}

// Deliver makes one attempt of a delivery (the River worker calls it). The
// delivery row is authoritative: its attempt count, not River's, decides
// when to give up (HR-159), and an expired notification is never sent.
// Nothing here can approve or change authority: the outcome only updates
// delivery and channel health (HR-039).
func (s *Service) Deliver(ctx context.Context, org ids.OrgID, delivery ids.UUID) error {
	var d dbq.LoadDeliveryRow
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		d, err = dbq.New(tx).LoadDelivery(ctx, org, delivery)
		return err
	}, db.ReadOnly())
	switch {
	case db.IsNoRows(err):
		return nil // deleted by the janitor
	case err != nil:
		return err
	case d.State != "PENDING":
		return nil // already finished (a duplicate job)
	case d.Expired:
		return s.finish(ctx, org, delivery, "EXPIRED", "notification_expired")
	case d.ChannelState != nil && *d.ChannelState == "PAUSED":
		return s.finish(ctx, org, delivery, "SKIPPED", "channel_paused")
	case d.ChannelState != nil && *d.ChannelState == "DISABLED":
		return s.finish(ctx, org, delivery, "CANCELLED", "channel_deleted") //nolint:misspell // the schema's state name
	}
	attempt := int(d.Attempts) + 1
	out := s.send(ctx, org, d)
	if out.skip {
		return s.finish(ctx, org, delivery, "SKIPPED", out.code)
	}
	return s.record(ctx, org, d, attempt, out)
}

func (s *Service) finish(ctx context.Context, org ids.OrgID, delivery ids.UUID, state, code string) error {
	return s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := dbq.New(tx).FinishDelivery(ctx, dbq.FinishDeliveryParams{State: state, LastError: &code, OrgID: org, ID: delivery})
		return err
	})
}

// record stores the attempt and the channel's health, pauses a channel that
// is gone or has failed for AutoPauseAfter, and tells River whether to
// retry.
func (s *Service) record(ctx context.Context, org ids.OrgID, d dbq.LoadDeliveryRow, attempt int, out outcome) error {
	state, retry := "DELIVERED", time.Duration(0)
	switch {
	case out.ok:
	case out.gone || out.permanent || attempt >= MaxAttempts:
		state = "FAILED"
	default:
		state, retry = "PENDING", domain.RetryDelay(attempt)
		if out.retryAfter > retry {
			retry = min(out.retryAfter, domain.MaxRetryAfter)
		}
	}
	p := dbq.RecordDeliveryAttemptParams{
		Attempts: int32(attempt), State: state, RetrySeconds: int32(retry / time.Second), OrgID: org, ID: d.ID, //nolint:gosec // G115: attempt <= 8
	}
	if out.status != 0 {
		st := int32(out.status) //nolint:gosec // G115: an HTTP status
		p.LastStatus = &st
	}
	if out.code != "" {
		p.LastError = &out.code
	}
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		n, err := q.RecordDeliveryAttempt(ctx, p)
		if err != nil || n == 0 {
			return err // 0 rows: a concurrent attempt recorded first
		}
		if d.ChannelID == nil || out.contended {
			return nil
		}
		if out.ok {
			return q.ChannelSucceeded(ctx, org, *d.ChannelID)
		}
		h, err := q.ChannelFailed(ctx, dbq.ChannelFailedParams{
			Code: &out.code, OrgID: org, ID: *d.ChannelID, PauseAfterSeconds: int32(domain.AutoPauseAfter / time.Second),
		})
		if err != nil {
			return err
		}
		switch {
		case out.gone:
			return s.pauseChannel(ctx, tx, q, org, *d.ChannelID, h.Name, "GONE", "the destination no longer exists")
		case h.Overdue:
			return s.pauseChannel(ctx, tx, q, org, *d.ChannelID, h.Name, "FAILING", "it failed for 72 hours")
		}
		return nil
	})
	if err != nil {
		return err
	}
	if state != "PENDING" {
		return nil
	}
	if out.retryAfter > 0 {
		return RetryAfterError{Wait: retry}
	}
	return errRetry
}

// pauseChannel pauses a channel automatically, audits it and tells the
// org's other channels (once per pause).
func (s *Service) pauseChannel(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, id ids.UUID, name, reason, why string) error {
	n, err := q.PauseChannel(ctx, &reason, org, id)
	if err != nil || n == 0 {
		return err
	}
	s.log.WarnContext(ctx, "notifications.channel_paused", slog.String("org", org.String()), slog.String("channel", id.String()),
		slog.String("reason", reason))
	if _, err := audit.Record(ctx, tx, audit.Event{
		Name: "notification.channel_paused", Actor: evdomain.Actor{Type: "system", ID: "notification-health"},
		Outcome: audit.Success, ReasonCode: reason, Object: &audit.Object{Type: "notification_channel", ID: id.String()},
	}); err != nil {
		return err
	}
	_, err = s.Enqueue(ctx, tx, Message{
		Org: org, Type: "notification.channel_paused", Params: map[string]string{"channel": name, "reason": why},
		Subject: &Subject{Type: "notification_channel", ID: id}, DedupeKey: "paused:" + id.String() + ":" + strconv.FormatInt(s.clock.Now().Unix(), 10),
	})
	return err
}

// link is the absolute deep link of a notification, naming the org so the
// page can send a signed-out person to the right sign-in.
func (s *Service) link(org ids.OrgID, path string) string {
	if path == "" {
		return ""
	}
	return strings.TrimSuffix(s.cfg.PublicURL, "/") + path + "?org=" + url.QueryEscape(org.String())
}

// send performs the attempt for the delivery's kind. Secrets are opened
// only here, in memory, for this one request.
func (s *Service) send(ctx context.Context, org ids.OrgID, d dbq.LoadDeliveryRow) outcome {
	link := s.link(org, d.LinkPath)
	switch domain.Kind(d.Kind) {
	case domain.KindLog:
		s.log.InfoContext(ctx, "notification.delivered", slog.String("org", org.String()), slog.String("delivery", d.ID.String()),
			slog.String("notification", d.NotificationID.String()), slog.String("type", d.Type), slog.String("severity", d.Severity),
			slog.String("title", d.Title), slog.String("link", link))
		return outcome{ok: true}
	case domain.KindEmail:
		return s.sendEmail(ctx, d, link)
	case domain.KindSlack:
		secret, err := s.openSecret(ctx, org, d, secretColumn, d.ChannelSecret)
		if err != nil {
			return outcome{code: "secret_unavailable"}
		}
		body, _ := json.Marshal(map[string]any{"text": domain.SlackText(d.Title, d.Body, link), "unfurl_links": false, "unfurl_media": false})
		return s.post(ctx, string(secret), body, nil, true)
	case domain.KindWebhook:
		return s.sendWebhook(ctx, org, d, link)
	case domain.KindSlackApp:
		return s.sendSlackApp(ctx, org, d, link)
	}
	return outcome{code: "unknown_kind", permanent: true}
}

func (s *Service) openSecret(ctx context.Context, org ids.OrgID, d dbq.LoadDeliveryRow, column string, blob []byte) ([]byte, error) {
	if d.ChannelID == nil || len(blob) == 0 {
		return nil, errors.New("notifications: channel has no secret")
	}
	return s.envelope.Decrypt(ctx, s.field(org, *d.ChannelID, column), SecretPurpose, blob)
}

func (s *Service) sendEmail(ctx context.Context, d dbq.LoadDeliveryRow, link string) outcome {
	if s.mailer == nil {
		return outcome{skip: true, code: "email_not_configured"}
	}
	if d.RecipientEmail == nil || *d.RecipientEmail == "" || d.RecipientState == nil || *d.RecipientState != "ACTIVE" {
		return outcome{skip: true, code: "no_recipient"}
	}
	body := d.Body + "\n\n"
	if link != "" {
		body += "Open PantherClaw: " + link + "\n\n"
	}
	body += "This message was sent by PantherClaw. It never asks you to approve anything by email.\n"
	err := s.mailer.Send(ctx, Mail{To: *d.RecipientEmail, Subject: d.Title, Body: body, MessageID: d.ID.String()})
	switch {
	case err == nil:
		return outcome{ok: true}
	case errors.Is(err, ErrPermanent):
		return outcome{code: "mail_refused", permanent: true}
	default:
		s.log.WarnContext(ctx, "notifications.mail_failed", slog.String("delivery", d.ID.String()), pclog.Err(err))
		return outcome{code: "mail_failed"}
	}
}

// webhookPayload is the Standard Webhooks body: ids, the rendered title and
// the link, nothing more (HR-158, F621).
type webhookPayload struct {
	Type      string      `json:"type"`
	Timestamp string      `json:"timestamp"`
	Data      webhookData `json:"data"`
}

type webhookData struct {
	ID       string `json:"id"`
	Org      string `json:"org"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	// Simulated is true for a notice caused by a simulated transaction; its
	// title starts with [SIMULATED] (HR-222).
	Simulated bool            `json:"simulated,omitempty"`
	Subject   *webhookSubject `json:"subject,omitempty"`
	Link      string          `json:"link,omitempty"`
}

type webhookSubject struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func (s *Service) sendWebhook(ctx context.Context, org ids.OrgID, d dbq.LoadDeliveryRow, link string) outcome {
	if d.ChannelUrl == nil {
		return outcome{code: "no_url", permanent: true}
	}
	secret, err := s.openSecret(ctx, org, d, secretColumn, d.ChannelSecret)
	if err != nil {
		return outcome{code: "secret_unavailable"}
	}
	secrets := [][]byte{secret}
	if d.PrevSecretLive && len(d.ChannelPrevSecret) > 0 {
		if prev, err := s.openSecret(ctx, org, d, prevSecretColumn, d.ChannelPrevSecret); err == nil {
			secrets = append(secrets, prev) // both signatures while a rotation overlaps
		}
	}
	p := webhookPayload{
		Type: d.Type, Timestamp: d.NotificationCreatedAt.UTC().Format(time.RFC3339),
		Data: webhookData{
			ID: d.NotificationID.String(), Org: org.String(), Severity: d.Severity, Title: d.Title, Link: link,
			Simulated: strings.HasPrefix(d.Title, domain.SimulatedPrefix),
		},
	}
	if d.SubjectType != nil && d.SubjectID != nil {
		p.Data.Subject = &webhookSubject{Type: *d.SubjectType, ID: d.SubjectID.String()}
	}
	body, err := json.Marshal(p)
	if err != nil {
		return outcome{code: "encode_failed", permanent: true}
	}
	// webhook-id is the delivery id: the same on every retry, so receivers
	// can drop duplicates.
	msgID := "msg_" + d.ID.String()
	ts := s.clock.Now().Unix()
	h := http.Header{}
	h.Set("webhook-id", msgID)
	h.Set("webhook-timestamp", strconv.FormatInt(ts, 10))
	h.Set("webhook-signature", domain.Signatures(secrets, msgID, ts, body))
	return s.post(ctx, *d.ChannelUrl, body, h, false)
}

// post sends one JSON request through the egress client and classifies the
// answer. Redirects are never followed (a 3xx is a failure). The response
// is read up to 4 KiB and never stored.
func (s *Service) post(ctx context.Context, target string, body []byte, h http.Header, slack bool) outcome {
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return outcome{code: "bad_url", permanent: true}
	}
	for k, v := range h {
		req.Header[k] = v
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := s.http.Do(req)
	if err != nil {
		if errors.Is(err, httpx.ErrDestinationDenied) {
			return outcome{code: "destination_denied"}
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return outcome{code: "timeout"}
		}
		return outcome{code: "connection_failed"}
	}
	defer func() { _ = resp.Body.Close() }()
	head, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseRead))
	out := outcome{status: resp.StatusCode}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		out.ok = true
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		out.code = "redirect_refused"
	case resp.StatusCode == http.StatusGone:
		out.code, out.gone = "gone", true
	case slack && slackGone(resp.StatusCode, head):
		out.code, out.gone = "slack_webhook_revoked", true
	case resp.StatusCode == http.StatusTooManyRequests:
		out.code = "rate_limited"
		if secs, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && secs > 0 {
			out.retryAfter = min(time.Duration(secs)*time.Second, domain.MaxRetryAfter)
		}
	default:
		out.code = "http_" + strconv.Itoa(resp.StatusCode)
	}
	return out
}

// slackGone recognizes Slack's answers for a webhook that was revoked or
// whose channel is gone.
func slackGone(status int, body []byte) bool {
	if status != http.StatusNotFound && status != http.StatusForbidden && status != http.StatusGone {
		return false
	}
	b := string(body)
	for _, s := range []string{"no_service", "channel_not_found", "channel_is_archived", "invalid_token", "action_prohibited"} {
		if strings.Contains(b, s) {
			return true
		}
	}
	return false
}
