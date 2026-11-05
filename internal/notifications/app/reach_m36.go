// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Approval reach (G0 M36 D1065, D1066): per-person preferences (a digest
// and quiet hours), the digest job, and Web Push. A digest and quiet hours
// delay only the person's own emails, direct messages and pushes; channels,
// routing and escalation to other people never wait (HR-792). A push
// carries a fixed title and a link only (HR-793). Nothing here can approve
// anything (HR-789).

// Errors of approval reach.
var (
	ErrPreferencesInvalid = pcerr.New(pcerr.InvalidArgument, "PREFERENCES_INVALID",
		"preferences need IMMEDIATE or DIGEST, a digest window of 15, 30 or 60 minutes, quiet hours as two different HH:MM times "+
			"(or none) and an IANA time zone")
	ErrPushEdition = pcerr.New(pcerr.PermissionDenied, "EDITION_REQUIRED", "Web Push needs the Team edition or above")
	ErrPushInvalid = pcerr.New(pcerr.InvalidArgument, "PUSH_SUBSCRIPTION_INVALID",
		"the subscription needs an https endpoint on an allowed push service, a P-256 p256dh key, a 16-byte auth secret "+
			"and a plain label of at most 64 characters")
	ErrPushExists   = pcerr.New(pcerr.AlreadyExists, "PUSH_SUBSCRIPTION_EXISTS", "this browser is already registered")
	ErrPushLimit    = pcerr.New(pcerr.ResourceExhausted, "PUSH_SUBSCRIPTION_LIMIT", "a person has at most 10 push subscriptions")
	ErrPushNotFound = pcerr.New(pcerr.NotFound, "PUSH_SUBSCRIPTION_NOT_FOUND", "push subscription not found")
	ErrPushNoKey    = pcerr.New(pcerr.FailedPrecondition, "WEB_PUSH_UNAVAILABLE", "Web Push is not configured on this deployment")
)

// MaxPushSubscriptions caps a person's live subscriptions.
const MaxPushSubscriptions = 10

// Encrypted subscription columns (HR-062): the AAD binds org, table, column
// and row.
const (
	pushTable        = "push_subscriptions"
	pushP256dhColumn = "p256dh"
	pushAuthColumn   = "auth"
)

// pushUserAgent identifies PantherClaw's push requests.
const pushUserAgent = "PantherClaw-WebPush/1"

// VAPIDKey returns the deployment's active web_push signing key.
type VAPIDKey func() (crypto.Signer, error)

// SetWebPush sets the VAPID key and the contact (a mailto: or https URL)
// pushes are signed with; without a key, nothing is pushed.
func (s *Service) SetWebPush(key VAPIDKey, subject string) {
	s.vapid, s.vapidSubject = key, subject
}

// webPush reports whether the edition includes Web Push (Team and above,
// D1066); without an edition source, Community applies.
func (s *Service) webPush(ctx context.Context) (bool, error) {
	if s.editions == nil {
		return false, nil
	}
	e, err := s.editions.Current(ctx)
	if err != nil {
		return false, err
	}
	return e.Edition.Paid(), nil
}

// ---- Preferences ----

func prefsOf(r dbq.PcNotificationPreference) domain.Preferences {
	p := domain.Preferences{Delivery: r.ApprovalDelivery, DigestMinutes: int(r.DigestMinutes), UpdatedAt: r.UpdatedAt}
	if r.QuietStart != nil && r.QuietEnd != nil {
		p.QuietStart, p.QuietEnd = *r.QuietStart, *r.QuietEnd
	}
	if r.TimeZone != nil {
		p.TimeZone = *r.TimeZone
	}
	return p
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// MyPreferences returns the caller's own preferences, or the defaults.
func (s *Service) MyPreferences(ctx context.Context) (domain.Preferences, error) {
	c, err := self(ctx)
	if err != nil {
		return domain.Preferences{}, err
	}
	out := domain.DefaultPreferences()
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).GetNotificationPreferences(ctx, c.Org, c.Principal.ID)
		if db.IsNoRows(err) {
			return nil
		} else if err != nil {
			return err
		}
		out = prefsOf(r)
		return nil
	}, db.ReadOnly())
	return out, err
}

// SetMyPreferences sets the caller's own preferences (D1065), audited.
// A zero digest window means the default.
func (s *Service) SetMyPreferences(ctx context.Context, p domain.Preferences) (domain.Preferences, error) {
	c, err := self(ctx)
	if err != nil {
		return domain.Preferences{}, err
	}
	if p.DigestMinutes == 0 {
		p.DigestMinutes = domain.DigestWindows[0]
	}
	if p.Validate() != nil {
		return domain.Preferences{}, ErrPreferencesInvalid
	}
	var out domain.Preferences
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).UpsertNotificationPreferences(ctx, dbq.UpsertNotificationPreferencesParams{
			OrgID: c.Org, UserID: c.Principal.ID, ApprovalDelivery: p.Delivery, DigestMinutes: int16(p.DigestMinutes), //nolint:gosec // 15, 30 or 60
			QuietStart: optional(p.QuietStart), QuietEnd: optional(p.QuietEnd), TimeZone: optional(p.TimeZone),
		})
		if err != nil {
			return err
		}
		out = prefsOf(r)
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: auditkind.NotificationPreferencesSet, Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "user", ID: c.Principal.ID.String()},
			Details: map[string]string{
				"approval_delivery": out.Delivery, "digest_minutes": strconv.Itoa(out.DigestMinutes),
				"quiet_hours": strconv.FormatBool(out.QuietStart != ""),
			},
		})
		return err
	})
	return out, err
}

// hold is how one person's own delivery of a notice waits.
type hold struct {
	// skip: the person takes approval notices as a digest, which carries it.
	skip bool
	// at: the person's quiet hours end then; the delivery waits until it.
	at time.Time
}

// personalHolds returns how m's personal recipients' own deliveries wait
// (D1065, HR-792). Only approval notices and the digest wait; everyone
// without preferences, and every channel, gets them at once.
func (s *Service) personalHolds(ctx context.Context, q *dbq.Queries, m Message) (map[ids.UUID]hold, error) {
	if len(m.Personal) == 0 || !domain.QuietDelays(m.Type) {
		return nil, nil
	}
	rows, err := q.PreferencesOf(ctx, m.Org, m.Personal)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	out := map[ids.UUID]hold{}
	for _, r := range rows {
		p := prefsOf(r)
		var h hold
		h.skip = p.Delivery == domain.DeliveryDigest && domain.DigestReplaces(m.Type)
		h.at = p.QuietUntil(now)
		if h.skip || !h.at.IsZero() {
			out[r.UserID] = h
		}
	}
	return out, nil
}

// ---- Digests ----

// DigestInterval is how often due digests are sent.
const DigestInterval = 5 * time.Minute

// SendDigests sends one approval.digest per person who takes approval
// notices as a digest and has open requests routed to them, at most once
// per digest window (the dedupe key is the person and the window). Link
// only (HR-313, HR-314).
func (s *Service) SendDigests(ctx context.Context, org ids.OrgID) (int, error) {
	n := 0
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.DigestRecipients(ctx, org)
		if err != nil {
			return err
		}
		now := s.clock.Now().Unix()
		for _, r := range rows {
			if r.Waiting <= 0 || r.DigestMinutes <= 0 {
				continue
			}
			window := now / (int64(r.DigestMinutes) * 60)
			enq, err := s.Enqueue(ctx, tx, Message{
				Org: org, Type: domain.DigestType, Params: map[string]string{"count": strconv.FormatInt(r.Waiting, 10)},
				Personal: []ids.UUID{r.UserID}, PersonalOnly: true,
				DedupeKey: "digest:" + r.UserID.String() + ":" + strconv.Itoa(int(r.DigestMinutes)) + ":" + strconv.FormatInt(window, 10),
			})
			if err != nil {
				return err
			}
			if !enq.Duplicate {
				n++
			}
		}
		return nil
	})
	return n, err
}

// DigestOrgArgs asks for one org's due digests (ids only, HR-056).
type DigestOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (DigestOrgArgs) Kind() string { return "notifications.digest_org" }

// InsertOpts keeps one queued job per org.
func (DigestOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type digestOrgWorker struct {
	river.WorkerDefaults[DigestOrgArgs]
	svc *Service
}

func (w *digestOrgWorker) Work(ctx context.Context, job *river.Job[DigestOrgArgs]) error {
	n, err := w.svc.SendDigests(ctx, job.Args.Org)
	if n > 0 {
		w.svc.log.InfoContext(ctx, "notifications.digests", slog.String("org", job.Args.Org.String()), slog.Int("sent", n))
	}
	return err
}

// DigestDispatchArgs fans the digest job out to every active org.
type DigestDispatchArgs struct{}

// Kind implements river.JobArgs.
func (DigestDispatchArgs) Kind() string { return "notifications.digest_dispatch" }

type digestDispatchWorker struct {
	river.WorkerDefaults[DigestDispatchArgs]
	pool *db.Pool
}

// Work lists orgs through the audited lister (HR-054) and enqueues one job
// per org.
func (w *digestDispatchWorker) Work(ctx context.Context, _ *river.Job[DigestDispatchArgs]) error {
	refs, err := w.pool.CrossOrgListAll(ctx, db.ListActiveOrgs, db.ListerPageSize)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("notifications digests: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: DigestOrgArgs{Org: r.Org}})
	}
	_, err = client.InsertMany(ctx, params)
	return err
}

// RegisterDigests adds the digest workers to reg.
func RegisterDigests(reg *jobs.Registry, svc *Service) error {
	if err := jobs.Register[DigestOrgArgs](reg, &digestOrgWorker{svc: svc}); err != nil {
		return err
	}
	return jobs.Register[DigestDispatchArgs](reg, &digestDispatchWorker{pool: svc.pool})
}

// DigestPeriodicJobs schedules the digest job.
func DigestPeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(DigestInterval),
			func() (river.JobArgs, *river.InsertOpts) { return DigestDispatchArgs{}, nil }, nil),
	}
}

// ---- Web Push subscriptions ----

// PushSubscription is a person's subscription without its keys.
type PushSubscription struct {
	ID           ids.UUID
	EndpointHost string
	Label        string
	Created      time.Time
	LastSuccess  *time.Time
	FailureCount int
}

func hostOf(endpoint string) string {
	h, err := domain.PushEndpointHost(endpoint)
	if err != nil {
		return ""
	}
	return h
}

func (s *Service) pushField(org ids.OrgID, id ids.UUID, column string) pccrypto.FieldContext {
	return pccrypto.FieldContext{Org: org, Table: pushTable, Column: column, RowID: id.String()}
}

// WebPushKey returns the deployment's VAPID public key (applicationServerKey).
func (s *Service) WebPushKey(ctx context.Context) (string, error) {
	if _, err := self(ctx); err != nil {
		return "", err
	}
	if s.vapid == nil {
		return "", ErrPushNoKey
	}
	k, err := s.vapid()
	if err != nil {
		return "", ErrPushNoKey
	}
	return domain.VAPIDPublicKey(k.Public())
}

// RegisterPushSubscription registers a browser subscription of the
// signed-in caller (Team edition, D1066), audited. Its keys are sealed per
// row; they are never returned.
func (s *Service) RegisterPushSubscription(ctx context.Context, endpoint, p256dh, auth, label string) (PushSubscription, error) {
	c, err := self(ctx)
	if err != nil {
		return PushSubscription{}, err
	}
	if ok, err := s.webPush(ctx); err != nil {
		return PushSubscription{}, err
	} else if !ok {
		return PushSubscription{}, ErrPushEdition
	}
	host, err := domain.PushEndpointHost(endpoint)
	if err != nil || len(endpoint) > 2048 {
		return PushSubscription{}, ErrPushInvalid
	}
	public, secret, err := domain.PushKeys(p256dh, auth)
	if err != nil || len([]rune(label)) > 64 || (label != "" && !domain.PlainValue(label)) {
		return PushSubscription{}, ErrPushInvalid
	}
	id := ids.NewV7()
	sealedKey, err := s.envelope.Encrypt(ctx, s.pushField(c.Org, id, pushP256dhColumn), SecretPurpose, public)
	if err != nil {
		return PushSubscription{}, err
	}
	sealedAuth, err := s.envelope.Encrypt(ctx, s.pushField(c.Org, id, pushAuthColumn), SecretPurpose, secret)
	if err != nil {
		return PushSubscription{}, err
	}
	var out PushSubscription
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		n, err := q.CountLivePushSubscriptions(ctx, c.Org, c.Principal.ID)
		if err != nil {
			return err
		}
		if n >= MaxPushSubscriptions {
			return ErrPushLimit
		}
		r, err := q.InsertPushSubscription(ctx, dbq.InsertPushSubscriptionParams{
			OrgID: c.Org, ID: id, UserID: c.Principal.ID, Endpoint: endpoint, P256dh: sealedKey, Auth: sealedAuth, Label: label,
		})
		if db.IsNoRows(err) {
			return ErrPushExists
		} else if err != nil {
			return err
		}
		out = PushSubscription{
			ID: r.ID, EndpointHost: host, Label: r.Label, Created: r.CreatedAt, LastSuccess: r.LastSuccessAt,
			FailureCount: int(r.FailureCount),
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: auditkind.NotificationPushSubscriptionRegistered, Actor: c.Actor(), Outcome: audit.Success,
			Object:  &audit.Object{Type: "push_subscription", ID: id.String()},
			Details: map[string]string{"push_service": host},
		})
		return err
	})
	return out, err
}

// RemovePushSubscription removes one of the caller's own subscriptions,
// audited; another person's is not found.
func (s *Service) RemovePushSubscription(ctx context.Context, id ids.UUID) error {
	c, err := self(ctx)
	if err != nil {
		return err
	}
	return s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).RemovePushSubscription(ctx, c.Org, id, c.Principal.ID)
		if db.IsNoRows(err) {
			return ErrPushNotFound
		} else if err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: auditkind.NotificationPushSubscriptionRemoved, Actor: c.Actor(), Outcome: audit.Success,
			Object:  &audit.Object{Type: "push_subscription", ID: id.String()},
			Details: map[string]string{"push_service": hostOf(r.Endpoint)},
		})
		return err
	})
}

// MyPushSubscriptions lists the caller's own live subscriptions.
func (s *Service) MyPushSubscriptions(ctx context.Context) ([]PushSubscription, error) {
	c, err := self(ctx)
	if err != nil {
		return nil, err
	}
	var out []PushSubscription
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListPushSubscriptionsOf(ctx, c.Org, c.Principal.ID)
		for _, r := range rows {
			out = append(out, PushSubscription{
				ID: r.ID, EndpointHost: hostOf(r.Endpoint), Label: r.Label, Created: r.CreatedAt, LastSuccess: r.LastSuccessAt,
				FailureCount: int(r.FailureCount),
			})
		}
		return err
	}, db.ReadOnly())
	return out, err
}

// pushRecipientsFor adds one web_push delivery per personal recipient of an
// approval notice or digest who has a live subscription (Team edition),
// waiting as the person's preferences say. An edition that cannot be read
// pushes nothing; it never fails the notice.
func (s *Service) pushRecipientsFor(ctx context.Context, tx db.TenantTx, q *dbq.Queries, m Message, note ids.UUID,
	holds map[ids.UUID]hold,
) (int, error) {
	if s.vapid == nil || len(m.Personal) == 0 || !domain.PushEvent(m.Type) {
		return 0, nil
	}
	if ok, err := s.webPush(ctx); err != nil || !ok {
		if err != nil {
			s.log.WarnContext(ctx, "notifications.push_edition_unreadable", pclog.Err(err))
		}
		return 0, nil
	}
	users, err := q.UsersWithPushSubscriptions(ctx, m.Org, m.Personal)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, u := range users {
		h := holds[u]
		if h.skip {
			continue
		}
		if err := s.addDeliveryAt(ctx, tx, q, m.Org, note, nil, &u, domain.KindWebPush, "PENDING", h.at); err != nil {
			return 0, err
		}
		n++
	}
	return n, nil
}

// pushCount reads a digest's count back from its rendered title.
func pushCount(title string) int {
	f := strings.Fields(strings.TrimPrefix(title, domain.SimulatedPrefix))
	if len(f) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(f[0])
	return n
}

// sendWebPush pushes a link-only payload to each of the recipient's live
// subscriptions (RFC 8291 aes128gcm, RFC 8292 VAPID, TTL 3600, Urgency
// high). A 404 or 410 marks a subscription REMOVED. The delivery succeeds
// when one push service accepted it.
func (s *Service) sendWebPush(ctx context.Context, org ids.OrgID, d dbq.LoadDeliveryRow) outcome {
	if s.vapid == nil {
		return outcome{skip: true, code: "web_push_not_configured"}
	}
	if d.RecipientUserID == nil || d.RecipientState == nil || *d.RecipientState != "ACTIVE" {
		return outcome{skip: true, code: "no_recipient"}
	}
	var subs []dbq.ActivePushSubscriptionsRow
	if err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		subs, err = dbq.New(tx).ActivePushSubscriptions(ctx, org, *d.RecipientUserID)
		return err
	}, db.ReadOnly()); err != nil {
		return outcome{code: "subscriptions_unreadable"}
	}
	if len(subs) == 0 {
		return outcome{skip: true, code: "no_subscription"}
	}
	if _, err := s.vapid(); err != nil {
		return outcome{code: "vapid_key_unavailable"}
	}
	request := strings.TrimPrefix(d.LinkPath, "/approvals/")
	payload := domain.PushPayloadFor(strings.TrimSuffix(s.cfg.PublicURL, "/"), d.Type, request, pushCount(d.Title))
	plain, err := json.Marshal(payload)
	if err != nil {
		return outcome{code: "encode_failed", permanent: true}
	}
	out := outcome{code: "push_failed"}
	gone := 0
	for _, sub := range subs {
		res := s.pushOne(ctx, org, sub, plain)
		switch {
		case res.ok:
			out = outcome{ok: true, status: res.status}
		case res.gone:
			gone++
		case !out.ok:
			out.code, out.status = res.code, res.status
		}
	}
	if !out.ok && gone == len(subs) {
		return outcome{skip: true, code: "subscriptions_gone"}
	}
	return out
}

// pushOne sends one encrypted push and records the subscription's health.
func (s *Service) pushOne(ctx context.Context, org ids.OrgID, sub dbq.ActivePushSubscriptionsRow, plain []byte) outcome {
	public, err := s.envelope.Decrypt(ctx, s.pushField(org, sub.ID, pushP256dhColumn), SecretPurpose, sub.P256dh)
	if err != nil {
		return outcome{code: "secret_unavailable"}
	}
	secret, err := s.envelope.Decrypt(ctx, s.pushField(org, sub.ID, pushAuthColumn), SecretPurpose, sub.Auth)
	if err != nil {
		return outcome{code: "secret_unavailable"}
	}
	body, err := domain.EncryptPush(plain, public, secret)
	if err != nil {
		return outcome{code: "encrypt_failed"}
	}
	signer, err := s.vapid()
	if err != nil {
		return outcome{code: "vapid_key_unavailable"}
	}
	authz, err := domain.VAPIDAuthorization(signer, sub.Endpoint, s.vapidSubject, s.clock.Now())
	if err != nil {
		return outcome{code: "vapid_failed"}
	}
	res := s.postPush(ctx, sub.Endpoint, body, authz)
	_ = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		switch {
		case res.ok:
			return q.PushSucceeded(ctx, org, sub.ID)
		case res.gone:
			_, err := q.PushGone(ctx, org, sub.ID)
			return err
		default:
			return q.PushFailed(ctx, org, sub.ID)
		}
	})
	return res
}

// postPush sends one push request through the egress client, never
// following redirects, and reads at most 4 KiB of the answer.
func (s *Service) postPush(ctx context.Context, endpoint string, body []byte, authz string) outcome {
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return outcome{code: "bad_url", permanent: true}
	}
	req.Header.Set("Authorization", authz)
	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("TTL", strconv.Itoa(domain.PushTTL))
	req.Header.Set("Urgency", domain.PushUrgency)
	req.Header.Set("User-Agent", pushUserAgent)
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
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseRead))
	out := outcome{status: resp.StatusCode}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		out.ok = true
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		out.code, out.gone = "subscription_gone", true
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		out.code = "redirect_refused"
	default:
		out.code = "http_" + strconv.Itoa(resp.StatusCode)
	}
	return out
}
