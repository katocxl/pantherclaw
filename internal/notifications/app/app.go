// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app holds the notification use cases (G0 M5 part 1): enqueueing
// a notification inside the producer's transaction (outbox), routing it to
// channels and recipients, and the channels themselves with their secrets
// encrypted per row (HR-062, HR-157..159).
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/riverqueue/river"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Delivery parameters (HR-159).
const (
	// Queue is the River queue of deliveries: slow destinations never hold
	// up other jobs.
	Queue = "notifications"
	// MaxAttempts bounds the attempts of one delivery (a schedule adapted
	// from the Standard Webhooks example, about 27 hours).
	MaxAttempts = domain.MaxAttempts
	// MaxPendingPerChannel bounds a channel's queue; beyond it new
	// deliveries are DROPPED and the channel is flagged.
	MaxPendingPerChannel = 1000
	// DefaultTTL is how long a notification is worth delivering.
	DefaultTTL = 24 * time.Hour
	// SecretPurpose is the DEK purpose of channel secrets.
	SecretPurpose = "notification_secrets"
)

// Delivery is the id kind of deliveries.
type Delivery struct{}

// KindName implements ids.Kind.
func (Delivery) KindName() string { return "delivery" }

// DeliverArgs asks for one delivery attempt. Job arguments carry ids only
// (HR-056).
type DeliverArgs struct {
	Org      ids.OrgID        `json:"org"`
	Delivery ids.ID[Delivery] `json:"delivery"`
}

// Kind implements river.JobArgs.
func (DeliverArgs) Kind() string { return "notifications.deliver" }

// InsertOpts puts deliveries on their own queue with the attempt cap.
func (DeliverArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: Queue, MaxAttempts: MaxAttempts}
}

// Config is the notification service's deployment configuration.
type Config struct {
	// PublicURL is PantherClaw's own URL: links point at it and webhooks
	// may not (HR-157).
	PublicURL string
	// AllowedPrivateRanges re-allows private destinations for self-hosted
	// deployments. Operator configuration only, never tenant input.
	AllowedPrivateRanges []netip.Prefix
}

// Service implements the notification use cases.
type Service struct {
	pool     *db.Pool
	jobs     *jobs.Client
	envelope *pccrypto.Envelope
	cfg      Config
	ownHost  string
	clock    clock.Clock
	log      *slog.Logger
	// mailer sends email (nil: not configured); http reaches Slack and
	// webhooks through the egress guards.
	mailer Mailer
	http   *http.Client
	// editions sets the channel limit (nil: Community).
	editions Editions
}

// New returns the service. jc may be an insert-only client (API role).
func New(pool *db.Pool, jc *jobs.Client, envelope *pccrypto.Envelope, cfg Config, clk clock.Clock, log *slog.Logger) (*Service, error) {
	u, err := url.Parse(cfg.PublicURL)
	if err != nil || u.Host == "" {
		return nil, errors.New("notifications: public URL must be an absolute URL")
	}
	if log == nil {
		log = pclog.Discard()
	}
	return &Service{
		pool: pool, jobs: jc, envelope: envelope, cfg: cfg, ownHost: u.Hostname(), clock: clk, log: log,
		http: httpx.NewEgressClient(httpx.EgressConfig{Timeout: RequestTimeout, AllowedPrefixes: cfg.AllowedPrivateRanges}),
	}, nil
}

// deniedHost is the egress guard's reading of a host as written, with the
// operator's allowed ranges: any spelling of a denied address, or a
// metadata service's name.
func (s *Service) deniedHost(host string) bool {
	return httpx.DeniedHost(host, s.cfg.AllowedPrivateRanges)
}

// Subject is what a notification is about (ids only).
type Subject struct {
	Type string
	ID   ids.UUID
}

// Message is a notification to enqueue.
type Message struct {
	Org    ids.OrgID
	Type   string
	Params map[string]string
	// Subject is optional.
	Subject *Subject
	// Personal lists users who get it by email whatever the channels say.
	Personal []ids.UUID
	// DedupeKey, when set, makes a second notification with the same key a
	// no-op (for example one notice per paused channel).
	DedupeKey string
	// TTL defaults to DefaultTTL; deliveries stop at expiry.
	TTL time.Duration
	// OnlyChannel delivers to that channel alone, whatever its
	// subscription (channel tests).
	OnlyChannel *ids.UUID
	// PersonalOnly delivers to the personal recipients alone, not to
	// subscribed channels (an escalation step that does not notify them).
	PersonalOnly bool
}

// Enqueued reports what Enqueue created.
type Enqueued struct {
	Notification ids.UUID
	Deliveries   int
	Duplicate    bool
	// Channels are the channels it was routed to.
	Channels []ids.UUID
}

// Enqueue renders m from its fixed template (HR-158), routes it to the
// matching channels and to its personal recipients, and inserts the
// notification, its deliveries and one job per pending delivery in tx, so a
// rolled-back change sends nothing. It never waits on a destination.
func (s *Service) Enqueue(ctx context.Context, tx db.TenantTx, m Message) (Enqueued, error) {
	r, err := domain.Render(m.Type, m.Params)
	if err != nil {
		return Enqueued{}, err
	}
	ttl := m.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	q := dbq.New(tx)
	out := Enqueued{Notification: ids.NewV7()}
	np := dbq.InsertNotificationParams{
		OrgID: m.Org, ID: out.Notification, Type: r.Type, Severity: string(r.Severity), Title: r.Title, Body: r.Body,
		LinkPath: r.Link, TtlSeconds: int32(ttl / time.Second),
	}
	if m.Subject != nil {
		np.SubjectType, np.SubjectID = &m.Subject.Type, &m.Subject.ID
	}
	if len(m.Personal) == 1 {
		np.RecipientUserID = &m.Personal[0]
	}
	if m.DedupeKey != "" {
		np.DedupeKey = &m.DedupeKey
	}
	n, err := q.InsertNotification(ctx, np)
	if err != nil {
		return Enqueued{}, err
	}
	if n == 0 {
		return Enqueued{Duplicate: true}, nil
	}
	emailed := map[ids.UUID]bool{}
	for _, u := range m.Personal {
		if emailed[u] {
			continue
		}
		emailed[u] = true
		if err := s.addDelivery(ctx, tx, q, m.Org, out.Notification, nil, &u, domain.KindEmail, "PENDING"); err != nil {
			return Enqueued{}, err
		}
		out.Deliveries++
	}
	if m.PersonalOnly {
		return out, nil
	}
	channels, err := q.ChannelsForRouting(ctx, m.Org)
	if err != nil {
		return Enqueued{}, err
	}
	for _, c := range channels {
		switch {
		case m.OnlyChannel != nil:
			if c.ID != *m.OnlyChannel {
				continue
			}
		case !domain.Matches(c.EventTypes, r.Type) || !r.Severity.AtLeast(domain.Severity(c.MinSeverity)):
			continue
		}
		added, err := s.route(ctx, tx, q, m.Org, out.Notification, c, emailed)
		if err != nil {
			return Enqueued{}, err
		}
		out.Deliveries += added
		out.Channels = append(out.Channels, c.ID)
	}
	return out, nil
}

// route adds a matching channel's deliveries: one for log, Slack and
// webhook channels, one per enabled holder of the role for email channels.
// A paused channel gets SKIPPED deliveries, a full one DROPPED (HR-159).
func (s *Service) route(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, note ids.UUID,
	c dbq.ChannelsForRoutingRow, emailed map[ids.UUID]bool,
) (int, error) {
	state := "PENDING"
	if c.State == "PAUSED" {
		state = "SKIPPED"
	} else {
		pending, err := q.PendingDeliveries(ctx, org, &c.ID, MaxPendingPerChannel)
		if err != nil {
			return 0, err
		}
		if pending >= MaxPendingPerChannel {
			state = "DROPPED"
			if err := q.FlagChannelQueueFull(ctx, org, c.ID); err != nil {
				return 0, err
			}
			s.log.WarnContext(ctx, "notifications.queue_full", slog.String("org", org.String()), slog.String("channel", c.ID.String()))
		}
	}
	kind := domain.Kind(c.Kind)
	if kind != domain.KindEmail {
		return 1, s.addDelivery(ctx, tx, q, org, note, &c.ID, nil, kind, state)
	}
	users, err := q.ActiveUsersWithOrgRole(ctx, org, deref(c.RecipientRole))
	if err != nil {
		return 0, err
	}
	added := 0
	for _, u := range users {
		if emailed[u] {
			continue // already emailed personally
		}
		emailed[u] = true
		if err := s.addDelivery(ctx, tx, q, org, note, &c.ID, &u, kind, state); err != nil {
			return 0, err
		}
		added++
	}
	return added, nil
}

func (s *Service) addDelivery(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, note ids.UUID,
	channel, user *ids.UUID, kind domain.Kind, state string,
) error {
	id := ids.NewV7()
	var reason *string
	switch state {
	case "SKIPPED":
		reason = ptr("channel_paused")
	case "DROPPED":
		reason = ptr("queue_full")
	}
	if err := q.InsertDelivery(ctx, dbq.InsertDeliveryParams{
		OrgID: org, ID: id, NotificationID: note, ChannelID: channel, RecipientUserID: user, Kind: string(kind),
		State: state, LastError: reason,
	}); err != nil {
		return err
	}
	if state != "PENDING" {
		return nil
	}
	if s.jobs == nil {
		return errors.New("notifications: no job client")
	}
	did, err := ids.FromUUID[Delivery](id)
	if err != nil {
		return err
	}
	return jobs.InsertTx(ctx, s.jobs, tx, DeliverArgs{Org: org, Delivery: did}, nil)
}

// SecurityNotice implements authn/app.SecurityNotifier: the user is emailed
// personally, and channels subscribed to security events are told too.
func (s *Service) SecurityNotice(ctx context.Context, tx db.TenantTx, n authnapp.SecurityNotice) error {
	u, err := dbq.New(tx).GetUser(ctx, n.Org, n.User)
	if err != nil {
		return err
	}
	who := td.SanitizeClaim(u.DisplayName, domain.MaxParamValue)
	if u.Email != "" {
		who = td.SanitizeClaim(u.Email, domain.MaxParamValue)
	}
	if !domain.PlainValue(who) {
		who = "user " + u.ID.String()
	}
	m := Message{Org: n.Org, Type: n.Type, Personal: []ids.UUID{n.User}}
	if n.Type == "security.sessions_revoked" {
		m.Params = map[string]string{"user": who, "count": strconv.Itoa(n.Count)}
		m.Subject = &Subject{Type: "user", ID: n.User}
	} else {
		name := td.SanitizeClaim(n.Name, 64)
		if !domain.PlainValue(name) {
			name = "(unnamed key)"
		}
		m.Params = map[string]string{"user": who, "key_name": name}
		m.Subject = &Subject{Type: "webauthn_credential", ID: n.Credential}
	}
	_, err = s.Enqueue(ctx, tx, m)
	if err != nil {
		return fmt.Errorf("notifications: security notice: %w", err)
	}
	return nil
}

var _ authnapp.SecurityNotifier = (*Service)(nil)

func ptr(s string) *string { return &s }

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// FailedSubjects returns the subjects of subjectType, among subjects, whose
// notices failed to deliver, read in tx (G0 M5 part 2: a waitlist entry's
// routing health). Delivery state is shown to people only and never
// reaches an authorization decision (HR-039).
func (s *Service) FailedSubjects(ctx context.Context, tx db.TenantTx, org ids.OrgID, subjectType string, subjects []ids.UUID) ([]ids.UUID, error) {
	if len(subjects) == 0 {
		return nil, nil
	}
	return dbq.New(tx).FailedNoticeSubjects(ctx, org, &subjectType, subjects)
}
