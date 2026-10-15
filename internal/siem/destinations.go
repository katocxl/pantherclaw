// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package siem exports evidence to SIEMs (G0 M10 D35, D36; PN-018, F537,
// HR-259, HR-260, founder decision F3). A destination is an HTTPS URL that
// receives OCSF 1.9 batches signed with Standard Webhooks:
//
//   - it is created PENDING through the API by a person holding
//     siem.manage, and sends nothing until a person activates it on its
//     page with a fresh WebAuthn step-up (HR-259);
//   - its URL passes the notification webhook rules (https, no
//     credentials, never PantherClaw's own host) and the egress guard: a
//     private or loopback address is refused unless the destination is
//     marked internal, which the activation step-up also confirms; a
//     metadata service is always refused, by name, address or at dial
//     time;
//   - its URL, internal flag and data classes never change: another
//     target is another destination;
//   - each request carries Standard Webhooks signatures with the
//     destination's own secret, and both the new and the old secret's
//     signatures for 24 hours after a rotation.
//
// The exporter (export.go) moves each destination's cursor over the
// evidence feed.
package siem

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/siem/ocsf"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Permissions (D4).
const (
	PermRead   = td.PermSIEMRead
	PermManage = td.PermSIEMManage
)

// Parameters.
const (
	// SecretPurpose is the DEK purpose of destination signing secrets.
	SecretPurpose = "siem_secrets"
	// RotationOverlap is how long the old secret keeps signing.
	RotationOverlap = 24 * time.Hour
	// RequestTimeout bounds one export request.
	RequestTimeout = 15 * time.Second
	// MaxList bounds one page of destinations.
	MaxList = 200
)

// Destination states.
const (
	StatePending  = "PENDING"
	StateActive   = "ACTIVE"
	StatePaused   = "PAUSED"
	StateDisabled = "DISABLED"
)

// Encrypted destination columns: the AAD binds org, table, column and row
// (HR-062).
const (
	destinationsTable = "siem_destinations"
	secretColumn      = "secret"
	prevSecretColumn  = "prev_secret"
)

// Errors.
var (
	ErrInvalid = pcerr.New(pcerr.InvalidArgument, "INVALID_SIEM_DESTINATION",
		"a destination has a name (lowercase letters, digits and dashes), an https URL and 1 to 6 distinct data classes")
	ErrURL = pcerr.New(pcerr.InvalidArgument, "SIEM_DESTINATION_URL",
		"the URL must be https, without credentials or fragment, on port 443 or 1024-65535, not PantherClaw's own host, and public unless the destination is internal")
	ErrMetadata       = pcerr.New(pcerr.InvalidArgument, "SIEM_DESTINATION_METADATA", "a cloud metadata service is never a destination")
	ErrExists         = pcerr.New(pcerr.AlreadyExists, "SIEM_DESTINATION_EXISTS", "a destination with this name exists")
	ErrNotFound       = pcerr.New(pcerr.NotFound, "SIEM_DESTINATION_NOT_FOUND", "destination not found")
	ErrState          = pcerr.New(pcerr.FailedPrecondition, "SIEM_DESTINATION_STATE", "the destination is not in a state that allows this")
	ErrHuman          = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can do this")
	ErrEdition        = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "SIEM export needs the Business edition or above")
	ErrNothingWaiting = pcerr.New(pcerr.FailedPrecondition, "SIEM_NOTHING_WAITING", "no batch is waiting for delivery")
)

// Feed reads the evidence feed (D2, reflex/feed.Reader).
type Feed interface {
	After(ctx context.Context, tx db.TenantTx, after int64, limit int) ([]ocsf.Event, error)
	Head(ctx context.Context, tx db.TenantTx) (int64, error)
}

// Config is the export service's deployment configuration.
type Config struct {
	// PublicURL is PantherClaw's own URL: no destination may point at it.
	PublicURL string
	// AllowedPrivateRanges re-allows private destinations for every
	// destination (self-hosted operators). Operator configuration only.
	AllowedPrivateRanges []netip.Prefix
	// ProductVersion goes into metadata.product.version.
	ProductVersion string
	// RootCAs overrides the system roots (tests).
	RootCAs *x509.CertPool
}

// internalPrefixes are the private and loopback ranges an internal
// destination may reach. Metadata services stay denied inside them
// (httpx.DeniedAddr).
var internalPrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("fc00::/7"),
}

// Service implements the destination and export use cases.
type Service struct {
	pool     *db.Pool
	envelope *pccrypto.Envelope
	feed     Feed
	cfg      Config
	ownHost  string
	clock    clock.Clock
	log      *slog.Logger
	// public reaches ordinary destinations; internal also reaches the
	// private and loopback ranges. Both are egress clients.
	public, internal *http.Client
	// signals reports delivery that started failing (nil: not wired).
	signals HealthSink
	// editions gates the use cases (Business, D5); nil is Community.
	editions Editions
	// failures records owned failures (a lapsed edition); nil: not wired.
	failures reflexdomain.FailureSink
}

// New returns the service.
func New(pool *db.Pool, envelope *pccrypto.Envelope, feed Feed, cfg Config, clk clock.Clock, log *slog.Logger) (*Service, error) {
	u, err := url.Parse(cfg.PublicURL)
	if err != nil || u.Host == "" {
		return nil, errors.New("siem: public URL must be an absolute URL")
	}
	if log == nil {
		log = pclog.Discard()
	}
	ec := httpx.EgressConfig{Timeout: RequestTimeout, AllowedPrefixes: cfg.AllowedPrivateRanges}
	if cfg.RootCAs != nil {
		ec.RootCAs = cfg.RootCAs
	}
	ic := ec
	ic.AllowedPrefixes = append(slices.Clone(cfg.AllowedPrivateRanges), internalPrefixes...)
	return &Service{
		pool: pool, envelope: envelope, feed: feed, cfg: cfg, ownHost: u.Hostname(), clock: clk, log: log,
		public: httpx.NewEgressClient(ec), internal: httpx.NewEgressClient(ic),
	}, nil
}

// WithHealthSink reports failing delivery (owned failure and signal).
func (s *Service) WithHealthSink(h HealthSink) *Service {
	s.signals = h
	return s
}

// CheckURL applies the destination URL rules (HR-259): the notification
// webhook rules, with the egress guard's reading of the host; an internal
// destination may name a private or loopback address, never a metadata
// service.
func CheckURL(raw, ownHost string, internal bool, allowed []netip.Prefix) error {
	u, err := url.Parse(raw)
	if err != nil {
		return ErrURL
	}
	if httpx.MetadataHost(u.Hostname()) {
		return ErrMetadata
	}
	if a, ok := httpx.HostAddr(u.Hostname()); ok && httpx.MetadataAddr(a) {
		return ErrMetadata
	}
	if internal {
		allowed = append(slices.Clone(allowed), internalPrefixes...)
	}
	denied := func(host string) bool { return httpx.DeniedHost(host, allowed) }
	if err := ndomain.CheckWebhookURL(raw, ownHost, denied); err != nil {
		return ErrURL
	}
	return nil
}

// NewDestination describes a destination to create.
type NewDestination struct {
	Name        string
	URL         string
	Internal    bool
	DataClasses []string
}

// Created is a new destination. Secret is its signing secret, shown once.
type Created struct {
	Destination Destination
	Secret      string
}

// Destination is a destination and its delivery health (F537).
type Destination struct {
	ID          ids.UUID
	Name        string
	URL         string
	Internal    bool
	DataClasses []string
	Format      string
	State       string
	CreatedBy   string
	CreatedAt   time.Time
	ActivatedBy *ids.UUID
	ActivatedAt *time.Time
	// Health: configured (ACTIVE) is separate from delivery confirmed
	// (ConfirmedAt, the first 2xx).
	ConfirmedAt         *time.Time
	CursorSeq           int64
	LastDeliveredSeq    int64
	LastDeliveredAt     *time.Time
	ConsecutiveFailures int
	FailingSince        *time.Time
	LastFailureAt       *time.Time
	LastFailureCode     string
	DeliveredBatches    int64
	FailedBatches       int64
	Retries             int64
	RotationEndsAt      *time.Time
	// WaitingSince is when the open batch (from CursorSeq, where export is
	// held) was first built: its oldest event has waited at least since
	// then. Nil when nothing is waiting.
	WaitingSince *time.Time
	Health       string
}

// Health values of a destination.
const (
	HealthNotConfirmed = "NOT_CONFIRMED"
	HealthHealthy      = "HEALTHY"
	HealthDegraded     = "DEGRADED"
	HealthFailing      = "FAILING"
)

func healthOf(confirmed *time.Time, failures int) string {
	switch h := ndomain.HealthOf(failures); {
	case h == ndomain.Failing:
		return HealthFailing
	case h == ndomain.Degraded:
		return HealthDegraded
	case confirmed == nil:
		return HealthNotConfirmed
	}
	return HealthHealthy
}

func validClasses(cs []string) bool {
	if len(cs) == 0 || len(cs) > len(ocsf.DataClasses) {
		return false
	}
	seen := map[string]bool{}
	for _, c := range cs {
		if !ocsf.DataClass(c).Valid() || seen[c] {
			return false
		}
		seen[c] = true
	}
	return true
}

func (s *Service) field(org ids.OrgID, id ids.UUID, column string) pccrypto.FieldContext {
	return pccrypto.FieldContext{Org: org, Table: destinationsTable, Column: column, RowID: id.String()}
}

// Editions reports the licence's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// WithEditions sets the licence source (without one the server is
// Community and export is refused).
func (s *Service) WithEditions(e Editions) *Service {
	s.editions = e
	return s
}

// WithFailures records owned failures (a lapsed edition).
func (s *Service) WithFailures(f reflexdomain.FailureSink) *Service {
	s.failures = f
	return s
}

// business refuses unless the licence includes SIEM export (D5).
func (s *Service) business(ctx context.Context) error {
	if s.editions == nil {
		return ErrEdition
	}
	e, err := s.editions.Current(ctx)
	if err != nil {
		return err
	}
	if !e.SIEMExport() {
		return ErrEdition
	}
	return nil
}

// manager returns the caller if it is a person holding siem.manage, and
// with edition the licence must include SIEM export. Pausing and
// disabling stay possible after the licence lapses.
func (s *Service) manager(ctx context.Context, edition bool) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if err := c.Require(PermManage, td.OrgPath(c.Org)); err != nil {
		return c, err
	}
	if !c.Human() {
		return c, ErrHuman
	}
	if edition {
		if err := s.business(ctx); err != nil {
			return c, err
		}
	}
	return c, nil
}

// Create stores a PENDING destination and returns its signing secret once
// (D35). It sends nothing until a person activates it.
func (s *Service) Create(ctx context.Context, in NewDestination) (Created, error) {
	c, err := s.manager(ctx, true)
	if err != nil {
		return Created{}, err
	}
	if !ndomain.ValidChannelName(in.Name) || !validClasses(in.DataClasses) {
		return Created{}, ErrInvalid
	}
	if err := CheckURL(in.URL, s.ownHost, in.Internal, s.cfg.AllowedPrivateRanges); err != nil {
		return Created{}, err
	}
	secret, err := ndomain.NewSigningSecret()
	if err != nil {
		return Created{}, err
	}
	id := ids.NewV7()
	var out Created
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		blob, err := s.envelope.Encrypt(ctx, s.field(c.Org, id, secretColumn), SecretPurpose, secret)
		if err != nil {
			return fmt.Errorf("siem: encrypt secret: %w", err)
		}
		q := dbq.New(tx)
		err = q.InsertSIEMDestination(ctx, dbq.InsertSIEMDestinationParams{
			OrgID: c.Org, ID: id, Name: in.Name, Url: in.URL, Internal: in.Internal, DataClasses: in.DataClasses,
			Secret: blob, CreatedBy: c.Principal.ID.String(),
		})
		if db.IsUniqueViolation(err) {
			return ErrExists
		} else if err != nil {
			return err
		}
		if err := s.audit(ctx, tx, c, "siem.destination_created", id, map[string]string{
			"name": in.Name, "host": hostOf(in.URL), "internal": boolString(in.Internal), "data_classes": joinClasses(in.DataClasses),
		}); err != nil {
			return err
		}
		out.Destination, err = get(ctx, q, c.Org, id)
		return err
	})
	if err != nil {
		return Created{}, err
	}
	out.Secret = ndomain.FormatSecret(secret)
	return out, nil
}

// Activate makes a PENDING destination ACTIVE (HR-259): a person holding
// siem.manage, with a fresh step-up made with their own active key. Its
// cursor starts at the feed's head: nothing recorded before activation is
// sent.
func (s *Service) Activate(ctx context.Context, id ids.UUID, su stepup.StepUp) (Destination, error) {
	c, err := s.manager(ctx, true)
	if err != nil {
		return Destination{}, err
	}
	var out Destination
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if err := stepup.Check(ctx, tx, c, su, now); err != nil {
			return err
		}
		d, err := get(ctx, q, c.Org, id)
		if err != nil {
			return err
		}
		if d.State != StatePending {
			return ErrState
		}
		// The rules may have changed since the destination was created.
		if err := CheckURL(d.URL, s.ownHost, d.Internal, s.cfg.AllowedPrivateRanges); err != nil {
			return err
		}
		n, err := q.ActivateSIEMDestination(ctx, dbq.ActivateSIEMDestinationParams{
			ActivatedBy: &c.Principal.ID, ActivatedCredential: &su.Credential, OrgID: c.Org, ID: id,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrState
		}
		head, err := s.feed.Head(ctx, tx)
		if err != nil {
			return err
		}
		if err := q.InsertSIEMCursor(ctx, c.Org, id, head); err != nil {
			return err
		}
		if err := s.audit(ctx, tx, c, "siem.destination_activated", id, map[string]string{
			"host": hostOf(d.URL), "internal": boolString(d.Internal), "security_key": su.Credential.String(),
		}); err != nil {
			return err
		}
		out, err = get(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

// SetState pauses, resumes or disables a destination. DISABLED is final.
func (s *Service) SetState(ctx context.Context, id ids.UUID, state string) (Destination, error) {
	c, err := s.manager(ctx, state == StateActive)
	if err != nil {
		return Destination{}, err
	}
	var from []string
	switch state {
	case StatePaused:
		from = []string{StateActive}
	case StateActive:
		from = []string{StatePaused}
	case StateDisabled:
		from = []string{StatePending, StateActive, StatePaused}
	default:
		return Destination{}, ErrInvalid
	}
	var out Destination
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		d, err := get(ctx, q, c.Org, id)
		if err != nil {
			return err
		}
		if !slices.Contains(from, d.State) {
			return ErrState
		}
		n, err := q.SetSIEMDestinationState(ctx, dbq.SetSIEMDestinationStateParams{State: state, OrgID: c.Org, ID: id, Expected: d.State})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrState
		}
		if err := s.audit(ctx, tx, c, "siem.destination_state_changed", id, map[string]string{"from": d.State, "to": state}); err != nil {
			return err
		}
		out, err = get(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

// RotateSecret replaces the signing secret and returns the new one once;
// the old one keeps signing for RotationOverlap.
func (s *Service) RotateSecret(ctx context.Context, id ids.UUID) (string, error) {
	c, err := s.manager(ctx, true)
	if err != nil {
		return "", err
	}
	secret, err := ndomain.NewSigningSecret()
	if err != nil {
		return "", err
	}
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.LoadSIEMSecrets(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if row.State == StateDisabled {
			return ErrState
		}
		// The current secret becomes the previous one: re-encrypt it for
		// its new column, since the AAD binds the column.
		old, err := s.envelope.Decrypt(ctx, s.field(c.Org, id, secretColumn), SecretPurpose, row.Secret)
		if err != nil {
			return fmt.Errorf("siem: decrypt secret: %w", err)
		}
		prev, err := s.envelope.Encrypt(ctx, s.field(c.Org, id, prevSecretColumn), SecretPurpose, old)
		if err != nil {
			return err
		}
		blob, err := s.envelope.Encrypt(ctx, s.field(c.Org, id, secretColumn), SecretPurpose, secret)
		if err != nil {
			return err
		}
		n, err := q.RotateSIEMSecret(ctx, dbq.RotateSIEMSecretParams{
			Secret: blob, PrevSecret: prev, OverlapSeconds: int32(RotationOverlap / time.Second), OrgID: c.Org, ID: id,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrState
		}
		return s.audit(ctx, tx, c, "siem.destination_secret_rotated", id, nil)
	})
	if err != nil {
		return "", err
	}
	return ndomain.FormatSecret(secret), nil
}

// RetryDestination tries the destination's open batch again now, with a
// fresh retry schedule (D46). The cursor stays where it is: no event is
// ever skipped.
func (s *Service) RetryDestination(ctx context.Context, id ids.UUID) (Destination, error) {
	c, err := s.manager(ctx, true)
	if err != nil {
		return Destination{}, err
	}
	var out Destination
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		d, err := get(ctx, q, c.Org, id)
		if err != nil {
			return err
		}
		if d.State != StateActive {
			return ErrState
		}
		n, err := q.RetrySIEMBatchNow(ctx, c.Org, id)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNothingWaiting
		}
		if err := s.audit(ctx, tx, c, "siem.destination_retried", id, map[string]string{"cursor_seq": strconv.FormatInt(d.CursorSeq, 10)}); err != nil {
			return err
		}
		out, err = get(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

// Get returns one destination (siem.read).
func (s *Service) Get(ctx context.Context, id ids.UUID) (Destination, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Destination{}, err
	}
	if err := c.Require(PermRead, td.OrgPath(c.Org)); err != nil {
		return Destination{}, err
	}
	var out Destination
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = get(ctx, dbq.New(tx), c.Org, id)
		return err
	}, db.ReadOnly())
	return out, err
}

// List returns one page of destinations by id (siem.read).
func (s *Service) List(ctx context.Context, size int32, token string) ([]Destination, string, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, "", err
	}
	if err := c.Require(PermRead, td.OrgPath(c.Org)); err != nil {
		return nil, "", err
	}
	pr, err := page.Parse(size, token)
	if err != nil {
		return nil, "", err
	}
	var after *ids.UUID
	if !pr.After.IsZero() {
		after = &pr.After
	}
	var out []Destination
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListSIEMDestinations(ctx, c.Org, after, pr.Limit())
		if err != nil {
			return err
		}
		for _, r := range rows {
			out = append(out, fromRow(dbq.GetSIEMDestinationRow(r)))
		}
		return nil
	}, db.ReadOnly())
	if err != nil {
		return nil, "", err
	}
	out, next := page.Finish(pr, out, func(d Destination) ids.UUID { return d.ID })
	return out, next, nil
}

// Batch is one export batch (F537).
type Batch struct {
	ID            ids.UUID
	FromSeq       int64
	ToSeq         int64
	EventCount    int
	BodyBytes     int
	State         string
	Attempts      int
	NextAttemptAt time.Time
	LastAttemptAt *time.Time
	LastStatus    int
	LastError     string
	CreatedAt     time.Time
	DeliveredAt   *time.Time
}

// Batches returns a destination's last 20 batches, newest first
// (siem.read).
func (s *Service) Batches(ctx context.Context, id ids.UUID) ([]Batch, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.Require(PermRead, td.OrgPath(c.Org)); err != nil {
		return nil, err
	}
	var out []Batch
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := get(ctx, q, c.Org, id); err != nil {
			return err
		}
		rows, err := q.RecentSIEMBatches(ctx, c.Org, id)
		if err != nil {
			return err
		}
		for _, r := range rows {
			b := Batch{
				ID: r.ID, FromSeq: r.FromSeq, ToSeq: r.ToSeq, EventCount: int(r.EventCount), BodyBytes: int(r.BodyBytes), State: r.State,
				Attempts: int(r.Attempts), NextAttemptAt: r.NextAttemptAt, LastAttemptAt: r.LastAttemptAt, CreatedAt: r.CreatedAt,
				DeliveredAt: r.DeliveredAt,
			}
			if r.LastStatus != nil {
				b.LastStatus = int(*r.LastStatus)
			}
			if r.LastError != nil {
				b.LastError = *r.LastError
			}
			out = append(out, b)
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// ConfirmURL is a destination's activation page.
func (s *Service) ConfirmURL(id ids.UUID) string {
	return strings.TrimSuffix(s.cfg.PublicURL, "/") + "/integrations/destinations/" + id.String() + "/confirm"
}

func get(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID) (Destination, error) {
	r, err := q.GetSIEMDestination(ctx, org, id)
	if db.IsNoRows(err) {
		return Destination{}, ErrNotFound
	} else if err != nil {
		return Destination{}, err
	}
	return fromRow(r), nil
}

func fromRow(r dbq.GetSIEMDestinationRow) Destination {
	d := Destination{
		ID: r.ID, Name: r.Name, URL: r.Url, Internal: r.Internal, DataClasses: r.DataClasses, Format: r.Format, State: r.State,
		CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, ActivatedBy: r.ActivatedBy, ActivatedAt: r.ActivatedAt,
		ConfirmedAt: r.ConfirmedAt, CursorSeq: r.CursorSeq, LastDeliveredSeq: r.LastDeliveredSeq, LastDeliveredAt: r.LastDeliveredAt,
		ConsecutiveFailures: int(r.ConsecutiveFailures), FailingSince: r.FailingSince, LastFailureAt: r.LastFailureAt,
		DeliveredBatches: r.DeliveredBatches, FailedBatches: r.FailedBatches, Retries: r.Retries, RotationEndsAt: r.PrevSecretExpiresAt,
		WaitingSince: r.OpenBatchSince,
	}
	if r.LastFailureCode != nil {
		d.LastFailureCode = *r.LastFailureCode
	}
	d.Health = healthOf(d.ConfirmedAt, d.ConsecutiveFailures)
	return d
}

func (s *Service) audit(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name string, id ids.UUID, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success,
		Object: &audit.Object{Type: "siem_destination", ID: id.String()}, Details: details,
	})
	return err
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func joinClasses(cs []string) string {
	out := ""
	for i, c := range cs {
		if i > 0 {
			out += ","
		}
		out += c
	}
	return out
}
