// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package signals receives Shared Signals (CAEP and RISC) security events
// from configured identity providers (G0 M10 D37; PN-024, HR-261, T-113,
// founder decision F1).
//
// A transmitter is created PENDING through the API by a person holding
// signals.manage and receives nothing until a person activates it on its
// page with a fresh WebAuthn step-up. Its issuer, JWKS URI (https, on the
// issuer's host) and audience never change: other keys or another issuer
// are another transmitter. The receiver (receiver.go) accepts only SETs
// that setverify verifies against an ACTIVE transmitter's pinned keys,
// refuses a jti it has seen, and records each event once. Every handled
// event opens a case; the identity playbook acts only when enabled.
package signals

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	"github.com/katocxl/pantherclaw/internal/signals/setverify"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Permissions (D4).
const (
	PermRead   = td.PermSignalsRead
	PermManage = td.PermSignalsManage
)

// Parameters.
const (
	// EndpointPath is the receiver's route; {org} and {transmitter} are ids.
	EndpointPath = "/v1/ssf/{org}/{transmitter}"
	// MaxList bounds one page of transmitters.
	MaxList = 200
	// FetchTimeout bounds one JWKS fetch.
	FetchTimeout = 10 * time.Second
)

// Transmitter states.
const (
	StatePending  = "PENDING"
	StateActive   = "ACTIVE"
	StatePaused   = "PAUSED"
	StateDisabled = "DISABLED"
)

// Errors.
var (
	ErrInvalid = pcerr.New(pcerr.InvalidArgument, "INVALID_SSF_TRANSMITTER",
		"a transmitter has a name (lowercase letters, digits and dashes), an https issuer, an https JWKS URI on the issuer's host and an audience of at most 2048 characters")
	ErrExists   = pcerr.New(pcerr.AlreadyExists, "SSF_TRANSMITTER_EXISTS", "a transmitter with this name exists")
	ErrNotFound = pcerr.New(pcerr.NotFound, "SSF_TRANSMITTER_NOT_FOUND", "transmitter not found")
	ErrState    = pcerr.New(pcerr.FailedPrecondition, "SSF_TRANSMITTER_STATE", "the transmitter is not in a state that allows this")
	ErrHuman    = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can do this")
	ErrEdition  = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "Shared Signals need the Business edition or above")
)

// Config is the receiver's deployment configuration.
type Config struct {
	// PublicURL is PantherClaw's URL: the default audience is the
	// transmitter's endpoint under it.
	PublicURL string
}

// Service implements the transmitter and receiver use cases.
type Service struct {
	pool   *db.Pool
	cfg    Config
	base   string
	clock  clock.Clock
	log    *slog.Logger
	client *http.Client
	// sink handles accepted events (cases, playbook); nil: record only.
	sink Sink
	// cases, container, raiser and notify handle accepted events (D37, D38);
	// each may be nil (D49).
	cases     reflexdomain.CaseOpener
	container reflexdomain.Container
	raiser    reflexdomain.Raiser
	notify    Notifier
	// editions gates the use cases and the receiver (Business, D5); nil
	// is Community.
	editions Editions
	// failures records owned failures (a lapsed edition); nil: not wired.
	failures reflexdomain.FailureSink

	mu   sync.Mutex
	jwks map[ids.UUID]*cachedJWKS
}

type cachedJWKS struct {
	issuer, uri string
	keys        *setverify.JWKS
}

// maxCachedJWKS bounds the key caches kept in memory.
const maxCachedJWKS = 1000

// New returns the service. Keys are fetched through an egress client
// (public addresses only).
func New(pool *db.Pool, cfg Config, clk clock.Clock, log *slog.Logger) (*Service, error) {
	u, err := url.Parse(cfg.PublicURL)
	if err != nil || u.Host == "" {
		return nil, errors.New("signals: public URL must be an absolute URL")
	}
	if log == nil {
		log = pclog.Discard()
	}
	return &Service{
		pool: pool, cfg: cfg, base: strings.TrimSuffix(cfg.PublicURL, "/"), clock: clk, log: log,
		client: httpx.NewEgressClient(httpx.EgressConfig{Timeout: FetchTimeout}),
		jwks:   map[ids.UUID]*cachedJWKS{},
	}, nil
}

// WithSink sets what handles accepted events.
func (s *Service) WithSink(k Sink) *Service {
	s.sink = k
	return s
}

// WithHTTPClient replaces the key-fetching client (tests: an egress client
// with the test CA).
func (s *Service) WithHTTPClient(c *http.Client) *Service {
	s.client = c
	return s
}

// EndpointURL is the receiver URL of a transmitter, its default audience.
func (s *Service) EndpointURL(org ids.OrgID, id ids.UUID) string {
	return s.base + "/v1/ssf/" + org.String() + "/" + id.String()
}

// NewTransmitter describes a transmitter to create. Audience defaults to
// the endpoint URL.
type NewTransmitter struct {
	Name     string
	Issuer   string
	JWKSURI  string
	Audience string
}

// Transmitter is a configured transmitter and what it sent.
type Transmitter struct {
	ID              ids.UUID
	Name            string
	Issuer          string
	JWKSURI         string
	Audience        string
	State           string
	EndpointURL     string
	CreatedBy       string
	CreatedAt       time.Time
	ActivatedBy     *ids.UUID
	ActivatedAt     *time.Time
	LastEventAt     *time.Time
	EventsAccepted  int64
	EventsRefused   int64
	LastRefusalAt   *time.Time
	LastRefusalCode string
}

// Editions reports the licence's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// WithEditions sets the licence source (without one the server is
// Community and Shared Signals are refused).
func (s *Service) WithEditions(e Editions) *Service {
	s.editions = e
	return s
}

// WithFailures records owned failures (a lapsed edition).
func (s *Service) WithFailures(f reflexdomain.FailureSink) *Service {
	s.failures = f
	return s
}

// business refuses unless the licence includes Shared Signals (D5).
func (s *Service) business(ctx context.Context) error {
	if s.editions == nil {
		return ErrEdition
	}
	e, err := s.editions.Current(ctx)
	if err != nil {
		return err
	}
	if !e.SharedSignals() {
		return ErrEdition
	}
	return nil
}

// manager returns the caller if it is a person holding signals.manage,
// and with edition the licence must include Shared Signals. Pausing and
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

// Create stores a PENDING transmitter.
func (s *Service) Create(ctx context.Context, in NewTransmitter) (Transmitter, error) {
	c, err := s.manager(ctx, true)
	if err != nil {
		return Transmitter{}, err
	}
	id := ids.NewV7()
	if in.Audience == "" {
		in.Audience = s.EndpointURL(c.Org, id)
	}
	if !ndomain.ValidChannelName(in.Name) || len(in.Issuer) > 512 || len(in.Audience) > 2048 ||
		setverify.CheckJWKSURI(in.Issuer, in.JWKSURI) != nil {
		return Transmitter{}, ErrInvalid
	}
	var out Transmitter
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		err := q.InsertSSFTransmitter(ctx, dbq.InsertSSFTransmitterParams{
			OrgID: c.Org, ID: id, Name: in.Name, Issuer: in.Issuer, JwksUri: in.JWKSURI, Audience: in.Audience,
			CreatedBy: c.Principal.ID.String(),
		})
		if db.IsUniqueViolation(err) {
			return ErrExists
		} else if err != nil {
			return err
		}
		if err := auditCaller(ctx, tx, c, "signals.transmitter_created", id, map[string]string{
			"name": in.Name, "issuer": in.Issuer, "jwks_uri": in.JWKSURI,
		}); err != nil {
			return err
		}
		out, err = s.get(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

// Activate makes a PENDING transmitter ACTIVE (HR-261): a person holding
// signals.manage with a fresh step-up made with their own active key.
func (s *Service) Activate(ctx context.Context, id ids.UUID, su stepup.StepUp) (Transmitter, error) {
	c, err := s.manager(ctx, true)
	if err != nil {
		return Transmitter{}, err
	}
	var out Transmitter
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if err := stepup.Check(ctx, tx, c, su, now); err != nil {
			return err
		}
		n, err := q.ActivateSSFTransmitter(ctx, dbq.ActivateSSFTransmitterParams{
			ActivatedBy: &c.Principal.ID, ActivatedCredential: &su.Credential, OrgID: c.Org, ID: id,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			if _, err := s.get(ctx, q, c.Org, id); err != nil {
				return err
			}
			return ErrState
		}
		if err := auditCaller(ctx, tx, c, "signals.transmitter_activated", id, map[string]string{"security_key": su.Credential.String()}); err != nil {
			return err
		}
		out, err = s.get(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

// SetState pauses, resumes or disables a transmitter. DISABLED is final.
func (s *Service) SetState(ctx context.Context, id ids.UUID, state string) (Transmitter, error) {
	c, err := s.manager(ctx, state == StateActive)
	if err != nil {
		return Transmitter{}, err
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
		return Transmitter{}, ErrInvalid
	}
	var out Transmitter
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		t, err := s.get(ctx, q, c.Org, id)
		if err != nil {
			return err
		}
		if !slices.Contains(from, t.State) {
			return ErrState
		}
		n, err := q.SetSSFTransmitterState(ctx, dbq.SetSSFTransmitterStateParams{State: state, OrgID: c.Org, ID: id, Expected: t.State})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrState
		}
		if err := auditCaller(ctx, tx, c, "signals.transmitter_state_changed", id, map[string]string{"from": t.State, "to": state}); err != nil {
			return err
		}
		out, err = s.get(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

// Get returns one transmitter (signals.read).
func (s *Service) Get(ctx context.Context, id ids.UUID) (Transmitter, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Transmitter{}, err
	}
	if err := c.Require(PermRead, td.OrgPath(c.Org)); err != nil {
		return Transmitter{}, err
	}
	var out Transmitter
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = s.get(ctx, dbq.New(tx), c.Org, id)
		return err
	}, db.ReadOnly())
	return out, err
}

// List returns one page of transmitters by id (signals.read).
func (s *Service) List(ctx context.Context, size int32, token string) ([]Transmitter, string, error) {
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
	var out []Transmitter
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListSSFTransmitters(ctx, c.Org, after, pr.Limit())
		if err != nil {
			return err
		}
		for _, r := range rows {
			out = append(out, s.fromRow(c.Org, dbq.GetSSFTransmitterRow(r)))
		}
		return nil
	}, db.ReadOnly())
	if err != nil {
		return nil, "", err
	}
	out, next := page.Finish(pr, out, func(t Transmitter) ids.UUID { return t.ID })
	return out, next, nil
}

// Event is one received event: its type and whom it matched, never the
// token or the subject's identifiers.
type Event struct {
	ID            ids.UUID
	JTI           string
	EventType     string
	IssuedAt      time.Time
	SubjectFormat string
	User          *ids.UUID
	MatchBasis    string
	Outcome       string
	Case          *ids.UUID
	ReceivedAt    time.Time
}

// Events returns a transmitter's last 50 events, newest first
// (signals.read).
func (s *Service) Events(ctx context.Context, id ids.UUID) ([]Event, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.Require(PermRead, td.OrgPath(c.Org)); err != nil {
		return nil, err
	}
	var out []Event
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := s.get(ctx, q, c.Org, id); err != nil {
			return err
		}
		rows, err := q.ListSSFEvents(ctx, c.Org, id)
		if err != nil {
			return err
		}
		for _, r := range rows {
			e := Event{
				ID: r.ID, JTI: r.Jti, EventType: r.EventType, IssuedAt: r.IssuedAt, User: r.UserID, Outcome: r.Outcome, Case: r.CaseID,
				ReceivedAt: r.ReceivedAt,
			}
			if r.SubjectFormat != nil {
				e.SubjectFormat = *r.SubjectFormat
			}
			if r.MatchBasis != nil {
				e.MatchBasis = *r.MatchBasis
			}
			out = append(out, e)
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// ConfirmURL is a transmitter's activation page.
func (s *Service) ConfirmURL(id ids.UUID) string {
	return s.base + "/integrations/transmitters/" + id.String() + "/confirm"
}

func (s *Service) get(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID) (Transmitter, error) {
	r, err := q.GetSSFTransmitter(ctx, org, id)
	if db.IsNoRows(err) {
		return Transmitter{}, ErrNotFound
	} else if err != nil {
		return Transmitter{}, err
	}
	return s.fromRow(org, r), nil
}

func (s *Service) fromRow(org ids.OrgID, r dbq.GetSSFTransmitterRow) Transmitter {
	t := Transmitter{
		ID: r.ID, Name: r.Name, Issuer: r.Issuer, JWKSURI: r.JwksUri, Audience: r.Audience, State: r.State,
		EndpointURL: s.EndpointURL(org, r.ID), CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, ActivatedBy: r.ActivatedBy,
		ActivatedAt: r.ActivatedAt, LastEventAt: r.LastEventAt, EventsAccepted: r.EventsAccepted, EventsRefused: r.EventsRefused,
		LastRefusalAt: r.LastRefusalAt,
	}
	if r.LastRefusalCode != nil {
		t.LastRefusalCode = *r.LastRefusalCode
	}
	return t
}

func auditCaller(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name string, id ids.UUID, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success,
		Object: &audit.Object{Type: "ssf_transmitter", ID: id.String()}, Details: details,
	})
	return err
}

// keysFor returns the key cache of a transmitter, replacing it when its
// issuer or JWKS URI differ from the cached ones.
func (s *Service) keysFor(id ids.UUID, issuer, uri string) (*setverify.JWKS, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.jwks[id]; ok && c.issuer == issuer && c.uri == uri {
		return c.keys, nil
	}
	k, err := setverify.NewJWKS(s.client, issuer, uri, s.clock.Now)
	if err != nil {
		return nil, err
	}
	if len(s.jwks) >= maxCachedJWKS {
		clear(s.jwks)
	}
	s.jwks[id] = &cachedJWKS{issuer: issuer, uri: uri, keys: k}
	return k, nil
}
