// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package endpoints holds the automation endpoints (G0 M11 part 2 D21,
// D22, D53; HR-275, T-122): inbound event sources with their signed
// receiver, and automation destinations with their Deliverer.
//
// Both are created PENDING by a person holding automation.endpoints.manage
// and show their Standard Webhooks secret once; a person activates them
// (and rotates their secrets) only with a fresh security-key step-up of a
// browser session, so the API refuses those calls with STEP_UP_REQUIRED
// (D53) and the integration pages make them. Secrets are sealed with the
// envelope key (HR-062). A rotated secret keeps verifying (sources) or
// signing (destinations) for 24 hours.
package endpoints

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/automations/triggers"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	reflexports "github.com/katocxl/pantherclaw/internal/reflex/ports"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Parameters.
const (
	// SecretPurpose is the DEK purpose of endpoint secrets.
	SecretPurpose = "automation_endpoint_secrets" //nolint:gosec // a DEK purpose name, not a credential
	// RequestTimeout bounds one delivery request (D22).
	RequestTimeout = 10 * time.Second
	// MaxList bounds one listing.
	MaxList = 200
)

// Endpoint states.
const (
	StatePending  = "PENDING"
	StateActive   = "ACTIVE"
	StatePaused   = "PAUSED"
	StateDisabled = "DISABLED"
)

// Encrypted columns: the AAD binds org, table, column and row (HR-062).
const (
	sourcesTable      = "automation_event_sources"
	destinationsTable = "automation_destinations"
	secretColumn      = "secret"
	prevSecretColumn  = "prev_secret"
)

// Errors.
var (
	ErrInvalidSource = pcerr.New(pcerr.InvalidArgument, "INVALID_EVENT_SOURCE",
		"an event source has a name (lowercase letters, digits and dashes), 1 to 20 distinct event types (lowercase, at most 100 characters) and a rate of 1 to 600 a minute")
	ErrInvalidDestination = pcerr.New(pcerr.InvalidArgument, "INVALID_AUTOMATION_DESTINATION",
		"a destination has a name (lowercase letters, digits and dashes), an https URL and 1 to 3 distinct purposes (LAUNCH, DIGEST, NOTICE)")
	ErrURL = pcerr.New(pcerr.InvalidArgument, "AUTOMATION_DESTINATION_URL",
		"the URL must be https, without credentials or fragment, on port 443 or 1024-65535, not PantherClaw's own host, and public unless the destination is internal")
	ErrMetadata = pcerr.New(pcerr.InvalidArgument, "AUTOMATION_DESTINATION_METADATA", "a cloud metadata service is never a destination")
	ErrExists   = pcerr.New(pcerr.AlreadyExists, "AUTOMATION_ENDPOINT_EXISTS", "an endpoint with this name exists")
	ErrNotFound = pcerr.New(pcerr.NotFound, "AUTOMATION_ENDPOINT_NOT_FOUND", "endpoint not found")
	ErrState    = pcerr.New(pcerr.FailedPrecondition, "AUTOMATION_ENDPOINT_STATE", "the endpoint is not in a state that allows this")
	ErrRotating = pcerr.New(pcerr.FailedPrecondition, "AUTOMATION_ENDPOINT_ROTATING",
		"the previous secret is still valid for its 24-hour overlap; rotate again once it ends")
	ErrHuman = triggers.ErrHuman
)

// Config is the endpoints' deployment configuration.
type Config struct {
	// PublicURL is PantherClaw's own URL: no destination may point at it.
	PublicURL string
	// AllowedPrivateRanges re-allows private destinations (operator
	// configuration only).
	AllowedPrivateRanges []netip.Prefix
	// RootCAs overrides the system roots (tests).
	RootCAs *x509.CertPool
	// ClientIP resolves the source address behind trusted proxies.
	ClientIP httpx.ClientIPFunc
}

// internalPrefixes are the private and loopback ranges an internal
// destination may reach; metadata services stay denied (as SIEM's).
var internalPrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("fc00::/7"),
}

// Service implements the endpoint use cases, the receiver and the
// Deliverer.
type Service struct {
	pool             *db.Pool
	envelope         *pccrypto.Envelope
	triggers         *triggers.Service
	editions         triggers.Editions
	failures         reflexports.FailureSink
	cfg              Config
	ownHost          string
	clock            clock.Clock
	log              *slog.Logger
	public, internal *http.Client
}

// New returns the service.
func New(pool *db.Pool, envelope *pccrypto.Envelope, trig *triggers.Service, editions triggers.Editions,
	cfg Config, clk clock.Clock, log *slog.Logger,
) (*Service, error) {
	u, err := url.Parse(cfg.PublicURL)
	if err != nil || u.Host == "" {
		return nil, errors.New("endpoints: public URL must be an absolute URL")
	}
	if clk == nil {
		clk = clock.System{}
	}
	if log == nil {
		log = pclog.Discard()
	}
	ec := httpx.EgressConfig{Timeout: RequestTimeout, AllowedPrefixes: cfg.AllowedPrivateRanges, RootCAs: cfg.RootCAs}
	ic := ec
	ic.AllowedPrefixes = append(slices.Clone(cfg.AllowedPrivateRanges), internalPrefixes...)
	return &Service{
		pool: pool, envelope: envelope, triggers: trig, editions: editions, cfg: cfg, ownHost: u.Hostname(),
		clock: clk, log: log, public: httpx.NewEgressClient(ec), internal: httpx.NewEgressClient(ic),
	}, nil
}

// WithFailures records owned failures (deliveries that failed).
func (s *Service) WithFailures(f reflexports.FailureSink) *Service {
	s.failures = f
	return s
}

func field(org ids.OrgID, table string, id ids.UUID, column string) pccrypto.FieldContext {
	return pccrypto.FieldContext{Org: org, Table: table, Column: column, RowID: id.String()}
}

// manager returns the caller if it is a person holding
// automation.endpoints.manage and the licence includes automations.
// Disabling stays possible after the licence lapses.
func (s *Service) manager(ctx context.Context, edition bool) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if err := c.Require(td.PermAutomationEndpointsManage, td.OrgPath(c.Org)); err != nil {
		return c, err
	}
	if !c.Human() {
		return c, ErrHuman
	}
	if edition {
		if err := s.entitled(ctx); err != nil {
			return c, err
		}
	}
	return c, nil
}

func (s *Service) reader(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	return c, c.Require(td.PermAutomationRead, td.OrgPath(c.Org))
}

func (s *Service) entitled(ctx context.Context) error {
	if s.editions == nil {
		return triggers.ErrEdition
	}
	e, err := s.editions.Current(ctx)
	if err != nil {
		return err
	}
	if !e.Automations() {
		return triggers.ErrEdition
	}
	return nil
}

func (s *Service) audit(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name, objType string, id ids.UUID, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success,
		Object: &audit.Object{Type: objType, ID: id.String()}, Details: details,
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

// PruneReceipts deletes inbound receipts past their seven days (D21).
func (s *Service) PruneReceipts(ctx context.Context, org ids.OrgID) (int64, error) {
	var n int64
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		n, err = dbq.New(tx).PruneEventReceipts(ctx, org)
		return err
	})
	return n, err
}
