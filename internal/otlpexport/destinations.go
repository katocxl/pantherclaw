// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package otlpexport sends an org's agent spans to the org's own
// OpenTelemetry collectors (G0 M36 D1061, D1062; FQ36-1, FQ36-2;
// HR-786..788; every edition). A destination is an OTLP/HTTP traces
// endpoint:
//
//   - it is created PENDING through the API by a person holding
//     otlp.manage, and sends nothing until a person activates it on its
//     page with a fresh WebAuthn step-up, as a SIEM destination (HR-259);
//   - its URL passes the SIEM destination rules (https, no credentials,
//     never PantherClaw's own host, never a private, loopback or metadata
//     address) and every request goes through the egress client;
//   - its URL and headers never change: another endpoint is another
//     destination. The headers (an API key, a Basic authorization) are
//     sealed under the org's DEK and never shown again.
//
// The exporter (export.go) follows a cursor over the evidence feed and
// posts each batch's decision, tool and model spans (spans.go) as
// OTLP/HTTP protobuf with this package's own client: the operator's
// telemetry (platform/telemetry, HR-380) is untouched. Spans carry
// metadata only, never prompts, arguments or answers.
package otlpexport

import (
	"context"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
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
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
	"github.com/katocxl/pantherclaw/internal/siem"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Permissions (D1061).
const (
	PermRead   = td.PermOTLPRead
	PermManage = td.PermOTLPManage
)

// Parameters.
const (
	// HeaderPurpose is the DEK purpose of sealed destination headers.
	HeaderPurpose = "otlp_headers"
	// RequestTimeout bounds one export request (D1061).
	RequestTimeout = 10 * time.Second
	// MaxHeaders bounds a destination's headers.
	MaxHeaders = 8
	// maxHeaderValue bounds one header value.
	maxHeaderValue = 4096
)

// Destination states.
const (
	StatePending  = "PENDING"
	StateActive   = "ACTIVE"
	StateDisabled = "DISABLED"
)

// The sealed column: the AAD binds org, table, column and row (HR-062).
const (
	destinationsTable = "otlp_destinations"
	headersColumn     = "header_secret_ref"
)

// Errors.
var (
	ErrInvalid = pcerr.New(pcerr.InvalidArgument, "INVALID_OTLP_DESTINATION",
		"a destination has a name (lowercase letters, digits and dashes), an https URL and at most 8 distinct headers")
	ErrHeader = pcerr.New(pcerr.InvalidArgument, "OTLP_DESTINATION_HEADER",
		"a header has a token name that is not a transport header (Host, Content-Type, Content-Encoding, Content-Length, "+
			"Connection, Transfer-Encoding, TE, Upgrade, User-Agent, Cookie) and a printable value of at most 4096 bytes")
	ErrURL = pcerr.New(pcerr.InvalidArgument, "OTLP_DESTINATION_URL",
		"the URL must be https, without credentials or fragment, on port 443 or 1024-65535, not PantherClaw's own host, and public")
	ErrMetadata = pcerr.New(pcerr.InvalidArgument, "OTLP_DESTINATION_METADATA", "a cloud metadata service is never a destination")
	ErrExists   = pcerr.New(pcerr.AlreadyExists, "OTLP_DESTINATION_EXISTS", "a destination with this name exists")
	ErrNotFound = pcerr.New(pcerr.NotFound, "OTLP_DESTINATION_NOT_FOUND", "destination not found")
	ErrState    = pcerr.New(pcerr.FailedPrecondition, "OTLP_DESTINATION_STATE", "the destination is not in a state that allows this")
	ErrHuman    = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can do this")
)

// Feed reads the evidence feed (reflex/feed.Reader).
type Feed interface {
	After(ctx context.Context, tx db.TenantTx, after int64, limit int) ([]feed.Event, error)
	Head(ctx context.Context, tx db.TenantTx) (int64, error)
}

// Config is the exporter's deployment configuration.
type Config struct {
	// PublicURL is PantherClaw's own URL: no destination may point at it,
	// and the activation page lives under it.
	PublicURL string
	// ConsoleURL is the console's base URL for the spans'
	// pantherclaw.console_url; empty leaves the attribute out.
	ConsoleURL string
	// AllowedPrivateRanges re-allows private destinations (self-hosted
	// operators). Operator configuration only.
	AllowedPrivateRanges []netip.Prefix
	// RootCAs overrides the system roots (tests).
	RootCAs *x509.CertPool
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
	// http is the egress client every export goes through.
	http *http.Client
}

// New returns the service.
func New(pool *db.Pool, envelope *pccrypto.Envelope, fd Feed, cfg Config, clk clock.Clock, log *slog.Logger) (*Service, error) {
	u, err := url.Parse(cfg.PublicURL)
	if err != nil || u.Host == "" {
		return nil, errors.New("otlpexport: public URL must be an absolute URL")
	}
	if log == nil {
		log = pclog.Discard()
	}
	ec := httpx.EgressConfig{Timeout: RequestTimeout, AllowedPrefixes: cfg.AllowedPrivateRanges}
	if cfg.RootCAs != nil {
		ec.RootCAs = cfg.RootCAs
	}
	return &Service{
		pool: pool, envelope: envelope, feed: fd, cfg: cfg, ownHost: u.Hostname(), clock: clk, log: log,
		http: httpx.NewEgressClient(ec),
	}, nil
}

// CheckURL applies the SIEM destination URL rules to a public destination
// (D1061, HR-786).
func CheckURL(raw, ownHost string, allowed []netip.Prefix) error {
	switch err := siem.CheckURL(raw, ownHost, false, allowed); {
	case err == nil:
		return nil
	case errors.Is(err, siem.ErrMetadata):
		return ErrMetadata
	default:
		return ErrURL
	}
}

// Header is one request header the collector needs.
type Header struct {
	Name, Value string
}

// sealedHeader is a header in the sealed blob.
type sealedHeader struct {
	Name  string `json:"n"`
	Value string `json:"v"`
}

// reservedHeaders are the transport headers a destination never sets.
var reservedHeaders = []string{
	"host", "content-type", "content-encoding", "content-length", "connection", "transfer-encoding", "te",
	"upgrade", "user-agent", "cookie", "keep-alive", "proxy-authorization", "proxy-connection",
}

func validHeaders(hs []Header) error {
	if len(hs) > MaxHeaders {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, h := range hs {
		name := strings.ToLower(h.Name)
		if !headerName(h.Name) || slices.Contains(reservedHeaders, name) || seen[name] {
			return ErrHeader
		}
		seen[name] = true
		if h.Value == "" || len(h.Value) > maxHeaderValue {
			return ErrHeader
		}
		for i := range len(h.Value) {
			if c := h.Value[i]; c < 0x20 || c > 0x7e {
				return ErrHeader
			}
		}
	}
	return nil
}

func headerName(n string) bool {
	if n == "" || len(n) > 64 || n[0] == '-' {
		return false
	}
	for i := range len(n) {
		c := n[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// NewDestination describes a destination to create.
type NewDestination struct {
	Name    string
	URL     string
	Headers []Header
}

// Destination is a destination and its export health.
type Destination struct {
	ID              ids.UUID
	Name            string
	URL             string
	HeaderNames     []string
	State           string
	CreatedBy       string
	CreatedAt       time.Time
	ActivatedBy     *ids.UUID
	ActivatedAt     *time.Time
	DisabledAt      *time.Time
	CursorSeq       int64
	LastSuccessAt   *time.Time
	FailureCount    int
	FailingSince    *time.Time
	LastFailureCode string
}

func (s *Service) field(org ids.OrgID, id ids.UUID) pccrypto.FieldContext {
	return pccrypto.FieldContext{Org: org, Table: destinationsTable, Column: headersColumn, RowID: id.String()}
}

// manager returns the caller if it is a person holding otlp.manage.
func manager(ctx context.Context) (tenancy.Caller, error) {
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
	return c, nil
}

// reader returns the caller if it holds otlp.read.
func reader(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	return c, c.Require(PermRead, td.OrgPath(c.Org))
}

// Create stores a PENDING destination with its headers sealed (D1061). It
// sends nothing until a person activates it.
func (s *Service) Create(ctx context.Context, in NewDestination) (Destination, error) {
	c, err := manager(ctx)
	if err != nil {
		return Destination{}, err
	}
	if !ndomain.ValidChannelName(in.Name) {
		return Destination{}, ErrInvalid
	}
	if err := validHeaders(in.Headers); err != nil {
		return Destination{}, err
	}
	if err := CheckURL(in.URL, s.ownHost, s.cfg.AllowedPrivateRanges); err != nil {
		return Destination{}, err
	}
	id := ids.NewV7()
	names := make([]string, 0, len(in.Headers))
	sealed := make([]sealedHeader, 0, len(in.Headers))
	for _, h := range in.Headers {
		names = append(names, h.Name)
		sealed = append(sealed, sealedHeader{Name: h.Name, Value: h.Value})
	}
	var out Destination
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var blob []byte
		if len(sealed) > 0 {
			plain, err := json.Marshal(sealed)
			if err != nil {
				return err
			}
			if blob, err = s.envelope.Encrypt(ctx, s.field(c.Org, id), HeaderPurpose, plain); err != nil {
				return fmt.Errorf("otlpexport: seal headers: %w", err)
			}
		}
		q := dbq.New(tx)
		err := q.InsertOTLPDestination(ctx, dbq.InsertOTLPDestinationParams{
			OrgID: c.Org, ID: id, Name: in.Name, Url: in.URL, HeaderSecretRef: blob, HeaderNames: names,
			CreatedBy: c.Principal.ID.String(),
		})
		if db.IsUniqueViolation(err) {
			return ErrExists
		} else if err != nil {
			return err
		}
		if err := record(ctx, tx, c.Actor(), auditkind.OtlpDestinationCreated, id, map[string]string{
			"name": in.Name, "host": hostOf(in.URL), "header_names": strings.Join(names, ","),
		}); err != nil {
			return err
		}
		out, err = get(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

// Activate makes a PENDING destination ACTIVE (HR-786): a person holding
// otlp.manage, with a fresh step-up made with their own active key; su is
// nil over the API, which refuses. Its cursor starts at the feed's head:
// nothing recorded before activation is sent.
func (s *Service) Activate(ctx context.Context, id ids.UUID, su *stepup.StepUp) (Destination, error) {
	c, err := manager(ctx)
	if err != nil {
		return Destination{}, err
	}
	if su == nil {
		return Destination{}, stepup.ErrStepUp
	}
	var out Destination
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if err := stepup.Check(ctx, tx, c, *su, now); err != nil {
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
		if err := CheckURL(d.URL, s.ownHost, s.cfg.AllowedPrivateRanges); err != nil {
			return err
		}
		head, err := s.feed.Head(ctx, tx)
		if err != nil {
			return err
		}
		n, err := q.ActivateOTLPDestination(ctx, dbq.ActivateOTLPDestinationParams{
			ActivatedBy: &c.Principal.ID, ActivatedCredential: &su.Credential, CursorSeq: head, OrgID: c.Org, ID: id,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrState
		}
		if err := record(ctx, tx, c.Actor(), auditkind.OtlpDestinationActivated, id, map[string]string{
			"host": hostOf(d.URL), "header_names": strings.Join(d.HeaderNames, ","), "security_key": su.Credential.String(),
		}); err != nil {
			return err
		}
		out, err = get(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

// Disable stops a destination for good (a person holding otlp.manage).
func (s *Service) Disable(ctx context.Context, id ids.UUID) (Destination, error) {
	c, err := manager(ctx)
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
		n, err := q.DisableOTLPDestination(ctx, c.Org, id)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrState
		}
		if err := record(ctx, tx, c.Actor(), auditkind.OtlpDestinationDisabled, id, map[string]string{
			"from": d.State, "reason": "person",
		}); err != nil {
			return err
		}
		out, err = get(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

// Get returns one destination (otlp.read).
func (s *Service) Get(ctx context.Context, id ids.UUID) (Destination, error) {
	c, err := reader(ctx)
	if err != nil {
		return Destination{}, err
	}
	var out Destination
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = get(ctx, dbq.New(tx), c.Org, id)
		return err
	}, db.ReadOnly())
	return out, err
}

// List returns one page of destinations by id (otlp.read).
func (s *Service) List(ctx context.Context, size int32, token string) ([]Destination, string, error) {
	c, err := reader(ctx)
	if err != nil {
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
		rows, err := dbq.New(tx).ListOTLPDestinations(ctx, c.Org, after, pr.Limit())
		if err != nil {
			return err
		}
		for _, r := range rows {
			out = append(out, fromRow(dbq.GetOTLPDestinationRow(r)))
		}
		return nil
	}, db.ReadOnly())
	if err != nil {
		return nil, "", err
	}
	out, next := page.Finish(pr, out, func(d Destination) ids.UUID { return d.ID })
	return out, next, nil
}

// TestResult is how a collector answered a test span.
type TestResult struct {
	Delivered bool
	Status    int
	Code      string
}

// Test sends one test span, which carries no agent data, to an ACTIVE
// destination (a person holding otlp.manage). A PENDING destination is
// never sent anything (HR-786).
func (s *Service) Test(ctx context.Context, id ids.UUID) (TestResult, error) {
	c, err := manager(ctx)
	if err != nil {
		return TestResult{}, err
	}
	var target string
	var headers []sealedHeader
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).LoadOTLPHeaders(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if row.State != StateActive {
			return ErrState
		}
		target = row.Url
		headers, err = s.open(ctx, c.Org, id, row.HeaderSecretRef)
		return err
	}, db.ReadOnly())
	if err != nil {
		return TestResult{}, err
	}
	out := s.post(ctx, target, headers, testTraces(c.Org, s.clock.Now()))
	res := TestResult{Delivered: out.ok, Status: out.status, Code: out.code}
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		details := map[string]string{"delivered": boolString(out.ok)}
		if out.code != "" {
			details["code"] = out.code
		}
		return record(ctx, tx, c.Actor(), auditkind.OtlpDestinationTested, id, details)
	})
	return res, err
}

// open decrypts a destination's sealed headers; none when blob is empty.
func (s *Service) open(ctx context.Context, org ids.OrgID, id ids.UUID, blob []byte) ([]sealedHeader, error) {
	if len(blob) == 0 {
		return nil, nil
	}
	plain, err := s.envelope.Decrypt(ctx, s.field(org, id), HeaderPurpose, blob)
	if err != nil {
		return nil, fmt.Errorf("otlpexport: open headers: %w", err)
	}
	var out []sealedHeader
	if err := json.Unmarshal(plain, &out); err != nil {
		return nil, fmt.Errorf("otlpexport: open headers: %w", err)
	}
	return out, nil
}

// ConfirmURL is a destination's activation page.
func (s *Service) ConfirmURL(id ids.UUID) string {
	return strings.TrimSuffix(s.cfg.PublicURL, "/") + ConfirmPath + "/" + id.String() + "/confirm"
}

// ConfirmPath is where the activation pages live.
const ConfirmPath = "/integrations/otlp-destinations"

func get(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID) (Destination, error) {
	r, err := q.GetOTLPDestination(ctx, org, id)
	if db.IsNoRows(err) {
		return Destination{}, ErrNotFound
	} else if err != nil {
		return Destination{}, err
	}
	return fromRow(r), nil
}

func fromRow(r dbq.GetOTLPDestinationRow) Destination {
	d := Destination{
		ID: r.ID, Name: r.Name, URL: r.Url, HeaderNames: r.HeaderNames, State: r.State, CreatedBy: r.CreatedBy,
		CreatedAt: r.CreatedAt, ActivatedBy: r.ActivatedBy, ActivatedAt: r.ActivatedAt, DisabledAt: r.DisabledAt,
		CursorSeq: r.CursorSeq, LastSuccessAt: r.LastSuccessAt, FailureCount: int(r.FailureCount), FailingSince: r.FailingSince,
	}
	if r.LastFailureCode != nil {
		d.LastFailureCode = *r.LastFailureCode
	}
	return d
}

func record(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, name string, id ids.UUID, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: actor, Outcome: audit.Success,
		Object: &audit.Object{Type: "otlp_destination", ID: id.String()}, Details: details,
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
