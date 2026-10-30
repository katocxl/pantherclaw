// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package exports pushes evidence packs, proof bundles and organization
// exports to destinations the customer controls (G0 M20 D252; F517,
// HR-513..516, T-223). The destination model is SIEM's (internal/siem): a
// destination is an HTTPS PUT target or an S3-compatible bucket and
//
//   - it is created PENDING through the API by a person holding
//     siem.manage, and receives nothing until a person activates it on its
//     page with a fresh WebAuthn step-up (HR-513);
//   - its target passes the notification webhook rules (https, no
//     credentials, never PantherClaw's own host) and the egress guard: a
//     private or loopback address is refused unless the destination is
//     marked internal, which the activation step-up also confirms; a
//     metadata service is always refused, by name, address or at dial
//     time. For a virtual-hosted bucket the rules read the host the
//     requests actually go to;
//   - its target and data classes never change: another target is another
//     destination;
//   - its credential is sealed under the org's DEK and never returned.
package exports

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
	"regexp"
	"slices"
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
	"github.com/katocxl/pantherclaw/internal/platform/sigv4"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Permissions: the SIEM destination permissions (G0 M20 D252).
const (
	PermRead   = td.PermSIEMRead
	PermManage = td.PermSIEMManage
)

// Parameters.
const (
	// SecretPurpose is the DEK purpose of destination credentials.
	SecretPurpose = "export_secrets"
	// RequestTimeout bounds one request: one part of a push.
	RequestTimeout = 5 * time.Minute
)

// Destination kinds.
const (
	KindHTTPSPut = "https_put"
	KindS3       = "s3"
)

// Destination states.
const (
	StatePending  = "PENDING"
	StateActive   = "ACTIVE"
	StatePaused   = "PAUSED"
	StateDisabled = "DISABLED"
)

// Data classes: what a destination may receive. A pack that holds opened
// payload captures also needs ClassPayloadCaptures.
const (
	ClassEvidencePacks   = "evidence_packs"
	ClassPayloadCaptures = "payload_captures"
	ClassProofBundles    = "proof_bundles"
	ClassOrgExports      = "org_exports"
)

var dataClasses = []string{ClassEvidencePacks, ClassPayloadCaptures, ClassProofBundles, ClassOrgExports}

// Encrypted destination columns: the AAD binds org, table, column and row
// (HR-062).
const (
	destinationsTable = "export_destinations"
	secretColumn      = "secret"
)

// Errors.
var (
	ErrInvalid = pcerr.New(pcerr.InvalidArgument, "INVALID_EXPORT_DESTINATION",
		"a destination has a name (lowercase letters, digits and dashes), a kind, a URL, its bucket and region when it is S3, a key prefix of plain path segments and 1 to 4 distinct data classes")
	ErrCredential = pcerr.New(pcerr.InvalidArgument, "INVALID_EXPORT_CREDENTIAL",
		"an https_put destination needs a bearer token; an s3 destination needs an access key id and a secret access key")
	ErrURL = pcerr.New(pcerr.InvalidArgument, "EXPORT_DESTINATION_URL",
		"the URL must be https, without credentials, query or fragment, on port 443 or 1024-65535, not PantherClaw's own host, and public unless the destination is internal")
	ErrMetadata = pcerr.New(pcerr.InvalidArgument, "EXPORT_DESTINATION_METADATA", "a cloud metadata service is never a destination")
	ErrExists   = pcerr.New(pcerr.AlreadyExists, "EXPORT_DESTINATION_EXISTS", "a destination with this name exists")
	ErrNotFound = pcerr.New(pcerr.NotFound, "EXPORT_DESTINATION_NOT_FOUND", "destination not found")
	ErrState    = pcerr.New(pcerr.FailedPrecondition, "EXPORT_DESTINATION_STATE", "the destination is not in a state that allows this")
	ErrHuman    = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can do this")
	ErrEdition  = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "export destinations need the Business edition or above")
)

// Editions reports the licence's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// Config is the export service's deployment configuration.
type Config struct {
	// PublicURL is PantherClaw's own URL: no destination may point at it.
	PublicURL string
	// AllowedPrivateRanges re-allows private destinations for every
	// destination (self-hosted operators). Operator configuration only.
	AllowedPrivateRanges []netip.Prefix
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

// Service implements the destination and push use cases.
type Service struct {
	pool     *db.Pool
	envelope *pccrypto.Envelope
	cfg      Config
	ownHost  string
	clock    clock.Clock
	log      *slog.Logger
	// public reaches ordinary destinations; internal also reaches the
	// private and loopback ranges. Both are egress clients.
	public, internal *http.Client
	// editions gates the use cases (Business); nil is Community.
	editions Editions
}

// New returns the service.
func New(pool *db.Pool, envelope *pccrypto.Envelope, cfg Config, clk clock.Clock, log *slog.Logger) (*Service, error) {
	u, err := url.Parse(cfg.PublicURL)
	if err != nil || u.Host == "" {
		return nil, errors.New("exports: public URL must be an absolute URL")
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
		pool: pool, envelope: envelope, cfg: cfg, ownHost: u.Hostname(), clock: clk, log: log,
		public: httpx.NewEgressClient(ec), internal: httpx.NewEgressClient(ic),
	}, nil
}

// WithEditions sets the licence source (without one the server is
// Community and export destinations are refused).
func (s *Service) WithEditions(e Editions) *Service {
	s.editions = e
	return s
}

// Target is where a destination's objects go. Its fields never change once
// stored.
type Target struct {
	Kind string
	// URL is the PUT base URL or the S3 endpoint.
	URL       string
	Bucket    string
	Region    string
	KeyPrefix string
	PathStyle bool
	Internal  bool
}

// Base returns the URL the target's objects hang under, the one the
// requests go to: for a virtual-hosted bucket its host starts with the
// bucket's name. The rules of CheckTarget read this URL.
func (t Target) Base() (*url.URL, error) {
	u, err := url.Parse(t.URL)
	if err != nil {
		return nil, ErrURL
	}
	if t.Kind == KindS3 {
		if t.PathStyle {
			u.Path = "/" + t.Bucket
		} else {
			u.Host = t.Bucket + "." + u.Host
		}
	}
	return u, nil
}

var (
	bucketRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	regionRE = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	prefixRE = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$`)
)

func (t Target) valid() bool {
	if t.KeyPrefix != "" && (len(t.KeyPrefix) > 256 || !prefixRE.MatchString(t.KeyPrefix)) {
		return false
	}
	switch t.Kind {
	case KindHTTPSPut:
		return t.Bucket == "" && t.Region == "" && !t.PathStyle
	case KindS3:
		return bucketRE.MatchString(t.Bucket) && regionRE.MatchString(t.Region) && !strings.Contains(t.Bucket, "..")
	}
	return false
}

// CheckTarget applies the destination rules (HR-513) to the URL requests
// actually go to: the notification webhook rules with the egress guard's
// reading of the host. An internal destination may name a private or
// loopback address, never a metadata service.
func CheckTarget(t Target, ownHost string, allowed []netip.Prefix) error {
	raw, err := url.Parse(t.URL)
	if err != nil {
		return ErrURL
	}
	if raw.RawQuery != "" || raw.ForceQuery || (t.Kind == KindS3 && strings.Trim(raw.Path, "/") != "") {
		return ErrURL
	}
	u, err := t.Base()
	if err != nil {
		return ErrURL
	}
	if httpx.MetadataHost(u.Hostname()) {
		return ErrMetadata
	}
	if a, ok := httpx.HostAddr(u.Hostname()); ok && httpx.MetadataAddr(a) {
		return ErrMetadata
	}
	if t.Internal {
		allowed = append(slices.Clone(allowed), internalPrefixes...)
	}
	denied := func(host string) bool { return httpx.DeniedHost(host, allowed) }
	if err := ndomain.CheckWebhookURL(u.String(), ownHost, denied); err != nil {
		return ErrURL
	}
	return nil
}

// Credential is what a destination authenticates with. It renders nowhere:
// fmt, slog and encoding/json see only which kind it is.
type Credential struct {
	// BearerToken authenticates an https_put destination.
	BearerToken string `json:"-"`
	// S3 authenticates an s3 destination.
	S3 sigv4.Credentials `json:"-"`
}

// String implements fmt.Stringer.
func (c Credential) String() string { return "exports.Credential{[REDACTED]}" }

// GoString implements fmt.GoStringer.
func (c Credential) GoString() string { return c.String() }

// LogValue implements slog.LogValuer.
func (c Credential) LogValue() slog.Value { return slog.StringValue(c.String()) }

// sealedCredential is a credential's plaintext under the envelope.
type sealedCredential struct {
	BearerToken     string `json:"bearer_token,omitzero"`
	AccessKeyID     string `json:"access_key_id,omitzero"`
	SecretAccessKey string `json:"secret_access_key,omitzero"`
}

var accessKeyRE = regexp.MustCompile(`^[A-Za-z0-9._-]{3,128}$`)

// printable reports whether v can go into a header or a signature: visible
// ASCII only, so no line break can start another header.
func printable(v string) bool {
	for i := range len(v) {
		if v[i] <= ' ' || v[i] > '~' {
			return false
		}
	}
	return true
}

func (c Credential) valid(kind string) bool {
	switch kind {
	case KindHTTPSPut:
		return len(c.BearerToken) >= 8 && len(c.BearerToken) <= 4096 && printable(c.BearerToken) && c.S3 == sigv4.Credentials{}
	case KindS3:
		return accessKeyRE.MatchString(c.S3.AccessKeyID) && len(c.S3.SecretAccessKey) >= 8 && len(c.S3.SecretAccessKey) <= 256 &&
			printable(c.S3.SecretAccessKey) && c.S3.SessionToken == "" && c.BearerToken == ""
	}
	return false
}

// NewDestination describes a destination to create.
type NewDestination struct {
	Name string
	Target
	DataClasses []string
	Credential  Credential
}

// Destination is a destination and its delivery health.
type Destination struct {
	ID ids.UUID
	Target
	Name             string
	DataClasses      []string
	State            string
	CreatedBy        string
	CreatedAt        time.Time
	ActivatedBy      *ids.UUID
	ActivatedAt      *time.Time
	SecretReplacedAt *time.Time
	// Health: configured (ACTIVE) is separate from delivery confirmed
	// (ConfirmedAt, the first delivered push).
	ConfirmedAt         *time.Time
	LastDeliveredAt     *time.Time
	ConsecutiveFailures int
	FailingSince        *time.Time
	LastFailureAt       *time.Time
	LastFailureCode     string
	DeliveredPushes     int64
	FailedPushes        int64
	Health              string
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
	if len(cs) == 0 || len(cs) > len(dataClasses) {
		return false
	}
	seen := map[string]bool{}
	for _, c := range cs {
		if !slices.Contains(dataClasses, c) || seen[c] {
			return false
		}
		seen[c] = true
	}
	return true
}

func (s *Service) field(org ids.OrgID, id ids.UUID) pccrypto.FieldContext {
	return pccrypto.FieldContext{Org: org, Table: destinationsTable, Column: secretColumn, RowID: id.String()}
}

func (s *Service) seal(ctx context.Context, org ids.OrgID, id ids.UUID, c Credential) ([]byte, error) {
	plain, err := json.Marshal(sealedCredential{BearerToken: c.BearerToken, AccessKeyID: c.S3.AccessKeyID, SecretAccessKey: c.S3.SecretAccessKey})
	if err != nil {
		return nil, err
	}
	blob, err := s.envelope.Encrypt(ctx, s.field(org, id), SecretPurpose, plain)
	if err != nil {
		return nil, fmt.Errorf("exports: encrypt credential: %w", err)
	}
	return blob, nil
}

// business refuses unless the licence includes SIEM export, whose edition
// export destinations share (Business, G0 M20).
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
// with edition the licence must include export destinations. Pausing and
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

// Create stores a PENDING destination with its sealed credential. It
// receives nothing until a person activates it.
func (s *Service) Create(ctx context.Context, in NewDestination) (Destination, error) {
	c, err := s.manager(ctx, true)
	if err != nil {
		return Destination{}, err
	}
	if !ndomain.ValidChannelName(in.Name) || !validClasses(in.DataClasses) || !in.valid() {
		return Destination{}, ErrInvalid
	}
	if !in.Credential.valid(in.Kind) {
		return Destination{}, ErrCredential
	}
	if err := CheckTarget(in.Target, s.ownHost, s.cfg.AllowedPrivateRanges); err != nil {
		return Destination{}, err
	}
	id := ids.NewV7()
	var out Destination
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		blob, err := s.seal(ctx, c.Org, id, in.Credential)
		if err != nil {
			return err
		}
		q := dbq.New(tx)
		err = q.InsertExportDestination(ctx, dbq.InsertExportDestinationParams{
			OrgID: c.Org, ID: id, Name: in.Name, Kind: in.Kind, Url: in.URL, Bucket: optional(in.Bucket), Region: optional(in.Region),
			KeyPrefix: in.KeyPrefix, PathStyle: in.PathStyle, Internal: in.Internal, DataClasses: in.DataClasses, Secret: blob,
			CreatedBy: c.Principal.ID.String(),
		})
		if db.IsUniqueViolation(err) {
			return ErrExists
		} else if err != nil {
			return err
		}
		if err := s.audit(ctx, tx, c, "export.destination_created", id, map[string]string{
			"name": in.Name, "kind": in.Kind, "host": hostOf(in.Target), "internal": boolString(in.Internal),
			"data_classes": strings.Join(in.DataClasses, ","),
		}); err != nil {
			return err
		}
		out, err = get(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

// Activate makes a PENDING destination ACTIVE (HR-513): a person holding
// siem.manage, with a fresh step-up made with their own active key.
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
		if err := CheckTarget(d.Target, s.ownHost, s.cfg.AllowedPrivateRanges); err != nil {
			return err
		}
		n, err := q.ActivateExportDestination(ctx, dbq.ActivateExportDestinationParams{
			ActivatedBy: &c.Principal.ID, ActivatedCredential: &su.Credential, OrgID: c.Org, ID: id,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrState
		}
		if err := s.audit(ctx, tx, c, "export.destination_activated", id, map[string]string{
			"host": hostOf(d.Target), "internal": boolString(d.Internal), "security_key": su.Credential.String(),
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
		n, err := q.SetExportDestinationState(ctx, dbq.SetExportDestinationStateParams{State: state, OrgID: c.Org, ID: id, Expected: d.State})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrState
		}
		if err := s.audit(ctx, tx, c, "export.destination_state_changed", id, map[string]string{"from": d.State, "to": state}); err != nil {
			return err
		}
		out, err = get(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

// ReplaceCredential replaces the sealed credential. The target never
// changes, so a credential alone cannot send anything somewhere else.
func (s *Service) ReplaceCredential(ctx context.Context, id ids.UUID, cred Credential) (Destination, error) {
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
		if !cred.valid(d.Kind) {
			return ErrCredential
		}
		blob, err := s.seal(ctx, c.Org, id, cred)
		if err != nil {
			return err
		}
		n, err := q.ReplaceExportSecret(ctx, blob, c.Org, id)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrState
		}
		if err := s.audit(ctx, tx, c, "export.destination_credential_replaced", id, nil); err != nil {
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
		rows, err := dbq.New(tx).ListExportDestinations(ctx, c.Org, after, pr.Limit())
		if err != nil {
			return err
		}
		for _, r := range rows {
			out = append(out, fromRow(dbq.GetExportDestinationRow(r)))
		}
		return nil
	}, db.ReadOnly())
	if err != nil {
		return nil, "", err
	}
	out, next := page.Finish(pr, out, func(d Destination) ids.UUID { return d.ID })
	return out, next, nil
}

// ConfirmURL is a destination's activation page.
func (s *Service) ConfirmURL(id ids.UUID) string {
	return strings.TrimSuffix(s.cfg.PublicURL, "/") + "/integrations/export-destinations/" + id.String() + "/confirm"
}

func get(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID) (Destination, error) {
	r, err := q.GetExportDestination(ctx, org, id)
	if db.IsNoRows(err) {
		return Destination{}, ErrNotFound
	} else if err != nil {
		return Destination{}, err
	}
	return fromRow(r), nil
}

func fromRow(r dbq.GetExportDestinationRow) Destination {
	d := Destination{
		ID: r.ID, Name: r.Name, DataClasses: r.DataClasses, State: r.State, CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt,
		Target:      Target{Kind: r.Kind, URL: r.Url, KeyPrefix: r.KeyPrefix, PathStyle: r.PathStyle, Internal: r.Internal},
		ActivatedBy: r.ActivatedBy, ActivatedAt: r.ActivatedAt, SecretReplacedAt: r.SecretReplacedAt, ConfirmedAt: r.ConfirmedAt,
		LastDeliveredAt: r.LastDeliveredAt, ConsecutiveFailures: int(r.ConsecutiveFailures), FailingSince: r.FailingSince,
		LastFailureAt: r.LastFailureAt, DeliveredPushes: r.DeliveredPushes, FailedPushes: r.FailedPushes,
	}
	if r.Bucket != nil {
		d.Bucket = *r.Bucket
	}
	if r.Region != nil {
		d.Region = *r.Region
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
		Object: &audit.Object{Type: "export_destination", ID: id.String()}, Details: details,
	})
	return err
}

func optional(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

func hostOf(t Target) string {
	u, err := t.Base()
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
