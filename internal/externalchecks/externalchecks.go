// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package externalchecks is an org's external policy checks (G0 M16 D81,
// founder decision F7; HR-436..440; Business edition): Open Policy Agent
// endpoints the Authority asks, after the policy rules, about the actions
// whose operation matches one of a check's patterns.
//
//   - A check is created PENDING by a person holding
//     policy.external_check.manage and is asked nothing until a person
//     activates it on its page with a fresh security-key step-up; the API
//     refuses activation (STEP_UP_REQUIRED, HR-438). At most three are
//     ACTIVE per org. Disabling is final.
//   - Its endpoint is https, without credentials or fragment, never a
//     metadata service, and starts with one of the server configuration's
//     external_checks.allowed_prefixes, checked at creation, at activation
//     and before every call: an ACTIVE check whose endpoint left the
//     prefixes is CANNOT_AUTHORIZE, audited and alerted. Its path holds no
//     dot segment or encoded slash. Each call goes through the egress client
//     (HR-070..074) with the check's own CA bundle and timeout (50 to 1000
//     ms), and never while a database connection is held (D96).
//   - It can only restrict (HR-436, ask.go); a failed, slow or malformed
//     answer, or more than MaxInFlight calls in flight for the org in this
//     process, is CANNOT_AUTHORIZE (HR-437). The cap is per process; the
//     M19 shared limits bound it across replicas.
//   - It is asked about the action's meaning, never the content of a
//     disclosure-capable parameter (HR-439), and its reasons are UNTRUSTED
//     text for people only (HR-440).
package externalchecks

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	reflexports "github.com/katocxl/pantherclaw/internal/reflex/ports"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Permissions.
const (
	PermManage = td.PermExternalCheckManage
	PermRead   = td.PermPolicyRead
)

// States.
const (
	StatePending  = "PENDING"
	StateActive   = "ACTIVE"
	StateDisabled = "DISABLED"
)

// Limits.
const (
	MaxActive        = 3
	MaxInFlight      = 16
	DefaultTimeoutMs = 250
	MinTimeoutMs     = 50
	MaxTimeoutMs     = 1000
	MaxOperations    = 32
	MaxReasons       = 5
	MaxReasonLen     = 200
	maxCABytes       = 16 << 10
)

// Errors.
var (
	ErrInvalid = pcerr.New(pcerr.InvalidArgument, "INVALID_EXTERNAL_CHECK",
		"a check has a name (lowercase letters, digits and dashes), a timeout of 50 to 1000 ms and 1 to 32 operations (names, or a prefix ending in *)")
	ErrEndpoint = pcerr.New(pcerr.InvalidArgument, "EXTERNAL_CHECK_ENDPOINT",
		"the endpoint must be https, without credentials or fragment, not a metadata service, and start with a prefix the server's external_checks.allowed_prefixes allows")
	ErrCA       = pcerr.New(pcerr.InvalidArgument, "EXTERNAL_CHECK_CA", "the CA bundle must hold at least one PEM certificate")
	ErrExists   = pcerr.New(pcerr.AlreadyExists, "EXTERNAL_CHECK_EXISTS", "a check with this name exists")
	ErrNotFound = pcerr.New(pcerr.NotFound, "EXTERNAL_CHECK_NOT_FOUND", "external check not found")
	ErrState    = pcerr.New(pcerr.FailedPrecondition, "EXTERNAL_CHECK_STATE", "the check is not in a state that allows this")
	ErrTooMany  = pcerr.New(pcerr.FailedPrecondition, "EXTERNAL_CHECKS_LIMIT", "at most three external checks are active; disable one first")
	ErrHuman    = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can do this")
	ErrEdition  = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "external policy checks need the Business edition or above")
)

// Config is the deployment configuration.
type Config struct {
	// AllowedPrefixes are the endpoint prefixes a check may use
	// (external_checks.allowed_prefixes). None: no check can be created.
	AllowedPrefixes []string
	// PublicURL is PantherClaw's own URL, for the activation page's link.
	PublicURL string
	// RootCAs overrides the system roots of checks without their own CA
	// (tests).
	RootCAs *x509.CertPool
	// AllowedAddrs re-allows otherwise denied address ranges for the egress
	// client (tests only: every endpoint is public in production).
	AllowedAddrs []netip.Prefix
}

// Editions reports the licence's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// Check is one external policy check.
type Check struct {
	ID          ids.UUID
	Name        string
	Endpoint    string
	CAPEM       string
	TimeoutMs   int
	Operations  []string
	State       string
	CreatedBy   string
	ActivatedBy *ids.UUID
	ActivatedAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Covers reports whether the check's operations cover an operation: an
// exact name, or a prefix ending in * (as policy rules match).
func (c Check) Covers(operation string) bool { return Covers(c.Operations, operation) }

// Covers reports whether patterns cover an operation.
func Covers(patterns []string, operation string) bool {
	return slices.ContainsFunc(patterns, func(op string) bool {
		prefix, isPrefix := strings.CutSuffix(op, "*")
		return op == operation || (isPrefix && strings.HasPrefix(operation, prefix))
	})
}

// NewCheck describes a check to create.
type NewCheck struct {
	Name       string
	Endpoint   string
	CAPEM      string
	TimeoutMs  int
	Operations []string
}

var (
	nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	// An operation such as stripe.refund.create, or a prefix such as
	// stripe.* or *.
	operationRe = regexp.MustCompile(`^([a-z][a-z0-9_]*(\.[a-z0-9_]+){0,7}(\.\*)?|\*)$`)
)

// Service runs the use cases and asks the checks (ask.go).
type Service struct {
	pool     *db.Pool
	cfg      Config
	editions Editions
	log      *slog.Logger
	asker    *asker
	cache    *activeCache
	// lookup reads an org's ACTIVE checks (active; tests replace it).
	lookup func(ctx context.Context, org ids.OrgID) ([]Check, error)
	// raiser alerts on a check whose endpoint left the allowed prefixes
	// (nil: audited only).
	raiser reflexports.Raiser
}

// New returns the service.
func New(pool *db.Pool, cfg Config, editions Editions, log *slog.Logger) *Service {
	if log == nil {
		log = pclog.Discard()
	}
	s := &Service{pool: pool, cfg: cfg, editions: editions, log: log, asker: newAsker(cfg), cache: newActiveCache()}
	s.lookup = s.active
	return s
}

// CheckEndpoint applies the endpoint rules (HR-438).
func CheckEndpoint(raw string, allowed []string) error {
	u, err := url.Parse(raw)
	switch {
	case err != nil, u.Scheme != "https", u.Host == "", u.User != nil, u.Fragment != "", u.RawFragment != "",
		strings.ContainsAny(raw, " \t\r\n\\"):
		return ErrEndpoint
	case httpx.MetadataHost(u.Hostname()):
		return ErrEndpoint
	}
	if a, ok := httpx.HostAddr(u.Hostname()); ok && httpx.MetadataAddr(a) {
		return ErrEndpoint
	}
	if escapingPath(u) {
		return ErrEndpoint
	}
	for _, p := range allowed {
		if p != "" && strings.HasPrefix(raw, p) && prefixBoundary(raw, p) {
			return nil
		}
	}
	return ErrEndpoint
}

// escapingPath reports a path that could leave a path-scoped prefix once a
// server or a proxy resolves it: a "." or ".." segment, raw or
// percent-encoded in any case (also twice encoded), or an encoded slash or
// backslash. Go sends the path as written; the far side may clean it.
func escapingPath(u *url.URL) bool {
	esc := strings.ToLower(u.EscapedPath())
	if strings.Contains(esc, "%2f") || strings.Contains(esc, "%5c") || strings.Contains(esc, "%25") {
		return true
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// prefixBoundary keeps a prefix from matching a longer host or path that
// starts with the same letters: https://opa.example.com never allows
// https://opa.example.com.evil.test, and https://opa.example.com/v1/data/pc
// never allows .../v1/data/pc-other. A prefix that ends in "/" is its own
// boundary; otherwise the endpoint ends there or goes on with "/" or "?".
func prefixBoundary(raw, prefix string) bool {
	if len(raw) == len(prefix) || strings.HasSuffix(prefix, "/") {
		return true
	}
	return raw[len(prefix)] == '/' || raw[len(prefix)] == '?'
}

func (in NewCheck) validate() (NewCheck, error) {
	if in.TimeoutMs == 0 {
		in.TimeoutMs = DefaultTimeoutMs
	}
	switch {
	case !nameRe.MatchString(in.Name), in.TimeoutMs < MinTimeoutMs, in.TimeoutMs > MaxTimeoutMs,
		len(in.Operations) == 0, len(in.Operations) > MaxOperations:
		return in, ErrInvalid
	}
	seen := map[string]bool{}
	for _, op := range in.Operations {
		if !operationRe.MatchString(op) || seen[op] {
			return in, ErrInvalid
		}
		seen[op] = true
	}
	if in.CAPEM != "" {
		if len(in.CAPEM) > maxCABytes || !x509.NewCertPool().AppendCertsFromPEM([]byte(in.CAPEM)) {
			return in, ErrCA
		}
	}
	return in, nil
}

// business refuses unless the licence includes external checks.
func (s *Service) business(ctx context.Context) error {
	if s.editions == nil {
		return ErrEdition
	}
	e, err := s.editions.Current(ctx)
	if err != nil {
		return err
	}
	if !e.ExternalPolicyChecks() {
		return ErrEdition
	}
	return nil
}

// manager returns the caller if it is a person holding
// policy.external_check.manage, and with edition the licence must include
// external checks. Disabling stays possible after the licence lapses.
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

// Create stores a PENDING check. It is asked nothing until a person
// activates it.
func (s *Service) Create(ctx context.Context, in NewCheck) (Check, error) {
	c, err := s.manager(ctx, true)
	if err != nil {
		return Check{}, err
	}
	in, err = in.validate()
	if err != nil {
		return Check{}, err
	}
	if err := CheckEndpoint(in.Endpoint, s.cfg.AllowedPrefixes); err != nil {
		return Check{}, err
	}
	id := ids.NewV7()
	var out Check
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var ca *string
		if in.CAPEM != "" {
			ca = &in.CAPEM
		}
		err := q.InsertExternalCheck(ctx, dbq.InsertExternalCheckParams{
			OrgID: c.Org, ID: id, Name: in.Name, Endpoint: in.Endpoint, CaPem: ca,
			TimeoutMs: int32(in.TimeoutMs), Operations: in.Operations, CreatedBy: c.Principal.ID.String(), //nolint:gosec // G115: ≤ 1000
		})
		if db.IsUniqueViolation(err) {
			return ErrExists
		} else if err != nil {
			return err
		}
		if err := s.audit(ctx, tx, c, "policy.external_check_created", id, map[string]string{
			"name": in.Name, "host": hostOf(in.Endpoint), "operations": strings.Join(in.Operations, ","),
			"timeout_ms": strconv.Itoa(in.TimeoutMs), "custom_ca": boolString(in.CAPEM != ""),
		}); err != nil {
			return err
		}
		out, err = get(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

// Activate makes a PENDING check ACTIVE (HR-438): a person holding
// policy.external_check.manage, with a fresh step-up of one of their own
// active keys; su is nil over the API, which refuses.
func (s *Service) Activate(ctx context.Context, id ids.UUID, su *stepup.StepUp) (Check, error) {
	c, err := s.manager(ctx, true)
	if err != nil {
		return Check{}, err
	}
	if su == nil {
		return Check{}, stepup.ErrStepUp
	}
	var out Check
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if err := stepup.Check(ctx, tx, c, *su, now); err != nil {
			return err
		}
		ch, err := get(ctx, q, c.Org, id)
		if err != nil {
			return err
		}
		if ch.State != StatePending {
			return ErrState
		}
		// The allowed prefixes may have changed since the check was created.
		if err := CheckEndpoint(ch.Endpoint, s.cfg.AllowedPrefixes); err != nil {
			return err
		}
		n, err := q.ActivateExternalCheck(ctx, dbq.ActivateExternalCheckParams{
			ActivatedBy: &c.Principal.ID, ActivatedCredential: &su.Credential, OrgID: c.Org, ID: id,
		})
		if db.IsCheckViolation(err) {
			return ErrTooMany
		} else if err != nil {
			return err
		}
		if n == 0 {
			return ErrState
		}
		if err := s.audit(ctx, tx, c, "policy.external_check_activated", id, map[string]string{
			"name": ch.Name, "host": hostOf(ch.Endpoint), "security_key": su.Credential.String(),
		}); err != nil {
			return err
		}
		out, err = get(ctx, q, c.Org, id)
		return err
	})
	if err == nil {
		s.cache.drop(c.Org)
	}
	return out, err
}

// Disable disables a PENDING or ACTIVE check; it is asked nothing from the
// next decision on.
func (s *Service) Disable(ctx context.Context, id ids.UUID) (Check, error) {
	c, err := s.manager(ctx, false)
	if err != nil {
		return Check{}, err
	}
	var out Check
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		ch, err := get(ctx, q, c.Org, id)
		if err != nil {
			return err
		}
		n, err := q.DisableExternalCheck(ctx, c.Org, id)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrState
		}
		if err := s.audit(ctx, tx, c, "policy.external_check_disabled", id, map[string]string{"name": ch.Name, "from": ch.State}); err != nil {
			return err
		}
		out, err = get(ctx, q, c.Org, id)
		return err
	})
	if err == nil {
		s.cache.drop(c.Org)
		s.asker.evict(id)
	}
	return out, err
}

// Get returns one check (policy.read).
func (s *Service) Get(ctx context.Context, id ids.UUID) (Check, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Check{}, err
	}
	if err := c.Require(PermRead, td.OrgPath(c.Org)); err != nil {
		return Check{}, err
	}
	var out Check
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = get(ctx, dbq.New(tx), c.Org, id)
		return err
	}, db.ReadOnly())
	return out, err
}

// List returns the org's checks by name (policy.read).
func (s *Service) List(ctx context.Context, includeDisabled bool) ([]Check, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.Require(PermRead, td.OrgPath(c.Org)); err != nil {
		return nil, err
	}
	var out []Check
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListExternalChecks(ctx, c.Org, includeDisabled)
		for _, r := range rows {
			out = append(out, Check{
				ID: r.ID, Name: r.Name, Endpoint: r.Endpoint, CAPEM: deref(r.CaPem), TimeoutMs: int(r.TimeoutMs), Operations: r.Operations,
				State: r.State, CreatedBy: r.CreatedBy, ActivatedBy: r.ActivatedBy, ActivatedAt: r.ActivatedAt,
				CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
			})
		}
		return err
	}, db.ReadOnly())
	return out, err
}

// ConfirmURL is the page where a person activates a check.
func (s *Service) ConfirmURL(id ids.UUID) string {
	return strings.TrimSuffix(s.cfg.PublicURL, "/") + "/policies/external-checks/" + id.String() + "/confirm"
}

func get(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID) (Check, error) {
	r, err := q.GetExternalCheck(ctx, org, id)
	if db.IsNoRows(err) {
		return Check{}, ErrNotFound
	} else if err != nil {
		return Check{}, err
	}
	return Check{
		ID: r.ID, Name: r.Name, Endpoint: r.Endpoint, CAPEM: deref(r.CaPem), TimeoutMs: int(r.TimeoutMs), Operations: r.Operations,
		State: r.State, CreatedBy: r.CreatedBy, ActivatedBy: r.ActivatedBy, ActivatedAt: r.ActivatedAt,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}, nil
}

func (s *Service) audit(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name string, id ids.UUID, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success,
		Object: &audit.Object{Type: "external_policy_check", ID: id.String()}, Details: details,
	})
	return err
}

// IsStepUp reports whether err is the step-up refusal.
func IsStepUp(err error) bool { return errors.Is(err, stepup.ErrStepUp) }

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// TestOperation is the synthetic action's operation when a check names no
// exact one.
const TestOperation = "test.operation"

// Test asks a PENDING or ACTIVE check about a synthetic action, in every
// edition (only Create and Activate need Business, D96a), and returns
// its answer and the input sent; no decision uses it.
func (s *Service) Test(ctx context.Context, id ids.UUID, operation string) (Answer, []byte, error) {
	c, err := s.manager(ctx, false)
	if err != nil {
		return Answer{}, nil, err
	}
	var ch Check
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		ch, err = get(ctx, dbq.New(tx), c.Org, id)
		return err
	}, db.ReadOnly())
	if err != nil {
		return Answer{}, nil, err
	}
	if ch.State == StateDisabled {
		return Answer{}, nil, ErrState
	}
	if err := CheckEndpoint(ch.Endpoint, s.cfg.AllowedPrefixes); err != nil {
		return Answer{}, nil, err
	}
	if operation == "" {
		operation = TestOperation
		if i := slices.IndexFunc(ch.Operations, func(op string) bool { return !strings.HasSuffix(op, "*") }); i >= 0 {
			operation = ch.Operations[i]
		}
	} else if !operationRe.MatchString(operation) || strings.Contains(operation, "*") {
		return Answer{}, nil, ErrInvalid
	}
	body, err := Body(c.Org, pipeline.ExternalInput{
		Operation: operation, Access: "write", Target: actionir.Target{Type: "test.target", ID: "test"},
		Agent: ids.UUID{}.String(), Instance: ids.UUID{}.String(), Run: ids.UUID{}.String(), Mode: "enforce",
	})
	if err != nil {
		return Answer{}, nil, err
	}
	ans := s.asker.ask(ctx, c.Org, ch, body)
	if err := s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		return s.audit(ctx, tx, c, "policy.external_check_tested", id, map[string]string{
			"name": ch.Name, "decision": ans.Decision, "error_code": ans.Unavailable,
		})
	}); err != nil {
		return Answer{}, nil, err
	}
	return ans, body, nil
}

// WithRaiser sets the alert raiser (reflex core).
func (s *Service) WithRaiser(r reflexports.Raiser) *Service {
	s.raiser = r
	return s
}

// notAllowed records, once per process and check, that an ACTIVE check's
// endpoint is no longer under the allowed prefixes, so decisions it covers
// are CANNOT_AUTHORIZE until a person disables it (HR-438): an audit event
// and an alert.
func (s *Service) notAllowed(ctx context.Context, org ids.OrgID, c Check) {
	if !s.cache.first(s.cache.reported, c.ID) {
		return
	}
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "policy.external_check_endpoint_not_allowed", Actor: evdomain.Actor{Type: "system", ID: "external_checks"}, Outcome: audit.Failure,
			Object: &audit.Object{Type: "external_policy_check", ID: c.ID.String()}, Details: map[string]string{"name": c.Name, "host": hostOf(c.Endpoint)},
		}); err != nil {
			return err
		}
		if s.raiser == nil {
			return nil
		}
		_, err := s.raiser.Raise(ctx, tx.Pgx(), reflexdomain.Signal{
			Org: org, Source: reflexdomain.SourceSystem, Title: "External policy check endpoint not allowed",
			Summary: "The active external policy check " + c.Name + " points outside the server's external_checks.allowed_prefixes; " +
				"the actions it covers cannot be authorized until it is disabled.",
			Severity: reflexdomain.SeverityHigh, Attention: reflexdomain.AttentionAlert, Basis: reflexdomain.BasisObserved,
			Subjects:  []reflexdomain.Subject{{Type: reflexdomain.SubjectResource, ID: "external_policy_check:" + c.ID.String()}},
			GroupKey:  "external_check:" + c.ID.String(),
			DedupeKey: "external_check.endpoint_not_allowed:" + c.ID.String(), OccurredAt: time.Now(),
			Facts: map[string]string{"check": c.ID.String(), "name": c.Name},
		})
		return err
	})
	if err != nil {
		s.log.WarnContext(ctx, "external_checks.endpoint_not_allowed_report_failed", "check", c.ID.String(), pclog.Err(err))
	}
}
