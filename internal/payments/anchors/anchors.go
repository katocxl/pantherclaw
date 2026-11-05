// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package anchors keeps an org's agent payment trust anchors and checks
// agents' request signatures with them (G0 M39 D1120, D1121, D1123;
// FQ39-1; HR-830..832, HR-838; Business).
//
// A trust anchor is where one party's keys come from: a MANDATE_ISSUER or
// MERCHANT JWKS, or an AGENT_DIRECTORY (a Web Bot Auth directory or a key
// service). PantherClaw verifies with these keys and never signs, and it
// stores no card or payment credential.
//
//   - Sandbox only (D1120): an anchor is marked sandbox and its URL names a
//     host on the sandbox allow-list in code (empty, plus loopback for the
//     simulator). Anything else is refused with PAYMENTS_LIVE_REFUSED and
//     audited security.payments_live_refused, at creation, activation and
//     every key fetch. There is no live switch.
//   - An anchor is created PENDING by a person holding payments.manage and
//     is used only once a person activates it on its page with a fresh
//     security-key step-up; over the API activation is always
//     STEP_UP_REQUIRED (HR-832). Its keys never change; REVOKED is final.
//   - Keys are fetched through the egress client: no redirects, 64 KiB, a
//     one-hour cache, ES256 (P-256) and Ed25519 keys only.
package anchors

import (
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	bdomain "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/payments/ap2"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Permissions (D1121).
const (
	PermRead   = td.PermPaymentsRead
	PermManage = td.PermPaymentsManage
)

// Anchor states.
const (
	StatePending = "PENDING"
	StateActive  = "ACTIVE"
	StateRevoked = "REVOKED"
)

// ConfirmPath is where the activation pages live.
const ConfirmPath = "/integrations/payment-anchors"

// Errors.
var (
	ErrInvalid = pcerr.New(pcerr.InvalidArgument, "INVALID_PAYMENT_ANCHOR",
		"an anchor has a kind, a name (lowercase letters, digits and dashes) and exactly one of a JWKS with ES256 or Ed25519 keys "+
			"and an https URL without credentials or fragment")
	ErrExists   = pcerr.New(pcerr.AlreadyExists, "PAYMENT_ANCHOR_EXISTS", "an anchor with this name exists")
	ErrNotFound = pcerr.New(pcerr.NotFound, "PAYMENT_ANCHOR_NOT_FOUND", "anchor not found")
	ErrState    = pcerr.New(pcerr.FailedPrecondition, "PAYMENT_ANCHOR_STATE", "the anchor is not in a state that allows this")
	ErrHuman    = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can do this")
	ErrEdition  = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "agent payments need the Business edition or above")
)

// Editions reports the licence's entitlements (billing.Service).
type Editions interface {
	Current(ctx context.Context) (bdomain.Entitlements, error)
}

// Config is the service's deployment configuration.
type Config struct {
	// PublicURL is PantherClaw's own URL, under which the pages live.
	PublicURL string
	// Keys configures key fetching.
	Keys KeyConfig
}

// Service implements the trust anchor and agent signature use cases.
type Service struct {
	pool     *db.Pool
	cfg      Config
	keys     *KeySource
	clock    clock.Clock
	log      *slog.Logger
	editions Editions
}

// New returns the service.
func New(pool *db.Pool, cfg Config, clk clock.Clock, log *slog.Logger) (*Service, error) {
	u, err := url.Parse(cfg.PublicURL)
	if err != nil || u.Host == "" {
		return nil, errors.New("anchors: public URL must be an absolute URL")
	}
	if log == nil {
		log = pclog.Discard()
	}
	if clk == nil {
		clk = clock.System{}
	}
	return &Service{pool: pool, cfg: cfg, keys: NewKeySource(cfg.Keys, clk, log), clock: clk, log: log}, nil
}

// WithEditions sets the licence source (without one the server is
// Community and agent payments are refused).
func (s *Service) WithEditions(e Editions) *Service {
	s.editions = e
	return s
}

// business refuses unless the licence is Business or Enterprise (N23).
func (s *Service) business(ctx context.Context) error {
	if s.editions == nil {
		return ErrEdition
	}
	e, err := s.editions.Current(ctx)
	if err != nil {
		return err
	}
	if e.Edition != bdomain.Business && e.Edition != bdomain.Enterprise {
		return ErrEdition
	}
	return nil
}

// NewAnchor describes an anchor to create: exactly one of JWKS and URL.
type NewAnchor struct {
	Kind    ap2.Kind
	Name    string
	JWKS    string
	URL     string
	Sandbox bool
}

// TrustAnchor is a stored anchor.
type TrustAnchor struct {
	ID          ids.UUID
	Kind        ap2.Kind
	Name        string
	JWKS        string
	URL         string
	Sandbox     bool
	State       string
	CreatedBy   string
	CreatedAt   time.Time
	ActivatedBy *ids.UUID
	ActivatedAt *time.Time
	RevokedAt   *time.Time
}

func validKind(k ap2.Kind) bool {
	return k == ap2.KindMandateIssuer || k == ap2.KindMerchant || k == ap2.KindAgentDirectory
}

// manager returns the caller if it is a person holding payments.manage.
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

// reader returns the caller if it holds payments.read.
func reader(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	return c, c.Require(PermRead, td.OrgPath(c.Org))
}

// Create stores a PENDING anchor (D1121). A live anchor (not marked
// sandbox, or a URL on a host off the sandbox allow-list) is refused with
// ap2.ErrLiveRefused and audited security.payments_live_refused (D1120).
func (s *Service) Create(ctx context.Context, in NewAnchor) (TrustAnchor, error) {
	c, err := manager(ctx)
	if err != nil {
		return TrustAnchor{}, err
	}
	if err := s.business(ctx); err != nil {
		return TrustAnchor{}, err
	}
	if !validKind(in.Kind) || !ndomain.ValidChannelName(in.Name) || (in.JWKS == "") == (in.URL == "") {
		return TrustAnchor{}, ErrInvalid
	}
	var jwks []byte
	var urlp *string
	live := !in.Sandbox
	if in.JWKS != "" {
		jwks = []byte(in.JWKS)
		if _, err := parseKeys(jwks); err != nil || !jsontext.Value(jwks).IsValid() {
			return TrustAnchor{}, ErrInvalid
		}
	} else {
		switch err := CheckURL(in.URL); {
		case errors.Is(err, ap2.ErrLiveRefused):
			live = true
		case err != nil:
			return TrustAnchor{}, err
		}
		u := in.URL
		urlp = &u
	}
	if live {
		return TrustAnchor{}, s.refuseLive(ctx, c, "create", in.Kind, hostOf(in.URL), nil)
	}
	id := ids.NewV7()
	var out TrustAnchor
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		err := q.InsertPaymentTrustAnchor(ctx, dbq.InsertPaymentTrustAnchorParams{
			OrgID: c.Org, ID: id, Kind: string(in.Kind), Name: in.Name, Jwks: jwks, Url: urlp, Sandbox: true,
			CreatedBy: c.Principal.ID.String(),
		})
		if db.IsUniqueViolation(err) {
			return ErrExists
		} else if err != nil {
			return err
		}
		if err := record(ctx, tx, c.Actor(), auditkind.PaymentsAnchorCreated, id, audit.Success, "", map[string]string{
			"kind": string(in.Kind), "name": in.Name, "host": hostOf(in.URL), "static_jwks": boolString(jwks != nil),
		}); err != nil {
			return err
		}
		out, err = get(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

// refuseLive audits security.payments_live_refused in a transaction of its
// own and returns ap2.ErrLiveRefused (D1120).
func (s *Service) refuseLive(ctx context.Context, c tenancy.Caller, step string, kind ap2.Kind, host string, id *ids.UUID) error {
	s.log.WarnContext(ctx, auditkind.SecurityPaymentsLiveRefused, slog.String("step", step), slog.String("host", host))
	err := s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		obj := ids.UUID{}
		if id != nil {
			obj = *id
		}
		return record(ctx, tx, c.Actor(), auditkind.SecurityPaymentsLiveRefused, obj, audit.Denied, "PAYMENTS_LIVE_REFUSED",
			map[string]string{"step": step, "kind": string(kind), "host": host})
	})
	if err != nil {
		return err
	}
	return ap2.ErrLiveRefused
}

// Activate makes a PENDING anchor ACTIVE (HR-832): a person holding
// payments.manage, with a fresh step-up made with their own active key; su
// is nil over the API, which refuses. The sandbox rules are checked again.
func (s *Service) Activate(ctx context.Context, id ids.UUID, su *stepup.StepUp) (TrustAnchor, error) {
	c, err := manager(ctx)
	if err != nil {
		return TrustAnchor{}, err
	}
	if su == nil {
		return TrustAnchor{}, stepup.ErrStepUp
	}
	if err := s.business(ctx); err != nil {
		return TrustAnchor{}, err
	}
	var out TrustAnchor
	var liveAnchor *TrustAnchor
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if err := stepup.Check(ctx, tx, c, *su, now); err != nil {
			return err
		}
		a, err := get(ctx, q, c.Org, id)
		if err != nil {
			return err
		}
		if a.State != StatePending {
			return ErrState
		}
		// The allow-list may have changed since the anchor was created.
		if !a.Sandbox || (a.URL != "" && errors.Is(CheckURL(a.URL), ap2.ErrLiveRefused)) {
			liveAnchor = &a
			return nil
		}
		n, err := q.ActivatePaymentTrustAnchor(ctx, dbq.ActivatePaymentTrustAnchorParams{
			ActivatedBy: &c.Principal.ID, ActivatedCredential: &su.Credential, OrgID: c.Org, ID: id,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrState
		}
		if err := record(ctx, tx, c.Actor(), auditkind.PaymentsAnchorActivated, id, audit.Success, "", map[string]string{
			"kind": string(a.Kind), "host": hostOf(a.URL), "security_key": su.Credential.String(),
		}); err != nil {
			return err
		}
		out, err = get(ctx, q, c.Org, id)
		return err
	})
	if err != nil {
		return TrustAnchor{}, err
	}
	if liveAnchor != nil {
		return TrustAnchor{}, s.refuseLive(ctx, c, "activate", liveAnchor.Kind, hostOf(liveAnchor.URL), &id)
	}
	return out, nil
}

// Revoke stops using an anchor for good (a person holding payments.manage;
// any edition, as it only stops trust).
func (s *Service) Revoke(ctx context.Context, id ids.UUID) (TrustAnchor, error) {
	c, err := manager(ctx)
	if err != nil {
		return TrustAnchor{}, err
	}
	var out TrustAnchor
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, err := get(ctx, q, c.Org, id)
		if err != nil {
			return err
		}
		n, err := q.RevokePaymentTrustAnchor(ctx, c.Org, id)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrState
		}
		if err := record(ctx, tx, c.Actor(), auditkind.PaymentsAnchorRevoked, id, audit.Success, "", map[string]string{
			"from": a.State, "kind": string(a.Kind),
		}); err != nil {
			return err
		}
		out, err = get(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

// Get returns one anchor (payments.read).
func (s *Service) Get(ctx context.Context, id ids.UUID) (TrustAnchor, error) {
	c, err := reader(ctx)
	if err != nil {
		return TrustAnchor{}, err
	}
	var out TrustAnchor
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = get(ctx, dbq.New(tx), c.Org, id)
		return err
	}, db.ReadOnly())
	return out, err
}

// List returns one page of anchors that are not revoked, by id
// (payments.read).
func (s *Service) List(ctx context.Context, size int32, token string) ([]TrustAnchor, string, error) {
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
	var out []TrustAnchor
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListPaymentTrustAnchors(ctx, c.Org, after, pr.Limit())
		if err != nil {
			return err
		}
		for _, r := range rows {
			out = append(out, fromRow(dbq.GetPaymentTrustAnchorRow(r)))
		}
		return nil
	}, db.ReadOnly())
	if err != nil {
		return nil, "", err
	}
	out, next := page.Finish(pr, out, func(a TrustAnchor) ids.UUID { return a.ID })
	return out, next, nil
}

// ForOrg returns the verifier view of org's ACTIVE anchors, for mandate
// verification (ap2.Verify) and agent signatures. It checks no caller: the
// server's own use cases call it for the org they act in.
func (s *Service) ForOrg(ctx context.Context, org ids.OrgID) (*Resolver, error) {
	var active []Anchor
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		for _, k := range []ap2.Kind{ap2.KindMandateIssuer, ap2.KindMerchant, ap2.KindAgentDirectory} {
			rows, err := q.ListActivePaymentTrustAnchors(ctx, org, string(k))
			if err != nil {
				return err
			}
			for _, r := range rows {
				a := Anchor{ID: r.ID, Kind: ap2.Kind(r.Kind), JWKS: r.Jwks, Sandbox: r.Sandbox}
				if r.Url != nil {
					a.URL = *r.Url
				}
				active = append(active, a)
			}
		}
		return nil
	}, db.ReadOnly())
	if err != nil {
		return nil, err
	}
	return s.keys.Resolver(active, nil), nil
}

// ConfirmURL is an anchor's activation page.
func (s *Service) ConfirmURL(id ids.UUID) string {
	return strings.TrimSuffix(s.cfg.PublicURL, "/") + ConfirmPath + "/" + id.String() + "/confirm"
}

func get(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID) (TrustAnchor, error) {
	r, err := q.GetPaymentTrustAnchor(ctx, org, id)
	if db.IsNoRows(err) {
		return TrustAnchor{}, ErrNotFound
	} else if err != nil {
		return TrustAnchor{}, err
	}
	return fromRow(r), nil
}

func fromRow(r dbq.GetPaymentTrustAnchorRow) TrustAnchor {
	a := TrustAnchor{
		ID: r.ID, Kind: ap2.Kind(r.Kind), Name: r.Name, JWKS: string(r.Jwks), Sandbox: r.Sandbox, State: r.State,
		CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, ActivatedBy: r.ActivatedBy, ActivatedAt: r.ActivatedAt,
		RevokedAt: r.RevokedAt,
	}
	if r.Url != nil {
		a.URL = *r.Url
	}
	return a
}

func record(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, name string, id ids.UUID, outcome audit.Outcome,
	reason string, details map[string]string,
) error {
	ev := audit.Event{Name: name, Actor: actor, Outcome: outcome, ReasonCode: reason, Details: details}
	if !id.IsZero() {
		ev.Object = &audit.Object{Type: "payment_trust_anchor", ID: id.String()}
	}
	_, err := audit.Record(ctx, tx, ev)
	if err != nil {
		return fmt.Errorf("anchors: audit: %w", err)
	}
	return nil
}

func hostOf(raw string) string {
	if raw == "" {
		return ""
	}
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

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
