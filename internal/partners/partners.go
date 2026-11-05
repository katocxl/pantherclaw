// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package partners is MSSP partner access (G0 M38 D1100–D1102, D1100a;
// FQ38-1; ADR-0065; HR-810..816). The partner org needs the Enterprise
// edition (PartnerAccess); the customer org needs none.
//
// A partner is an ordinary org on the same deployment whose people are its
// members. A person of the partner org holding partner.manage asks a
// customer org for a link (READ always, PROPOSE optionally) for 1 to 90
// days. A customer person holding partner.approve decides it only on its
// page with a WebAuthn step-up, and never one their own account asked for;
// the window starts at the approval and the customer revokes the link at
// any time (HR-810). Every link event is recorded in both orgs' audit logs.
//
// Under an ACTIVE link a partner person holding partner.operate opens a
// partner session in the customer org on its page, after a step-up of
// their own (D1100a). The session's principal is KindPartner, which is
// never a person, so every human-only path refuses it (HR-812); it holds
// only the internal partner role (what a support session reads) and may
// propose rollouts, nothing else (HR-811). Every call re-checks the link,
// the partner's edition and the partner person, and is recorded in the
// customer's audit log before it runs (HR-813).
//
// A rollout proposal only ever becomes a DRAFT, by a customer person's
// acceptance (HR-814); a loosening whose version came from a partner
// always needs two customer people (HR-815, policy/app/change.go). The
// cross-customer summary carries counts only (HR-816).
package partners

import (
	"context"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Permissions (D1100, D1100a).
const (
	PermManage  = td.PermPartnerManage
	PermApprove = td.PermPartnerApprove
	PermOperate = td.PermPartnerOperate
	PermRead    = td.PermPartnerRead
)

// Limits (D1100, D1101, D1102).
const (
	MaxDays        = 90
	MaxReasonRunes = 500
	SessionIdle    = 30 * time.Minute
	SessionMaxAge  = 12 * time.Hour
	MaxBodyBytes   = 256 << 10
	MaxTitleRunes  = 200
	MaxCustomers   = 100
)

// Link states.
const (
	StateRequested = "REQUESTED"
	StateActive    = "ACTIVE"
	StateDenied    = "DENIED"
	StateRevoked   = "REVOKED"
	StateExpired   = "EXPIRED"
)

// Link scopes.
const (
	ScopeRead    = "READ"
	ScopePropose = "PROPOSE"
)

// Pages.
const (
	// LinksPath is where a customer person decides a link
	// (LinksPath/{id}/decide).
	LinksPath = "/partners/links"
	// CustomersPath is where a partner person opens a partner session
	// (CustomersPath/{org}/open).
	CustomersPath = "/partners/customers"
	// LogoutPath ends the browser's partner session.
	LogoutPath = "/partners/logout"
)

// Errors.
var (
	ErrEdition = pcerr.New(pcerr.PermissionDenied, "EDITION_REQUIRED",
		"MSSP partner access needs the Enterprise edition for the partner org")
	ErrInvalid = pcerr.New(pcerr.InvalidArgument, "INVALID_PARTNER_LINK",
		"a partner link needs another org of this deployment, the READ scope (PROPOSE optional), 1 to 90 days "+
			"and a reason of at most 500 characters of plain text")
	ErrHuman       = pcerr.New(pcerr.PermissionDenied, "PERSON_REQUIRED", "only a person may do this")
	ErrPartnerSide = pcerr.New(pcerr.PermissionDenied, "PARTNER_SESSION_REFUSED",
		"a partner session cannot do this; sign in to your own org")
	ErrOrgNotFound     = pcerr.New(pcerr.NotFound, "ORG_NOT_FOUND", "organization not found")
	ErrLinkNotFound    = pcerr.New(pcerr.NotFound, "PARTNER_LINK_NOT_FOUND", "partner link not found")
	ErrNotRequested    = pcerr.New(pcerr.FailedPrecondition, "PARTNER_LINK_NOT_REQUESTED", "the link was already decided or has expired")
	ErrNotRenewable    = pcerr.New(pcerr.FailedPrecondition, "PARTNER_LINK_NOT_RENEWABLE", "only an active or expired link can be renewed")
	ErrNotLive         = pcerr.New(pcerr.FailedPrecondition, "PARTNER_LINK_ENDED", "the link is not requested or active")
	ErrSelfDecision    = pcerr.New(pcerr.PermissionDenied, "SELF_APPROVAL", "nobody decides a partner link their own account asked for")
	ErrNoLink          = pcerr.New(pcerr.FailedPrecondition, "NO_PARTNER_LINK", "there is no active partner link with this customer")
	ErrNoPropose       = pcerr.New(pcerr.PermissionDenied, "PARTNER_LINK_NO_PROPOSE", "the partner link does not allow proposals")
	ErrNotSession      = pcerr.New(pcerr.FailedPrecondition, "NOT_A_PARTNER_SESSION", "this is not a partner session")
	ErrUnauthenticated = pcerr.New(pcerr.Unauthenticated, "UNAUTHENTICATED", "authentication required")
)

// Plans resolves org plans (entitlements.Service).
type Plans interface {
	For(ctx context.Context, org ids.OrgID) (billing.Entitlements, error)
}

// Service is the partner access use cases.
type Service struct {
	pool  *db.Pool
	plans Plans
	// publicURL is the server's URL for the decide and open pages.
	publicURL string
	drafts    Drafts
	packs     Packs
	clock     clock.Clock
	log       *slog.Logger
}

// New returns the service. Without plans no org is a partner (fail closed).
func New(pool *db.Pool, plans Plans, publicURL string, log *slog.Logger) *Service {
	if log == nil {
		log = pclog.Discard()
	}
	return &Service{pool: pool, plans: plans, publicURL: strings.TrimSuffix(publicURL, "/"), clock: clock.System{}, log: log}
}

// partnerAccess refuses unless org's plan allows MSSP partner access.
func (s *Service) partnerAccess(ctx context.Context, org ids.OrgID) error {
	if s.plans == nil {
		return ErrEdition
	}
	e, err := s.plans.For(ctx, org)
	if err != nil {
		return err
	}
	if !e.PartnerAccess() {
		return ErrEdition
	}
	return nil
}

// DecideURL is a link's decide page on the customer side.
func (s *Service) DecideURL(id ids.UUID) string {
	return s.publicURL + LinksPath + "/" + id.String() + "/decide"
}

// OpenURL is a customer's open page on the partner side.
func (s *Service) OpenURL(customer ids.UUID) string {
	return s.publicURL + CustomersPath + "/" + customer.String() + "/open"
}

// Link is one partner link.
type Link struct {
	ID               ids.UUID
	PartnerOrg       ids.UUID
	PartnerName      string
	CustomerOrg      ids.UUID
	State            string
	Scopes           []string
	DurationDays     int
	Reason           string
	Renews           *ids.UUID
	RequestedBy      ids.UUID
	RequestedAccount *ids.UUID
	RequestedAt      time.Time
	RequestExpiresAt time.Time
	DecidedBy        *ids.UUID
	DecidedAt        *time.Time
	StartsAt         *time.Time
	EndsAt           *time.Time
	RevokedBy        string
	RevokedAt        *time.Time
	EndReason        string
}

// Has reports whether the link has scope.
func (l Link) Has(scope string) bool { return slices.Contains(l.Scopes, scope) }

func linkOf(r dbq.GetPartnerLinkRow) Link {
	l := Link{
		ID: r.ID, PartnerOrg: r.PartnerOrg, PartnerName: r.PartnerName, CustomerOrg: r.CustomerOrg, State: r.State,
		Scopes: r.Scopes, DurationDays: int(r.DurationDays), Reason: r.Reason, Renews: r.Renews, RequestedBy: r.RequestedBy,
		RequestedAccount: r.RequestedAccount, RequestedAt: r.RequestedAt, RequestExpiresAt: r.RequestExpiresAt,
		DecidedBy: r.DecidedBy, DecidedAt: r.DecidedAt, StartsAt: r.StartsAt, EndsAt: r.EndsAt, RevokedAt: r.RevokedAt,
	}
	// A request or window the sweep has not ended yet reads as EXPIRED.
	if r.RequestExpired || r.WindowOver {
		l.State = StateExpired
	}
	if r.RevokedBy != nil {
		l.RevokedBy = *r.RevokedBy
	}
	if r.EndReason != nil {
		l.EndReason = *r.EndReason
	}
	return l
}

// partnerActor is the audit actor of a partner person:
// partner/<partner org>/<user> (D1101, D1100a Q3).
func partnerActor(partnerOrg, user ids.UUID) evdomain.Actor {
	return evdomain.Actor{Type: string(td.KindPartner), ID: partnerOrg.String() + "/" + user.String()}
}

// actorOf is the audit actor of a caller: a partner session's partner
// person, or the caller itself.
func actorOf(c tapp.Caller, partnerOrg ids.UUID) evdomain.Actor {
	if c.Partner() {
		return partnerActor(partnerOrg, c.Principal.ID)
	}
	return c.Actor()
}

// actorString is how proposals and links store an actor.
func actorString(a evdomain.Actor) string { return a.Type + "/" + a.ID }

func record(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, name, objType string, id ids.UUID,
	details map[string]string,
) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: actor, Outcome: audit.Success,
		Object: &audit.Object{Type: objType, ID: id.String()}, Details: details,
	})
	return err
}

// mirror records the same event in the other org of a link, in its own
// transaction (link and proposal events are recorded in both orgs, D1100).
func (s *Service) mirror(ctx context.Context, org ids.UUID, actor evdomain.Actor, name, objType string, id ids.UUID,
	details map[string]string,
) error {
	o, err := ids.FromUUID[ids.Org](org)
	if err != nil {
		return err
	}
	return s.pool.InTenantTx(ctx, o, func(ctx context.Context, tx db.TenantTx) error {
		return record(ctx, tx, actor, name, objType, id, details)
	})
}

// person returns the caller if it is a person signed in to its own org
// (never a partner or support session or an API key) holding perm.
func person(ctx context.Context, perm td.Permission) (tapp.Caller, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if c.Partner() {
		return c, ErrPartnerSide
	}
	if err := c.Require(perm, td.OrgPath(c.Org)); err != nil {
		return c, err
	}
	if !c.Human() || c.Credential == tapp.CredAPIKey || c.Credential == tapp.CredSupportSession {
		return c, ErrHuman
	}
	return c, nil
}

// reader returns the caller if it holds partner.read.
func reader(ctx context.Context) (tapp.Caller, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	return c, c.Require(PermRead, td.OrgPath(c.Org))
}

// plainText checks free text: at most max runes, valid UTF-8, no control
// characters.
func plainText(s string, max int) bool {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > max {
		return false
	}
	return !strings.ContainsFunc(s, unicode.IsControl)
}

// NewLink is a partner's request.
type NewLink struct {
	Customer ids.UUID
	Propose  bool
	Days     int
	Reason   string
}

func scopesOf(propose bool) []string {
	if propose {
		return []string{ScopeRead, ScopePropose}
	}
	return []string{ScopeRead}
}

// Request asks a customer org for a link (partner.manage, a person, the
// partner org on Enterprise). It is recorded in both orgs.
func (s *Service) Request(ctx context.Context, in NewLink) (Link, error) {
	c, err := person(ctx, PermManage)
	if err != nil {
		return Link{}, err
	}
	return s.request(ctx, c, in, nil)
}

func (s *Service) request(ctx context.Context, c tapp.Caller, in NewLink, renews *ids.UUID) (Link, error) {
	if in.Days < 1 || in.Days > MaxDays || !plainText(in.Reason, MaxReasonRunes) || in.Customer == c.Org.UUID() {
		return Link{}, ErrInvalid
	}
	customer, err := ids.FromUUID[ids.Org](in.Customer)
	if err != nil {
		return Link{}, ErrInvalid
	}
	if err := s.partnerAccess(ctx, c.Org); err != nil {
		return Link{}, err
	}
	// The customer must be an active org of this deployment.
	err = s.pool.InTenantTx(ctx, customer, func(ctx context.Context, tx db.TenantTx) error {
		state, err := dbq.New(tx).OrgState(ctx, customer)
		if db.IsNoRows(err) || (err == nil && state != "ACTIVE") {
			return ErrOrgNotFound
		}
		return err
	}, db.ReadOnly())
	if err != nil {
		return Link{}, err
	}
	id := ids.NewV7()
	actor := c.Actor()
	details := map[string]string{
		"partner_org": c.Org.String(), "customer_org": in.Customer.String(),
		"scopes": strings.Join(scopesOf(in.Propose), ","), "days": strconv.Itoa(in.Days),
	}
	if renews != nil {
		details["renews"] = renews.String()
	}
	var out Link
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		o, err := q.GetOrg(ctx, c.Org)
		if err != nil {
			return err
		}
		u, err := q.UserIdentityForSupport(ctx, c.Org, c.Principal.ID)
		if err != nil {
			return err
		}
		if err := q.InsertPartnerLink(ctx, dbq.InsertPartnerLinkParams{
			ID: id, PartnerOrg: c.Org.UUID(), CustomerOrg: in.Customer, PartnerName: trim(o.Name, 200),
			Scopes: scopesOf(in.Propose), DurationDays: int32(in.Days), Reason: in.Reason, Renews: renews, //nolint:gosec // G115: 1..90
			RequestedBy: c.Principal.ID, RequestedAccount: u.AccountID,
		}); err != nil {
			return err
		}
		if err := record(ctx, tx, actor, auditkind.PartnerLinkRequested, "partner_link", id, details); err != nil {
			return err
		}
		r, err := q.GetPartnerLink(ctx, id, c.Org.UUID())
		out = linkOf(r)
		return err
	})
	if err != nil {
		return Link{}, err
	}
	return out, s.mirror(ctx, in.Customer, actor, auditkind.PartnerLinkRequested, "partner_link", id, details)
}

// Renew asks again with an earlier link's scopes (partner side,
// partner.manage, a person): a new REQUESTED link. Only an ACTIVE or
// EXPIRED link is renewed; a denied or revoked one is the customer's
// answer.
func (s *Service) Renew(ctx context.Context, id ids.UUID, days int, reason string) (Link, error) {
	c, err := person(ctx, PermManage)
	if err != nil {
		return Link{}, err
	}
	old, err := s.get(ctx, c.Org, id)
	if err != nil {
		return Link{}, err
	}
	if old.PartnerOrg != c.Org.UUID() {
		return Link{}, ErrLinkNotFound
	}
	if old.State != StateActive && old.State != StateExpired {
		return Link{}, ErrNotRenewable
	}
	return s.request(ctx, c, NewLink{Customer: old.CustomerOrg, Propose: old.Has(ScopePropose), Days: days, Reason: reason}, &id)
}

func (s *Service) get(ctx context.Context, org ids.OrgID, id ids.UUID) (Link, error) {
	var out Link
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).GetPartnerLink(ctx, id, org.UUID())
		if db.IsNoRows(err) {
			return ErrLinkNotFound
		} else if err != nil {
			return err
		}
		out = linkOf(r)
		return nil
	}, db.ReadOnly())
	return out, err
}

// Get returns one link of the caller's org, as partner or customer
// (partner.read).
func (s *Service) Get(ctx context.Context, id ids.UUID) (Link, error) {
	c, err := reader(ctx)
	if err != nil {
		return Link{}, err
	}
	return s.get(ctx, c.Org, id)
}

// List returns one page of the caller's org's links by id (partner.read).
func (s *Service) List(ctx context.Context, size int32, token string) ([]Link, string, error) {
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
	var out []Link
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListPartnerLinks(ctx, c.Org.UUID(), after, pr.Limit())
		if err != nil {
			return err
		}
		for _, r := range rows {
			out = append(out, linkOf(dbq.GetPartnerLinkRow(r)))
		}
		return nil
	}, db.ReadOnly())
	if err != nil {
		return nil, "", err
	}
	out, next := page.Finish(pr, out, func(l Link) ids.UUID { return l.ID })
	return out, next, nil
}

// Decide approves or denies a REQUESTED link (HR-810): a customer person
// holding partner.approve, with a fresh step-up made with their own active
// key; su is nil over the API, which refuses. Nobody decides a link their
// own account asked for, and the partner org must still be on Enterprise.
func (s *Service) Decide(ctx context.Context, id ids.UUID, approve bool, su *stepup.StepUp) (Link, error) {
	c, err := person(ctx, PermApprove)
	if err != nil {
		return Link{}, err
	}
	if su == nil {
		return Link{}, stepup.ErrStepUp
	}
	cur, err := s.get(ctx, c.Org, id)
	if err != nil {
		return Link{}, err
	}
	if cur.CustomerOrg != c.Org.UUID() {
		return Link{}, ErrLinkNotFound
	}
	if cur.State != StateRequested {
		return Link{}, ErrNotRequested
	}
	if approve {
		partner, err := ids.FromUUID[ids.Org](cur.PartnerOrg)
		if err != nil {
			return Link{}, err
		}
		if err := s.partnerAccess(ctx, partner); err != nil {
			return Link{}, err
		}
	}
	state, name := StateDenied, auditkind.PartnerLinkDenied
	if approve {
		state, name = StateActive, auditkind.PartnerLinkApproved
	}
	actor := c.Actor()
	details := map[string]string{
		"partner_org": cur.PartnerOrg.String(), "customer_org": cur.CustomerOrg.String(),
		"scopes": strings.Join(cur.Scopes, ","), "security_key": su.Credential.String(),
	}
	var out Link
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if err := stepup.Check(ctx, tx, c, *su, now); err != nil {
			return err
		}
		u, err := q.UserIdentityForSupport(ctx, c.Org, c.Principal.ID)
		if err != nil {
			return err
		}
		if cur.RequestedAccount != nil && u.AccountID != nil && *u.AccountID == *cur.RequestedAccount {
			return ErrSelfDecision
		}
		n, err := q.DecidePartnerLink(ctx, dbq.DecidePartnerLinkParams{
			State: state, DecidedBy: &c.Principal.ID, DecidedCredential: &su.Credential, ID: id, CustomerOrg: c.Org.UUID(),
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotRequested
		}
		r, err := q.GetPartnerLink(ctx, id, c.Org.UUID())
		if err != nil {
			return err
		}
		out = linkOf(r)
		if out.EndsAt != nil {
			details["until"] = out.EndsAt.UTC().Format(time.RFC3339)
		}
		return record(ctx, tx, actor, name, "partner_link", id, details)
	})
	if err != nil {
		return Link{}, err
	}
	return out, s.mirror(ctx, cur.PartnerOrg, actor, name, "partner_link", id, details)
}

// Revoke ends a requested or active link at once (customer side,
// partner.approve, a person; no step-up) and ends its partner sessions
// (HR-810).
func (s *Service) Revoke(ctx context.Context, id ids.UUID, reason string) (Link, error) {
	c, err := person(ctx, PermApprove)
	if err != nil {
		return Link{}, err
	}
	if !plainText(reason, MaxReasonRunes) {
		return Link{}, ErrInvalid
	}
	actor := c.Actor()
	var out Link
	details := map[string]string{"customer_org": c.Org.String()}
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var why *string
		if reason != "" {
			why = &reason
		}
		n, err := q.RevokePartnerLink(ctx, dbq.RevokePartnerLinkParams{
			RevokedBy: new(actorString(actor)), EndReason: why, ID: id, CustomerOrg: c.Org.UUID(),
		})
		if err != nil {
			return err
		}
		r, err := q.GetPartnerLink(ctx, id, c.Org.UUID())
		if db.IsNoRows(err) || (err == nil && r.CustomerOrg != c.Org.UUID()) {
			return ErrLinkNotFound
		} else if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotLive
		}
		out = linkOf(r)
		ended, err := q.EndPartnerSessionsOfLink(ctx, c.Org, id)
		if err != nil {
			return err
		}
		details["partner_org"] = r.PartnerOrg.String()
		details["sessions_ended"] = strconv.Itoa(int(ended))
		return record(ctx, tx, actor, auditkind.PartnerLinkRevoked, "partner_link", id, details)
	})
	if err != nil {
		return Link{}, err
	}
	return out, s.mirror(ctx, out.PartnerOrg, actor, auditkind.PartnerLinkRevoked, "partner_link", id, details)
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
