// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package accounts

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/telemetry"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Self-serve sign-up errors (D8, HR-351).
var (
	ErrSignupDisabled  = pcerr.New(pcerr.FailedPrecondition, "SIGNUP_DISABLED", "creating organizations is not available on this server")
	ErrEmailUnverified = pcerr.New(pcerr.FailedPrecondition, "EMAIL_UNVERIFIED",
		"your identity provider has not verified your email address")
	ErrAccountOrgLimit = pcerr.New(pcerr.FailedPrecondition, "ACCOUNT_ORG_LIMIT",
		"your account has reached its limit of organizations, or one of them still needs a plan")
	ErrRateLimited = pcerr.New(pcerr.ResourceExhausted, "RATE_LIMITED", "too many organizations created recently; try again later")
	ErrTerms       = pcerr.New(pcerr.InvalidArgument, "TERMS_VERSION", "accept the current terms of service and DPA")
	ErrSlug        = pcerr.New(pcerr.InvalidArgument, "INVALID_SLUG", "the short name may use lowercase letters, digits and hyphens")
)

// SignupConfig is the self-serve sign-up policy (config signup.*).
type SignupConfig struct {
	// SelfServe allows account sessions and CreateOrg (hosted only).
	SelfServe bool
	// MaxOrgsPerAccount and MaxUnplannedPerAccount bound the orgs one
	// account creates (D8: 3 and 1).
	MaxOrgsPerAccount, MaxUnplannedPerAccount int
	// PerAccountPerHour and PerIPPerHour bound creation attempts.
	PerAccountPerHour, PerIPPerHour int
	// TermsVersion and DPAVersion, when set, are the versions a creator
	// must accept.
	TermsVersion, DPAVersion string
}

// DefaultSignup is D8's policy, self-serve off.
func DefaultSignup() SignupConfig {
	return SignupConfig{MaxOrgsPerAccount: 3, MaxUnplannedPerAccount: 1, PerAccountPerHour: 5, PerIPPerHour: 20}
}

// Plans reads an org's effective plan (entitlements.Service).
type Plans interface {
	Plan(ctx context.Context, org ids.OrgID) (entitlements.Plan, error)
}

// Signup creates organizations for accounts.
type Signup struct {
	store *Store
	plans Plans
	cfg   SignupConfig
}

// NewSignup returns the sign-up use cases.
func NewSignup(store *Store, plans Plans, cfg SignupConfig) *Signup {
	return &Signup{store: store, plans: plans, cfg: cfg}
}

// SelfServe reports whether self-serve sign-up is on.
func (s *Signup) SelfServe() bool { return s != nil && s.cfg.SelfServe }

// NewOrg is a CreateOrg request.
type NewOrg struct {
	Name, Slug               string
	TermsVersion, DPAVersion string
}

// CreatedOrg is the new org and its first user, the creator.
type CreatedOrg struct {
	Org       ids.OrgID
	User      ids.UUID
	Name      string
	Slug      string
	CreatedAt time.Time
}

var (
	slugPattern    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

const hour = int32(3600)

// CreateOrg creates an org for the account caller (HR-351): only with
// self-serve on, a provider-verified email, within the per-account org
// limits (at most MaxOrgsPerAccount, at most MaxUnplannedPerAccount without
// a plan) and the rate limits per account and IP. The creator becomes the
// org's first user with Org Admin, the terms and DPA versions are recorded,
// and every step is audited.
func (s *Signup) CreateOrg(ctx context.Context, in NewOrg) (CreatedOrg, error) {
	c, ok := CallerFrom(ctx)
	if !ok {
		return CreatedOrg{}, ErrNoAccount
	}
	if !s.SelfServe() {
		return CreatedOrg{}, ErrSignupDisabled
	}
	name, err := td.CheckName("name", in.Name)
	if err != nil {
		return CreatedOrg{}, err
	}
	switch {
	case !slugPattern.MatchString(in.Slug):
		return CreatedOrg{}, ErrSlug
	case !versionPattern.MatchString(in.TermsVersion) || !versionPattern.MatchString(in.DPAVersion),
		s.cfg.TermsVersion != "" && in.TermsVersion != s.cfg.TermsVersion,
		s.cfg.DPAVersion != "" && in.DPAVersion != s.cfg.DPAVersion:
		return CreatedOrg{}, ErrTerms
	}
	org := ids.New[ids.Org]()
	var acct Account
	refuse := func(err error, detail string) (CreatedOrg, error) {
		if rerr := s.store.event(context.WithoutCancel(ctx), c.Account, "ORG_CREATE_REFUSED", nil, c.IP, detail); rerr != nil {
			return CreatedOrg{}, errors.Join(err, rerr)
		}
		return CreatedOrg{}, err
	}
	// One account's creations are serialized on its row: the checks and
	// the ORG_CREATED event that the next check counts commit together.
	var refusal error
	err = s.store.pool.InGlobalTx(ctx, db.GlobalAccounts, func(ctx context.Context, tx db.GlobalTx) error {
		q := dbq.New(tx)
		identity, err := q.GetAccount(ctx, c.Account)
		if db.IsNoRows(err) {
			return ErrNoAccount
		}
		if err != nil {
			return err
		}
		available, err := q.AccountIdentityShared(ctx, identity.Issuer, identity.Subject)
		if err != nil {
			return err
		}
		if !available || identity.DeletedAt != nil {
			return ErrDeletionPending
		}
		a, err := q.LockAccount(ctx, c.Account)
		if db.IsNoRows(err) {
			return ErrNoAccount
		} else if err != nil {
			return err
		}
		acct = view(a)
		if !a.EmailVerified {
			refusal = ErrEmailUnverified
			return nil
		}
		kinds := []string{"ORG_CREATED", "ORG_CREATE_REFUSED"}
		if n, err := q.CountAccountEventsSince(ctx, c.Account, kinds, hour); err != nil {
			return err
		} else if int(n) >= s.cfg.PerAccountPerHour {
			refusal = ErrRateLimited
			return nil
		}
		if c.IP != "" {
			if n, err := q.CountIPEventsSince(ctx, trim(c.IP, 64), kinds, hour); err != nil {
				return err
			} else if int(n) >= s.cfg.PerIPPerHour {
				refusal = ErrRateLimited
				return nil
			}
		}
		created, err := q.AccountCreatedOrgs(ctx, c.Account)
		if err != nil {
			return err
		}
		if len(created) >= s.cfg.MaxOrgsPerAccount {
			refusal = ErrAccountOrgLimit
			return nil
		}
		unplanned := 0
		for _, o := range created {
			oid, err := ids.FromUUID[ids.Org](o)
			if err != nil {
				return err
			}
			p, err := s.plans.Plan(ctx, oid)
			if err != nil {
				return err
			}
			if p.Status == entitlements.StatusNone {
				unplanned++
			}
		}
		if unplanned >= s.cfg.MaxUnplannedPerAccount {
			refusal = ErrAccountOrgLimit
			return nil
		}
		return q.InsertAccountEvent(ctx, dbq.InsertAccountEventParams{
			AccountID: c.Account, Kind: "ORG_CREATED", OrgID: org, ClientIp: trim(c.IP, 64),
		})
	})
	if err != nil {
		return CreatedOrg{}, err
	}
	if refusal != nil {
		if errors.Is(refusal, ErrRateLimited) {
			telemetry.RateLimited(ctx, telemetry.ScopeSignup)
		}
		var pe *pcerr.Error
		reason := "refused"
		if errors.As(refusal, &pe) {
			reason = pe.Reason()
		}
		return refuse(refusal, reason)
	}
	out := CreatedOrg{Org: org, Name: name, Slug: in.Slug}
	err = s.store.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.InsertOrg(ctx, org, name); err != nil {
			return err
		}
		slug := in.Slug
		if err := q.SetOrgSignup(ctx, &slug, &c.Account, org); err != nil {
			return err
		}
		if err := q.InsertContainment(ctx, org); err != nil {
			return err
		}
		if err := db.SetAccountContext(ctx, tx, c.Account); err != nil {
			return err
		}
		u, err := q.InsertAccountUser(ctx, dbq.InsertAccountUserParams{
			OrgID: org, ID: ids.NewV7(), Issuer: acct.Issuer, Subject: acct.Subject, Email: acct.Email,
			DisplayName: acct.DisplayName, AccountID: &c.Account,
		})
		if err != nil {
			return err
		}
		out.User, out.CreatedAt = u.ID, u.CreatedAt
		if _, err := q.InsertRoleBinding(ctx, dbq.InsertRoleBindingParams{
			OrgID: org, ID: ids.NewV7(), Role: string(td.RoleOrgAdmin), UserID: &u.ID, ScopeType: string(td.ScopeOrg),
			CreatedBy: "signup:" + c.Account.String(),
		}); err != nil {
			return err
		}
		if err := q.InsertTermsAcceptance(ctx, dbq.InsertTermsAcceptanceParams{
			OrgID: org, ID: ids.NewV7(), AccountID: c.Account, UserID: u.ID, TermsVersion: in.TermsVersion,
			DpaVersion: in.DPAVersion, ClientIp: trim(c.IP, 64),
		}); err != nil {
			return err
		}
		actor := evdomain.Actor{Type: string(td.KindUser), ID: u.ID.String()}
		for _, ev := range []audit.Event{
			{
				Name: "tenancy.org_created", Object: &audit.Object{Type: "org", ID: org.String()},
				Details: map[string]string{"via": "self_serve", "account": c.Account.String(), "slug": in.Slug},
			},
			{
				Name: "access.user_created", Object: &audit.Object{Type: "user", ID: u.ID.String()},
				Details: map[string]string{"provider": c.Provider, "role": string(td.RoleOrgAdmin)},
			},
			{
				Name: "tenancy.terms_accepted", Object: &audit.Object{Type: "org", ID: org.String()},
				Details: map[string]string{"terms_version": in.TermsVersion, "dpa_version": in.DPAVersion},
			},
		} {
			ev.Actor, ev.Outcome = actor, audit.Success
			if _, err := audit.Record(ctx, tx, ev); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return CreatedOrg{}, err
	}
	return out, nil
}

// ListMyOrgs lists the account caller's orgs (HR-349).
func (s *Signup) ListMyOrgs(ctx context.Context) ([]Membership, error) {
	c, ok := CallerFrom(ctx)
	if !ok {
		return nil, ErrNoAccount
	}
	return s.store.Memberships(ctx, c.Account)
}
