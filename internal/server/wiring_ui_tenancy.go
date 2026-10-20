// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"net/http"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/accounts"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/extension"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/onboarding"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/tenancy/adapters/tenancyrpc"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// Hosted accounts and self-serve organizations (G0 UI D8): accounts, sign-in
// without an org, the org picker, CreateOrg, ListMyOrgs and browser
// invitations; and the services built with them.

// uiTenancy is the UI phase's core services of one process.
type uiTenancy struct {
	ents       *entitlements.Service
	store      *accounts.Store
	signup     *accounts.Signup
	invites    *accounts.Invitations
	onboarding *onboarding.Service
	// browser and web are set once the browser pages exist (API role).
	browser *authnapp.Browser
	web     *webhttp.Handler
	// invitations emails new invitations' links (nil: off).
	invitations invitationMailer
	publicURL   string
}

// invitationMailer emails an invitation link (notifications.Service).
type invitationMailer interface {
	SendInvitation(ctx context.Context, org ids.OrgID, invitation ids.UUID, link string) error
}

// wireInvitationEmails turns on invitation emails (signup.invitation_emails).
func (u *uiTenancy) wireInvitationEmails(cfg *Config, m invitationMailer) {
	if u == nil || m == nil || !cfg.Signup.InvitationEmails {
		return
	}
	u.invitations, u.publicURL = m, cfg.Auth.PublicURL
}

// newUITenancy builds the services over pool and the per-org plans.
func newUITenancy(cfg *Config, pool *db.Pool, ents *entitlements.Service) *uiTenancy {
	store := accounts.NewStore(pool)
	return &uiTenancy{
		ents: ents, store: store, signup: accounts.NewSignup(store, ents, cfg.signup()),
		invites: accounts.NewInvitations(store, ents), onboarding: onboarding.New(pool),
	}
}

// wireBrowser enables sign-in without an org, the org picker and browser
// invitations on the pages.
func (u *uiTenancy) wireBrowser(b *authnapp.Browser, web *webhttp.Handler) {
	if u == nil || b == nil || web == nil {
		return
	}
	u.browser, u.web = b, web
	b.WithAccounts(u.store, u.invites, u.signup.SelfServe())
	web.WithAccounts(b, u.signup.SelfServe())
}

// extensionDeps adds the plan writer, the account reader and the billing
// links to what the extension gets.
func (u *uiTenancy) extensionDeps(d extension.Deps) extension.Deps {
	if u == nil {
		return d
	}
	d.Plans = planWriter{svc: u.ents}
	d.Accounts = accountReader{store: u.store}
	d.BillingLinks = u.links()
	return d
}

// links is the billing links the extension uses (D37).
func (u *uiTenancy) links() billingLinks { return billingLinks{l: u.ents.NewLinks()} }

// accountReader is extension.AccountReader.
type accountReader struct{ store *accounts.Store }

// Account implements extension.AccountReader.
func (r accountReader) Account(ctx context.Context, accountID string) (extension.Account, error) {
	id, err := ids.ParseUUID(accountID)
	if err != nil {
		return extension.Account{}, accounts.ErrAccountNotFound
	}
	a, err := r.store.Get(ctx, id)
	if err != nil {
		return extension.Account{}, err
	}
	return extension.Account{ID: a.ID.String(), Email: a.Email, EmailVerified: a.EmailVerified, DisplayName: a.DisplayName}, nil
}

// registerUITenancy serves the UI phase's core services.
func registerUITenancy(rs *connect.Server, d apiDeps) {
	registerUIEntitlements(rs, d)
	registerUIOnboarding(rs, d)
}

// uiTenancyHandler adds CreateOrg and ListMyOrgs to TenancyService.
type uiTenancyHandler struct {
	*tenancyrpc.Tenancy
	ui *uiTenancy
}

// tenancyHandler returns TenancyService with the account procedures.
func tenancyHandler(t *tenancyrpc.Tenancy, ui *uiTenancy) uiTenancyHandler {
	return uiTenancyHandler{Tenancy: t, ui: ui}
}

// CreateOrg implements TenancyServiceHandler (HR-351): the account session
// is replaced by a session in the new org.
func (h uiTenancyHandler) CreateOrg(ctx context.Context, req *pantherclawv1.CreateOrgRequest) (*pantherclawv1.CreateOrgResponse, error) {
	if h.ui == nil {
		return nil, accounts.ErrSignupDisabled
	}
	c, ok := accounts.CallerFrom(ctx)
	if !ok {
		return nil, accounts.ErrNoAccount
	}
	out, err := h.ui.signup.CreateOrg(ctx, accounts.NewOrg{
		Name: req.GetName(), Slug: req.GetSlug(), TermsVersion: req.GetTermsVersion(), DPAVersion: req.GetDpaVersion(),
	})
	if err != nil {
		return nil, err
	}
	if h.ui.browser != nil && h.ui.web != nil {
		in, err := h.ui.browser.OpenOrgSession(ctx, out.Org, out.User, c.Account, c.Provider, c.AuthTime, false,
			authnapp.ClientMeta{IP: c.IP}, authnapp.AccountPath)
		if err != nil {
			return nil, err
		}
		if in.Reason == "" {
			if err := h.ui.browser.EndAccountSession(ctx, authnapp.AccountSession{Caller: c}, "ORG_SELECTED"); err != nil {
				return nil, err
			}
			setCookies(ctx, h.ui.web.OrgSessionCookie(in.Secret), h.ui.web.AccountSessionCookie(""))
		}
	}
	return &pantherclawv1.CreateOrgResponse{Org: &pantherclawv1.Org{
		Id: out.Org.String(), Name: out.Name, CreateTime: timestamppb.New(out.CreatedAt),
	}}, nil
}

// ListMyOrgs implements TenancyServiceHandler (HR-349).
func (h uiTenancyHandler) ListMyOrgs(ctx context.Context, _ *pantherclawv1.ListMyOrgsRequest) (*pantherclawv1.ListMyOrgsResponse, error) {
	if h.ui == nil {
		return nil, accounts.ErrNoAccount
	}
	ms, err := h.ui.signup.ListMyOrgs(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListMyOrgsResponse{}
	for _, m := range ms {
		out.Orgs = append(out.Orgs, &pantherclawv1.OrgSummary{OrgId: m.Org.String(), Name: m.Name, Slug: m.Slug})
	}
	return out, nil
}

// uiAccessHandler adds AcceptInvitation to AccessService.
type uiAccessHandler struct {
	*tenancyrpc.Access
	ui *uiTenancy
}

// accessHandler returns AccessService with browser invitations.
func accessHandler(a *tenancyrpc.Access, ui *uiTenancy) uiAccessHandler {
	return uiAccessHandler{Access: a, ui: ui}
}

// CreateInvitation implements AccessServiceHandler: with invitation emails
// on, the link goes to the invited address only (HR-157 widened for
// invitations). A failed email never fails the invitation; the token is
// still returned once.
func (h uiAccessHandler) CreateInvitation(ctx context.Context, req *pantherclawv1.CreateInvitationRequest) (*pantherclawv1.CreateInvitationResponse, error) {
	out, err := h.Access.CreateInvitation(ctx, req)
	if err != nil || h.ui == nil || h.ui.invitations == nil {
		return out, err
	}
	if c, cerr := tapp.CallerFrom(ctx); cerr == nil {
		if id, perr := ids.ParseUUID(out.GetInvitation().GetId()); perr == nil {
			link := h.ui.publicURL + authnapp.InvitePath + "/" + out.GetToken()
			_ = h.ui.invitations.SendInvitation(ctx, c.Org, id, link) // recorded and logged by the sender
		}
	}
	return out, nil
}

// AcceptInvitation implements AccessServiceHandler (HR-352). The caller's
// session stays where it is; the joined org opens on a fresh sign-in
// (HR-353).
func (h uiAccessHandler) AcceptInvitation(ctx context.Context, req *pantherclawv1.AcceptInvitationRequest) (*pantherclawv1.AcceptInvitationResponse, error) {
	if h.ui == nil {
		return nil, accounts.ErrInvitationInvalid
	}
	c, ok := accounts.CallerFrom(ctx)
	if !ok {
		return nil, accounts.ErrNoAccount
	}
	got, err := h.ui.invites.Accept(ctx, c.Account, req.GetToken(), c.IP)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.AcceptInvitationResponse{OrgId: got.Org.String()}, nil
}

// setCookies adds Set-Cookie headers to a Connect response.
func setCookies(ctx context.Context, cs ...*http.Cookie) {
	info, ok := connect.CallInfoForServerContext(ctx)
	if !ok {
		return
	}
	for _, c := range cs {
		info.ResponseHeader().Add("Set-Cookie", c.String())
	}
}
