// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app serves the org's browser sites (G0 M33 D976; HR-749). It
// mirrors the owned accounts service: adding a site loosens the browser
// step (D977), so it files a protected change that applies only when a
// second person confirms it with a security key; removing one applies at
// once. Every change gives the org's gateways a new configuration, which
// carries the sites marked for the cloaking compare (D986).
package app

import (
	"context"
	"encoding/json/v2"
	"slices"
	"strconv"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/browsersites/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/protect"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors.
var (
	ErrHost = pcerr.New(pcerr.InvalidArgument, "BROWSER_SITE_HOST_INVALID",
		"the host must be a lower-case DNS name of at least two labels, with no IP and no port")
	ErrSelectors = pcerr.New(pcerr.InvalidArgument, "BROWSER_SITE_SELECTORS_INVALID",
		"at most 16 click selectors of 1 to 256 characters each")
	ErrNote    = pcerr.New(pcerr.InvalidArgument, "BROWSER_SITE_NOTE_INVALID", "the note is at most 256 characters")
	ErrReason  = pcerr.New(pcerr.InvalidArgument, "BROWSER_SITE_REASON_INVALID", "a reason of 1 to 500 characters is required")
	ErrHuman   = pcerr.New(pcerr.PermissionDenied, "BROWSER_SITE_HUMAN_ONLY", "only a person may change the browser sites")
	ErrListed  = pcerr.New(pcerr.AlreadyExists, "BROWSER_SITE_LISTED", "the site is already on the browser site list")
	ErrMissing = pcerr.New(pcerr.NotFound, "BROWSER_SITE_NOT_FOUND", "browser site not found")
	ErrLimit   = pcerr.New(pcerr.ResourceExhausted, "BROWSER_SITE_LIMIT",
		"the org lists the most browser sites it may (500); remove one first")
)

// Service serves the browser sites.
type Service struct {
	Pool *db.Pool
	// Protect holds every addition (RegisterProtect); nil refuses it.
	Protect *protect.Gate
}

// Site is a site to add.
type Site struct {
	Host              string   `json:"host"`
	IncludeSubdomains bool     `json:"include_subdomains"`
	Compare           bool     `json:"compare"`
	ClickSelectors    []string `json:"click_selectors"`
	Note              string   `json:"note"`
}

// addPayload is a held addition.
type addPayload struct {
	Site   Site   `json:"site"`
	Reason string `json:"reason"`
}

func (s Site) validate() error {
	switch {
	case !domain.ValidHost(s.Host):
		return ErrHost
	case !domain.ValidSelectors(s.ClickSelectors):
		return ErrSelectors
	case !domain.ValidNote(s.Note):
		return ErrNote
	}
	return nil
}

// RegisterProtect sets the Gate's applier for additions.
func (s *Service) RegisterProtect(g *protect.Gate) {
	s.Protect = g
	if g != nil {
		g.Register(protect.SurfaceBrowserSiteAdd, s.ApplyAdd, s.addState)
	}
}

func caller(ctx context.Context, p td.Permission) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return tenancy.Caller{}, err
	}
	return c, c.Require(p, td.OrgPath(c.Org))
}

func validReason(reason string) error {
	if n := utf8.RuneCountInString(reason); !utf8.ValidString(reason) || n < 1 || n > 500 {
		return ErrReason
	}
	return nil
}

// List reads the org's browser sites.
func (s *Service) List(ctx context.Context) ([]dbq.PcBrowserSite, error) {
	c, err := caller(ctx, td.PermOwnedAccountsRead)
	if err != nil {
		return nil, err
	}
	var out []dbq.PcBrowserSite
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = dbq.New(tx).ListBrowserSites(ctx, c.Org)
		return err
	})
	return out, err
}

// Add files the protected change that adds a site, a person holding
// org.owned_accounts.manage (HR-749). It never applies here: a second
// person decides it with a security key.
func (s *Service) Add(ctx context.Context, site Site, reason string) (*protect.PendingError, error) {
	site.ClickSelectors = slices.Clone(site.ClickSelectors)
	if site.ClickSelectors == nil {
		site.ClickSelectors = []string{}
	}
	if err := site.validate(); err != nil {
		return nil, err
	}
	if err := validReason(reason); err != nil {
		return nil, err
	}
	c, err := caller(ctx, td.PermOwnedAccountsManage)
	if err != nil {
		return nil, err
	}
	if !c.Human() {
		return nil, ErrHuman
	}
	if s.Protect == nil {
		return nil, protect.ErrUnavailable
	}
	var held *protect.PendingError
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		switch _, err := q.GetBrowserSiteByHost(ctx, c.Org, site.Host, site.IncludeSubdomains); {
		case err == nil:
			return ErrListed
		case !db.IsNoRows(err):
			return err
		}
		if n, err := q.CountBrowserSites(ctx, c.Org); err != nil {
			return err
		} else if n >= domain.SiteLimit {
			return ErrLimit
		}
		key := siteKey(site.Host, site.IncludeSubdomains)
		held, err = s.Protect.Hold(ctx, tx, c, protect.Change{
			Category: protect.ConsequenceRules, Surface: protect.SurfaceBrowserSiteAdd, Subject: key,
			SubjectID: protect.SubjectID(protect.SurfaceBrowserSiteAdd, key),
			Summary: map[string]string{
				"host": site.Host, "include_subdomains": strconv.FormatBool(site.IncludeSubdomains),
				"compare": strconv.FormatBool(site.Compare), "selectors": strconv.Itoa(len(site.ClickSelectors)), "reason": reason,
			},
			Widening: []string{"browser_site"},
			Payload:  addPayload{Site: site, Reason: reason},
		}, func(context.Context) error { return protect.ErrUnavailable })
		if err != nil {
			return err
		}
		if held == nil {
			return protect.ErrUnavailable // never applied without a second person
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return held, nil
}

func siteKey(host string, subdomains bool) string {
	if subdomains {
		return "*." + host
	}
	return host
}

// ApplyAdd is the confirmed re-run of a held addition (a protect.Applier),
// as its requester, in the confirming transaction.
func (s *Service) ApplyAdd(ctx context.Context, tx db.TenantTx, author tenancy.Caller, payload []byte) error {
	var p addPayload
	if err := json.Unmarshal(payload, &p); err != nil || p.Site.validate() != nil {
		return protect.ErrInvalid
	}
	if err := author.Require(td.PermOwnedAccountsManage, td.OrgPath(author.Org)); err != nil {
		return err
	}
	q := dbq.New(tx)
	org := tx.OrgID()
	switch _, err := q.GetBrowserSiteByHost(ctx, org, p.Site.Host, p.Site.IncludeSubdomains); {
	case err == nil:
		return ErrListed
	case !db.IsNoRows(err):
		return err
	}
	if n, err := q.CountBrowserSites(ctx, org); err != nil {
		return err
	} else if n >= domain.SiteLimit {
		return ErrLimit
	}
	selectors := p.Site.ClickSelectors
	if selectors == nil {
		selectors = []string{}
	}
	row, err := q.InsertBrowserSite(ctx, dbq.InsertBrowserSiteParams{
		ID: ids.NewV7(), OrgID: org, Host: p.Site.Host, IncludeSubdomains: p.Site.IncludeSubdomains, Compare: p.Site.Compare,
		ClickSelectors: selectors, Note: p.Site.Note, CreatedBy: author.Principal.String(),
	})
	if err != nil {
		return err
	}
	if err := q.BumpOrgGateways(ctx, org); err != nil {
		return err
	}
	details := siteDetails(row, p.Reason)
	if publisher, ok := protect.Publisher(ctx); ok {
		details["confirmed_by"] = publisher.String()
	}
	return record(ctx, tx, author, auditkind.BrowserSiteAdded, row, details)
}

// addState is what a confirmed re-run must still find: the site still
// absent from the list.
func (s *Service) addState(ctx context.Context, tx db.TenantTx, payload []byte) ([]byte, error) {
	var p addPayload
	if err := json.Unmarshal(payload, &p); err != nil || !domain.ValidHost(p.Site.Host) {
		return nil, protect.ErrInvalid
	}
	switch _, err := dbq.New(tx).GetBrowserSiteByHost(ctx, tx.OrgID(), p.Site.Host, p.Site.IncludeSubdomains); {
	case err == nil:
		return []byte("listed"), nil
	case db.IsNoRows(err):
		return []byte("absent"), nil
	default:
		return nil, err
	}
}

// Remove takes a site off the list at once, a person holding
// org.owned_accounts.manage: browser actions on it hold again.
func (s *Service) Remove(ctx context.Context, id ids.UUID, reason string) error {
	if err := validReason(reason); err != nil {
		return err
	}
	c, err := caller(ctx, td.PermOwnedAccountsManage)
	if err != nil {
		return err
	}
	if !c.Human() {
		return ErrHuman
	}
	return s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.DeleteBrowserSite(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrMissing
		} else if err != nil {
			return err
		}
		if err := q.BumpOrgGateways(ctx, c.Org); err != nil {
			return err
		}
		return record(ctx, tx, c, auditkind.BrowserSiteRemoved, row, siteDetails(row, reason))
	})
}

func siteDetails(row dbq.PcBrowserSite, reason string) map[string]string {
	return map[string]string{
		"host": row.Host, "include_subdomains": strconv.FormatBool(row.IncludeSubdomains),
		"compare": strconv.FormatBool(row.Compare), "selector_count": strconv.Itoa(len(row.ClickSelectors)), "reason": reason,
	}
}

func record(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name string, row dbq.PcBrowserSite, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "browser_site", ID: row.ID.String()},
		Details: details,
	})
	return err
}
