// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"context"
	"regexp"
	"strings"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The browser step (G0 M33 D977; HR-745, HR-746). It applies to an action
// whose pinned definition's target type is browser.site (pc.browser). A
// takeover always holds for a person (BROWSER_TAKEOVER): no grant, policy
// or exception removes the hold. Every other browser action holds when its
// target host matches no site on the org's browser site list
// (SITE_NOT_LISTED); an IP host never matches, and an empty list holds
// everything. The step only ever adds a hold.

// Reason codes, level and target type of a browser hold.
const (
	// ReasonBrowserTakeover: a person takes over the agent's browser tab.
	ReasonBrowserTakeover = "BROWSER_TAKEOVER"
	// ReasonSiteNotListed: the target host is not on the org's site list.
	ReasonSiteNotListed = "SITE_NOT_LISTED"
	// BrowserLevel is the source of the hold's requirement.
	BrowserLevel = "browser"
	// BrowserTargetType is pc.browser's target type.
	BrowserTargetType = "browser.site"
	// browserTakeover is pc.browser's takeover operation.
	browserTakeover = "browser.takeover"
)

// BrowserSite is one site of the org's browser site list as the step
// matches it.
type BrowserSite struct {
	Host              string
	IncludeSubdomains bool
}

// BrowserSites is the port the browser step reads the org's site list
// through. A Reader that does not implement it lists nothing, so every
// browser action holds (fail closed).
type BrowserSites interface {
	BrowserSites(ctx context.Context, org ids.OrgID) ([]BrowserSite, error)
}

var browserIPv4 = regexp.MustCompile(`^[0-9.]+$`)

// browserSiteMatches reports whether host matches a listed site: host
// equals its host, or the site includes subdomains and host ends with "."
// and its host. An IP host never matches.
func browserSiteMatches(host string, sites []BrowserSite) bool {
	if host == "" || strings.HasPrefix(host, "[") || browserIPv4.MatchString(host) {
		return false
	}
	for _, e := range sites {
		if host == e.Host || (e.IncludeSubdomains && strings.HasSuffix(host, "."+e.Host)) {
			return true
		}
	}
	return false
}

// browser holds a takeover, and a browser action on a site not listed
// (D977).
func (p *Pipeline) browser(ctx context.Context, s *state) {
	if s.def == nil || s.def.Target.Type != BrowserTargetType {
		return
	}
	var reason, detail string
	if s.def.Operation == browserTakeover {
		reason, detail = ReasonBrowserTakeover, "a person takes over the agent's browser tab"
	} else {
		var sites []BrowserSite
		if port, ok := p.Reader.(BrowserSites); ok {
			var err error
			if sites, err = port.BrowserSites(ctx, s.req.Org); err != nil {
				s.missing(StepFacts, err, "the org's browser sites")
				return
			}
		}
		if browserSiteMatches(s.a.Target.ID, sites) {
			return
		}
		reason, detail = ReasonSiteNotListed, "the site "+s.a.Target.ID+" is not on the org's browser site list"
	}
	s.cl.add(StepRequirements, adomain.RequireApproval, reason,
		"approval by "+string(td.RoleApprover)+" is required: "+detail, BrowserLevel)
	a := pdomain.ApprovalRequirement{Role: string(td.RoleApprover), Count: 1}
	s.ev.Approvals = append(s.ev.Approvals, a)
	s.ev.Requirements = append(s.ev.Requirements, input(&a, nil, apdomain.Source{Level: BrowserLevel, Reason: reason}))
}
