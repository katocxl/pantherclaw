// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package issuerkeys

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// EntraApp is one entry of identity.entra_apps (D129): an Entra app in a
// tenant whose tokens attest for exactly one org.
type EntraApp struct {
	TenantID string `json:"tenant_id"`
	AppID    string `json:"app_id"`
	OrgID    string `json:"org_id"`
}

// ValidateEntra checks the entries and refuses an app id listed twice:
// each app maps to exactly one org (HR-469).
func ValidateEntra(apps []EntraApp) error {
	var errs []error
	seen := map[string]bool{}
	for _, a := range apps {
		if !issuers.ValidGUID(a.TenantID) || !issuers.ValidGUID(a.AppID) {
			errs = append(errs, fmt.Errorf("entra app %q: tenant_id and app_id must be lower-case GUIDs", a.AppID))
		}
		if _, err := ids.Parse[ids.Org](a.OrgID); err != nil {
			errs = append(errs, fmt.Errorf("entra app %q: org_id %q is not an org id", a.AppID, a.OrgID))
		}
		if seen[a.AppID] {
			errs = append(errs, fmt.Errorf("entra app %q is configured twice", a.AppID))
		}
		seen[a.AppID] = true
	}
	return errors.Join(errs...)
}

// Entra is the configured Entra apps, with one key fetcher per tenant on
// the tenant's pinned keys URL.
type Entra struct {
	apps    map[string]EntraApp // by app id
	tenants map[string]*Fetcher
}

// NewEntra returns the configured apps; none means the Azure presets
// refuse every attestation.
func NewEntra(apps []EntraApp, timeout time.Duration) (*Entra, error) {
	if err := ValidateEntra(apps); err != nil {
		return nil, err
	}
	client := httpx.NewEgressClient(httpx.EgressConfig{Timeout: timeout})
	e := &Entra{apps: map[string]EntraApp{}, tenants: map[string]*Fetcher{}}
	for _, a := range apps {
		e.apps[a.AppID] = a
		if e.tenants[a.TenantID] != nil {
			continue
		}
		f, err := NewFetcher(client, Config{JWKSURL: issuers.AzureKeysURL(a.TenantID), Algorithms: issuers.AzureAlgorithms}, nil)
		if err != nil {
			return nil, err
		}
		e.tenants[a.TenantID] = f
	}
	return e, nil
}

// OrgOf returns the org an app id attests for, or the zero id.
func (e *Entra) OrgOf(app string) ids.OrgID {
	if e == nil {
		return ids.OrgID{}
	}
	org, err := ids.Parse[ids.Org](e.apps[app].OrgID)
	if err != nil {
		return ids.OrgID{}
	}
	return org
}

// Allowed reports whether org may pin the tenant and app pair.
func (e *Entra) Allowed(tenant, app string, org ids.OrgID) bool {
	if e == nil {
		return false
	}
	a, ok := e.apps[app]
	return ok && a.TenantID == tenant && a.OrgID == org.String()
}

// Verify checks token with the pinned keys of the tenant app belongs to,
// when app attests for org; the payload's claims are the preset's to
// check.
func (e *Entra) Verify(ctx context.Context, app string, org ids.OrgID, token string) ([]byte, error) {
	if e.OrgOf(app) != org || org.IsZero() {
		return nil, fmt.Errorf("%w: app %q is not configured for this organization", ErrUnverified, app)
	}
	return e.tenants[e.apps[app].TenantID].Verify(ctx, token)
}
