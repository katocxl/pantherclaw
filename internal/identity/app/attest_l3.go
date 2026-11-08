// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// The L3 "Infrastructure-attested" presets (PAP-1 §3.3, G0 M35 D1030).
// Their evidence binds the org, the nonce of the request it arrives with
// and the thumbprint of the key that signed that request, so it attests
// only the enrollment or renewal it was made for (HR-777). Each is still
// single use (HR-143).

// attestSPIFFEX509 verifies an X.509-SVID signed binding with the X.509
// bundle of the leaf's trust domain, which must be configured for org
// (HR-778). It attests until the SVID expires, for at most
// MaxTokenLifetime.
func (s *Service) attestSPIFFEX509(ctx context.Context, org ids.OrgID, a Attestation, revs []dbq.PcTrustedIssuer) ([]attested, error) {
	if s.att.SPIFFEX509 == nil {
		return nil, attErr(errors.New("no SPIFFE trust domain is configured"))
	}
	if a.bind.Org != org {
		return nil, attErr(errors.New("the binding names another org"))
	}
	svid, err := s.att.SPIFFEX509.Verify(ctx, org, a.Token)
	if err != nil {
		return nil, attErr(err)
	}
	now := s.clk.Now()
	w := issuers.Window{IssuedAt: now, ExpiresAt: now.Add(issuers.MaxTokenLifetime)}
	if svid.NotAfter.Before(w.ExpiresAt) {
		w.ExpiresAt = svid.NotAfter
	}
	if err := w.Check(now); err != nil {
		return nil, attErr(err)
	}
	var out []attested
	var last error
	for _, r := range revs {
		b, err := bindingOf(r)
		if err != nil || b.SPIFFEX509 == nil {
			continue
		}
		m, err := issuers.MatchSPIFFEX509(*b.SPIFFEX509, a.bind, svid)
		if err != nil {
			last = err
			continue
		}
		out = append(out, attested{
			rev: r, match: m, issuer: b.SPIFFEX509.Issuer(), key: issuers.ReplayKey("", a.Token), window: w,
			claims: withClaims(m.Binding, map[string]string{"svid_not_after": svid.NotAfter.UTC().Format(time.RFC3339)}),
		})
	}
	if len(out) == 0 {
		return nil, attErr(last)
	}
	return out, nil
}

// attestGCPInstance verifies a GCE identity token (format=full) with the
// pinned Google keys; its audience must be the L3 audience of this
// request (HR-779). It attests until the token expires.
func (s *Service) attestGCPInstance(ctx context.Context, org ids.OrgID, a Attestation, revs []dbq.PcTrustedIssuer) ([]attested, error) {
	if s.att.GCP == nil {
		return nil, attErr(errors.New("the GCP presets are not configured"))
	}
	payload, err := s.att.GCP.Verify(ctx, a.Token)
	if err != nil {
		return nil, attErr(err)
	}
	c, err := issuers.ParseGCPClaims(payload)
	if err != nil {
		return nil, attErr(err)
	}
	w, err := issuers.ParseWindow(payload)
	if err == nil {
		err = w.Check(s.clk.Now())
	}
	if err != nil {
		return nil, attErr(err)
	}
	if a.bind.Org != org {
		return nil, attErr(errors.New("the binding names another org"))
	}
	var out []attested
	var last error
	for _, r := range revs {
		b, err := bindingOf(r)
		if err != nil || b.GCPInstance == nil {
			continue
		}
		m, err := issuers.MatchGCPInstance(*b.GCPInstance, a.bind, c)
		if err != nil {
			last = err
			continue
		}
		ce := c.Google.ComputeEngine
		out = append(out, attested{
			rev: r, match: m, issuer: c.Issuer, key: issuers.ReplayKey(w.JTI, a.Token), window: w,
			claims: withClaims(m.Binding, map[string]string{"zone": ce.Zone, "service_account_id": c.Subject}),
		})
	}
	if len(out) == 0 {
		return nil, attErr(last)
	}
	return out, nil
}

// attestedLevel is the level an instance holds while an attestation
// through rev is current, capped by the agent's context (HR-092).
func attestedLevel(rev dbq.PcTrustedIssuer, a dbq.PcAgent) int {
	return min(issuers.Level(issuers.Kind(rev.Kind)), maxLevel(a))
}
