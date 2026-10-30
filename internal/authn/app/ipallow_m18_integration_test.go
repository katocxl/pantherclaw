// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// limitedKey adds an API key of w's service account usable only from
// 198.51.100.0/24 and 2001:db8::/32.
func (e *env) limitedKey(t *testing.T, w world) (ids.UUID, credential.Token) {
	t.Helper()
	tok, err := credential.New(credential.APIKey, credential.EnvTest, w.org)
	if err != nil {
		t.Fatal(err)
	}
	id := ids.NewV7()
	e.exec(t, w.org, `INSERT INTO pc.api_keys (org_id, id, service_account_id, name, secret_hash, hint, scopes, created_by, expires_at, allowed_cidrs)
		VALUES ($1, $2, $3, 'limited', $4, $5, ARRAY['team.read'], 'test', now() + interval '90 days',
		        ARRAY['198.51.100.0/24', '2001:db8::/32']::cidr[])`,
		w.org, id, w.sa, tok.Hash(), tok.Hint())
	return id, tok
}

func (e *env) refusals(t *testing.T, w world, key ids.UUID) int {
	t.Helper()
	var n int
	err := e.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, `SELECT count(*)::int FROM pc.ledger_entries
			WHERE org_id = $1 AND kind = 'audit.`+authnapp.IPRefusedName+`' AND convert_from(body, 'UTF8') LIKE '%' || $2 || '%'`, w.org, key.String()).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestHR475_CIDRRestrictedKeyIsRefusedLikeABadKey: a key limited to
// address ranges works from inside them; from any other address, or with no
// known address, it gets exactly the bad-key error, and the refusal is
// audited (once per key and address per minute). A key without ranges
// works from anywhere, and pc_app cannot change a key's ranges.
//
// Covers: PN-012.8
func TestHR475_CIDRRestrictedKeyIsRefusedLikeABadKey(t *testing.T) {
	e := newEnv(t)
	w := e.world(t, "acme")
	id, tok := e.limitedKey(t, w)
	for _, ip := range []string{"198.51.100.7", "2001:db8::1", "::ffff:198.51.100.200"} {
		if _, err := e.authn.Authenticate(httpx.WithClientIP(context.Background(), ip), tok.Reveal()); err != nil {
			t.Errorf("from %s: %v", ip, err)
		}
	}
	bad := e.authn.Authenticate
	for _, ip := range []string{"203.0.113.9", "198.51.101.1", "2001:db9::1", "", "not-an-ip"} {
		_, err := bad(httpx.WithClientIP(context.Background(), ip), tok.Reveal())
		if !errors.Is(err, authnapp.ErrUnauthenticated) {
			t.Errorf("from %q: err = %v, want ErrUnauthenticated", ip, err)
		}
	}
	// The same address again within the minute is not audited twice.
	_, _ = bad(httpx.WithClientIP(context.Background(), "203.0.113.9"), tok.Reveal())
	if n := e.refusals(t, w, id); n != 5 {
		t.Errorf("apikey.ip_refused audited %d times, want 5", n)
	}
	unknown, err := credential.New(credential.APIKey, credential.EnvTest, w.org)
	if err != nil {
		t.Fatal(err)
	}
	_, unknownErr := bad(httpx.WithClientIP(context.Background(), "203.0.113.9"), unknown.Reveal())
	_, refusedErr := bad(httpx.WithClientIP(context.Background(), "203.0.113.9"), tok.Reveal())
	if unknownErr == nil || refusedErr == nil || unknownErr.Error() != refusedErr.Error() {
		t.Errorf("refusal %v differs from a bad key %v", refusedErr, unknownErr)
	}
	if _, err := e.authn.Authenticate(httpx.WithClientIP(context.Background(), "203.0.113.9"), w.apiKey.Reveal()); err != nil {
		t.Errorf("a key without ranges: %v", err)
	}
	err = e.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "UPDATE pc.api_keys SET allowed_cidrs = NULL WHERE id = $1", id)
		return err
	})
	if !db.IsPermissionDenied(err) {
		t.Errorf("pc_app changed a key's ranges: %v", err)
	}
}

// TestHR476_ClientIPComesOnlyFromTrustedProxies: behind the server's
// client-address middleware, forwarding headers count only from a trusted
// proxy. A direct client naming an allowed address in X-Forwarded-For is
// refused; the same request through the trusted proxy is accepted.
//
// Covers: PN-012.8
func TestHR476_ClientIPComesOnlyFromTrustedProxies(t *testing.T) {
	e := newEnv(t)
	w := e.world(t, "acme")
	_, tok := e.limitedKey(t, w)
	h := e.behindProxy(netip.MustParsePrefix("10.0.0.0/8"))
	if got := h.call(t, "203.0.113.9:4000", "198.51.100.7", tok); got != http.StatusUnauthorized {
		t.Errorf("untrusted peer with a forged header: %d", got)
	}
	if got := h.call(t, "10.1.2.3:4000", "198.51.100.7", tok); got != http.StatusOK {
		t.Errorf("trusted proxy forwarding an allowed client: %d", got)
	}
	none := e.behindProxy()
	if got := none.call(t, "10.1.2.3:4000", "198.51.100.7", tok); got != http.StatusUnauthorized {
		t.Errorf("without trusted proxies the header counted: %d", got)
	}
}

// TestT208_ForwardedForSpoofAgainstACIDRList: a client outside the ranges
// puts an allowed address first in X-Forwarded-For and sends it through the
// trusted proxy, which appends the real address. The right-most untrusted
// hop is the real client, so the key is refused.
func TestT208_ForwardedForSpoofAgainstACIDRList(t *testing.T) {
	e := newEnv(t)
	w := e.world(t, "acme")
	_, tok := e.limitedKey(t, w)
	h := e.behindProxy(netip.MustParsePrefix("10.0.0.0/8"))
	for name, xff := range map[string]string{
		"prepended":     "198.51.100.7, 203.0.113.9",
		"proxy spoofed": "198.51.100.7, 203.0.113.9, 10.9.9.9",
		"malformed":     "198.51.100.7, bogus",
	} {
		if got := h.call(t, "10.1.2.3:4000", xff, tok); got != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 401", name, got)
		}
	}
}

type proxied struct {
	e *env
	h http.Handler
}

// behindProxy is the server's client-address wiring: the trusted-proxy
// aware address (or the peer, without proxies) stored by the middleware.
func (e *env) behindProxy(trusted ...netip.Prefix) proxied {
	f := httpx.ClientIP
	if len(trusted) > 0 {
		f = httpx.TrustedProxyClientIP(trusted)
	}
	return proxied{e: e, h: httpx.ClientIPMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if _, err := e.authn.Authenticate(r.Context(), r.Header.Get("Authorization")); err != nil {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		rw.WriteHeader(http.StatusOK)
	}), f)}
}

func (p proxied) call(t *testing.T, peer, xff string, tok credential.Token) int {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = peer
	r.Header.Set("X-Forwarded-For", xff)
	r.Header.Set("Authorization", tok.Reveal())
	rw := httptest.NewRecorder()
	p.h.ServeHTTP(rw, r)
	return rw.Code
}

type editionOf struct{ ed billing.Edition }

func (e *editionOf) Current(context.Context) (billing.Entitlements, error) {
	out := billing.CommunityEntitlements()
	out.Edition = e.ed
	return out, nil
}

// TestHR475_RangesStayEnforcedAfterADowngrade: creating a key with ranges
// needs Team (PN-012.8), but a downgrade never drops a restriction
// (D161): the key keeps its ranges and is still refused from elsewhere,
// while keys without ranges can still be created.
//
// Covers: PN-012.8
func TestHR475_RangesStayEnforcedAfterADowngrade(t *testing.T) {
	e := newEnv(t)
	w := e.world(t, "acme")
	ed := &editionOf{ed: billing.Team}
	s := tapp.NewServiceAccounts(e.pool, credential.EnvTest).WithEntitlements(ed)
	admin := tapp.WithCaller(context.Background(), tapp.Caller{
		Subject: td.Subject{Org: w.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: w.user}, Bindings: []td.Binding{
			{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}},
		}},
		Credential: tapp.CredAccessToken,
	})
	sa := idOf(t, w.sa)
	ranges := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	k, tok, err := s.CreateLimitedAPIKey(admin, sa, "ranged", []td.Permission{td.PermTeamRead}, 0, ranges)
	if err != nil || len(k.AllowedCIDRs) != 1 || k.AllowedCIDRs[0] != ranges[0] {
		t.Fatalf("Team key with ranges: %+v (%v)", k, err)
	}
	ed.ed = billing.Community
	if _, _, err := s.CreateLimitedAPIKey(admin, sa, "again", []td.Permission{td.PermTeamRead}, 0, ranges); pcerr.ReasonOf(err) != "EDITION_REQUIRED" {
		t.Errorf("Community key with ranges: %v", err)
	}
	if _, _, err := s.CreateAPIKey(admin, sa, "plain", []td.Permission{td.PermTeamRead}, 0); err != nil {
		t.Errorf("Community key without ranges: %v", err)
	}
	if _, err := e.authn.Authenticate(httpx.WithClientIP(context.Background(), "203.0.113.9"), tok.Reveal()); !errors.Is(err, authnapp.ErrUnauthenticated) {
		t.Errorf("after the downgrade the key was accepted from outside its ranges: %v", err)
	}
	if _, err := e.authn.Authenticate(httpx.WithClientIP(context.Background(), "198.51.100.7"), tok.Reveal()); err != nil {
		t.Errorf("after the downgrade, from inside its ranges: %v", err)
	}
}

func idOf(t *testing.T, id ids.UUID) td.ServiceAccountID {
	t.Helper()
	out, err := ids.FromUUID[td.ServiceAccount](id)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
