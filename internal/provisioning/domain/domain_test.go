// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR630_EveryRoleIsDecidedByWhatItCanDo walks every role, so a new one
// can't slip through: anything holding role.bind is refused, the four named
// roles are refused, and the schema's list stays what the rule says (D409).
//
// Covers: F920
func TestHR630_EveryRoleIsDecidedByWhatItCanDo(t *testing.T) {
	refused := UnmappableRoles()
	for _, r := range td.Roles() {
		wantRefused := r.Has(td.PermRoleBind) || slices.Contains(keptInPantherClaw, r.Name)
		if slices.Contains(refused, r.Name) != wantRefused {
			t.Errorf("%s: refused %v, want %v", r.Name, slices.Contains(refused, r.Name), wantRefused)
		}
		for _, s := range []td.ScopeType{td.ScopeOrg, td.ScopeBusinessUnit, td.ScopeTeam, td.ScopeEnvironment} {
			err := CheckMappable(r.Name, s)
			if !r.BindableAt(s) || r.ServiceOnly {
				if err == nil {
					t.Errorf("%s at %s: a group may carry a role a person can't hold there", r.Name, s)
				}
				continue
			}
			if wantRefused && !errors.Is(err, ErrRoleNotMappable) {
				t.Errorf("%s at %s: %v, want ROLE_NOT_MAPPABLE", r.Name, s, err)
			}
		}
	}
	for _, n := range []td.RoleName{td.RoleOrgAdmin, td.RoleSecurityAdmin, td.RoleScopeAdmin, td.RoleEmergency} {
		if !slices.Contains(refused, n) {
			t.Errorf("%s is mappable", n)
		}
	}
	// The list in migration 00292: a new unmappable role must be added there.
	schema := []td.RoleName{td.RoleOrgAdmin, td.RoleSecurityAdmin, td.RoleScopeAdmin, td.RoleEmergency}
	for _, n := range refused {
		if !slices.Contains(schema, n) {
			t.Errorf("%s is refused here but not by the checks of migration 00292", n)
		}
	}
	if err := CheckMappable(td.RoleViewer, td.ScopeOrg); err != nil {
		t.Errorf("viewer: %v", err)
	}
	if err := CheckMappable("no_such_role", td.ScopeOrg); !errors.Is(err, td.ErrUnknownRole) {
		t.Errorf("an unknown role: %v", err)
	}
}

func cert(t *testing.T, pub, priv any, notAfter time.Time) string {
	t.Helper()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "idp"}, NotBefore: notAfter.Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// Covers: F921. Only keys a signature can be trusted with, in one form.
func TestCheckCertificates(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	later := now.Add(24 * time.Hour)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // G403: the test of the refusal
	if err != nil {
		t.Fatal(err)
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	good := cert(t, &ec.PublicKey, ec, later)
	if err := CheckCertificates([]string{good, cert(t, &rs.PublicKey, rs, later)}, now); err != nil {
		t.Fatal(err)
	}
	for name, certs := range map[string][]string{
		"none":     nil,
		"five":     {good, good, good, good, good},
		"not b64":  {"%%%"},
		"not DER":  {"AAAA"},
		"pem":      {"-----BEGIN CERTIFICATE-----\n" + good + "\n-----END CERTIFICATE-----"},
		"weak RSA": {cert(t, &weak.PublicKey, weak, later)},
		"ed25519":  {cert(t, edPub, edPriv, later)},
		"expired":  {cert(t, &ec.PublicKey, ec, now.Add(-time.Hour))},
	} {
		if err := CheckCertificates(certs, now); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// Covers: F921.
func TestConnectionValidate(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ok := Connection{
		Name: "okta", EntityID: "https://idp.example.com", SSOURL: "https://idp.example.com/sso",
		Certificates: []string{cert(t, &ec.PublicKey, ec, now.Add(time.Hour))},
	}
	check := func(u string) error {
		if !strings.HasPrefix(u, "https://") {
			return errors.New("not https")
		}
		return nil
	}
	if err := ok.Validate(check, now); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Connection){
		"name":      func(c *Connection) { c.Name = "Okta" },
		"long name": func(c *Connection) { c.Name = strings.Repeat("a", 28) },
		"no entity": func(c *Connection) { c.EntityID = "" },
		"spaces":    func(c *Connection) { c.EntityID = "a b" },
		"long":      func(c *Connection) { c.EntityID = strings.Repeat("a", 501) },
		"http":      func(c *Connection) { c.SSOURL = "http://idp.example.com/sso" },
		"certs":     func(c *Connection) { c.Certificates = nil },
	} {
		c := ok
		change(&c)
		if err := c.Validate(check, now); !errors.Is(err, ErrInvalidConnection) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
