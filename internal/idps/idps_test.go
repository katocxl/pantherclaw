// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package idps

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// TestHR484_LockOutRule: a change is refused when no active org admin's
// identity issuer is among the providers left to sign in with, and allowed
// while one is (G0 M18 D155).
//
// Covers: PN-012.7
func TestHR484_LockOutRule(t *testing.T) {
	admins := []dbq.OrgAdminIssuersRow{{Issuer: "https://a.example.com", Admins: 1}, {Issuer: "https://b.example.com", Admins: 2}}
	if err := lockOut(admins, map[string]bool{"https://b.example.com": true}); err != nil {
		t.Fatalf("an admin can still sign in: %v", err)
	}
	if err := lockOut(admins, map[string]bool{"https://c.example.com": true}); !errors.Is(err, ErrLockOut) {
		t.Fatalf("no admin can sign in: %v", err)
	}
	if err := lockOut(admins, nil); !errors.Is(err, ErrLockOut) {
		t.Fatalf("no provider at all: %v", err)
	}
}

// TestHR482_SecretNeverInProvider: the provider people see, and every row
// a listing reads, has no field that could carry the client secret; only
// the resolver's row has the sealed one (G0 M18 D155).
//
// Covers: PN-012.7
func TestHR482_SecretNeverInProvider(t *testing.T) {
	for _, v := range []any{
		Provider{}, dbq.GetOrgIdentityProviderRow{}, dbq.ListOrgIdentityProvidersRow{},
		dbq.InsertOrgIdentityProviderRow{}, dbq.LockOrgIdentityProviderRow{},
	} {
		typ := reflect.TypeOf(v)
		for i := range typ.NumField() {
			f := typ.Field(i)
			if strings.Contains(strings.ToLower(f.Name), "secret") && f.Name != "SecretDigest" {
				t.Errorf("%s.%s carries the secret", typ.Name(), f.Name)
			}
		}
	}
}

// TestHR483_InputIssuer: a provider's issuer is HTTPS on a public host;
// names, client ids and secrets are bounded (G0 M18 D155).
//
// Covers: PN-012.7
func TestHR483_InputIssuer(t *testing.T) {
	ok := Input{Name: "acme", Issuer: "https://idp.example.com", ClientID: "c", ClientSecret: pclog.NewSecret([]byte("s"))}
	if err := ok.validate(true); err != nil {
		t.Fatal(err)
	}
	for _, mut := range []func(*Input){
		func(in *Input) { in.Issuer = "http://idp.example.com" },
		func(in *Input) { in.Issuer = "https://127.0.0.1" },
		func(in *Input) { in.Issuer = "https://10.0.0.8" },
		func(in *Input) { in.Issuer = "https://localhost" },
		func(in *Input) { in.Issuer = "https://169.254.169.254" },
		func(in *Input) { in.Issuer = "https://" + strings.Repeat("a", 520) + ".com" },
		func(in *Input) { in.Name = "Acme" },
		func(in *Input) { in.ClientID = "" },
		func(in *Input) { in.ClientSecret = pclog.Secret[[]byte]{} },
		func(in *Input) { in.ClientSecret = pclog.NewSecret(make([]byte, 4097)) },
	} {
		in := ok
		mut(&in)
		if err := in.validate(true); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v: %v", in, err)
		}
	}
	keep := ok
	keep.ClientSecret = pclog.Secret[[]byte]{}
	if err := keep.validate(false); err != nil {
		t.Fatalf("a change that keeps the secret: %v", err)
	}
}
