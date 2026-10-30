// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package idps

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// TestHR484_LockOutRule: a change that leaves no active org admin a
// provider to sign in with is refused; one that strands one of two admins
// is allowed and names that admin; an admin who had no provider before is
// not counted as stranded (G0 M18 D155, D162).
//
// Covers: PN-012.7
func TestHR484_LockOutRule(t *testing.T) {
	alice, bob := ids.NewV7(), ids.NewV7()
	const a, b, c = "https://a.example.com", "https://b.example.com", "https://c.example.com"
	admins := []dbq.OrgAdminIdentitiesRow{{ID: alice, Issuer: a}, {ID: bob, Issuer: b}}
	both := map[string]bool{a: true, b: true}

	stranded, err := lockOut(admins, both, map[string]bool{b: true})
	if err != nil || !slices.Equal(stranded, []ids.UUID{alice}) {
		t.Fatalf("one of two stranded: %v %v", stranded, err)
	}
	if _, err := lockOut(admins, both, map[string]bool{c: true}); !errors.Is(err, ErrLockOut) {
		t.Fatalf("no admin left: %v", err)
	}
	if _, err := lockOut(admins, both, nil); !errors.Is(err, ErrLockOut) {
		t.Fatalf("no provider at all: %v", err)
	}
	stranded, err = lockOut(admins, map[string]bool{b: true}, map[string]bool{b: true})
	if err != nil || len(stranded) != 0 {
		t.Fatalf("an admin without a provider before is not stranded: %v %v", stranded, err)
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
