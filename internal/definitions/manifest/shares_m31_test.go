// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package manifest

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	pcgmail "github.com/katocxl/pantherclaw/packages/pc-gmail"
	pcgoogleworkspace "github.com/katocxl/pantherclaw/packages/pc-google-workspace"
	pcm365 "github.com/katocxl/pantherclaw/packages/pc-m365"
)

func m31Def(t *testing.T, raw []byte, op string) *domain.Definition {
	t.Helper()
	p, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	d, ok := p.Definition(op)
	if !ok {
		t.Fatalf("no %s", op)
	}
	return d
}

func domainShare(id string) actionir.Destination {
	return actionir.Destination{Kind: actionir.ShareEmailDomain, ID: id}
}

var publicShare = actionir.Destination{Kind: actionir.SharePublic, ID: actionir.ShareIDPublic}

// TestHR725_DriveAndM365SharesNameTheirDestinations: a Drive permission to
// anyone and an anonymous link are public; a domain, user or group share
// and each invited address name their email domain, lowercased; an
// organization link names none; mail send names no share (it stays a
// disclosure).
//
// Covers: HR-725
func TestHR725_DriveAndM365SharesNameTheirDestinations(t *testing.T) {
	drive := m31Def(t, pcgoogleworkspace.Package, "drive.permission.create")
	for name, c := range map[string]struct {
		vals domain.Values
		want []actionir.Destination
	}{
		"anyone": {domain.Values{"type": {Str: "anyone"}, "role": {Str: "reader"}}, []actionir.Destination{publicShare}},
		"domain": {domain.Values{"type": {Str: "domain"}, "role": {Str: "reader"}, "domain": {Str: "Partner.example"}}, []actionir.Destination{domainShare("partner.example")}},
		"user":   {domain.Values{"type": {Str: "user"}, "role": {Str: "writer"}, "email_address": {Str: "bob@Partner.example"}}, []actionir.Destination{domainShare("partner.example")}},
		"group":  {domain.Values{"type": {Str: "group"}, "role": {Str: "reader"}, "email_address": {Str: "eng@example.test"}}, []actionir.Destination{domainShare("example.test")}},
	} {
		got, err := drive.Shares(c.vals)
		if err != nil || !slices.Equal(got, c.want) {
			t.Errorf("drive %s: %v %v", name, got, err)
		}
	}
	invite := m31Def(t, pcm365.Package, "m365.drive.item.invite")
	got, err := invite.Shares(domain.Values{"recipients": {List: []string{"a@partner.example", "b@PARTNER.example", "c@example.test"}}, "role": {Str: "read"}})
	if err != nil || !slices.Equal(got, []actionir.Destination{domainShare("partner.example"), domainShare("example.test")}) {
		t.Errorf("invite: %v %v", got, err)
	}
	link := m31Def(t, pcm365.Package, "m365.drive.item.create_link")
	if got, err := link.Shares(domain.Values{"type": {Str: "view"}, "scope": {Str: "anonymous"}}); err != nil || !slices.Equal(got, []actionir.Destination{publicShare}) {
		t.Errorf("anonymous link: %v %v", got, err)
	}
	if got, err := link.Shares(domain.Values{"type": {Str: "edit"}, "scope": {Str: "organization"}}); err != nil || len(got) != 0 {
		t.Errorf("organization link: %v %v", got, err)
	}
	for raw, op := range map[string]string{string(pcgmail.Package): "gmail.message.send", string(pcm365.Package): "m365.mail.send"} {
		d := m31Def(t, []byte(raw), op)
		if got, _ := d.Shares(domain.Values{"to": {List: []string{"a@partner.example"}}}); len(got) != 0 {
			t.Errorf("%s names shares %v", op, got)
		}
	}
}

// TestHR725_AShareItCannotReadIsPublic: a Drive share whose domain or
// address is missing or malformed, and an invited address without a
// well-formed domain, fail closed to public, so the share is never
// unseen (T-332).
//
// Covers: HR-725, T-332
func TestHR725_AShareItCannotReadIsPublic(t *testing.T) {
	drive := m31Def(t, pcgoogleworkspace.Package, "drive.permission.create")
	for name, vals := range map[string]domain.Values{
		"domain without one": {"type": {Str: "domain"}, "role": {Str: "reader"}},
		"user without one":   {"type": {Str: "user"}, "role": {Str: "reader"}},
		"bad domain":         {"type": {Str: "domain"}, "role": {Str: "reader"}, "domain": {Str: "partner"}},
		"bad address":        {"type": {Str: "user"}, "role": {Str: "reader"}, "email_address": {Str: "bob@-x-.example"}},
	} {
		if got, err := drive.Shares(vals); err != nil || !slices.Equal(got, []actionir.Destination{publicShare}) {
			t.Errorf("%s: %v %v", name, got, err)
		}
	}
	invite := m31Def(t, pcm365.Package, "m365.drive.item.invite")
	got, err := invite.Shares(domain.Values{"recipients": {List: []string{"a@partner.example", "nobody"}}, "role": {Str: "read"}})
	if err != nil || !slices.Contains(got, publicShare) || !slices.Contains(got, domainShare("partner.example")) {
		t.Errorf("invite: %v %v", got, err)
	}
}
