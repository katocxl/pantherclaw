// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pcawss3 "github.com/katocxl/pantherclaw/packages/pc-aws-s3"
	pcgithub "github.com/katocxl/pantherclaw/packages/pc-github"
)

// ownedReader is a Reader that answers only the owned-accounts port.
type ownedReader struct {
	Reader
	owned map[string][]string
	err   error
}

func (r ownedReader) OwnedAccounts(_ context.Context, _ ids.OrgID, kind string) ([]string, error) {
	return r.owned[kind], r.err
}

// runShares runs the share step on an action with the given shares.
func runShares(r Reader, def *defs.Definition, vals defs.Values, shares ...actionir.Destination) *state {
	s := &state{a: actionir.ActionIR{Shares: shares}, ev: &Evaluation{}, def: def, vals: vals}
	(&Pipeline{Reader: r}).shares(context.Background(), s)
	return s
}

// codes are the share step's checklist items by code and effect.
func codes(s *state) map[string]adomain.Decision {
	out := map[string]adomain.Decision{}
	for _, it := range s.cl.items {
		out[it.Code] = it.effect
	}
	return out
}

var (
	ownedAWS = actionir.Destination{Kind: actionir.ShareAWSAccount, ID: "111122223333"}
	otherAWS = actionir.Destination{Kind: actionir.ShareAWSAccount, ID: "444455556666"}
	shPublic = actionir.Destination{Kind: actionir.SharePublic, ID: actionir.ShareIDPublic}
)

// TestHR707_OwnedShareHasNoEffect: a share to an account on the org's owned
// list adds nothing, and an action with no share adds nothing (G0 M30 D935).
//
// Covers: HR-707
func TestHR707_OwnedShareHasNoEffect(t *testing.T) {
	r := ownedReader{owned: map[string][]string{actionir.ShareAWSAccount: {ownedAWS.ID}}}
	for name, s := range map[string]*state{
		"owned":    runShares(r, nil, nil, ownedAWS),
		"no share": runShares(r, nil, nil),
	} {
		if len(s.cl.items) != 0 || len(s.ev.Approvals) != 0 {
			t.Errorf("%s: %+v %+v", name, s.cl.items, s.ev.Approvals)
		}
	}
}

// TestHR707_PublicAndUnlistedSharesHold: a public share holds SHARE_PUBLIC;
// a share to an unlisted account holds SHARE_ACCOUNT_NOT_OWNED; an empty
// list (or a Reader without the port) holds every account share; a failed
// read cannot authorize; the step never allows (G0 M30 D935).
//
// Covers: HR-707
func TestHR707_PublicAndUnlistedSharesHold(t *testing.T) {
	r := ownedReader{owned: map[string][]string{actionir.ShareAWSAccount: {ownedAWS.ID}}}
	cases := map[string]struct {
		s    *state
		code string
	}{
		"public":          {runShares(r, nil, nil, shPublic), ReasonSharePublic},
		"unlisted":        {runShares(r, nil, nil, ownedAWS, otherAWS), ReasonShareAccountNotOwned},
		"empty list":      {runShares(ownedReader{}, nil, nil, ownedAWS), ReasonShareAccountNotOwned},
		"no port":         {runShares(nil, nil, nil, ownedAWS), ReasonShareAccountNotOwned},
		"read fails":      {runShares(ownedReader{err: errors.New("down")}, nil, nil, ownedAWS), ReasonEvidenceUnavailable},
		"github org":      {runShares(r, nil, nil, actionir.Destination{Kind: actionir.ShareGitHubOrg, ID: "acme"}), ReasonShareAccountNotOwned},
		"public and more": {runShares(r, nil, nil, shPublic, otherAWS), ReasonSharePublic},
	}
	for name, tt := range cases {
		got := codes(tt.s)
		want := adomain.RequireApproval
		if tt.code == ReasonEvidenceUnavailable {
			want = adomain.CannotAuthorize
		}
		if got[tt.code] != want {
			t.Errorf("%s: %+v, want %s %s", name, got, tt.code, want)
		}
		for c, d := range got {
			if d == adomain.Allow || d == adomain.AllowWithObligations {
				t.Errorf("%s: the share step allowed (%s)", name, c)
			}
		}
		if want == adomain.RequireApproval && len(tt.s.ev.Approvals) != 1 {
			t.Errorf("%s: approvals %+v", name, tt.s.ev.Approvals)
		}
	}
}

// TestHR707_AGitHubOrgMatchesWithoutCase (G0 M30 D1211): a share to "Acme"
// is owned when "acme" is listed, as GitHub compares names; another org
// still holds, and an AWS account still matches exactly.
//
// Covers: HR-707
func TestHR707_AGitHubOrgMatchesWithoutCase(t *testing.T) {
	r := ownedReader{owned: map[string][]string{actionir.ShareGitHubOrg: {"acme"}}}
	for _, id := range []string{"Acme", "acme", "ACME"} {
		if got := codes(runShares(r, nil, nil, actionir.Destination{Kind: actionir.ShareGitHubOrg, ID: id})); len(got) != 0 {
			t.Errorf("%s: %+v", id, got)
		}
	}
	if got := codes(runShares(r, nil, nil, actionir.Destination{Kind: actionir.ShareGitHubOrg, ID: "Acme-Evil"})); got[ReasonShareAccountNotOwned] != adomain.RequireApproval {
		t.Errorf("another org: %+v", got)
	}
}

// TestHR707_PinnedDefinitionSharesCountWithoutTheMapper: the Authority also
// reads shares from the pinned definition's extractors, so an action that
// left its shares out still holds; an unparseable bucket policy is public
// (G0 M30 D934, D935).
//
// Covers: HR-707
func TestHR707_PinnedDefinitionSharesCountWithoutTheMapper(t *testing.T) {
	def := shippedDef(t, pcawss3.Package, "aws.s3.bucket_policy.put")
	r := ownedReader{owned: map[string][]string{actionir.ShareAWSAccount: {ownedAWS.ID}}}
	vals := func(policy string) defs.Values { return defs.Values{"policy": {Type: defs.TypeContent, Str: policy}} }
	if got := codes(runShares(r, def, vals(`{"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:root"}}]}`))); len(got) != 0 {
		t.Fatalf("owned principal: %+v", got)
	}
	for name, policy := range map[string]string{
		"star":          `{"Statement": [{"Effect": "Allow", "Principal": "*"}]}`,
		"unparseable":   `{"Statement": [`,
		"not principal": `{"Statement": [{"Effect": "Allow", "NotPrincipal": {"AWS": "111122223333"}}]}`,
		// D1215: what the extractor cannot read is public.
		"unknown member":      `{"Statement": [{"Effect": "Allow", "Principal": {"AWS": "111122223333"}, "Grantee": "*"}]}`,
		"principal lowercase": `{"Statement": [{"Effect": "Allow", "principal": "*", "Action": "s3:GetObject"}]}`,
		"null principal":      `{"Statement": [{"Effect": "Allow", "Principal": null}]}`,
		"null statement":      `{"Statement": null}`,
		"missing statement":   `{"Version": "2012-10-17"}`,
		"string statement":    `{"Statement": "Allow *"}`,
		"null in the list":    `{"Statement": [null]}`,
	} {
		if got := codes(runShares(r, def, vals(policy))); got[ReasonSharePublic] != adomain.RequireApproval {
			t.Errorf("%s: %+v", name, got)
		}
	}
	if got := codes(runShares(r, def, vals(`{"Statement": {"Principal": {"AWS": ["444455556666"]}}}`))); got[ReasonShareAccountNotOwned] != adomain.RequireApproval {
		t.Fatalf("unlisted principal: %+v", got)
	}
}

// shippedDef is one definition of a shipped package.
func shippedDef(t *testing.T, raw []byte, op string) *defs.Definition {
	t.Helper()
	pkg, err := manifest.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	for i := range pkg.Definitions {
		if pkg.Definitions[i].Operation == op {
			return &pkg.Definitions[i]
		}
	}
	t.Fatalf("no %s", op)
	return nil
}

// TestT324_SharesOutOfTheOrgWaitForAPerson: making a bucket public through
// its ACL, a repository public, or transferring a repository to an account
// the org has not listed waits for a person; private, and a transfer to an
// owned organization, do not (T-324; G0 M30 D934, D935).
//
// Covers: T-324
func TestT324_SharesOutOfTheOrgWaitForAPerson(t *testing.T) {
	acl := shippedDef(t, pcawss3.Package, "aws.s3.bucket_acl.put")
	vis := shippedDef(t, pcgithub.Package, "github.repo.visibility.update")
	xfer := shippedDef(t, pcgithub.Package, "github.repo.transfer")
	r := ownedReader{owned: map[string][]string{actionir.ShareGitHubOrg: {"acme"}}}
	enum := func(name, v string) defs.Values { return defs.Values{name: {Type: defs.TypeEnum, Str: v}} }
	ident := func(name, v string) defs.Values { return defs.Values{name: {Type: defs.TypeIdentifier, Str: v}} }
	held := map[string]struct {
		s    *state
		code string
	}{
		"public-read acl":    {runShares(r, acl, enum("canned_acl", "public-read")), ReasonSharePublic},
		"public repository":  {runShares(r, vis, enum("visibility", "public")), ReasonSharePublic},
		"transfer elsewhere": {runShares(r, xfer, ident("new_owner", "evil-org")), ReasonShareAccountNotOwned},
	}
	for name, tt := range held {
		if got := codes(tt.s); got[tt.code] != adomain.RequireApproval {
			t.Errorf("%s: %+v, want %s", name, got, tt.code)
		}
	}
	for name, s := range map[string]*state{
		"private acl":        runShares(r, acl, enum("canned_acl", "private")),
		"private repository": runShares(r, vis, enum("visibility", "private")),
		"transfer to owned":  runShares(r, xfer, ident("new_owner", "acme")),
	} {
		if len(s.cl.items) != 0 {
			t.Errorf("%s: %+v", name, s.cl.items)
		}
	}
}
