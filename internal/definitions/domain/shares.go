// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// ShareExtractor names how the accounts an action shares to are read from
// one parameter's value (G0 M30 D934). Every extractor fails closed: what it
// cannot read is a public share.
type ShareExtractor string

// Share extractors.
const (
	// ShareAWSPolicyPrincipals parses an S3 bucket policy: every principal
	// ARN or 12-digit id under Principal/AWS is an aws_account share, "*"
	// is public, and an unparseable policy or any other principal is one
	// public share.
	ShareAWSPolicyPrincipals ShareExtractor = "aws_policy_principals"
	// ShareAWSCannedACL reads an S3 canned ACL: private shares to no one,
	// every other value is public (G0 M30 D934a).
	ShareAWSCannedACL ShareExtractor = "aws_canned_acl"
	// ShareGitHubVisibility is public when the value is "public".
	ShareGitHubVisibility ShareExtractor = "github_visibility"
	// ShareGitHubOwner is a github_org share of the value.
	ShareGitHubOwner ShareExtractor = "github_owner"
	// ShareGoogleDrivePermission reads a Drive permission's type (G0 M31
	// D958): anyone is public; domain is an email_domain share of the
	// domain param; user and group are an email_domain share of the
	// email_address param's domain. A missing or malformed value is public.
	ShareGoogleDrivePermission ShareExtractor = "google_drive_permission"
	// ShareEmailRecipients is an email_domain share of each address's
	// domain (D958); a malformed address is public.
	ShareEmailRecipients ShareExtractor = "email_recipients"
	// ShareM365LinkScope reads a Microsoft 365 sharing link's scope (D958):
	// anonymous is public, organization shares to no one outside it, and
	// any other value is public.
	ShareM365LinkScope ShareExtractor = "m365_link_scope"
)

// accepts reports whether the extractor reads a param of type t.
func (e ShareExtractor) accepts(t ParamType) bool {
	switch e {
	case ShareAWSPolicyPrincipals:
		return t == TypeContent
	case ShareAWSCannedACL, ShareGitHubVisibility, ShareGoogleDrivePermission, ShareM365LinkScope:
		return t == TypeEnum
	case ShareGitHubOwner:
		return t == TypeIdentifier
	case ShareEmailRecipients:
		return t == TypeIdentifierList
	}
	return false
}

var (
	awsAccountIDRe  = regexp.MustCompile(`^[0-9]{12}$`)
	awsARNAccountRe = regexp.MustCompile(`^arn:aws[a-z-]{0,16}:[a-z0-9-]{1,32}:[a-z0-9-]{0,32}:([0-9]{12}):`)
)

var public = actionir.Destination{Kind: actionir.SharePublic, ID: actionir.ShareIDPublic}

// Shares returns the share destinations of an action's values under d's
// share extractors, deduplicated, in a stable order. More than
// actionir.MaxShares is refused (the caller fails closed).
func (d *Definition) Shares(vals Values) ([]actionir.Destination, error) {
	var out []actionir.Destination
	for _, name := range slices.Sorted(maps.Keys(d.Params)) {
		p := d.Params[name]
		if p.Share == "" {
			continue
		}
		v, ok := vals[name]
		if !ok {
			continue
		}
		for _, s := range p.Share.extract(v, vals) {
			if !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
	}
	if len(out) > actionir.MaxShares {
		return nil, invalid("%s: more than %d share destinations", d.Operation, actionir.MaxShares)
	}
	return out, nil
}

// extract reads one param's shares; vals are the action's values, which an
// extractor that combines params reads (G0 M31 D958).
func (e ShareExtractor) extract(v Value, vals Values) []actionir.Destination {
	switch e {
	case ShareGoogleDrivePermission:
		switch v.Str {
		case "domain":
			return []actionir.Destination{emailDomain("@" + vals["domain"].Str)}
		case "user", "group":
			return []actionir.Destination{emailDomain(vals["email_address"].Str)}
		}
		return []actionir.Destination{public} // anyone, or a type it does not read
	case ShareEmailRecipients:
		var out []actionir.Destination
		for _, addr := range v.List {
			if d := emailDomain(addr); !slices.Contains(out, d) {
				out = append(out, d)
			}
		}
		return out
	case ShareM365LinkScope:
		if v.Str == "organization" {
			return nil
		}
		return []actionir.Destination{public}
	case ShareAWSPolicyPrincipals:
		return policyPrincipals(v.Str)
	case ShareAWSCannedACL:
		if v.Str == "private" {
			return nil
		}
		return []actionir.Destination{public}
	case ShareGitHubVisibility:
		if v.Str == "public" {
			return []actionir.Destination{public}
		}
		return nil
	case ShareGitHubOwner:
		if v.Str == "" {
			return nil
		}
		return []actionir.Destination{{Kind: actionir.ShareGitHubOrg, ID: v.Str}}
	}
	return []actionir.Destination{public}
}

// statementElements are the IAM policy elements a statement may hold.
var statementElements = []string{"Sid", "Effect", "Principal", "NotPrincipal", "Action", "NotAction", "Resource", "NotResource", "Condition"}

// knownElements reports whether every member of a statement is an IAM
// element, spelled as IAM spells it.
func knownElements(s map[string]jsontext.Value) bool {
	for k := range s {
		if !slices.Contains(statementElements, k) {
			return false
		}
	}
	return true
}

// shareDomainRe is a lowercase DNS name with at least one dot, as an
// email_domain owned account is recorded.
var shareDomainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// emailDomain is the email_domain share of an address's domain, lowercased
// (G0 M31 D958); an address without one well-formed domain is public (fail
// closed).
func emailDomain(addr string) actionir.Destination {
	i := strings.LastIndexByte(addr, '@')
	if i < 0 {
		return public
	}
	d := strings.ToLower(addr[i+1:])
	if len(d) > 253 || !shareDomainRe.MatchString(d) {
		return public
	}
	return actionir.Destination{Kind: actionir.ShareEmailDomain, ID: d}
}

// policyPrincipals reads an S3 bucket policy's principals; anything it
// cannot read is public (fail closed).
func policyPrincipals(policy string) []actionir.Destination {
	var doc struct {
		Statement jsontext.Value `json:"Statement"`
	}
	// A missing or null Statement, or one that is not an object or a list,
	// is something this cannot read: public (G0 M30 D1215).
	if err := json.Unmarshal([]byte(policy), &doc); err != nil || len(doc.Statement) == 0 ||
		(doc.Statement.Kind() != '{' && doc.Statement.Kind() != '[') {
		return []actionir.Destination{public}
	}
	var raws []jsontext.Value
	if doc.Statement.Kind() == '{' {
		raws = []jsontext.Value{doc.Statement}
	} else if err := json.Unmarshal(doc.Statement, &raws); err != nil {
		return []actionir.Destination{public}
	}
	var out []actionir.Destination
	add := func(d actionir.Destination) {
		if !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	for _, raw := range raws {
		// A statement is an object of the IAM elements only: any other
		// member, a Principal spelled another way among them, is something
		// this cannot read, so the statement is public (D1215).
		var s map[string]jsontext.Value
		if raw.Kind() != '{' || json.Unmarshal(raw, &s) != nil {
			add(public)
			continue
		}
		if !knownElements(s) {
			add(public)
			continue
		}
		principal, notPrincipal := s["Principal"], s["NotPrincipal"]
		// NotPrincipal grants to everyone but the accounts it names, so a
		// statement with it is public (fail closed, G0 M30 D934).
		if len(notPrincipal) != 0 {
			add(public)
			continue
		}
		if len(principal) == 0 {
			continue // no principal: nothing to share to here
		}
		if principal.Kind() != '{' {
			add(public) // "*", a string that names no account, or not a principal at all
			continue
		}
		var byKind map[string]jsontext.Value
		if err := json.Unmarshal(principal, &byKind); err != nil {
			add(public)
			continue
		}
		for k, raw := range byKind {
			if k != "AWS" {
				add(public) // a principal kind this extractor does not read
				continue
			}
			for _, p := range stringOrList(raw) {
				add(awsPrincipal(p))
			}
		}
	}
	return out
}

// stringOrList reads a policy value that is a string or a list of strings;
// anything else reads as one "*".
func stringOrList(raw jsontext.Value) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil && len(many) > 0 {
		return many
	}
	return []string{"*"}
}

// awsPrincipal maps one Principal/AWS entry to its share.
func awsPrincipal(p string) actionir.Destination {
	if awsAccountIDRe.MatchString(p) {
		return actionir.Destination{Kind: actionir.ShareAWSAccount, ID: p}
	}
	if m := awsARNAccountRe.FindStringSubmatch(p); m != nil {
		return actionir.Destination{Kind: actionir.ShareAWSAccount, ID: m[1]}
	}
	return public
}
