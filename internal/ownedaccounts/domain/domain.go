// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the kinds and value formats of the org's owned
// accounts (G0 M30 D933, D935; HR-707, HR-708). It is pure.
package domain

import (
	"regexp"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Kind is a kind of owned account.
type Kind string

// Kinds (pc.owned_accounts.kind).
const (
	KindAWSAccount  Kind = "aws_account"
	KindGitHubOrg   Kind = "github_org"
	KindEmailDomain Kind = "email_domain"
	KindGCPProject  Kind = "gcp_project"
	KindAzureTenant Kind = "azure_tenant"
)

// Kinds lists every kind in a stable order.
func Kinds() []Kind {
	return []Kind{KindAWSAccount, KindGitHubOrg, KindEmailDomain, KindGCPProject, KindAzureTenant}
}

// Valid reports whether k is a kind.
func (k Kind) Valid() bool { return slices.Contains(Kinds(), k) }

var (
	awsAccountRe = regexp.MustCompile(`^\d{12}$`)
	githubOrgRe  = regexp.MustCompile(`^[A-Za-z0-9-]{1,39}$`)
	gcpProjectRe = regexp.MustCompile(`^[a-z][a-z0-9-]{5,29}$`)
	// A lower-case hostname: dot-separated labels of letters, digits and
	// inner hyphens, at least two labels.
	domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// ValidValue reports whether v is a well-formed value of kind k (D933).
func ValidValue(k Kind, v string) bool {
	if v == "" || len(v) > 253 {
		return false
	}
	switch k {
	case KindAWSAccount:
		return awsAccountRe.MatchString(v)
	case KindGitHubOrg:
		return githubOrgRe.MatchString(v)
	case KindEmailDomain:
		return domainRe.MatchString(v) && strings.Contains(v, ".")
	case KindGCPProject:
		return gcpProjectRe.MatchString(v)
	case KindAzureTenant:
		u, err := ids.ParseUUID(v)
		return err == nil && u.String() == v
	}
	return false
}
