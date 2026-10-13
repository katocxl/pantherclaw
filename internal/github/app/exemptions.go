// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Exemptions (founder decision 2026-10-13, HR-207): an independent approval
// of a pull request is refused while a person it lists is linked to nobody
// in the org (GITHUB_PEOPLE_NOT_LINKED). A GitHub account that is not a
// person, a bot or a machine user, never links; an identity manager
// registers it here instead. Every change is audited and notified, since
// exempting a person's account would let them approve their own change.

// MaxExemptions bounds an org's exemptions.
const MaxExemptions = 500

// Exemption is one exempted account.
type Exemption = dbq.PcGithubExemption

// Exemption errors.
var (
	ErrExempted     = pcerr.New(pcerr.AlreadyExists, "GITHUB_ACCOUNT_EXEMPTED", "that GitHub account is exempted already")
	ErrNotExempted  = pcerr.New(pcerr.NotFound, "GITHUB_EXEMPTION_NOT_FOUND", "that GitHub account is not exempted")
	ErrExemptionBad = pcerr.New(pcerr.InvalidArgument, "GITHUB_EXEMPTION_INVALID",
		"an exemption needs the account's GitHub user id, its login and a reason of 1..256 characters")
	ErrTooManyExemptions = pcerr.New(pcerr.ResourceExhausted, "GITHUB_EXEMPTIONS_FULL", "the org has 500 exemptions; remove one first")
)

// exemptLoginRe is a GitHub login, or a GitHub App's bot login (name[bot]).
var exemptLoginRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}(\[bot\])?$`)

// Exempt registers a GitHub account as not a person (github.identity.manage,
// a person only).
func (s *Service) Exempt(ctx context.Context, githubID int64, login, reason string) (Exemption, error) {
	c, err := person(ctx, td.PermGitHubIdentityManage)
	if err != nil {
		return Exemption{}, err
	}
	reason = strings.TrimSpace(reason)
	if githubID <= 0 || !exemptLoginRe.MatchString(login) || reason == "" || len(reason) > 256 ||
		strings.ContainsFunc(reason, unicode.IsControl) {
		return Exemption{}, ErrExemptionBad
	}
	var out Exemption
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		all, err := q.ListGitHubExemptions(ctx, c.Org, MaxExemptions)
		if err != nil {
			return err
		}
		if len(all) >= MaxExemptions {
			return ErrTooManyExemptions
		}
		out, err = q.InsertGitHubExemption(ctx, dbq.InsertGitHubExemptionParams{
			OrgID: c.Org, GithubUserID: githubID, GithubLogin: login, Reason: reason, CreatedBy: c.Principal.String(),
		})
		if err != nil {
			return err
		}
		return s.exemptionChanged(ctx, tx, c, "github.account_exempted", out)
	})
	if db.IsUniqueViolation(err) {
		return Exemption{}, ErrExempted
	}
	return out, err
}

// RemoveExemption removes an account's exemption (github.identity.manage, a
// person only): unlinked, it stops approvals again.
func (s *Service) RemoveExemption(ctx context.Context, githubID int64) error {
	c, err := person(ctx, td.PermGitHubIdentityManage)
	if err != nil {
		return err
	}
	return s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		gone, err := dbq.New(tx).DeleteGitHubExemption(ctx, c.Org, githubID)
		if db.IsNoRows(err) {
			return ErrNotExempted
		} else if err != nil {
			return err
		}
		return s.exemptionChanged(ctx, tx, c, "github.exemption_removed", gone)
	})
}

// Exemptions lists the org's exemptions (user.read).
func (s *Service) Exemptions(ctx context.Context) ([]Exemption, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.Require(td.PermUserRead, td.OrgPath(c.Org)); err != nil {
		return nil, err
	}
	var out []Exemption
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = dbq.New(tx).ListGitHubExemptions(ctx, c.Org, MaxExemptions)
		return err
	}, db.ReadOnly())
	return out, err
}

// exemptionChanged audits an exemption change and notifies the security
// channels in the caller's transaction.
func (s *Service) exemptionChanged(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name string, e Exemption) error {
	id := strconv.FormatInt(e.GithubUserID, 10)
	if _, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "github_account", ID: id},
		Details: map[string]string{"github_login": e.GithubLogin, "reason": e.Reason},
	}); err != nil {
		return err
	}
	if s.Notify == nil {
		return nil
	}
	_, err := s.Notify.Enqueue(ctx, tx, napp.Message{Org: c.Org, Type: "security." + strings.ReplaceAll(name, ".", "_"), Params: map[string]string{
		"github_login": e.GithubLogin, "github_user_id": id, "reason": e.Reason, "by": c.Principal.String(),
	}})
	return err
}
