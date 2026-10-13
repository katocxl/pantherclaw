// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app links the org's people to their GitHub accounts (G0 M8,
// HR-207). Independence (HR-170) compares GitHub user ids: whoever
// authored, committed or pushed to a pull request, when linked to a person,
// cannot review it. A GitHub user id links to one person of the org; links
// are made and removed only by a person holding github.identity.manage, and
// audited.
package app

import (
	"context"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors.
var (
	ErrHumanOnly = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person links GitHub identities")
	ErrLinked    = pcerr.New(pcerr.AlreadyExists, "GITHUB_USER_LINKED", "that GitHub user is already linked to a person of the org")
	ErrNoPerson  = pcerr.New(pcerr.FailedPrecondition, "USER_UNKNOWN", "no such person in the org")
	ErrNotFound  = pcerr.New(pcerr.NotFound, "IDENTITY_NOT_FOUND", "no such GitHub identity link")
)

// Identity is one link.
type Identity = dbq.PcGithubIdentity

// Service serves GitHub identities.
type Service struct {
	Pool *db.Pool
}

// manager is the caller, when a person holding github.identity.manage.
func manager(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if err := c.Require(td.PermGitHubIdentityManage, td.OrgPath(c.Org)); err != nil {
		return c, err
	}
	if !c.Human() {
		return c, ErrHumanOnly
	}
	return c, nil
}

// Link links a person to a GitHub user id.
func (s *Service) Link(ctx context.Context, user ids.UUID, login string, githubID int64) (Identity, error) {
	c, err := manager(ctx)
	if err != nil {
		return Identity{}, err
	}
	var out Identity
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = dbq.New(tx).InsertGitHubIdentity(ctx, dbq.InsertGitHubIdentityParams{
			OrgID: c.Org, ID: ids.NewV7(), UserID: user, GithubLogin: login, GithubUserID: githubID, LinkedBy: c.Principal.String(),
		})
		if err != nil {
			return err
		}
		return record(ctx, tx, c, "github.identity_linked", out)
	})
	switch {
	case db.IsUniqueViolation(err):
		return Identity{}, ErrLinked
	case db.IsForeignKeyViolation(err):
		return Identity{}, ErrNoPerson
	}
	return out, err
}

// Unlink removes a link.
func (s *Service) Unlink(ctx context.Context, id ids.UUID) error {
	c, err := manager(ctx)
	if err != nil {
		return err
	}
	return s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		gone, err := dbq.New(tx).DeleteGitHubIdentity(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		return record(ctx, tx, c, "github.identity_unlinked", gone)
	})
}

// List pages through the links (user.read), of one person when user is set.
func (s *Service) List(ctx context.Context, user *ids.UUID, size int32, token string) ([]Identity, string, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, "", err
	}
	if err := c.Require(td.PermUserRead, td.OrgPath(c.Org)); err != nil {
		return nil, "", err
	}
	pr, err := page.Parse(size, token)
	if err != nil {
		return nil, "", err
	}
	var out []Identity
	var next string
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListGitHubIdentities(ctx, dbq.ListGitHubIdentitiesParams{OrgID: c.Org, UserID: user, AfterID: pr.After, MaxRows: pr.Limit()})
		if err != nil {
			return err
		}
		out, next = page.Finish(pr, rows, func(r Identity) ids.UUID { return r.ID })
		return nil
	}, db.ReadOnly())
	return out, next, err
}

func record(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name string, i Identity) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "user", ID: i.UserID.String()},
		Details: map[string]string{"github_login": i.GithubLogin, "github_user_id": strconv.FormatInt(i.GithubUserID, 10)},
	})
	return err
}
