// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app links the org's people to their GitHub accounts (G0 M8,
// HR-207). Independence (HR-170) compares GitHub user ids: whoever
// authored, committed or pushed to a pull request, when linked to a person,
// cannot review it. A GitHub user id links to one person of the org.
//
// A person links their own account only by proving it: they sign in to
// GitHub and the server reads, from GitHub, the account the sign-in's user
// access token belongs to (founder decision 2026-10-13, P2f). Nobody else
// can link it, and they remove it the same way; a person holding
// github.identity.manage can only unlink other people. Every change is
// audited and notified.
package app

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
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
	ErrNotFound  = pcerr.New(pcerr.NotFound, "IDENTITY_NOT_FOUND", "no such GitHub identity link")
	// ErrOwnLink: a person's own link changes only through GitHub sign-in.
	ErrOwnLink = pcerr.New(pcerr.PermissionDenied, "OWN_GITHUB_LINK",
		"your own GitHub link changes only through GitHub sign-in: pclaw github link, or pclaw github unlink")
	// ErrNotYours: the account signed in to is not linked to the caller.
	ErrNotYours = pcerr.New(pcerr.FailedPrecondition, "GITHUB_LINK_NOT_YOURS", "the GitHub account you signed in to is not linked to you")
	// ErrProof: GitHub did not accept the sign-in's token.
	ErrProof = pcerr.New(pcerr.InvalidArgument, "GITHUB_SIGN_IN_REFUSED", "GitHub did not accept the sign-in")
	// ErrNoSignIn: the server cannot ask GitHub who signed in.
	ErrNoSignIn = pcerr.New(pcerr.Unavailable, "GITHUB_SIGN_IN_UNAVAILABLE", "GitHub sign-in is not configured on this server")
	// ErrGitHubUnavailable: GitHub did not say who signed in.
	ErrGitHubUnavailable = pcerr.New(pcerr.Unavailable, "GITHUB_UNAVAILABLE", "GitHub could not be asked who signed in; try again")
)

// Identity is one link.
type Identity = dbq.PcGithubIdentity

// GitHubUser is the GitHub account a sign-in's token belongs to.
type GitHubUser struct {
	ID    int64
	Login string
}

// Verifier asks GitHub which account a user access token belongs to: the
// proof that whoever sent the token signed in as that account. It never
// keeps the token. An error wrapping ErrProof means GitHub refused it.
type Verifier interface {
	User(ctx context.Context, token string) (GitHubUser, error)
}

// Notifier enqueues a notification in the caller's transaction.
type Notifier interface {
	Enqueue(ctx context.Context, tx db.TenantTx, m napp.Message) (napp.Enqueued, error)
}

// Service serves GitHub identities.
type Service struct {
	Pool *db.Pool
	// Verifier reads the account of a GitHub sign-in; nil refuses proofs.
	Verifier Verifier
	// Notify sends the notice of each link change; nil sends none.
	Notify Notifier
	// SignIn is where pclaw sends people to sign in to GitHub.
	SignIn SignIn
}

// SignIn is the GitHub App's device flow: its client id and GitHub's web
// origin. An empty client id means GitHub sign-in is off.
type SignIn struct {
	ClientID, WebURL string
}

// SignInConfig returns where to sign in to GitHub to link an account, to a
// person who may (github.identity.prove).
func (s *Service) SignInConfig(ctx context.Context) (SignIn, error) {
	if _, err := person(ctx, td.PermGitHubIdentityProve); err != nil {
		return SignIn{}, err
	}
	if s.SignIn.ClientID == "" || s.Verifier == nil {
		return SignIn{}, ErrNoSignIn
	}
	return s.SignIn, nil
}

// person is the caller, when a person holding perm.
func person(ctx context.Context, perm td.Permission) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if err := c.Require(perm, td.OrgPath(c.Org)); err != nil {
		return c, err
	}
	if !c.Human() {
		return c, ErrHumanOnly
	}
	return c, nil
}

// Prove links the caller's own GitHub account, or with unlink removes that
// link, once GitHub has said which account token belongs to (P2f). Proving
// an account already linked to the caller renews the link; one linked to
// someone else is ErrLinked.
func (s *Service) Prove(ctx context.Context, token string, unlink bool) (Identity, error) {
	c, err := person(ctx, td.PermGitHubIdentityProve)
	if err != nil {
		return Identity{}, err
	}
	if s.Verifier == nil {
		return Identity{}, ErrNoSignIn
	}
	u, err := s.Verifier.User(ctx, token)
	if err != nil {
		return Identity{}, err
	}
	var out Identity
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		existing, err := q.GitHubIdentityByGitHubUser(ctx, c.Org, u.ID)
		found := err == nil
		switch {
		case err != nil && !db.IsNoRows(err):
			return err
		case found && existing.UserID != c.Principal.ID:
			if unlink {
				return ErrNotYours
			}
			return ErrLinked
		case unlink && !found:
			return ErrNotYours
		case found:
			if _, err := q.DeleteGitHubIdentity(ctx, c.Org, existing.ID); err != nil {
				return err
			}
			if unlink {
				out = existing
				return s.changed(ctx, tx, c, "github.identity_unlinked", existing)
			}
		}
		out, err = q.InsertGitHubIdentity(ctx, dbq.InsertGitHubIdentityParams{
			OrgID: c.Org, ID: ids.NewV7(), UserID: c.Principal.ID, GithubLogin: u.Login, GithubUserID: u.ID, LinkedBy: c.Principal.String(),
		})
		if err != nil {
			return err
		}
		if err := q.InsertGitHubIdentityHistory(ctx, c.Org, u.ID, c.Principal.ID); err != nil {
			return err
		}
		return s.changed(ctx, tx, c, "github.identity_linked", out)
	})
	if db.IsUniqueViolation(err) {
		err = ErrLinked
	}
	if errors.Is(err, ErrLinked) || errors.Is(err, ErrNotYours) {
		return Identity{}, s.refused(ctx, c, u, unlink, err)
	}
	return out, err
}

// refused audits a sign-in that proved a GitHub account the caller may not
// link or unlink, because it is linked to someone else or to no one (P2f,
// review 2026-10-13): someone trying to take an account's link is worth a
// security admin's look. It returns why.
func (s *Service) refused(ctx context.Context, c tenancy.Caller, u GitHubUser, unlink bool, why error) error {
	err := s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := audit.Record(ctx, tx, audit.Event{
			Name: "github.identity_link_refused", Actor: c.Actor(), Outcome: audit.Denied,
			Object: &audit.Object{Type: "user", ID: c.Principal.ID.String()},
			Details: map[string]string{
				"github_login": u.Login, "github_user_id": strconv.FormatInt(u.ID, 10), "unlink": strconv.FormatBool(unlink),
				"reason": pcerr.ReasonOf(why),
			},
		})
		return err
	})
	if err != nil {
		return errors.Join(why, err)
	}
	return why
}

// Unlink removes another person's link (github.identity.manage). Nobody
// removes their own link here: that takes GitHub sign-in (Prove).
func (s *Service) Unlink(ctx context.Context, id ids.UUID) error {
	c, err := person(ctx, td.PermGitHubIdentityManage)
	if err != nil {
		return err
	}
	return s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		link, err := q.GitHubIdentity(ctx, c.Org, id)
		switch {
		case db.IsNoRows(err):
			return ErrNotFound
		case err != nil:
			return err
		case link.UserID == c.Principal.ID:
			return ErrOwnLink
		}
		if _, err := q.DeleteGitHubIdentity(ctx, c.Org, id); err != nil {
			return err
		}
		return s.changed(ctx, tx, c, "github.identity_unlinked", link)
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

// changed audits a link change (name) and notifies it
// (security.github_identity_linked or _unlinked): a link decides who can
// review whose pull requests.
func (s *Service) changed(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name string, i Identity) error {
	details := map[string]string{"github_login": i.GithubLogin, "github_user_id": strconv.FormatInt(i.GithubUserID, 10)}
	if _, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "user", ID: i.UserID.String()}, Details: details,
	}); err != nil {
		return err
	}
	if s.Notify == nil {
		return nil
	}
	_, err := s.Notify.Enqueue(ctx, tx, napp.Message{Org: c.Org, Type: "security." + strings.ReplaceAll(name, ".", "_"), Params: map[string]string{
		"user": i.UserID.String(), "github_login": i.GithubLogin, "github_user_id": details["github_user_id"], "by": c.Principal.String(),
	}})
	return err
}
