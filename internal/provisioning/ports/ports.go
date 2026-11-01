// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package ports is the contract between the core's provisioning tables and
// the SCIM and SAML protocol code, which lives in the private enterprise
// package (G0 M26 D405, H7). The core owns every rule a protocol must not be
// able to change: which issuer a token provisions, the last admin, which
// roles a group may carry, who may sign an assertion. The protocol code
// parses, verifies and answers.
//
// Like internal/extension, this contract uses string ids, so it stays stable
// as the core's id types change.
package ports

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Errors of Directory and SignIn. A protocol maps them to its own answers;
// each is matched with errors.Is.
var (
	// ErrUnauthenticated: the bearer token is unknown, revoked or expired.
	// It says no more, so it is no probe of which.
	ErrUnauthenticated = errors.New("provisioning: unauthenticated")
	// ErrNotFound: nothing by that id for this token's issuer.
	ErrNotFound = errors.New("provisioning: not found")
	// ErrConflict: the identity, group name or external id is taken.
	ErrConflict = errors.New("provisioning: conflict")
	// ErrInvalid: the input breaks a bound of the tables.
	ErrInvalid = errors.New("provisioning: invalid")
	// ErrImmutable: the change would move a user to another subject.
	ErrImmutable = errors.New("provisioning: immutable")
	// ErrEdition: this organization's edition does not include the change.
	ErrEdition = errors.New("provisioning: edition required")
	// ErrPlanLimit: the plan allows no more members.
	ErrPlanLimit = errors.New("provisioning: plan limit")
	// ErrLastAdmin: the change would leave no active Org Admin with a way
	// to sign in (HR-484). The provider's sync can never get past it: a
	// person has to act in PantherClaw.
	ErrLastAdmin = errors.New("provisioning: last admin")
	// ErrDisabledHere: a person disabled this user in PantherClaw; a sync
	// does not overrule them.
	ErrDisabledHere = errors.New("provisioning: disabled in PantherClaw")
	// ErrReplayed: the assertion id was already accepted.
	ErrReplayed = errors.New("provisioning: replayed")
	// ErrSignInUnavailable: the connection is not ACTIVE, or the sign-in
	// request is unknown, used or expired.
	ErrSignInUnavailable = errors.New("provisioning: sign-in unavailable")
)

// Token is an authenticated SCIM token: what it provisions, nothing more.
type Token struct {
	ID, OrgID string
	// Issuer is the one issuer whose users and groups this token sees.
	Issuer string
	// SubjectAttribute is "userName" or "externalId": the attribute that
	// holds the identity's subject at sign-in.
	SubjectAttribute string
}

// User is a user as SCIM sees it.
type User struct {
	ID, UserName, ExternalID, Email, DisplayName string
	Active                                       bool
	CreatedAt, UpdatedAt                         time.Time
}

// UserInput creates a user.
type UserInput struct {
	UserName, ExternalID, Email, DisplayName string
	Active                                   bool
}

// UserChange changes a user; a nil field stays as it is.
type UserChange struct {
	UserName, ExternalID, Email, DisplayName *string
	Active                                   *bool
}

// Page is one page of a list. StartIndex is 1-based (RFC 7644 3.4.2.4) and
// Count at most what the core allows; the core clamps both.
type Page struct{ StartIndex, Count int }

// UserFilter narrows a list to one exact value; empty means every user.
type UserFilter struct{ UserName, ExternalID string }

// Users is one page of users and how many match in all.
type Users struct {
	Total int
	Items []User
}

// Group is a group as SCIM sees it.
type Group struct {
	ID, DisplayName, ExternalID string
	// Members are user ids.
	Members              []string
	CreatedAt, UpdatedAt time.Time
}

// GroupInput creates or replaces a group.
type GroupInput struct {
	DisplayName, ExternalID string
	Members                 []string
}

// GroupChange changes a group; a nil field stays as it is. Members to add
// and remove are applied together.
type GroupChange struct {
	DisplayName, ExternalID *string
	AddMembers, RemoveUsers []string
}

// GroupFilter narrows a list to one exact value; empty means every group.
type GroupFilter struct{ DisplayName, ExternalID string }

// Groups is one page of groups and how many match in all.
type Groups struct {
	Total int
	Items []Group
}

// Directory is the provisioning side of the tables. Every call but
// Authenticate takes the Token it returned and stays inside that token's
// org and issuer. Membership changes re-derive the role bindings of the
// users they touch, in the same transaction.
type Directory interface {
	// Authenticate resolves a bearer token and records its use.
	Authenticate(ctx context.Context, bearer string) (Token, error)

	ListUsers(ctx context.Context, t Token, f UserFilter, p Page) (Users, error)
	GetUser(ctx context.Context, t Token, id string) (User, error)
	CreateUser(ctx context.Context, t Token, in UserInput) (User, error)
	// ReplaceUser sets every field of UserInput (PUT).
	ReplaceUser(ctx context.Context, t Token, id string, in UserInput) (User, error)
	// ChangeUser applies a partial change (PATCH). Active false deprovisions:
	// it ends the user's sessions and API keys, or fails with ErrLastAdmin.
	ChangeUser(ctx context.Context, t Token, id string, c UserChange) (User, error)
	// DeleteUser deprovisions like ChangeUser, drops the user's group
	// memberships and hides the user from this directory. The record of who
	// they were and what they did stays.
	DeleteUser(ctx context.Context, t Token, id string) error

	ListGroups(ctx context.Context, t Token, f GroupFilter, p Page) (Groups, error)
	GetGroup(ctx context.Context, t Token, id string) (Group, error)
	CreateGroup(ctx context.Context, t Token, in GroupInput) (Group, error)
	ReplaceGroup(ctx context.Context, t Token, id string, in GroupInput) (Group, error)
	ChangeGroup(ctx context.Context, t Token, id string, c GroupChange) (Group, error)
	DeleteGroup(ctx context.Context, t Token, id string) error
}

// Connection is an ACTIVE SAML connection, as far as the protocol needs it.
type Connection struct {
	ID, OrgID, Name string
	// IdPEntityID must equal the assertion's Issuer.
	IdPEntityID string
	// SSOURL is where the browser goes with the AuthnRequest.
	SSOURL string
	// Certificates are the DER certificates that may sign an assertion:
	// these and no others, never one carried in the message.
	Certificates [][]byte
}

// Started is a stored SP-initiated sign-in.
type Started struct {
	// RelayState goes to the provider and comes back with the response.
	RelayState string
	// Binding goes in a cookie on this browser; ConsumeSignIn needs it back.
	Binding string
	// Expires is when the sign-in lapses.
	Expires time.Time
}

// Pending is a consumed sign-in request.
type Pending struct {
	// RequestID must equal the response's InResponseTo.
	RequestID string
	// Next is the validated page to open after sign-in.
	Next string
}

// Verified is an assertion the protocol code has fully checked.
type Verified struct {
	OrgID, ConnectionID string
	// Subject is the NameID.
	Subject, Email, DisplayName string
	// Next comes from ConsumeSignIn.
	Next string
	// AuthenticatedAt is the assertion's AuthnInstant; zero when absent.
	AuthenticatedAt time.Time
}

// SignIn is the sign-in side of the tables. A connection signs in existing
// users only: SCIM or an invitation made them.
type SignIn interface {
	// Connection returns an ACTIVE connection, or ErrSignInUnavailable.
	Connection(ctx context.Context, orgID, connectionID string) (Connection, error)
	// StartSignIn stores a sign-in for AuthnRequest requestID, single use and
	// bound to this browser. A next the core does not accept is refused.
	StartSignIn(ctx context.Context, orgID, connectionID, requestID, next, clientIP string) (Started, error)
	// ConsumeSignIn takes a stored sign-in once, whatever the outcome that
	// follows: ErrSignInUnavailable when it is unknown, used, expired, of
	// another connection or of another browser.
	ConsumeSignIn(ctx context.Context, orgID, connectionID, relayState, binding string) (Pending, error)
	// RecordAssertion accepts an assertion id once until notOnOrAfter:
	// ErrReplayed the second time.
	RecordAssertion(ctx context.Context, orgID, connectionID, assertionID string, notOnOrAfter time.Time) error
	// FinishSignIn answers the browser: it opens a session for the verified
	// identity with the core's cookie and page, or the core's refusal when
	// the identity is no enabled user of the org. Only the core sets a
	// session cookie.
	FinishSignIn(w http.ResponseWriter, r *http.Request, v Verified)
}
