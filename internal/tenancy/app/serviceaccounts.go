// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/assertion"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors of the service-account use cases.
var (
	ErrNameTaken      = pcerr.New(pcerr.AlreadyExists, "NAME_TAKEN", "name already in use")
	ErrKeyNotFound    = pcerr.New(pcerr.NotFound, "KEY_NOT_FOUND", "key not found")
	ErrKeyExists      = pcerr.New(pcerr.AlreadyExists, "KEY_EXISTS", "this public key is already registered")
	ErrKeyClosed      = pcerr.New(pcerr.FailedPrecondition, "KEY_REVOKED", "key is already revoked")
	ErrAPIKeyNotFound = pcerr.New(pcerr.NotFound, "API_KEY_NOT_FOUND", "API key not found")
	ErrAPIKeyClosed   = pcerr.New(pcerr.FailedPrecondition, "API_KEY_REVOKED", "API key is already revoked")
	ErrInvalidKey     = pcerr.New(pcerr.InvalidArgument, "INVALID_PUBLIC_KEY",
		"public_jwk must be a public Ed25519 key for EdDSA or a P-256 key for ES256")
)

// Validity of keys and API keys (SB-2: at most a year, 90 days by default).
const (
	DefaultKeyTTL = 90 * 24 * time.Hour
	MaxKeyTTL     = 365 * 24 * time.Hour
)

// ServiceAccounts implements the ServiceAccountService use cases.
type ServiceAccounts struct {
	pool *db.Pool
	env  credential.Env
}

// NewServiceAccounts returns the use cases; env is the environment of the
// API keys this deployment mints.
func NewServiceAccounts(pool *db.Pool, env credential.Env) *ServiceAccounts {
	return &ServiceAccounts{pool: pool, env: env}
}

// ServiceAccount is a non-human principal.
type ServiceAccount struct {
	ID                   td.ServiceAccountID
	Name, Description    string
	State                td.AccountState
	ClientID             string
	CreatedBy            string
	CreatedAt, UpdatedAt time.Time
}

// CredentialState is the effective state of a key or API key.
type CredentialState string

// Credential states (EXPIRED is an active credential past its expiry).
const (
	CredentialActive  CredentialState = "ACTIVE"
	CredentialRevoked CredentialState = "REVOKED"
	CredentialExpired CredentialState = "EXPIRED"
)

// ServiceAccountKey is a registered public key.
type ServiceAccountKey struct {
	ID                   ids.UUID
	ServiceAccount       td.ServiceAccountID
	KID                  string
	Alg                  assertion.Alg
	PublicJWK            string
	State                CredentialState
	CreatedBy            string
	CreatedAt, ExpiresAt time.Time
	RevokedAt            *time.Time
}

// APIKey is a scoped API key (never its secret).
type APIKey struct {
	ID                   ids.UUID
	ServiceAccount       td.ServiceAccountID
	Name, Hint           string
	Scopes               []td.Permission
	State                CredentialState
	CreatedBy            string
	CreatedAt, ExpiresAt time.Time
	RevokedAt, LastUsed  *time.Time
}

func serviceAccountView(org ids.OrgID, r dbq.PcServiceAccount) ServiceAccount {
	id := idOf[td.ServiceAccount](r.ID)
	return ServiceAccount{
		ID: id, Name: r.Name, Description: r.Description, State: td.AccountState(r.State),
		ClientID: credential.FormatClientID(org, id), CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

func keyView(r dbq.ListServiceAccountKeysRow) ServiceAccountKey {
	return ServiceAccountKey{
		ID: r.ID, ServiceAccount: idOf[td.ServiceAccount](r.ServiceAccountID), KID: r.Kid, Alg: assertion.Alg(r.Alg),
		PublicJWK: string(r.PublicJwk), State: CredentialState(r.EffectiveState), CreatedBy: r.CreatedBy,
		CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, RevokedAt: r.RevokedAt,
	}
}

func apiKeyView(r dbq.ListAPIKeysRow) APIKey {
	scopes := make([]td.Permission, len(r.Scopes))
	for i, s := range r.Scopes {
		scopes[i] = td.Permission(s)
	}
	return APIKey{
		ID: r.ID, ServiceAccount: idOf[td.ServiceAccount](r.ServiceAccountID), Name: r.Name, Hint: r.Hint, Scopes: scopes,
		State: CredentialState(r.EffectiveState), CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt,
		RevokedAt: r.RevokedAt, LastUsed: r.LastUsedAt,
	}
}

func ttlDays(ttl time.Duration) (int32, error) {
	if ttl == 0 {
		ttl = DefaultKeyTTL
	}
	if ttl < 24*time.Hour || ttl > MaxKeyTTL {
		return 0, ErrInvalidTTL
	}
	return int32(ttl / (24 * time.Hour)), nil
}

// activeAccount locks a service account for share and requires it active.
func activeAccount(ctx context.Context, q *dbq.Queries, org ids.OrgID, id td.ServiceAccountID) (dbq.PcServiceAccount, error) {
	sa, err := q.ShareServiceAccount(ctx, org, id.UUID())
	if err != nil {
		return sa, notFound(err, ErrServiceAccountNotFound)
	}
	if td.AccountState(sa.State) != td.Enabled {
		return sa, ErrPrincipalDisabled
	}
	return sa, nil
}

// Create creates a service account.
func (s *ServiceAccounts) Create(ctx context.Context, name, description string) (ServiceAccount, error) {
	if err := td.CheckSlug("name", name); err != nil {
		return ServiceAccount{}, err
	}
	if strings.HasPrefix(name, AutomationAccountPrefix) {
		return ServiceAccount{}, ErrAutomationName
	}
	description, err := td.CheckDescription(description)
	if err != nil {
		return ServiceAccount{}, err
	}
	var out ServiceAccount
	err = inOrg(ctx, s.pool, func(ctx context.Context, c Caller, q *dbq.Queries, tx db.TenantTx) error {
		if err := c.Require(td.PermServiceAccountManage, td.OrgPath(c.Org)); err != nil {
			return err
		}
		r, err := q.InsertServiceAccount(ctx, dbq.InsertServiceAccountParams{
			OrgID: c.Org, ID: ids.NewV7(), Name: name, Description: description, CreatedBy: c.Principal.String(),
		})
		if db.IsUniqueViolation(err) {
			return ErrNameTaken
		} else if err != nil {
			return err
		}
		out = serviceAccountView(c.Org, r)
		return record(ctx, tx, c, "access.service_account_created", "service_account", r.ID, map[string]string{"name": name})
	})
	return out, err
}

// Get returns one service account.
func (s *ServiceAccounts) Get(ctx context.Context, id td.ServiceAccountID) (ServiceAccount, error) {
	var out ServiceAccount
	err := inOrg(ctx, s.pool, func(ctx context.Context, c Caller, q *dbq.Queries, _ db.TenantTx) error {
		if err := c.Require(td.PermServiceAccountRead, td.OrgPath(c.Org)); err != nil {
			return err
		}
		r, err := q.GetServiceAccount(ctx, c.Org, id.UUID())
		if err != nil {
			return notFound(err, ErrServiceAccountNotFound)
		}
		out = serviceAccountView(c.Org, r)
		return nil
	}, db.ReadOnly())
	return out, err
}

// List lists service accounts.
func (s *ServiceAccounts) List(ctx context.Context, pr page.Request) (Page[ServiceAccount], error) {
	var out Page[ServiceAccount]
	err := inOrg(ctx, s.pool, func(ctx context.Context, c Caller, q *dbq.Queries, _ db.TenantTx) error {
		if err := c.Require(td.PermServiceAccountRead, td.OrgPath(c.Org)); err != nil {
			return err
		}
		rows, err := q.ListServiceAccounts(ctx, c.Org, pr.After, pr.Limit())
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(pr, rows, func(r dbq.PcServiceAccount) ids.UUID { return r.ID })
		for _, r := range rows {
			out.Items = append(out.Items, serviceAccountView(c.Org, r))
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// Update changes the description.
func (s *ServiceAccounts) Update(ctx context.Context, id td.ServiceAccountID, description *string) (ServiceAccount, error) {
	_, description, err := checkText(nil, description)
	if err != nil {
		return ServiceAccount{}, err
	}
	var out ServiceAccount
	err = inOrg(ctx, s.pool, func(ctx context.Context, c Caller, q *dbq.Queries, tx db.TenantTx) error {
		if err := c.Require(td.PermServiceAccountManage, td.OrgPath(c.Org)); err != nil {
			return err
		}
		if err := notAutomationIdentity(ctx, q, c.Org, id.UUID()); err != nil {
			return err
		}
		r, err := q.UpdateServiceAccount(ctx, description, c.Org, id.UUID())
		if err != nil {
			return notFound(err, ErrServiceAccountNotFound)
		}
		out = serviceAccountView(c.Org, r)
		return record(ctx, tx, c, "access.service_account_updated", "service_account", r.ID, changed(nil, description))
	})
	return out, err
}

// SetState disables or re-enables a service account. Its tokens and API
// keys are checked against this state on every request.
func (s *ServiceAccounts) SetState(ctx context.Context, id td.ServiceAccountID, state td.AccountState) (ServiceAccount, error) {
	if state != td.Enabled && state != td.Disabled {
		return ServiceAccount{}, pcerr.New(pcerr.InvalidArgument, "INVALID_STATE", "state must be ACTIVE or DISABLED")
	}
	var out ServiceAccount
	err := inOrg(ctx, s.pool, func(ctx context.Context, c Caller, q *dbq.Queries, tx db.TenantTx) error {
		if err := c.Require(td.PermServiceAccountManage, td.OrgPath(c.Org)); err != nil {
			return err
		}
		if err := notAutomationIdentity(ctx, q, c.Org, id.UUID()); err != nil {
			return err
		}
		r, err := q.SetServiceAccountState(ctx, string(state), c.Org, id.UUID())
		if err != nil {
			return notFound(err, ErrServiceAccountNotFound)
		}
		out = serviceAccountView(c.Org, r)
		event := "access.service_account_enabled"
		if state == td.Disabled {
			event = "access.service_account_disabled"
		}
		return record(ctx, tx, c, event, "service_account", r.ID, nil)
	})
	return out, err
}

// AddKey registers a public key for client assertions, pinned to alg
// (HR-095). The private key never reaches PantherClaw.
func (s *ServiceAccounts) AddKey(ctx context.Context, id td.ServiceAccountID, alg assertion.Alg, jwk string, ttl time.Duration) (ServiceAccountKey, error) {
	pk, err := assertion.ParsePublicJWK(alg, []byte(jwk))
	if err != nil {
		return ServiceAccountKey{}, ErrInvalidKey
	}
	days, err := ttlDays(ttl)
	if err != nil {
		return ServiceAccountKey{}, err
	}
	var out ServiceAccountKey
	err = inOrg(ctx, s.pool, func(ctx context.Context, c Caller, q *dbq.Queries, tx db.TenantTx) error {
		if err := c.Require(td.PermServiceAccountManage, td.OrgPath(c.Org)); err != nil {
			return err
		}
		sa, err := activeAccount(ctx, q, c.Org, id)
		if err != nil {
			return err
		}
		if err := notAutomationIdentity(ctx, q, c.Org, sa.ID); err != nil {
			return err
		}
		if err := noEscalation(ctx, q, c, sa.ID, nil); err != nil {
			return err
		}
		r, err := q.InsertServiceAccountKey(ctx, dbq.InsertServiceAccountKeyParams{
			OrgID: c.Org, ID: ids.NewV7(), ServiceAccountID: sa.ID, Kid: pk.Thumbprint, Alg: string(pk.Alg),
			PublicJwk: pk.Canonical, CreatedBy: c.Principal.String(), TtlDays: days,
		})
		if db.IsUniqueViolation(err) {
			return ErrKeyExists
		} else if err != nil {
			return err
		}
		out = keyView(dbq.ListServiceAccountKeysRow(r))
		return record(ctx, tx, c, "access.service_account_key_added", "service_account", sa.ID,
			map[string]string{"key": r.ID.String(), "kid": r.Kid, "alg": r.Alg})
	})
	return out, err
}

// ListKeys lists a service account's keys.
func (s *ServiceAccounts) ListKeys(ctx context.Context, id td.ServiceAccountID, pr page.Request) (Page[ServiceAccountKey], error) {
	var out Page[ServiceAccountKey]
	err := inOrg(ctx, s.pool, func(ctx context.Context, c Caller, q *dbq.Queries, _ db.TenantTx) error {
		if err := c.Require(td.PermServiceAccountRead, td.OrgPath(c.Org)); err != nil {
			return err
		}
		if _, err := q.GetServiceAccount(ctx, c.Org, id.UUID()); err != nil {
			return notFound(err, ErrServiceAccountNotFound)
		}
		rows, err := q.ListServiceAccountKeys(ctx, dbq.ListServiceAccountKeysParams{
			OrgID: c.Org, ServiceAccountID: id.UUID(), After: pr.After, PageLimit: pr.Limit(),
		})
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(pr, rows, func(r dbq.ListServiceAccountKeysRow) ids.UUID { return r.ID })
		for _, r := range rows {
			out.Items = append(out.Items, keyView(r))
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// RevokeKey revokes a key; tokens obtained with it stop working at the next
// request.
func (s *ServiceAccounts) RevokeKey(ctx context.Context, id td.ServiceAccountID, key ids.UUID) (ServiceAccountKey, error) {
	var out ServiceAccountKey
	err := inOrg(ctx, s.pool, func(ctx context.Context, c Caller, q *dbq.Queries, tx db.TenantTx) error {
		if err := c.Require(td.PermServiceAccountManage, td.OrgPath(c.Org)); err != nil {
			return err
		}
		r, err := q.RevokeServiceAccountKey(ctx, c.Org, id.UUID(), key)
		if db.IsNoRows(err) {
			if ok, err := q.ServiceAccountKeyExists(ctx, c.Org, id.UUID(), key); err != nil {
				return err
			} else if ok {
				return ErrKeyClosed
			}
			return ErrKeyNotFound
		} else if err != nil {
			return err
		}
		out = keyView(dbq.ListServiceAccountKeysRow(r))
		return record(ctx, tx, c, "access.service_account_key_revoked", "service_account", r.ServiceAccountID,
			map[string]string{"key": r.ID.String(), "kid": r.Kid})
	})
	return out, err
}

// CreateAPIKey creates a scoped pck_ API key for an active service account.
// The secret is returned once; only its SHA-256 is stored. Human-only
// permissions are refused as scopes, and the key can never use more than
// the account's roles allow.
func (s *ServiceAccounts) CreateAPIKey(ctx context.Context, id td.ServiceAccountID, name string, scopes []td.Permission, ttl time.Duration) (APIKey, credential.Token, error) {
	if err := td.CheckSlug("name", name); err != nil {
		return APIKey{}, credential.Token{}, err
	}
	if err := td.CheckAPIKeyScopes(scopes); err != nil {
		return APIKey{}, credential.Token{}, err
	}
	days, err := ttlDays(ttl)
	if err != nil {
		return APIKey{}, credential.Token{}, err
	}
	var out APIKey
	var tok credential.Token
	err = inOrg(ctx, s.pool, func(ctx context.Context, c Caller, q *dbq.Queries, tx db.TenantTx) error {
		if err := c.Require(td.PermServiceAccountManage, td.OrgPath(c.Org)); err != nil {
			return err
		}
		sa, err := activeAccount(ctx, q, c.Org, id)
		if err != nil {
			return err
		}
		if err := notAutomationIdentity(ctx, q, c.Org, sa.ID); err != nil {
			return err
		}
		if err := noEscalation(ctx, q, c, sa.ID, scopes); err != nil {
			return err
		}
		if tok, err = credential.New(credential.APIKey, s.env, c.Org); err != nil {
			return err
		}
		ss := make([]string, len(scopes))
		for i, p := range scopes {
			ss[i] = string(p)
		}
		r, err := q.InsertAPIKey(ctx, dbq.InsertAPIKeyParams{
			OrgID: c.Org, ID: ids.NewV7(), ServiceAccountID: sa.ID, Name: name, SecretHash: tok.Hash(), Hint: tok.Hint(),
			Scopes: ss, CreatedBy: c.Principal.String(), TtlDays: days,
		})
		if db.IsUniqueViolation(err) {
			return ErrNameTaken
		} else if err != nil {
			return err
		}
		out = apiKeyView(dbq.ListAPIKeysRow(r))
		return record(ctx, tx, c, "access.api_key_created", "api_key", r.ID,
			map[string]string{"service_account": sa.ID.String(), "name": name, "scopes": strings.Join(ss, ",")})
	})
	return out, tok, err
}

// ListAPIKeys lists API keys, optionally of one service account.
func (s *ServiceAccounts) ListAPIKeys(ctx context.Context, id td.ServiceAccountID, pr page.Request) (Page[APIKey], error) {
	var out Page[APIKey]
	err := inOrg(ctx, s.pool, func(ctx context.Context, c Caller, q *dbq.Queries, _ db.TenantTx) error {
		if err := c.Require(td.PermServiceAccountRead, td.OrgPath(c.Org)); err != nil {
			return err
		}
		rows, err := q.ListAPIKeys(ctx, dbq.ListAPIKeysParams{
			OrgID: c.Org, After: pr.After, ServiceAccountID: optUUID(id), PageLimit: pr.Limit(),
		})
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(pr, rows, func(r dbq.ListAPIKeysRow) ids.UUID { return r.ID })
		for _, r := range rows {
			out.Items = append(out.Items, apiKeyView(r))
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// RevokeAPIKey revokes an API key immediately.
func (s *ServiceAccounts) RevokeAPIKey(ctx context.Context, id ids.UUID) (APIKey, error) {
	var out APIKey
	err := inOrg(ctx, s.pool, func(ctx context.Context, c Caller, q *dbq.Queries, tx db.TenantTx) error {
		if err := c.Require(td.PermServiceAccountManage, td.OrgPath(c.Org)); err != nil {
			return err
		}
		r, err := q.RevokeAPIKey(ctx, c.Org, id)
		if db.IsNoRows(err) {
			if ok, err := q.APIKeyExists(ctx, c.Org, id); err != nil {
				return err
			} else if ok {
				return ErrAPIKeyClosed
			}
			return ErrAPIKeyNotFound
		} else if err != nil {
			return err
		}
		out = apiKeyView(dbq.ListAPIKeysRow(r))
		return record(ctx, tx, c, "access.api_key_revoked", "api_key", r.ID, nil)
	})
	return out, err
}

// ErrEscalation refuses a credential that would let the caller act with
// permissions it does not hold itself (CWE-269).
var ErrEscalation = pcerr.New(pcerr.PermissionDenied, "PRIVILEGE_ESCALATION",
	"this service account holds permissions you do not hold; you cannot issue credentials for it")

// noEscalation checks, before a key or API key is issued for a service
// account, that the caller already holds every permission the credential
// could exercise, at the scope the account holds it. scopes limits the
// check to an API key's scopes (nil: a key, which carries all of the
// account's permissions). A caller that may bind roles at org scope could
// grant itself those permissions anyway (audited), so it passes.
func noEscalation(ctx context.Context, q *dbq.Queries, c Caller, account ids.UUID, scopes []td.Permission) error {
	if c.Can(td.PermRoleBind, td.OrgPath(c.Org)) {
		return nil
	}
	bs, err := Bindings(ctx, q, c.Org, td.PrincipalRef{Kind: td.KindServiceAccount, ID: account})
	if err != nil {
		return err
	}
	for _, b := range bs {
		r, ok := td.LookupRole(b.Role)
		if !ok {
			continue // unknown roles grant nothing
		}
		path, err := scopePath(ctx, q, c.Org, b.Scope)
		if err != nil {
			return err
		}
		for _, p := range r.Permissions {
			if p.HumanOnly() || (scopes != nil && !slices.Contains(scopes, p)) {
				continue // never effective for the credential
			}
			if !c.Can(p, path) {
				return ErrEscalation
			}
		}
	}
	return nil
}

// scopePath returns the full path from the org to a binding's scope.
func scopePath(ctx context.Context, q *dbq.Queries, org ids.OrgID, s td.Scope) (td.Path, error) {
	switch s.Type {
	case td.ScopeOrg:
		return td.OrgPath(org), nil
	case td.ScopeBusinessUnit:
		return businessUnitPath(org, s.ID), nil
	case td.ScopeTeam:
		t, err := q.GetTeam(ctx, org, s.ID)
		if err != nil {
			return nil, err
		}
		return teamPath(org, t), nil
	case td.ScopeEnvironment:
		e, err := q.GetEnvironment(ctx, org, s.ID)
		if err != nil {
			return nil, err
		}
		if e.TeamID == nil {
			return td.OrgPath(org).Child(td.ScopeEnvironment, e.ID), nil
		}
		t, err := q.GetTeam(ctx, org, *e.TeamID)
		if err != nil {
			return nil, err
		}
		return teamPath(org, t).Child(td.ScopeEnvironment, e.ID), nil
	default:
		return td.OrgPath(org), nil
	}
}

// AutomationAccountPrefix starts the name of every automation's execution
// identity (G0 M11 part 2 D8, D63 L4); ordinary accounts cannot use it.
const AutomationAccountPrefix = "automation-"

// Execution identity errors (HR-270).
var (
	ErrAutomationIdentity = pcerr.New(pcerr.FailedPrecondition, "AUTOMATION_IDENTITY",
		"this service account is an automation's execution identity: it holds no keys or role bindings and changes only with its automation")
	ErrAutomationName = pcerr.New(pcerr.InvalidArgument, "AUTOMATION_NAME_RESERVED",
		"service account names starting with automation- are reserved for automations")
)

// notAutomationIdentity refuses an automation's execution identity (D8):
// the service-account API never edits, re-enables or adds credentials to
// it. The database refuses the same rows as a backstop.
func notAutomationIdentity(ctx context.Context, q *dbq.Queries, org ids.OrgID, sa ids.UUID) error {
	_, err := q.ServiceAccountAutomation(ctx, org, sa)
	switch {
	case db.IsNoRows(err):
		return nil
	case err != nil:
		return err
	}
	return ErrAutomationIdentity
}
