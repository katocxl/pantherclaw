// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package idps holds organization identity providers (G0 M18 D155, G6;
// HR-481..484, T-207): OIDC providers an organization's own admin
// configures next to the deployment's auth.oidc_providers.
//
// A provider is PENDING until a second person confirms it, then ACTIVE;
// DISABLED turns it off. Only ACTIVE providers sign anyone in, and the
// sign-in flows resolve them on each request (Resolver). Its issuer is
// fixed once it has been ACTIVE: users are (org, issuer, subject), so a
// swapped issuer would sign in as other people (T-207). The client secret
// is sealed with the org's DEK (purpose idp_client_secret) and never
// returned (HR-482). Discovery is HTTPS only through the egress guard,
// with no private or loopback address and no subject tokens (HR-483). The
// last provider through which an active org admin can sign in can't be
// disabled (HR-484).
package idps

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/oidcrp"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Sealing: the AAD binds org, table, column and row, so a secret copied to
// another provider or org does not decrypt (HR-062, HR-482).
const (
	SecretPurpose = "idp_client_secret" //nolint:gosec // G101: a DEK purpose, not a credential
	table         = "org_identity_providers"
	secretColumn  = "client_secret"
)

// MaxProviders bounds an org's ACTIVE providers and those whose activation
// is filed (D169).
const MaxProviders = 20

// States.
const (
	StatePending  = "PENDING"
	StateActive   = "ACTIVE"
	StateDisabled = "DISABLED"
)

// Errors.
var (
	ErrInvalid   = pcerr.New(pcerr.InvalidArgument, "IDENTITY_PROVIDER_INVALID", "the identity provider is not valid")
	ErrNotFound  = pcerr.New(pcerr.NotFound, "IDENTITY_PROVIDER_NOT_FOUND", "identity provider not found")
	ErrNameTaken = pcerr.New(pcerr.AlreadyExists, "IDENTITY_PROVIDER_NAME_TAKEN",
		"an identity provider of the organization or the deployment has this name")
	// ErrTooMany: ACTIVE providers and PENDING ones whose activation is
	// filed count toward the limit (D169).
	ErrTooMany = pcerr.New(pcerr.ResourceExhausted, "IDENTITY_PROVIDER_LIMIT", fmt.Sprintf(
		"an organization has at most %d active or pending identity providers; a provider that was never activated "+
			"can be changed and filed again with UpdateIdentityProvider instead of creating a new one", MaxProviders))
	// ErrIssuerFixed: users are (org, issuer, subject), so an issuer that
	// has signed people in can't change (T-207).
	ErrIssuerFixed = pcerr.New(pcerr.FailedPrecondition, "IDENTITY_PROVIDER_ISSUER_FIXED",
		"the issuer of an identity provider that has been active can't change; add a new provider instead")
	ErrState = pcerr.New(pcerr.FailedPrecondition, "IDENTITY_PROVIDER_STATE", "the identity provider is not in a state that allows this")
	// ErrLockOut: the change would leave no active org admin a way to sign
	// in (HR-484).
	ErrLockOut = pcerr.New(pcerr.FailedPrecondition, "IDENTITY_PROVIDER_LOCK_OUT",
		"this would leave no organization admin a provider to sign in with")
)

var namePattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// Provider is an organization's provider as people see it: never its
// secret (HR-482).
type Provider struct {
	ID           ids.UUID
	Name, Issuer string
	ClientID     string
	TrustEmail   bool
	State        string
	CreatedBy    ids.UUID
	CreatedAt    time.Time
	UpdatedBy    ids.UUID
	UpdatedAt    time.Time
	ActivatedAt  *time.Time
	DisabledBy   *ids.UUID
	DisabledAt   *time.Time
}

// Input is a provider's settings. ClientSecret is required to create one;
// on a change an unset secret keeps the stored one.
type Input struct {
	Name, Issuer, ClientID string
	ClientSecret           pclog.Secret[[]byte]
	TrustEmail             bool
}

func (in Input) validate(secretRequired bool) error {
	var errs []error
	if !namePattern.MatchString(in.Name) {
		errs = append(errs, errors.New("name must be 1-32 lowercase letters, digits or hyphens"))
	}
	if len(in.Issuer) > 512 {
		errs = append(errs, errors.New("issuer is at most 512 characters"))
	} else if err := oidcrp.CheckOrgURL(in.Issuer); err != nil {
		errs = append(errs, fmt.Errorf("issuer: %w", err))
	}
	if in.ClientID == "" || len(in.ClientID) > 256 {
		errs = append(errs, errors.New("client_id is 1-256 characters"))
	}
	n := len(in.ClientSecret.Reveal())
	switch {
	case secretRequired && n == 0:
		errs = append(errs, errors.New("a client secret is required"))
	case n > 4096:
		errs = append(errs, errors.New("the client secret is at most 4096 bytes"))
	}
	if err := errors.Join(errs...); err != nil {
		return pcerr.New(pcerr.InvalidArgument, ErrInvalid.Reason(), err.Error())
	}
	return nil
}

// Deployment is one of the deployment's providers (auth.oidc_providers),
// as the lock-out guard and the name check see it.
type Deployment struct {
	Name, Issuer string
}

// Store reads and writes an org's providers inside the caller's
// transaction. It decides nothing about who may: the protected change
// that calls it does (HR-481).
type Store struct {
	Envelope   *pccrypto.Envelope
	Deployment []Deployment
}

func field(org ids.OrgID, id ids.UUID) pccrypto.FieldContext {
	return pccrypto.FieldContext{Org: org, Table: table, Column: secretColumn, RowID: id.String()}
}

// Seal seals a client secret for provider id of org (HR-482).
func (s *Store) Seal(ctx context.Context, org ids.OrgID, id ids.UUID, secret pclog.Secret[[]byte]) ([]byte, error) {
	if s.Envelope == nil {
		return nil, errors.New("idps: no envelope")
	}
	return s.Envelope.Encrypt(ctx, field(org, id), SecretPurpose, secret.Reveal())
}

// open unseals a provider's client secret.
func (s *Store) open(ctx context.Context, org ids.OrgID, id ids.UUID, blob []byte) (pclog.Secret[[]byte], error) {
	if s.Envelope == nil {
		return pclog.Secret[[]byte]{}, errors.New("idps: no envelope")
	}
	b, err := s.Envelope.Decrypt(ctx, field(org, id), SecretPurpose, blob)
	if err != nil {
		return pclog.Secret[[]byte]{}, err
	}
	return pclog.NewSecret(b), nil
}

func (s *Store) deploymentName(name string) bool {
	return slices.ContainsFunc(s.Deployment, func(d Deployment) bool { return d.Name == name })
}

// Create stores a new PENDING provider with its secret sealed. It signs
// nobody in until Put activates it.
func (s *Store) Create(ctx context.Context, tx db.TenantTx, by evdomain.Actor, author ids.UUID, id ids.UUID, in Input) (Provider, error) {
	if err := in.validate(true); err != nil {
		return Provider{}, err
	}
	if s.deploymentName(in.Name) {
		return Provider{}, ErrNameTaken
	}
	q := dbq.New(tx)
	org := tx.OrgID()
	if err := q.LockOrgIdentityProviderSettings(ctx, org.UUID()); err != nil {
		return Provider{}, err
	}
	n, err := q.CountOrgIdentityProviders(ctx, org, nil)
	if err != nil {
		return Provider{}, err
	}
	if n >= MaxProviders {
		return Provider{}, ErrTooMany
	}
	sealed, err := s.Seal(ctx, org, id, in.ClientSecret)
	if err != nil {
		return Provider{}, err
	}
	row, err := q.InsertOrgIdentityProvider(ctx, dbq.InsertOrgIdentityProviderParams{
		OrgID: org, ID: id, Name: in.Name, Issuer: in.Issuer, ClientID: in.ClientID, ClientSecret: sealed,
		TrustEmail: in.TrustEmail, CreatedBy: author,
	})
	if db.IsUniqueViolation(err) {
		return Provider{}, ErrNameTaken
	} else if err != nil {
		return Provider{}, err
	}
	p := Provider(row)
	return p, record(ctx, tx, by, "identity_provider.created", p)
}

// Change is a stored change to a provider: Put applies it. SealedSecret
// is nil to keep the stored secret.
type Change struct {
	Name, Issuer, ClientID string
	SealedSecret           []byte
	TrustEmail             bool
}

// Put applies a change to provider id and makes it ACTIVE. The issuer
// can't change once the provider has been active (T-207).
func (s *Store) Put(ctx context.Context, tx db.TenantTx, by evdomain.Actor, author ids.UUID, id ids.UUID, c Change) error {
	if err := (Input{Name: c.Name, Issuer: c.Issuer, ClientID: c.ClientID}).validate(false); err != nil {
		return err
	}
	if s.deploymentName(c.Name) {
		return ErrNameTaken
	}
	q := dbq.New(tx)
	org := tx.OrgID()
	if err := q.LockOrgIdentityProviderSettings(ctx, org.UUID()); err != nil {
		return err
	}
	cur, err := q.LockOrgIdentityProvider(ctx, org, id)
	if db.IsNoRows(err) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if cur.ActivatedAt != nil && cur.Issuer != c.Issuer {
		return ErrIssuerFixed
	}
	if cur.State != StateActive {
		if err := s.underLimit(ctx, tx, id); err != nil {
			return err
		}
	}
	if c.SealedSecret != nil {
		// The sealed secret must be this provider's (the AAD binds the row).
		if _, err := s.open(ctx, org, id, c.SealedSecret); err != nil {
			return ErrInvalid
		}
	}
	n, err := q.PutOrgIdentityProvider(ctx, dbq.PutOrgIdentityProviderParams{
		Name: c.Name, Issuer: c.Issuer, ClientID: c.ClientID, ClientSecret: c.SealedSecret, TrustEmail: c.TrustEmail,
		UpdatedBy: author, OrgID: org, ID: id,
	})
	if db.IsUniqueViolation(err) {
		return ErrNameTaken
	} else if err != nil {
		return err
	}
	if n != 1 {
		return ErrState
	}
	p, err := s.Get(ctx, tx, id)
	if err != nil {
		return err
	}
	return record(ctx, tx, by, "identity_provider.activated", p, "client_auth_changed", fmt.Sprint(c.SealedSecret != nil))
}

// Disable turns provider id off, unless that leaves no active org admin a
// provider to sign in with (HR-484).
func (s *Store) Disable(ctx context.Context, tx db.TenantTx, by evdomain.Actor, author ids.UUID, id ids.UUID) error {
	q := dbq.New(tx)
	org := tx.OrgID()
	if err := q.LockOrgIdentityProviderSettings(ctx, org.UUID()); err != nil {
		return err
	}
	cur, err := q.LockOrgIdentityProvider(ctx, org, id)
	if db.IsNoRows(err) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if cur.State == StateDisabled {
		return ErrState
	}
	if _, err := s.StrandedByDisable(ctx, tx, id); err != nil {
		return err
	}
	a := author
	n, err := q.DisableOrgIdentityProvider(ctx, &a, org, id)
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrState
	}
	p, err := s.Get(ctx, tx, id)
	if err != nil {
		return err
	}
	return record(ctx, tx, by, "identity_provider.disabled", p)
}

// SetOwnOnly sets whether the org signs in with its own providers alone.
// Turning it on is refused when no active org admin could then sign in
// (HR-484).
func (s *Store) SetOwnOnly(ctx context.Context, tx db.TenantTx, by evdomain.Actor, author ids.UUID, on bool) error {
	q := dbq.New(tx)
	org := tx.OrgID()
	if err := q.LockOrgIdentityProviderSettings(ctx, org.UUID()); err != nil {
		return err
	}
	if _, err := s.StrandedByOwnOnly(ctx, tx, on); err != nil {
		return err
	}
	if err := q.SetOwnProvidersOnly(ctx, org, on, author); err != nil {
		return err
	}
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: "identity_provider.own_only_set", Actor: by, Outcome: audit.Success,
		Object:  &audit.Object{Type: "org", ID: org.String()},
		Details: map[string]string{"own_providers_only": fmt.Sprint(on)},
	})
	return err
}

// StrandedByDisable checks disabling provider id for lock-out (HR-484):
// ErrLockOut, or the active admins who would lose their last provider.
func (s *Store) StrandedByDisable(ctx context.Context, tx db.TenantTx, id ids.UUID) ([]ids.UUID, error) {
	own, err := s.OwnOnly(ctx, tx)
	if err != nil {
		return nil, err
	}
	return s.guardLockOut(ctx, tx, id, own)
}

// StrandedByOwnOnly checks setting "own providers only" to on the same
// way; turning it off strands nobody.
func (s *Store) StrandedByOwnOnly(ctx context.Context, tx db.TenantTx, on bool) ([]ids.UUID, error) {
	if !on {
		return nil, nil
	}
	return s.guardLockOut(ctx, tx, ids.UUID{}, true)
}

// OwnOnly reports whether the org signs in with its own providers alone.
func (s *Store) OwnOnly(ctx context.Context, tx db.TenantTx) (bool, error) {
	row, err := dbq.New(tx).OrgIdentityProviderSettings(ctx, tx.OrgID())
	if db.IsNoRows(err) {
		return false, nil
	}
	return row.OwnProvidersOnly, err
}

// Get returns provider id.
func (s *Store) Get(ctx context.Context, tx db.TenantTx, id ids.UUID) (Provider, error) {
	row, err := dbq.New(tx).GetOrgIdentityProvider(ctx, tx.OrgID(), id)
	if db.IsNoRows(err) {
		return Provider{}, ErrNotFound
	} else if err != nil {
		return Provider{}, err
	}
	return Provider(row), nil
}

// List returns the org's providers by name.
func (s *Store) List(ctx context.Context, tx db.TenantTx) ([]Provider, error) {
	rows, err := dbq.New(tx).ListOrgIdentityProviders(ctx, tx.OrgID())
	if err != nil {
		return nil, err
	}
	out := make([]Provider, 0, len(rows))
	for _, r := range rows {
		out = append(out, Provider(r))
	}
	return out, nil
}

func record(ctx context.Context, tx db.TenantTx, by evdomain.Actor, name string, p Provider, kv ...string) error {
	details := map[string]string{
		"name": p.Name, "issuer": p.Issuer, "client_id": p.ClientID, "trust_email": fmt.Sprint(p.TrustEmail), "state": p.State,
	}
	for i := 0; i+1 < len(kv); i += 2 {
		details[kv[i]] = kv[i+1]
	}
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: by, Outcome: audit.Success,
		Object: &audit.Object{Type: "identity_provider", ID: p.ID.String()}, Details: details,
	})
	return err
}

// underLimit is ErrTooMany when the org's other counted providers (ACTIVE,
// or PENDING with a filed activation) already reach MaxProviders (D169).
func (s *Store) underLimit(ctx context.Context, tx db.TenantTx, except ids.UUID) error {
	n, err := dbq.New(tx).CountOrgIdentityProviders(ctx, tx.OrgID(), &except)
	if err != nil {
		return err
	}
	if n >= MaxProviders {
		return ErrTooMany
	}
	return nil
}

// Lapse disables provider id when it was never activated: its activation
// was declined or expired, so it stops counting toward the limit (D169).
// Any other provider is left as it is.
func (s *Store) Lapse(ctx context.Context, tx db.TenantTx, author ids.UUID, id ids.UUID) error {
	a := author
	n, err := dbq.New(tx).LapseOrgIdentityProvider(ctx, &a, tx.OrgID(), id)
	if err != nil || n == 0 {
		return err
	}
	p, err := s.Get(ctx, tx, id)
	if err != nil {
		return err
	}
	return record(ctx, tx, evdomain.Actor{Type: "system", ID: "idps"}, "identity_provider.lapsed", p)
}

// ClosePut runs when a filed put is declined or expires (a protect.Closer,
// registered in every role, since the jobs role expires requests): a
// provider that was never activated is disabled (D169).
func (s *Store) ClosePut(ctx context.Context, tx db.TenantTx, author ids.UUID, payload []byte) error {
	var p struct {
		ID ids.UUID `json:"id"`
	}
	if err := json.Unmarshal(payload, &p); err != nil || p.ID.IsZero() {
		return nil // nothing of ours to lapse
	}
	return s.Lapse(ctx, tx, author, p.ID)
}
