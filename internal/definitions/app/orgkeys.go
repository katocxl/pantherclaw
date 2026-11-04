// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"context"
	"crypto/ed25519"
	"errors"
	"regexp"
	"strings"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Org package-signing keys (HR-162; G0 M4 decision 2, Team edition). An org
// admin registers the public half of a key the org keeps offline; packages
// listed in targets signed with it can then be imported into that org, and
// only that org. Importing never activates: a Policy Publisher still
// activates each version, as for PantherClaw's packages.

// PermPackageKeyManage registers and revokes signing keys.
const PermPackageKeyManage = tdomain.PermPackageKeyManage

// MaxActiveSigningKeys bounds an org's active package-signing keys.
const MaxActiveSigningKeys = 5

// KeyState is a signing key's state. A revoked key never becomes active
// again, and its kid can never be registered again in the org.
type KeyState string

// Key states.
const (
	KeyActive  KeyState = "ACTIVE"
	KeyRevoked KeyState = "REVOKED"
)

// RevokeReason says why a key was revoked, which decides what happens to
// the versions it signed.
type RevokeReason string

// Revocation reasons.
const (
	// RevokeRotated: the key was replaced. What it signed keeps working.
	RevokeRotated RevokeReason = "ROTATED"
	// RevokeCompromised: someone else may hold the private key. Every
	// version it signed is withdrawn (Withdrawn) and can never be activated
	// again, and permits already issued fail (the containment epoch rises).
	RevokeCompromised RevokeReason = "COMPROMISED"
)

// Valid reports whether r is a known reason.
func (r RevokeReason) Valid() bool { return r == RevokeRotated || r == RevokeCompromised }

// SigningKey is an org package-signing key.
type SigningKey struct {
	ID     ids.UUID
	KID    string
	Name   string
	Public ed25519.PublicKey
	State  KeyState
	// Reason is set once the key is revoked.
	Reason RevokeReason
	// Metadata is the last targets metadata accepted under this key (nil
	// before its first import): anti-rollback is per key (HR-123).
	Metadata  *trust.State
	CreatedBy string
	CreatedAt time.Time
	RevokedBy string
	RevokedAt time.Time
}

// VersionChange is a package version that revoking a compromised key moved.
type VersionChange struct {
	Name, Version string
	From, To      domain.State
}

// Withdrawn returns the state a version signed by a compromised key moves
// to: versions that decide (ACTIVE, STALE) are quarantined, so their
// actions are denied; versions not yet active are retired, so nobody can
// activate them. Quarantined and retired versions stay as they are.
func Withdrawn(s domain.State) (domain.State, bool) {
	switch s {
	case domain.StateActive, domain.StateStale:
		return domain.StateQuarantined, true
	case domain.StateUnclassified, domain.StateDraft, domain.StateReviewed:
		return domain.StateRetired, true
	case domain.StateQuarantined, domain.StateRetired:
		return s, false
	}
	return s, false
}

// Keys stores an org's package-signing keys.
type Keys interface {
	// SigningKey returns the org's key with this kid, in any state, or
	// ErrMissing.
	SigningKey(ctx context.Context, org ids.OrgID, kid string) (SigningKey, error)
	// ListSigningKeys lists the org's keys, newest first.
	ListSigningKeys(ctx context.Context, org ids.OrgID) ([]SigningKey, error)
	// RegisterSigningKey stores k as ACTIVE and audits ev in one
	// transaction, serialized per org. It returns ErrKeyRegistered when the
	// kid was ever registered in the org and ErrKeyLimit when
	// MaxActiveSigningKeys keys are already active.
	RegisterSigningKey(ctx context.Context, org ids.OrgID, k SigningKey, ev *audit.Event) error
	// RevokeSigningKey moves an ACTIVE key to REVOKED (ErrConflict when it
	// is not active) and audits ev. For RevokeCompromised the same
	// transaction first raises the org's containment epoch, then moves every
	// version the key signed as Withdrawn says, auditing each move as
	// package.transitioned by ev's actor, and returns the moves.
	RevokeSigningKey(ctx context.Context, org ids.OrgID, kid string, reason RevokeReason, by string, ev *audit.Event) ([]VersionChange, error)
	// VersionSigner returns the key that signed a package version, or nil
	// when a package root signed it (ErrMissing when there is no version).
	VersionSigner(ctx context.Context, org ids.OrgID, pkg, version string) (*SigningKey, error)
}

// Repository and import errors of org keys.
var (
	// ErrKeyRegistered reports a kid the org registered before (a revoked
	// key can never be registered again).
	ErrKeyRegistered = errors.New("definitions: signing key already registered")
	// ErrKeyLimit reports an org with MaxActiveSigningKeys active keys.
	ErrKeyLimit = errors.New("definitions: too many active signing keys")
	// ErrOperationTaken reports a package defining an operation that a
	// version from the other kind of signer already defines in the org:
	// an org key never redefines a PantherClaw operation, and the reverse
	// (HR-162). Retired versions do not count.
	ErrOperationTaken = errors.New("definitions: operation is defined by another publisher")
	// ErrKeyCompromised reports activating a version whose signing key was
	// revoked as compromised.
	ErrKeyCompromised = errors.New("definitions: the version's signing key was revoked as compromised")
)

// Entitlements reports the current edition (billing.Service).
type Entitlements interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// API errors of org keys.
var (
	ErrEditionRequired = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
		"org package-signing keys need the Team edition or above")
	ErrKeyNotFound   = pcerr.New(pcerr.NotFound, "SIGNING_KEY_NOT_FOUND", "package-signing key not found")
	errKeyName       = pcerr.New(pcerr.InvalidArgument, "SIGNING_KEY_INVALID", "the key name must be 1-64 letters, digits, spaces, dots, dashes or underscores")
	errKeyRegistered = pcerr.New(pcerr.AlreadyExists, "SIGNING_KEY_EXISTS", "this key is or was registered in the org; a revoked key cannot come back")
	errKeyLimit      = pcerr.New(pcerr.FailedPrecondition, "SIGNING_KEY_LIMIT", "the org already has the maximum of 5 active package-signing keys; revoke one first")
	errKeyRevoked    = pcerr.New(pcerr.FailedPrecondition, "SIGNING_KEY_REVOKED", "the key is already revoked")
	errKeyReason     = pcerr.New(pcerr.InvalidArgument, "SIGNING_KEY_INVALID", "the reason must be ROTATED or COMPROMISED")
	errNoKeys        = pcerr.New(pcerr.Unimplemented, "SIGNING_KEYS_UNAVAILABLE", "this server does not support org package-signing keys")
)

var keyName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)

// entitled reports whether the org may use its own package-signing keys.
// Without entitlements wired the answer is no (fail closed).
func (a *Admin) entitled(ctx context.Context) error {
	if a.Ents == nil {
		return ErrEditionRequired
	}
	e, err := a.Ents.Current(ctx)
	if err != nil {
		return err
	}
	if !e.OrgPackageKeys() {
		return ErrEditionRequired
	}
	return nil
}

func (a *Admin) keys() (Keys, error) {
	if a.Importer.Keys == nil {
		return nil, errNoKeys
	}
	return a.Importer.Keys, nil
}

// RegisterKey registers an org package-signing key from its public JWK
// (package.key.manage at the org; a person, Team edition or above).
func (a *Admin) RegisterKey(ctx context.Context, name string, jwk []byte) (SigningKey, error) {
	c, err := a.caller(ctx, PermPackageKeyManage)
	if err != nil {
		return SigningKey{}, err
	}
	if !c.Human() {
		return SigningKey{}, ErrHumanOnly
	}
	if err := a.entitled(ctx); err != nil {
		return SigningKey{}, err
	}
	keys, err := a.keys()
	if err != nil {
		return SigningKey{}, err
	}
	if !keyName.MatchString(name) {
		return SigningKey{}, errKeyName
	}
	kid, pub, err := trust.ParseOrgKey(jwk)
	if err != nil {
		return SigningKey{}, pcerr.Wrap(err, pcerr.InvalidArgument, "SIGNING_KEY_INVALID", strings.TrimPrefix(err.Error(), trust.ErrUntrusted.Error()+": "))
	}
	ev := &audit.Event{
		Name: auditkind.PackageSigningKeyRegistered, Actor: c.Actor(), Outcome: audit.Success,
		Object: &audit.Object{Type: "package_signing_key", ID: kid}, Details: map[string]string{"name": name},
	}
	k := SigningKey{ID: ids.NewV7(), KID: kid, Name: name, Public: pub, State: KeyActive, CreatedBy: c.Principal.String()}
	switch err := keys.RegisterSigningKey(ctx, c.Org, k, ev); {
	case errors.Is(err, ErrKeyRegistered):
		return SigningKey{}, errKeyRegistered
	case errors.Is(err, ErrKeyLimit):
		return SigningKey{}, errKeyLimit
	case err != nil:
		return SigningKey{}, err
	}
	return keys.SigningKey(ctx, c.Org, kid)
}

// RevokeKey revokes an org package-signing key (package.key.manage at the
// org). Revoking only removes trust, so it needs no particular edition and
// a service account holding the permission may do it. It returns the key
// and, for a compromised key, the versions it withdrew.
func (a *Admin) RevokeKey(ctx context.Context, kid string, reason RevokeReason) (SigningKey, []VersionChange, error) {
	c, err := a.caller(ctx, PermPackageKeyManage)
	if err != nil {
		return SigningKey{}, nil, err
	}
	if !reason.Valid() {
		return SigningKey{}, nil, errKeyReason
	}
	keys, err := a.keys()
	if err != nil {
		return SigningKey{}, nil, err
	}
	k, err := keys.SigningKey(ctx, c.Org, kid)
	if errors.Is(err, ErrMissing) {
		return SigningKey{}, nil, ErrKeyNotFound
	}
	if err != nil {
		return SigningKey{}, nil, err
	}
	if k.State != KeyActive {
		return SigningKey{}, nil, errKeyRevoked
	}
	ev := &audit.Event{
		Name: auditkind.PackageSigningKeyRevoked, Actor: c.Actor(), Outcome: audit.Success,
		Object: &audit.Object{Type: "package_signing_key", ID: kid}, Details: map[string]string{"reason": string(reason)},
	}
	moved, err := keys.RevokeSigningKey(ctx, c.Org, kid, reason, c.Principal.String(), ev)
	switch {
	case errors.Is(err, ErrConflict):
		return SigningKey{}, nil, errKeyRevoked
	case err != nil:
		return SigningKey{}, nil, err
	}
	k, err = keys.SigningKey(ctx, c.Org, kid)
	return k, moved, err
}

// ListKeys lists the org's package-signing keys (package.read at the org).
func (a *Admin) ListKeys(ctx context.Context) ([]SigningKey, error) {
	c, err := a.caller(ctx, PermPackageRead)
	if err != nil {
		return nil, err
	}
	keys, err := a.keys()
	if err != nil {
		return nil, err
	}
	return keys.ListSigningKeys(ctx, c.Org)
}
