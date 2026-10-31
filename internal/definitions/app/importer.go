// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app holds the definitions use cases: importing signed tool packages
// into an org and moving them through their lifecycle. Persistence is behind
// the Repository port; the tables arrive after M2 (migrations from 00020).
package app

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// ErrMissing is the repository's "no such record" error.
var ErrMissing = errors.New("definitions: not found")

// ErrConflict reports that stored metadata, a pin or a lifecycle state
// changed between read and write (a lost race on a conditional update,
// HR-004). The caller may retry the whole use case.
var ErrConflict = errors.New("definitions: concurrent change")

// Record is everything one import writes, in one transaction.
type Record struct {
	// PreviousMetadata is the trusted metadata state that was read (nil if
	// none); Metadata replaces it only if it is unchanged.
	PreviousMetadata *trust.State
	Metadata         trust.State
	MetadataExpiry   time.Time
	// SigningKey is the org package-signing key that signed the metadata,
	// nil when a package root did (HR-162). With a key, the metadata state
	// that advances is the key's, conditional on the key still being
	// ACTIVE, and the version records the key.
	SigningKey *ids.UUID
	// SigningKID is the kid that signed the metadata, which tells the
	// development key apart (HR-163).
	SigningKID string
	// Package and Raw are the decoded and exact package bytes; FileDigest
	// is the digest the signed metadata lists.
	Package    *domain.Package
	Raw        []byte
	FileDigest string
	// PreviousPin is the org's pin that was read (nil if none); Pin replaces
	// it only if it is unchanged.
	PreviousPin *domain.Pin
	Pin         domain.Pin
	// State is the lifecycle state the new version starts in for the org.
	State domain.State
	// Event, when set, is audited in the same transaction.
	Event *audit.Event
}

// Repository persists trusted metadata, package versions, pins and
// lifecycle states. Every write is conditional on the state that was read
// and returns ErrConflict when it changed.
type Repository interface {
	// TrustedMetadata returns the highest package-root targets metadata the
	// org has accepted (anti-rollback is per org, so no table is global).
	TrustedMetadata(ctx context.Context, org ids.OrgID) (*trust.State, error)
	CurrentPin(ctx context.Context, org ids.OrgID, pkg string) (*domain.Pin, error)
	// Import stores one version. Imports into an org are serialized, and
	// one whose package defines an operation that a non-retired version
	// from the other kind of signer (package root or org key) defines
	// returns ErrOperationTaken (HR-162).
	Import(ctx context.Context, org ids.OrgID, rec Record) error
	State(ctx context.Context, org ids.OrgID, pkg, version string) (domain.State, error)
	// Transition moves a version from one state to another and, when ev is
	// set, audits it in the same transaction.
	Transition(ctx context.Context, org ids.OrgID, pkg, version string, from, to domain.State, ev *audit.Event) error
}

// Importer imports signed tool packages (HR-123, HR-162).
type Importer struct {
	Roots trust.Roots
	Repo  Repository
	// Keys holds the orgs' package-signing keys; without it only package
	// roots verify.
	Keys  Keys
	Clock clock.Clock
}

// Result describes an import.
type Result struct {
	Package   *domain.Package
	Pin       domain.Pin
	Unchanged bool
}

// Import verifies the targets document, checks that raw is exactly the
// signed file for name@version, decodes it, and advances the org's pin.
// Bytes are matched against the signed hash before they are parsed, so
// only signed bytes ever reach the YAML decoder. A new version starts
// REVIEWED: the publisher's signature is the review, and activation for the
// org is a separate, explicit step (F395).
func (im *Importer) Import(ctx context.Context, org ids.OrgID, name, version, targets string, raw []byte, ev *audit.Event) (Result, error) {
	if org.IsZero() {
		return Result{}, fmt.Errorf("%w: org is required", domain.ErrInvalid)
	}
	v, last, key, err := im.verify(ctx, org, targets)
	if err != nil {
		return Result{}, err
	}
	if err := trust.CheckAdvance(last, v); err != nil {
		return Result{}, err
	}
	digest, err := v.Match(name, version, raw)
	if err != nil {
		return Result{}, err
	}
	p, err := manifest.Decode(raw)
	if err != nil {
		return Result{}, err
	}
	if p.Name != name || p.Version != version {
		return Result{}, fmt.Errorf("%w: file declares %s, signed as %s", trust.ErrUntrusted, trust.Key(p.Name, p.Version), trust.Key(name, version))
	}
	pin := domain.Pin{Package: name, Version: version, Digest: digest}
	cur, err := im.Repo.CurrentPin(ctx, org, name)
	if err != nil {
		return Result{}, err
	}
	if err := domain.CheckPinAdvance(cur, pin); err != nil {
		return Result{}, err
	}
	if cur != nil && *cur == pin {
		return Result{Package: p, Pin: pin, Unchanged: true}, nil
	}
	if ev != nil {
		// The signer's kid tells a package root, an org key and the
		// development key (HR-163) apart in the audit log.
		ev.Details = map[string]string{"digest": digest, "definitions": strconv.Itoa(len(p.Definitions)), "signing_key": v.KID}
	}
	err = im.Repo.Import(ctx, org, Record{
		PreviousMetadata: last, Metadata: trust.State{Version: v.Version, PayloadDigest: v.PayloadDigest},
		MetadataExpiry: v.Expiry, SigningKey: key, SigningKID: v.KID, Package: p, Raw: raw, FileDigest: digest,
		PreviousPin: cur, Pin: pin, State: domain.StateReviewed,
		Event: ev,
	})
	if err != nil {
		return Result{}, err
	}
	return Result{Package: p, Pin: pin}, nil
}

// verify checks the targets document against the keys its kid routes to:
// an org package-signing key the org registered and has not revoked
// (HR-162), or else the package roots. The kid is read unverified only to
// choose the key set; the signature is then checked against that set
// alone. It returns the metadata state anti-rollback compares against and,
// for an org key, the key's id.
func (im *Importer) verify(ctx context.Context, org ids.OrgID, targets string) (trust.Verified, *trust.State, *ids.UUID, error) {
	kid, _, err := jws.Unverified(strings.TrimSpace(targets))
	if err != nil || !trust.IsOrgKID(kid) {
		v, err := trust.Verify(targets, im.Roots, im.Clock.Now())
		if err != nil {
			return trust.Verified{}, nil, nil, err
		}
		last, err := im.Repo.TrustedMetadata(ctx, org)
		return v, last, nil, err
	}
	if im.Keys == nil {
		return trust.Verified{}, nil, nil, fmt.Errorf("%w: org package-signing keys are not supported here", trust.ErrUntrusted)
	}
	k, err := im.Keys.SigningKey(ctx, org, kid)
	switch {
	case errors.Is(err, ErrMissing):
		return trust.Verified{}, nil, nil, fmt.Errorf("%w: %s is not a package-signing key of this org", trust.ErrUntrusted, kid)
	case err != nil:
		return trust.Verified{}, nil, nil, err
	case k.State != KeyActive:
		return trust.Verified{}, nil, nil, fmt.Errorf("%w: package-signing key %s is revoked", trust.ErrUntrusted, kid)
	}
	v, err := trust.Verify(targets, trust.Roots{k.KID: k.Public}, im.Clock.Now())
	if err != nil {
		return trust.Verified{}, nil, nil, err
	}
	return v, k.Metadata, &k.ID, nil
}

// Transition moves an org's package version through the lifecycle (for
// example REVIEWED → ACTIVE to activate it, ACTIVE → QUARANTINED on a
// behavior mismatch). Illegal transitions are refused before any write.
func (im *Importer) Transition(ctx context.Context, org ids.OrgID, pkg, version string, to domain.State, ev *audit.Event) error {
	from, err := im.Repo.State(ctx, org, pkg, version)
	if err != nil {
		return err
	}
	if err := domain.Lifecycle.Check(from, to); err != nil {
		return err
	}
	if to == domain.StateActive && im.Keys != nil {
		k, err := im.Keys.VersionSigner(ctx, org, pkg, version)
		if err != nil {
			return err
		}
		// A revocation racing this check either withdraws the version
		// first, so the conditional transition below fails, or quarantines
		// it once it is active.
		if k != nil && k.Reason == RevokeCompromised {
			return ErrKeyCompromised
		}
	}
	return im.Repo.Transition(ctx, org, pkg, version, from, to, ev)
}
