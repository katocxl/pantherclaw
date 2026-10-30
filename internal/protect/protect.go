// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package protect holds protected changes and compromised publishers (G0
// M11 part 2 D42, D42a, D43; HR-292, HR-293, T-129).
//
// An org protects a category of change by setting it to
// DISTINCT_PUBLISHER. A surface (package activation, change windows,
// sealed credentials, connection settings, coverage exclusions) hands each
// widening change to the Gate before it writes: with the category OFF the
// Gate runs the surface's own write, unchanged; with it on, the change is
// stored PENDING with a change request (domain "protected") and the
// surface reports PROTECTED_CHANGE_PENDING. When a different person with
// the category's permission, who is not marked compromised, confirms the
// request with a security key, the surface's code runs again inside the
// confirming transaction as the author. An emergency change applies at
// once and must be reviewed by a distinct publisher within 72 hours.
//
// A person marked compromised (Business) stops confirming at once, their
// pending requests are voided, and what they published since a given time
// is listed for an independent KEEP/ROLLBACK review before two other
// people can clear the mark.
package protect

import (
	"context"
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"slices"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Category is a kind of protected change (D42).
type Category string

// Categories.
const (
	ToolMeaning       Category = "TOOL_MEANING"
	ConsequenceRules  Category = "CONSEQUENCE_RULES"
	Custody           Category = "CUSTODY"
	CoverageExclusion Category = "COVERAGE_EXCLUSION"
)

// Categories lists every category in a stable order.
func Categories() []Category {
	return []Category{ToolMeaning, ConsequenceRules, Custody, CoverageExclusion}
}

// Valid reports whether c is a category.
func (c Category) Valid() bool { return slices.Contains(Categories(), c) }

// Mode is a category's protection.
type Mode string

// Modes. A category without a stored mode is OFF.
const (
	ModeOff               Mode = "OFF"
	ModeDistinctPublisher Mode = "DISTINCT_PUBLISHER"
)

// Valid reports whether m is a mode.
func (m Mode) Valid() bool { return m == ModeOff || m == ModeDistinctPublisher }

// Surface names the code that applies a stored change: each registers an
// Applier under its name (D42a).
type Surface string

// Surfaces.
const (
	SurfacePackageActivate  Surface = "package.activate"
	SurfaceWindowCreate     Surface = "release.window.create"
	SurfaceWindowRetire     Surface = "release.window.retire"
	SurfaceCredentialPut    Surface = "credential.put" //nolint:gosec // G101: a surface name, not a credential
	SurfaceConnectionUpdate Surface = "connection.update"
	SurfaceRouteMode        Surface = "connection.route_mode"
	SurfaceExclusionCreate  Surface = "coverage.exclusion.create"
	// SurfaceConsequenceRule activates or retires a customer consequence
	// rule (G0 M17 D107): always held for a second person, whatever the
	// CONSEQUENCE_RULES mode (AlwaysProtected).
	SurfaceConsequenceRule Surface = "consequence.rule.put"
	// The organization identity provider surfaces (G0 M18 D155, D162):
	// always held for a second person, whatever the CUSTODY mode
	// (AlwaysProtected). Put activates or changes a provider, Disable
	// turns one off, OwnOnly sets "own providers only".
	SurfaceIdentityProviderPut     Surface = "identity_provider.put"
	SurfaceIdentityProviderDisable Surface = "identity_provider.disable"
	SurfaceIdentityProviderOwnOnly Surface = "identity_provider.own_only"
	// SurfaceCredentialRotate activates a GitHub App key rotation's tested
	// candidate (G0 M20 S20c, D253, D259; CUSTODY).
	SurfaceCredentialRotate Surface = "credential.rotate" //nolint:gosec // G101: a surface name, not a credential
	// SurfaceTicketFieldOwner gives a field of an org's ticket sync to the
	// ticket system (G0 M20 D264); taking one back applies directly.
	SurfaceTicketFieldOwner Surface = "ticket.field_owner"
	// SurfaceSettings turns a category OFF (a change request of kind
	// SETTINGS, D42).
	SurfaceSettings Surface = "protect.settings"
)

// Permission is the permission a surface's author needs and its publisher
// must hold at the org (D42a (1)).
func (s Surface) Permission() td.Permission {
	switch s {
	case SurfacePackageActivate:
		return td.PermPackageActivate
	case SurfaceWindowCreate, SurfaceWindowRetire:
		return td.PermReleaseWindowManage
	case SurfaceCredentialPut:
		return td.PermCredentialSeal
	case SurfaceCredentialRotate:
		return td.PermCredentialSeal
	case SurfaceConnectionUpdate, SurfaceRouteMode:
		return td.PermConnectionManage
	case SurfaceExclusionCreate:
		return td.PermCoverageManage
	case SurfaceConsequenceRule:
		return td.PermConsequenceRuleManage
	case SurfaceIdentityProviderPut, SurfaceIdentityProviderDisable, SurfaceIdentityProviderOwnOnly:
		return td.PermIdentityProviderManage
	case SurfaceTicketFieldOwner:
		return td.PermConnectionManage
	case SurfaceSettings:
		return td.PermProtectedChangeManage
	}
	return ""
}

// AlwaysProtected reports whether every change of the surface waits for a
// second person, in every mode of its category, and can never be applied
// as an emergency (G0 M17 D107, HR-453; G0 M18 D155, HR-481).
func (s Surface) AlwaysProtected() bool {
	return s == SurfaceConsequenceRule ||
		s == SurfaceIdentityProviderPut || s == SurfaceIdentityProviderDisable || s == SurfaceIdentityProviderOwnOnly
}

// Change domains and kinds of internal/changes (D6).
const (
	DomainProtected = "protected"
	DomainPublisher = "publisher"
	// KindSettings turns a category off; KindEmergencyReview is the 72-hour
	// review of an emergency change; KindClear clears a compromise.
	KindSettings        = "SETTINGS"
	KindEmergencyReview = "EMERGENCY_REVIEW"
	KindClear           = "CLEAR"
)

// Change is one widening change a surface hands to the Gate.
type Change struct {
	Category Category
	Surface  Surface
	// Subject is what the change is about: a stable key such as a
	// connection id or "pkg@1.0.0". SubjectID is derived from it when
	// zero.
	Subject   string
	SubjectID ids.UUID
	// Summary is what a publisher sees: metadata and fingerprints, never
	// secret material (D42a (3)).
	Summary map[string]string
	// Widening names what the change weakens, one entry per field.
	Widening []string
	// Payload is the surface's input as JSON, replayed by its Applier.
	// Credentials stay sealed in it.
	Payload any
}

// Errors.
var (
	// ErrPending: the change waits for a distinct publisher.
	ErrPending = pcerr.New(pcerr.FailedPrecondition, "PROTECTED_CHANGE_PENDING",
		"this change is protected: it applies when a different person with the same permission confirms it")
	// ErrUnavailable: the category is on but the change ceremony is not
	// wired, so nothing protected applies.
	ErrUnavailable = pcerr.New(pcerr.Unavailable, "PROTECTED_CHANGES_UNAVAILABLE",
		"protected changes are not available on this server")
	ErrInvalid  = pcerr.New(pcerr.InvalidArgument, "PROTECTED_CHANGE_INVALID", "the protected change is not valid")
	ErrNotFound = pcerr.New(pcerr.NotFound, "PROTECTED_CHANGE_NOT_FOUND", "protected change not found")
	ErrState    = pcerr.New(pcerr.FailedPrecondition, "PROTECTED_CHANGE_STATE", "the protected change is not in a state that allows this")
	ErrHuman    = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can do this")
	ErrSettings = pcerr.New(pcerr.FailedPrecondition, "PROTECTED_SETTINGS_REQUEST",
		"turning a protected category off is itself a protected change: it waits for a second person")
)

// PendingError is ErrPending with the stored change and its request.
type PendingError struct {
	Change, Request ids.UUID
}

func (e *PendingError) Error() string { return e.Unwrap().Error() }

// Unwrap is ErrPending with the ids in its message.
func (e *PendingError) Unwrap() error {
	return pcerr.New(pcerr.FailedPrecondition, ErrPending.Reason(),
		fmt.Sprintf("%s (protected change %s, change request %s)", ErrPending.Message(), e.Change, e.Request))
}

// Is matches ErrPending.
func (e *PendingError) Is(target error) bool { return target == ErrPending }

// SubjectID derives a stable uuid from a surface and a subject key, for
// subjects that have none of their own (a package version).
func SubjectID(s Surface, key string) ids.UUID {
	sum := sha256.Sum256([]byte("pantherclaw.protect.subject\x00" + string(s) + "\x00" + key))
	var u ids.UUID
	copy(u[:], sum[:16])
	u[6] = u[6]&0x0f | 0x80 // version 8 (custom)
	u[8] = u[8]&0x3f | 0x80 // RFC 9562 variant
	return u
}

// digest is SHA-256 over the change's identity, payload and subject state.
func digest(org ids.OrgID, c Change, payload, subject []byte) ([]byte, error) {
	b, err := json.Marshal(struct {
		Org      string         `json:"org"`
		Category Category       `json:"category"`
		Surface  Surface        `json:"surface"`
		Subject  string         `json:"subject_id"`
		Widening []string       `json:"widening"`
		Payload  jsontext.Value `json:"payload"`
		State    []byte         `json:"subject_state"`
	}{org.String(), c.Category, c.Surface, c.SubjectID.String(), c.Widening, payload, subject}, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}

// Applier runs a stored change again in tx as its author (a re-run of the
// surface's own code; ctx is marked so the Gate lets it through).
type Applier func(ctx context.Context, tx db.TenantTx, author tenancy.Caller, payload []byte) error

type applyingKey struct{}

// applying marks ctx as the re-run of one stored change.
func applying(ctx context.Context, s Surface, subject ids.UUID) context.Context {
	return context.WithValue(ctx, applyingKey{}, string(s)+"/"+subject.String())
}

func isApplying(ctx context.Context, s Surface, subject ids.UUID) bool {
	v, _ := ctx.Value(applyingKey{}).(string)
	return v == string(s)+"/"+subject.String()
}

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }

// ReasonSubjectChanged voids a request whose subject changed since it was
// asked (D72 P5).
const ReasonSubjectChanged = "SUBJECT_CHANGED"

// ErrSubjectChanged: the subject is no longer as it was when the change
// was asked, so the confirmation would apply something nobody reviewed.
var ErrSubjectChanged = pcerr.New(pcerr.FailedPrecondition, ReasonSubjectChanged,
	"what this change is about changed since it was asked; ask again")

// VoidError is a refusal that voids the request it was confirming: the
// change ceremony voids the request with Reason instead of failing the
// confirmation.
type VoidError struct{ Reason string }

func (e *VoidError) Error() string { return e.Unwrap().Error() }

// Unwrap is the public refusal.
func (e *VoidError) Unwrap() error {
	if e.Reason == ReasonSubjectChanged {
		return ErrSubjectChanged
	}
	return pcerr.New(pcerr.FailedPrecondition, e.Reason, "the request was voided")
}

// VoidReason is the reason the request is voided with.
func (e *VoidError) VoidReason() string { return e.Reason }

type publisherKey struct{}

// Publisher is, inside the confirmed re-run of a stored change, the
// person who confirmed it: a customer consequence rule's approver (G0 M17
// D106). It reports false anywhere else, an emergency included.
func Publisher(ctx context.Context) (ids.UUID, bool) {
	p, ok := ctx.Value(publisherKey{}).(ids.UUID)
	return p, ok && !p.IsZero()
}
