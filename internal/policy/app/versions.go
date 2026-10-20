// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Permissions of the policy use cases (the tenancy catalog's).
const (
	PermPolicyRead    = tdomain.PermPolicyRead
	PermPolicyAuthor  = tdomain.PermPolicyAuthor
	PermPolicyPublish = tdomain.PermPolicyPublish // human only
)

// Errors.
var (
	ErrVersionNotFound = pcerr.New(pcerr.NotFound, "POLICY_VERSION_NOT_FOUND", "policy version not found")
	ErrHumanOnly       = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can do this")
	// ErrNotDraft is returned by the store when the version is no longer a
	// draft (published already, or superseded).
	ErrNotDraft = pcerr.New(pcerr.FailedPrecondition, "POLICY_NOT_DRAFT", "only a draft can be published")
	// ErrPublishedChanged: the call expected another published version (C4).
	ErrPublishedChanged = pcerr.New(pcerr.FailedPrecondition, "POLICY_PUBLISHED_CHANGED",
		"another policy version was published since the one this call expected; read the published policy again")
)

// VersionInfo is one stored bundle version.
type VersionInfo struct {
	ID          ids.UUID
	BundleID    string
	Version     int
	State       string
	Bundle      []byte // canonical JSON; empty in listings
	CreatedBy   string
	CreatedAt   time.Time
	PublishedAt *time.Time
	// ContentDigest is the SHA-256 of the bundle without its version (D2);
	// empty for a version stored before the publish gate.
	ContentDigest []byte
}

// VersionStore persists bundle versions. CreateVersion and the gate's
// publication audit ev in their own transaction. Only the gate publishes
// (HR-230).
type VersionStore interface {
	GateStore
	CreateVersion(ctx context.Context, org ids.OrgID, b *domain.Bundle, createdBy string, ev *audit.Event) (ids.UUID, int, error)
	Version(ctx context.Context, org ids.OrgID, id ids.UUID) (VersionInfo, error)
	PublishedVersion(ctx context.Context, org ids.OrgID) (*VersionInfo, error)
	ListVersions(ctx context.Context, org ids.OrgID, limit int) ([]VersionInfo, error)
}

// FactCatalog returns the org's declared fact names and types.
type FactCatalog interface {
	Catalog(ctx context.Context, org ids.OrgID) (map[string]fdomain.Type, error)
}

// FactSubjects returns, by fact name, the subject type the org's provider
// declares it about.
type FactSubjects interface {
	FactSubjects(ctx context.Context, org ids.OrgID) (map[string]string, error)
}

// ActiveDefinitions returns the definitions of the org's active packages.
type ActiveDefinitions interface {
	ActiveDefinitions(ctx context.Context, org ids.OrgID) ([]*defs.Definition, error)
}

// Authorizer checks a caller's permission at a path.
type Authorizer interface {
	Require(c tapp.Caller, p tdomain.Permission, path tdomain.Path) error
}

// Versions runs the policy-version use cases of the API (HR-040..044).
// Authoring and publishing are separate permissions (F582); publishing is
// human only. A bundle is compiled against the org's active definitions
// and fact catalog when it is created, and goes through the publish gate
// (gate.go, HR-230) when it is published, so a version that no longer
// compiles, validates or passes its tests is never published.
type Versions struct {
	Store VersionStore
	Facts FactCatalog
	// Subjects, when set, refuses a rule on a consequence that reads a
	// fact no provider reports about the consequence's target (Engine).
	Subjects    FactSubjects
	Definitions ActiveDefinitions
	Authz       Authorizer
	Limits      celenv.Limits
	// Validator and Tests are the gate's ports (D7a); without either,
	// nothing is validated, tested or published (fail closed).
	Validator Validator
	Tests     TestRunner
	// Outcomes, when set, adds sample outcome changes to Diff (D8).
	Outcomes OutcomeDiffer
	// Changes holds the change requests a loosening waits in; without it a
	// loosening is refused (fail closed).
	Changes *Changes
	// OnPublished, when set, runs in every publishing transaction (D6).
	OnPublished PublishedHook
	// Editions gates publishing data scope rules (G0 M14 D11); without it
	// such a version is not published (fail closed).
	Editions Editions
}

func (v *Versions) caller(ctx context.Context, p tdomain.Permission) (tapp.Caller, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return tapp.Caller{}, err
	}
	return c, v.Authz.Require(c, p, tdomain.OrgPath(c.Org))
}

// DecodeBundle strictly decodes a submitted bundle (unknown members and
// duplicate keys are refused). The server assigns the version.
func DecodeBundle(raw []byte) (*domain.Bundle, error) {
	var b domain.Bundle
	if err := json.Unmarshal(raw, &b, json.RejectUnknownMembers(true)); err != nil {
		return nil, invalidBundle(err)
	}
	b.Version = 1
	if err := b.Validate(); err != nil {
		return nil, invalidBundle(err)
	}
	if err := b.CheckApprovalRoles(); err != nil {
		return nil, invalidBundle(err)
	}
	if err := checkVisible(&b); err != nil {
		return nil, invalidBundle(err)
	}
	return &b, nil
}

// checkVisible refuses format (Cf) and bidi-control characters in a new
// bundle's ids, rule summaries and reasons and test summaries, which the
// change-request page shows people who confirm a change (G0 M11.1 D29,
// HR-034). Stored bundles are not checked again, so they still decode.
func checkVisible(b *domain.Bundle) error {
	bad := func(what, s string) error {
		for _, r := range s {
			if unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Bidi_Control, r) {
				return fmt.Errorf("%w: %s has an invisible or bidi control character (U+%04X)", domain.ErrInvalid, what, r)
			}
		}
		return nil
	}
	errs := []error{bad("the bundle id", b.ID)}
	for _, r := range b.Rules {
		errs = append(errs, bad("rule id "+r.ID, r.ID), bad("rule "+r.ID+" summary", r.Summary), bad("rule "+r.ID+" reason", r.Reason))
	}
	for _, tc := range b.Tests {
		errs = append(errs, bad("test id "+tc.ID, tc.ID), bad("test "+tc.ID+" summary", tc.Summary))
	}
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func invalidBundle(err error) error {
	return pcerr.Wrap(err, pcerr.InvalidArgument, "POLICY_INVALID", strings.TrimPrefix(err.Error(), domain.ErrInvalid.Error()+": "))
}

// compile type-checks b against the org's definitions and facts now.
func (v *Versions) compile(ctx context.Context, org ids.OrgID, b *domain.Bundle) error {
	catalog, err := v.Facts.Catalog(ctx, org)
	if err != nil {
		return err
	}
	ds, err := v.Definitions.ActiveDefinitions(ctx, org)
	if err != nil {
		return err
	}
	var subjects map[string]string
	if v.Subjects != nil {
		if subjects, err = v.Subjects.FactSubjects(ctx, org); err != nil {
			return err
		}
	}
	if _, err := (&Engine{Limits: v.Limits, Facts: catalog, Subjects: subjects}).Compile(b, ds); err != nil {
		return pcerr.Wrap(err, pcerr.InvalidArgument, "POLICY_DOES_NOT_COMPILE", err.Error())
	}
	return nil
}

// Create stores a new draft version of a bundle (policy.author at the org).
func (v *Versions) Create(ctx context.Context, raw []byte) (VersionInfo, error) {
	return v.CreateExpecting(ctx, raw, nil)
}

// CreateExpecting creates a version as Create does, and with expected set
// only while the published version is *expected (the zero id: none is
// published), else ErrPublishedChanged. Creating changes no published
// version, so a read is enough; the publish checks again under a lock.
func (v *Versions) CreateExpecting(ctx context.Context, raw []byte, expected *ids.UUID) (VersionInfo, error) {
	return v.CreateExpectingWith(ctx, raw, expected, nil)
}

// CreateExpectingWith is CreateExpecting with details added to the
// version's policy.version_created audit record, written in the same
// transaction as the version (a reference pack names itself, G0 M11
// part 2 D41, D71 G11).
func (v *Versions) CreateExpectingWith(ctx context.Context, raw []byte, expected *ids.UUID, details map[string]string) (VersionInfo, error) {
	c, err := v.caller(ctx, PermPolicyAuthor)
	if err != nil {
		return VersionInfo{}, err
	}
	if expected != nil {
		cur, err := v.Store.PublishedVersion(ctx, c.Org)
		if err != nil {
			return VersionInfo{}, err
		}
		if (cur == nil && !expected.IsZero()) || (cur != nil && cur.ID != *expected) {
			return VersionInfo{}, ErrPublishedChanged
		}
	}
	b, err := DecodeBundle(raw)
	if err != nil {
		return VersionInfo{}, err
	}
	if err := v.compile(ctx, c.Org, b); err != nil {
		return VersionInfo{}, err
	}
	ev := &audit.Event{
		Name: "policy.version_created", Actor: c.Actor(), Outcome: audit.Success,
		Object: &audit.Object{Type: "policy", ID: b.ID}, Details: details,
	}
	id, _, err := v.Store.CreateVersion(ctx, c.Org, b, c.Principal.String(), ev)
	if errors.Is(err, domain.ErrInvalid) {
		return VersionInfo{}, invalidBundle(err)
	}
	if err != nil {
		return VersionInfo{}, err
	}
	return v.Store.Version(ctx, c.Org, id)
}

func decodeStored(raw []byte) (*domain.Bundle, error) {
	var b domain.Bundle
	if err := json.Unmarshal(raw, &b, json.RejectUnknownMembers(true)); err != nil {
		return nil, err
	}
	return &b, b.Validate()
}

// Published returns the published version, or nil (policy.read at the org).
func (v *Versions) Published(ctx context.Context) (*VersionInfo, error) {
	c, err := v.caller(ctx, PermPolicyRead)
	if err != nil {
		return nil, err
	}
	return v.Store.PublishedVersion(ctx, c.Org)
}

// Get returns one version with its bundle (policy.read at the org).
func (v *Versions) Get(ctx context.Context, id ids.UUID) (VersionInfo, error) {
	c, err := v.caller(ctx, PermPolicyRead)
	if err != nil {
		return VersionInfo{}, err
	}
	return v.Store.Version(ctx, c.Org, id)
}

// List lists versions, newest first, without bundles (policy.read).
func (v *Versions) List(ctx context.Context, limit int) ([]VersionInfo, error) {
	c, err := v.caller(ctx, PermPolicyRead)
	if err != nil {
		return nil, err
	}
	return v.Store.ListVersions(ctx, c.Org, limit)
}
