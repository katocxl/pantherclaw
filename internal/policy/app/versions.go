// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"strings"
	"time"

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
}

// VersionStore persists bundle versions. CreateVersion and Publish audit ev
// in their own transaction.
type VersionStore interface {
	CreateVersion(ctx context.Context, org ids.OrgID, b *domain.Bundle, createdBy string, ev *audit.Event) (ids.UUID, int, error)
	Publish(ctx context.Context, org ids.OrgID, id ids.UUID, publishedBy string, ev *audit.Event) error
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
// and fact catalog when it is created and again when it is published, so a
// version that no longer compiles is never published.
type Versions struct {
	Store VersionStore
	Facts FactCatalog
	// Subjects, when set, refuses a rule on a consequence that reads a
	// fact no provider reports about the consequence's target (Engine).
	Subjects    FactSubjects
	Definitions ActiveDefinitions
	Authz       Authorizer
	Limits      celenv.Limits
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
	return &b, nil
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
	c, err := v.caller(ctx, PermPolicyAuthor)
	if err != nil {
		return VersionInfo{}, err
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
		Object: &audit.Object{Type: "policy", ID: b.ID},
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

// Publish makes a draft the org's published version (policy.publish at
// the org, human only), after compiling it again.
func (v *Versions) Publish(ctx context.Context, id ids.UUID) (VersionInfo, error) {
	c, err := v.caller(ctx, PermPolicyPublish)
	if err != nil {
		return VersionInfo{}, err
	}
	if !c.Human() {
		return VersionInfo{}, ErrHumanOnly
	}
	cur, err := v.Store.Version(ctx, c.Org, id)
	if err != nil {
		return VersionInfo{}, err
	}
	b, err := decodeStored(cur.Bundle)
	if err != nil {
		return VersionInfo{}, err
	}
	if err := v.compile(ctx, c.Org, b); err != nil {
		return VersionInfo{}, err
	}
	ev := &audit.Event{
		Name: "policy.published", Actor: c.Actor(), Outcome: audit.Success,
		Object: &audit.Object{Type: "policy", ID: cur.BundleID},
	}
	if err := v.Store.Publish(ctx, c.Org, id, c.Principal.String(), ev); err != nil {
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
