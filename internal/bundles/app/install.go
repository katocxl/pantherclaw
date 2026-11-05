// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"regexp"
	"strconv"
	"time"

	autoapp "github.com/katocxl/pantherclaw/internal/automations/app"
	bdomain "github.com/katocxl/pantherclaw/internal/bundles/domain"
	"github.com/katocxl/pantherclaw/internal/bundles/format"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// Item is what one bundle item became.
type Item struct {
	Kind, Name, SHA256, TargetType, TargetID, State string
}

// Install is one bundle install.
type Install struct {
	ID           ids.UUID
	Publisher    string
	Name         string
	Version      string
	BundleSHA256 string
	PinID        *ids.UUID
	State        string
	InstalledBy  ids.UUID
	CreatedAt    time.Time
	FinishedAt   *time.Time
	FailureCode  string
	Items        []Item
}

// Install errors.
var (
	errAlreadyInstalled = pcerr.New(pcerr.AlreadyExists, "BUNDLE_ALREADY_INSTALLED", "this version of the bundle is already installed")
	errNoUseCase        = pcerr.New(pcerr.FailedPrecondition, "BUNDLE_KIND_UNAVAILABLE", "this server cannot draft that item kind")
)

// InstallBundle verifies a .pcbundle file and drafts its items (D1082,
// FD8, FQ37-2; HR-796..798): a person holding bundle.install, signed in as
// themselves. Decode reads it strictly as data; it must verify against an
// ACTIVE pin of its publisher allowing every item kind; a revoked version,
// an older version (ROLLBACK) and the same version with other contents
// (EQUIVOCATION) are refused. Each item goes to its kind's DRAFT path in
// one transaction with the caller's own permission and edition checks, and
// nothing is activated, published or enabled. A refusal after decode is
// recorded as a FAILED install.
func (s *Service) InstallBundle(ctx context.Context, raw []byte) (Install, error) {
	c, err := person(ctx, bdomain.PermBundleInstall)
	if err != nil {
		return Install{}, err
	}
	b, err := format.Decode(raw)
	if err != nil {
		err = bdomain.FormatError(err)
		s.recordUndecodable(ctx, c, raw, err)
		return Install{}, err
	}
	id := ids.NewV7()
	var out Install
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = s.installTx(ctx, tx, c, id, b)
		return err
	})
	if err == nil {
		return out, nil
	}
	err = bdomain.FormatError(err)
	if ferr := s.recordFailed(ctx, c, id, b, err); ferr != nil {
		s.log.ErrorContext(ctx, "bundles.install_failed_record", pclog.Err(ferr))
	}
	return Install{}, err
}

func (s *Service) installTx(ctx context.Context, tx db.TenantTx, c tenancy.Caller, id ids.UUID, b format.Bundle) (Install, error) {
	q := dbq.New(tx)
	m := b.Manifest
	now, err := q.DBNow(ctx)
	if err != nil {
		return Install{}, err
	}
	rows, err := q.ActivePublisherPins(ctx, c.Org, m.Publisher)
	if err != nil {
		return Install{}, err
	}
	pins := make([]format.PinnedKey, 0, len(rows))
	byKID := map[string]ids.UUID{}
	for _, r := range rows {
		k := format.PinnedKey{Publisher: m.Publisher, KID: r.Kid, PublicKey: ed25519.PublicKey(r.PublicKey)}
		for _, kind := range r.AllowedKinds {
			k.AllowedKinds = append(k.AllowedKinds, format.Kind(kind))
		}
		pins = append(pins, k)
		byKID[r.Kid] = r.ID
	}
	if err := format.Verify(b, pins, now); err != nil {
		return Install{}, err
	}
	kid, _, err := jws.Unverified(b.Signature)
	if err != nil {
		return Install{}, err
	}
	pinID, ok := byKID[kid]
	if !ok {
		return Install{}, format.ErrUnpinned
	}
	name := m.Name
	revoked, err := q.BundleRevokedVersions(ctx, c.Org, &name)
	if err != nil {
		return Install{}, err
	}
	for _, v := range revoked {
		if format.CompareVersions(m.Version, v) <= 0 {
			return Install{}, bdomain.ErrBundleRevoked
		}
	}
	st, err := q.LockBundleState(ctx, c.Org, m.Name)
	switch {
	case db.IsNoRows(err):
	case err != nil:
		return Install{}, err
	default:
		switch cmp := format.CompareVersions(m.Version, st.MaxVersion); {
		case cmp < 0:
			return Install{}, bdomain.ErrRollback
		case cmp == 0 && st.MaxSha256 != b.SHA256:
			return Install{}, bdomain.ErrEquivocation
		case cmp == 0:
			return Install{}, errAlreadyInstalled
		}
	}
	if err := q.InsertBundleInstall(ctx, dbq.InsertBundleInstallParams{
		OrgID: c.Org, ID: id, Publisher: m.Publisher, Name: m.Name, Version: m.Version, BundleSha256: b.SHA256,
		InstalledBy: c.Principal.ID,
	}); err != nil {
		return Install{}, err
	}
	for i := range b.Items {
		it, err := s.draft(ctx, tx, c, m, &b.Items[i])
		if err != nil {
			return Install{}, err
		}
		if err := q.InsertBundleItem(ctx, dbq.InsertBundleItemParams{
			OrgID: c.Org, InstallID: id, Kind: it.Kind, Name: it.Name, Sha256: it.SHA256, TargetType: it.TargetType,
			TargetID: it.TargetID, State: it.State,
		}); err != nil {
			return Install{}, err
		}
	}
	if n, err := q.FinishBundleInstall(ctx, &pinID, c.Org, id); err != nil {
		return Install{}, err
	} else if n == 0 {
		return Install{}, bdomain.ErrInstallState
	}
	if err := q.UpsertBundleState(ctx, dbq.UpsertBundleStateParams{
		OrgID: c.Org, Publisher: m.Publisher, Name: m.Name, MaxVersion: m.Version, MaxSha256: b.SHA256,
	}); err != nil {
		return Install{}, err
	}
	if err := record(ctx, tx, c.Actor(), audit.Success, auditkind.BundleInstalled, "bundle_install", id.String(), map[string]string{
		"publisher": m.Publisher, "bundle": m.Name, "version": m.Version, "bundle_sha256": b.SHA256, "kid": kid,
		"pin": pinID.String(), "items": strconv.Itoa(len(b.Items)),
	}); err != nil {
		return Install{}, err
	}
	return getInstall(ctx, q, c.Org, id, true)
}

// draft hands one item to its kind's DRAFT path (D1082, HR-798). Nothing
// it calls activates, publishes or enables anything.
func (s *Service) draft(ctx context.Context, tx db.TenantTx, c tenancy.Caller, m format.Manifest, it *format.Item) (Item, error) {
	out := Item{
		Kind: string(it.Kind), Name: it.Name, SHA256: it.SHA256, TargetType: bdomain.TargetTemplate, TargetID: it.Name,
		State: bdomain.ItemTemplate,
	}
	switch it.Kind {
	case format.KindToolPackage:
		// A package draft like the OpenAPI importer's (FD8): nothing loads
		// on the server. A person reviews the package file, signs it with an
		// org package key (ext. names are not reserved) and imports it; a
		// revocation withdraws that name@version.
		out.TargetType, out.TargetID, out.State = bdomain.TargetPackageDraft, it.Package.Name+"@"+it.Package.Version, bdomain.ItemDrafted
	case format.KindDetectionRule:
		if s.deps.Rules == nil {
			return Item{}, errNoUseCase
		}
		rid, err := s.deps.Rules.CreateBundleRuleTx(ctx, tx, string(it.Data), m.Publisher)
		if err != nil {
			return Item{}, err
		}
		out.TargetType, out.TargetID, out.State = bdomain.TargetCustomRule, rid.String(), bdomain.ItemDrafted
	case format.KindPlaybook:
		if s.deps.Automations == nil {
			return Item{}, errNoUseCase
		}
		name, err := format.PlaybookAutomationName(it.Name)
		if err != nil {
			return Item{}, err
		}
		a, _, err := s.deps.Automations.CreateDraftTx(ctx, tx, autoapp.Draft{
			Name: name, Purpose: it.Playbook.Purpose, Kind: it.Playbook.WorkKind, Owner: c.Principal.ID, Definition: it.Data,
		})
		if errors.Is(err, autoapp.ErrNameTaken) {
			return Item{}, pcerr.Wrap(err, pcerr.AlreadyExists, "BUNDLE_AUTOMATION_NAME_TAKEN", "an automation named "+name+" exists")
		} else if err != nil {
			return Item{}, err
		}
		out.TargetType, out.TargetID, out.State = bdomain.TargetAutomation, a.ID.String(), bdomain.ItemDrafted
	case format.KindOpenAPISpec, format.KindFactsDeclaration, format.KindChannelTemplate:
		// Recorded as a template: no draft path exists for a fact provider
		// declaration, an OpenAPI spec serves only its package's simulator,
		// and an admin creates a channel and its secrets through the
		// existing flow (HR-801).
	default:
		return Item{}, format.ErrKind
	}
	return out, nil
}

var failureCodeRe = regexp.MustCompile(`^[A-Z0-9_]{1,64}$`)

func failureCode(err error) string {
	if r := pcerr.ReasonOf(err); failureCodeRe.MatchString(r) {
		return r
	}
	return "INTERNAL"
}

// recordFailed records a refused install of a decoded bundle.
func (s *Service) recordFailed(ctx context.Context, c tenancy.Caller, id ids.UUID, b format.Bundle, cause error) error {
	code := failureCode(cause)
	m := b.Manifest
	return s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		if err := dbq.New(tx).InsertFailedBundleInstall(ctx, dbq.InsertFailedBundleInstallParams{
			OrgID: c.Org, ID: id, Publisher: m.Publisher, Name: m.Name, Version: m.Version, BundleSha256: b.SHA256,
			InstalledBy: c.Principal.ID, FailureCode: &code,
		}); err != nil {
			return err
		}
		return record(ctx, tx, c.Actor(), audit.Failure, auditkind.BundleInstallFailed, "bundle_install", id.String(), map[string]string{
			"publisher": m.Publisher, "bundle": m.Name, "version": m.Version, "bundle_sha256": b.SHA256, "code": code,
		})
	})
}

// recordUndecodable audits a file that is not a bundle: there is no
// publisher, name or version to record an install under.
func (s *Service) recordUndecodable(ctx context.Context, c tenancy.Caller, raw []byte, cause error) {
	sum := format.Fingerprint(raw)
	err := s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		return record(ctx, tx, c.Actor(), audit.Failure, auditkind.BundleInstallFailed, "bundle_file", sum, map[string]string{
			"bundle_sha256": sum, "code": failureCode(cause), "bytes": strconv.Itoa(len(raw)),
		})
	})
	if err != nil {
		s.log.ErrorContext(ctx, "bundles.install_failed_record", pclog.Err(err))
	}
}

// GetInstall returns one install and its items (bundle.read).
func (s *Service) GetInstall(ctx context.Context, id ids.UUID) (Install, error) {
	c, err := reader(ctx)
	if err != nil {
		return Install{}, err
	}
	var out Install
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = getInstall(ctx, dbq.New(tx), c.Org, id, true)
		return err
	}, db.ReadOnly())
	return out, err
}

// ListInstalls returns one page of installs by id (bundle.read).
func (s *Service) ListInstalls(ctx context.Context, size int32, token string) ([]Install, string, error) {
	c, err := reader(ctx)
	if err != nil {
		return nil, "", err
	}
	pr, err := page.Parse(size, token)
	if err != nil {
		return nil, "", err
	}
	var after *ids.UUID
	if !pr.After.IsZero() {
		after = &pr.After
	}
	var out []Install
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListBundleInstalls(ctx, c.Org, after, pr.Limit())
		if err != nil {
			return err
		}
		for _, r := range rows {
			out = append(out, installOf(dbq.GetBundleInstallRow(r)))
		}
		return nil
	}, db.ReadOnly())
	if err != nil {
		return nil, "", err
	}
	out, next := page.Finish(pr, out, func(i Install) ids.UUID { return i.ID })
	return out, next, nil
}

func getInstall(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID, items bool) (Install, error) {
	r, err := q.GetBundleInstall(ctx, org, id)
	if db.IsNoRows(err) {
		return Install{}, bdomain.ErrNotFound
	} else if err != nil {
		return Install{}, err
	}
	out := installOf(r)
	if items {
		rows, err := q.ListBundleItems(ctx, org, id)
		if err != nil {
			return Install{}, err
		}
		for _, it := range rows {
			out.Items = append(out.Items, Item{
				Kind: it.Kind, Name: it.Name, SHA256: it.Sha256, TargetType: it.TargetType, TargetID: it.TargetID, State: it.State,
			})
		}
	}
	return out, nil
}

func installOf(r dbq.GetBundleInstallRow) Install {
	i := Install{
		ID: r.ID, Publisher: r.Publisher, Name: r.Name, Version: r.Version, BundleSHA256: r.BundleSha256, PinID: r.PinID,
		State: r.State, InstalledBy: r.InstalledBy, CreatedAt: r.CreatedAt, FinishedAt: r.FinishedAt,
	}
	if r.FailureCode != nil {
		i.FailureCode = *r.FailureCode
	}
	return i
}
