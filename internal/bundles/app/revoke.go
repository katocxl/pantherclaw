// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	bdomain "github.com/katocxl/pantherclaw/internal/bundles/domain"
	"github.com/katocxl/pantherclaw/internal/bundles/format"
	defsapp "github.com/katocxl/pantherclaw/internal/definitions/app"
	ddomain "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// NoticeType is the notification of a revoked install (D1083).
const NoticeType = auditkind.BundleRevoked

// RevokeInstall revokes an install and every installed version of its
// bundle up to it, which install then refuses (a person holding
// bundle.install; D1083, HR-799). Installing a later version resumes.
func (s *Service) RevokeInstall(ctx context.Context, id ids.UUID) ([]ids.UUID, error) {
	c, err := person(ctx, bdomain.PermBundleInstall)
	if err != nil {
		return nil, err
	}
	var out []ids.UUID
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		in, err := getInstall(ctx, q, c.Org, id, false)
		if err != nil {
			return err
		}
		if in.State != bdomain.InstallInstalled {
			return bdomain.ErrInstallState
		}
		name, version := in.Name, in.Version
		if _, err := q.InsertBundleRevocation(ctx, dbq.InsertBundleRevocationParams{
			OrgID: c.Org, ID: ids.NewV7(), Publisher: in.Publisher, Scope: format.ScopeBundle, Name: &name, MaxVersion: &version,
			Source: bdomain.SourceAdmin,
		}); err != nil {
			return err
		}
		out, err = s.revokeBundleTx(ctx, tx, c.Actor(), name, version, bdomain.SourceAdmin)
		return err
	})
	return out, err
}

// Applied is what a revocation statement did.
type Applied struct {
	Installs, Pins []ids.UUID
	// AlreadyApplied is true when the same statement was applied before.
	AlreadyApplied bool
}

// SubmitRevocation applies a publisher-signed revocation statement (a
// person holding bundle.install; D1083, HR-800).
func (s *Service) SubmitRevocation(ctx context.Context, statement string) (Applied, error) {
	c, err := person(ctx, bdomain.PermBundleInstall)
	if err != nil {
		return Applied{}, err
	}
	return s.applyStatement(ctx, c.Org, c.Actor(), statement, bdomain.SourceStatement)
}

// applyStatement verifies a statement against every key the org has ever
// pinned for its publisher and applies it in one transaction, once.
func (s *Service) applyStatement(ctx context.Context, org ids.OrgID, actor evdomain.Actor, statement, source string) (Applied, error) {
	kid, _, err := jws.Unverified(strings.TrimSpace(statement))
	if err != nil {
		return Applied{}, bdomain.FormatError(fmt.Errorf("%w: %w", format.ErrRevocation, err))
	}
	publisher, ok := format.KIDPublisher(kid)
	if !ok {
		return Applied{}, bdomain.FormatError(format.ErrRevocation)
	}
	var out Applied
	err = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		rows, err := q.PublisherKeysEver(ctx, org, publisher)
		if err != nil {
			return err
		}
		keys := make([]format.PinnedKey, 0, len(rows))
		for _, r := range rows {
			keys = append(keys, format.PinnedKey{Publisher: publisher, KID: r.Kid, PublicKey: ed25519.PublicKey(r.PublicKey)})
		}
		v, err := format.VerifyRevocation(statement, keys, now)
		if err != nil {
			return err
		}
		sha := v.SHA256
		signed := time.Unix(v.IssuedAt, 0).UTC()
		p := dbq.InsertBundleRevocationParams{
			OrgID: org, ID: ids.NewV7(), Publisher: v.Publisher, StatementSha256: &sha, Scope: v.Scope, SignedAt: &signed, Source: source,
		}
		if v.Scope == format.ScopeKey {
			p.Kid = &v.Kid
		} else {
			p.Name, p.MaxVersion = &v.Name, &v.MaxVersion
		}
		n, err := q.InsertBundleRevocation(ctx, p)
		if err != nil {
			return err
		}
		if n == 0 {
			out.AlreadyApplied = true
			return nil
		}
		if v.Scope == format.ScopeKey {
			pins, err := q.LivePinsOfKid(ctx, org, v.Kid)
			if err != nil {
				return err
			}
			reason := bdomain.ReasonPublisherRevoked
			for _, id := range pins {
				if _, err := q.RevokePublisherPin(ctx, &reason, org, id); err != nil {
					return err
				}
				if err := record(ctx, tx, actor, audit.Success, auditkind.PublisherPinRevoked, "publisher_pin", id.String(), map[string]string{
					"publisher": v.Publisher, "kid": v.Kid, "reason": reason, "source": source, "statement_sha256": sha,
				}); err != nil {
					return err
				}
			}
			out.Pins = pins
			out.Installs, err = s.revokeKidTx(ctx, tx, actor, v.Kid, source)
			return err
		}
		out.Installs, err = s.revokeBundleTx(ctx, tx, actor, v.Name, v.MaxVersion, source)
		return err
	})
	if err != nil {
		return Applied{}, bdomain.FormatError(err)
	}
	return out, nil
}

// revokeKidTx revokes every install a kid signed.
func (s *Service) revokeKidTx(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, kid, source string) ([]ids.UUID, error) {
	installs, err := dbq.New(tx).InstalledOfKid(ctx, tx.OrgID(), kid)
	if err != nil {
		return nil, err
	}
	return s.revokeInstallsTx(ctx, tx, actor, installs, source)
}

// revokeBundleTx revokes every installed version of a bundle up to
// maxVersion.
func (s *Service) revokeBundleTx(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, name, maxVersion, source string) ([]ids.UUID, error) {
	rows, err := dbq.New(tx).InstalledOfName(ctx, tx.OrgID(), name)
	if err != nil {
		return nil, err
	}
	var installs []ids.UUID
	for _, r := range rows {
		if format.CompareVersions(r.Version, maxVersion) <= 0 {
			installs = append(installs, r.ID)
		}
	}
	return s.revokeInstallsTx(ctx, tx, actor, installs, source)
}

// revokeInstallsTx stops installs at once, in the caller's transaction
// (D1083, HR-799): each install and its items REVOKED, its package
// versions withdrawn (ACTIVE and STALE quarantined, the others retired, as
// org-key COMPROMISED does), its custom rule versions disabled, its
// automations paused (AUTHORITY_REVOKED), an audit event and a
// notification to the org's Org Admins and Security Admins.
func (s *Service) revokeInstallsTx(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, installs []ids.UUID, source string) ([]ids.UUID, error) {
	q := dbq.New(tx)
	org := tx.OrgID()
	var out []ids.UUID
	contained := false
	for _, id := range installs {
		in, err := getInstall(ctx, q, org, id, false)
		if err != nil {
			return nil, err
		}
		n, err := q.RevokeBundleInstall(ctx, org, id)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			continue
		}
		items, err := q.RevokeBundleItems(ctx, org, id)
		if err != nil {
			return nil, err
		}
		reason := "bundle " + in.Name + " " + in.Version + " revoked (" + source + ")"
		stopped := map[string]int{}
		for _, it := range items {
			switch it.TargetType {
			case bdomain.TargetPackageDraft:
				if !contained {
					// The containment row the epoch raise needs, as the MCP
					// catalog revoke makes it.
					if err := q.InsertContainment(ctx, org); err != nil {
						return nil, err
					}
					contained = true
				}
				k, err := s.withdrawPackage(ctx, tx, actor, id, it.TargetID)
				if err != nil {
					return nil, err
				}
				stopped["package_versions"] += k
			case bdomain.TargetCustomRule:
				rid, err := ids.ParseUUID(it.TargetID)
				if err != nil {
					return nil, err
				}
				if s.deps.Rules == nil {
					return nil, errNoUseCase
				}
				if ok, err := s.deps.Rules.DisableCustomRuleTx(ctx, tx, actor, rid, reason); err != nil {
					return nil, err
				} else if ok {
					stopped["custom_rules"]++
				}
			case bdomain.TargetAutomation:
				aid, err := ids.ParseUUID(it.TargetID)
				if err != nil {
					return nil, err
				}
				if s.deps.Automations == nil {
					return nil, errNoUseCase
				}
				paused, err := s.deps.Automations.Pause(ctx, tx.Pgx(), org, autodomain.PauseSelector{Automations: []ids.UUID{aid}},
					autodomain.PauseAuthorityRevoked)
				if err != nil {
					return nil, err
				}
				stopped["automations_paused"] += len(paused)
			}
		}
		if err := record(ctx, tx, actor, audit.Success, auditkind.BundleRevoked, "bundle_install", id.String(), map[string]string{
			"publisher": in.Publisher, "bundle": in.Name, "version": in.Version, "source": source,
			"items": fmt.Sprint(len(items)), "package_versions": fmt.Sprint(stopped["package_versions"]),
			"custom_rules": fmt.Sprint(stopped["custom_rules"]), "automations_paused": fmt.Sprint(stopped["automations_paused"]),
		}); err != nil {
			return nil, err
		}
		if err := s.notify(ctx, tx, in, source); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

// withdrawPackage moves the org's versions of a drafted package
// (name@version) as revoking a compromised org key does.
func (s *Service) withdrawPackage(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, install ids.UUID, target string) (int, error) {
	name, version, ok := strings.Cut(target, "@")
	if !ok {
		return 0, fmt.Errorf("bundles: package draft target %q", target)
	}
	if s.deps.Versions == nil {
		return 0, errNoUseCase
	}
	rows, err := dbq.New(tx).BundlePackageVersions(ctx, tx.OrgID(), name, version)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, v := range rows {
		from := ddomain.State(v.State)
		to, move := defsapp.Withdrawn(from)
		if !move {
			continue
		}
		if err := s.deps.Versions.TransitionTx(ctx, tx, v.Package, v.Version, from, to, &audit.Event{
			Name: auditkind.PackageTransitioned, Actor: actor, Outcome: audit.Success,
			Object:  &audit.Object{Type: "package_version", ID: v.Package + "@" + v.Version},
			Details: map[string]string{"from": v.State, "to": string(to), "bundle_install": install.String()},
		}); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// notify tells the org's Org Admins and Security Admins (D1083).
func (s *Service) notify(ctx context.Context, tx db.TenantTx, in Install, source string) error {
	if s.deps.Notify == nil {
		return nil
	}
	people, err := dbq.New(tx).BundleNoticeRecipients(ctx, tx.OrgID())
	if err != nil {
		return err
	}
	_, err = s.deps.Notify.Enqueue(ctx, tx, napp.Message{
		Org: tx.OrgID(), Type: NoticeType, Personal: people, DedupeKey: "bundle_revoked:" + in.ID.String(),
		Params: map[string]string{"publisher": in.Publisher, "bundle": in.Name, "version": in.Version, "source": source},
	})
	return err
}
