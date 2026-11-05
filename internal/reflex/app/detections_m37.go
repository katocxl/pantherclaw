// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/sha256"
	"slices"

	"github.com/katocxl/pantherclaw/internal/detection/rules"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Publisher bundle rules (G0 M37 D1082, D1083): a bundle's detection_rule
// becomes a DRAFT custom rule through the same checks as CreateCustomRule,
// with an ext.<publisher>.<name> id that only this path stores; publishing
// it keeps the two-person confirmation. A revocation disables it.

var errExtensionRule = invalidRule("a rule id starting with ext. comes only from an installed publisher bundle")

// CreateBundleRuleTx stores a DRAFT version of a bundle's custom rule in
// the caller's transaction: the caller needs what CreateCustomRule needs
// (detection.manage as a person, the Business edition), and the rule id
// must be ext.<publisher>.<name> of the bundle's publisher.
func (s *Detections) CreateBundleRuleTx(ctx context.Context, tx db.TenantTx, content, publisher string) (ids.UUID, error) {
	c, err := detectionManager(ctx)
	if err != nil {
		return ids.UUID{}, err
	}
	if err := s.custom(ctx); err != nil {
		return ids.UUID{}, err
	}
	cr, err := s.compile(content)
	if err != nil {
		return ids.UUID{}, err
	}
	if pub, ok := rules.ExtensionPublisher(cr.Rule.ID); !ok || pub != publisher {
		return ids.UUID{}, invalidRule("a bundle rule's id is ext." + publisher + ".<name>")
	}
	sum := sha256.Sum256([]byte(content))
	row, err := dbq.New(tx).InsertCustomRule(ctx, dbq.InsertCustomRuleParams{
		OrgID: c.Org, ID: ids.NewV7(), RuleID: cr.Rule.ID, Content: content, ContentDigest: sum[:], CreatedBy: c.Principal.ID,
	})
	if err != nil {
		return ids.UUID{}, err
	}
	return row.ID, detectionAudit(ctx, tx, c, auditkind.DetectionRuleCreated, row, map[string]string{"source": "bundle"})
}

// DisableCustomRuleTx disables a custom rule version in the caller's
// transaction for a revocation (D1083): no person is the disabler, and its
// confirmation ends as DisableCustomRule's does. It reports whether the
// version was live (DRAFT or PUBLISHED).
func (s *Detections) DisableCustomRuleTx(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, id ids.UUID, reason string) (bool, error) {
	q := dbq.New(tx)
	org := tx.OrgID()
	n, err := q.DisableCustomRule(ctx, dbq.DisableCustomRuleParams{Reason: &reason, OrgID: org, ID: id})
	if err != nil || n == 0 {
		return false, err
	}
	row, err := q.GetCustomRule(ctx, org, id)
	if err != nil {
		return false, err
	}
	why, by := confirmationDisabled, actor.Type+":"+actor.ID
	ended, err := q.EndCustomRuleConfirmations(ctx, dbq.EndCustomRuleConfirmationsParams{
		Reason: &why, EndedBy: &by, OrgID: org, RuleID: row.RuleID, Versions: []int32{row.Version},
	})
	if err != nil {
		return false, err
	}
	details := map[string]string{"version": itoa(int(row.Version)), "reason": reason}
	if len(ended) > 0 {
		details["confirmation_ended"] = ended[0].ID.String()
	}
	_, err = audit.Record(ctx, tx, audit.Event{
		Name: auditkind.DetectionRuleDisabled, Actor: actor, Outcome: audit.Success,
		Object: &audit.Object{Type: "detection_rule", ID: row.RuleID}, Details: details,
	})
	return true, err
}

// ErrBundleRevoked refuses publishing a custom rule version a revoked
// publisher bundle drafted, or confirming its publication: revoked stays
// off (D1083a, HR-799).
var ErrBundleRevoked = pcerr.New(pcerr.FailedPrecondition, "BUNDLE_REVOKED",
	"the rule version came from a revoked bundle and stays off")

// bundleRevoked reports whether a REVOKED bundle item drafted the custom
// rule version row. It locks the item rows, so a revocation running at the
// same time waits; callers check before they lock the rule.
func bundleRevoked(ctx context.Context, q *dbq.Queries, org ids.OrgID, row ids.UUID) (bool, error) {
	states, err := q.LockBundleTargetStates(ctx, org, "custom_rule", row.String())
	if err != nil {
		return false, err
	}
	return slices.Contains(states, "REVOKED"), nil
}
