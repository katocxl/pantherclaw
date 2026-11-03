// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/protect"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Why a confirmation ended (pc.custom_detection_rule_confirmations).
const (
	confirmationWithdrawn  = "withdrawn"
	confirmationSuperseded = "superseded"
	confirmationDisabled   = "disabled"
)

// confirmPayload is a held confirmation of one exact published version.
type confirmPayload struct {
	RuleID  string `json:"rule_id"`
	Version int32  `json:"version"`
	Digest  string `json:"content_digest"`
	Reason  string `json:"reason"`
}

// RegisterProtect sets the Gate's applier for custom rule confirmations
// (HR-666).
func (s *Detections) RegisterProtect(g *protect.Gate) {
	s.Protect = g
	if g != nil {
		g.Register(protect.SurfaceCustomRuleConfirm, s.ApplyConfirmation, s.confirmationState)
	}
}

func validReason(reason string) error {
	if n := utf8.RuneCountInString(reason); !utf8.ValidString(reason) || n < 1 || n > 500 {
		return ErrReason
	}
	return nil
}

// RequestCustomRuleConfirmation files the protected change that confirms
// one exact published version of a custom rule (HR-666; Business, a person
// holding detection.manage). It never applies here: a second person with
// detection.manage decides it with a security key, and only then are the
// version's alerts RULE_MATCH.
func (s *Detections) RequestCustomRuleConfirmation(ctx context.Context, ruleID string, version int32, reason string) (*protect.PendingError, error) {
	if err := validReason(reason); err != nil {
		return nil, err
	}
	c, err := detectionManager(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.custom(ctx); err != nil {
		return nil, err
	}
	if s.Protect == nil {
		return nil, protect.ErrUnavailable
	}
	var held *protect.PendingError
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.PublishedCustomRule(ctx, c.Org, ruleID)
		switch {
		case db.IsNoRows(err):
			return ErrNotPublishedVersion
		case err != nil:
			return err
		case row.Version != version || !intact(row):
			return ErrNotPublishedVersion
		}
		open, err := q.OpenCustomRuleConfirmation(ctx, c.Org, ruleID)
		switch {
		case err == nil && applies(&open, row):
			return ErrAlreadyConfirmed
		case err != nil && !db.IsNoRows(err):
			return err
		}
		digest := hex.EncodeToString(row.ContentDigest)
		held, err = s.Protect.Hold(ctx, tx, c, protect.Change{
			Category: protect.ConsequenceRules, Surface: protect.SurfaceCustomRuleConfirm, Subject: ruleID,
			Summary: map[string]string{
				"rule": ruleID, "version": itoa(int(version)), "content_digest": digest, "reason": reason, "basis": "RULE_MATCH",
			},
			Widening: []string{"custom_rule_basis"},
			Payload:  confirmPayload{RuleID: ruleID, Version: version, Digest: digest, Reason: reason},
		}, func(context.Context) error { return protect.ErrUnavailable })
		if err != nil {
			return err
		}
		if held == nil {
			return protect.ErrUnavailable // never applied without a second person
		}
		return detectionAudit(ctx, tx, c, "detection.custom_rule.confirmation_requested", row, map[string]string{
			"protected_change": held.Change.String(), "change_request": held.Request.String(), "reason": reason,
		})
	})
	if err != nil {
		return nil, err
	}
	return held, nil
}

// ApplyConfirmation is the confirmed re-run of a held confirmation (a
// protect.Applier), as its requester, in the confirming transaction: the
// rule must still be published at that version with that content, on
// Business (else CUSTOM_RULE_CHANGED), and the confirmer someone else.
func (s *Detections) ApplyConfirmation(ctx context.Context, tx db.TenantTx, author tenancy.Caller, payload []byte) error {
	var p confirmPayload
	if err := json.Unmarshal(payload, &p); err != nil || p.RuleID == "" || p.Version < 1 {
		return protect.ErrInvalid
	}
	publisher, ok := protect.Publisher(ctx)
	if !ok || publisher == author.Principal.ID {
		return ErrState
	}
	if err := author.Require(td.PermDetectionManage, td.OrgPath(author.Org)); err != nil {
		return err
	}
	if s.custom(ctx) != nil {
		return ErrRuleChanged // no longer on Business (HR-666)
	}
	q := dbq.New(tx)
	org := tx.OrgID()
	row, err := q.PublishedCustomRule(ctx, org, p.RuleID)
	switch {
	case db.IsNoRows(err):
		return ErrRuleChanged
	case err != nil:
		return err
	case row.Version != p.Version || hex.EncodeToString(row.ContentDigest) != p.Digest || !intact(row):
		return ErrRuleChanged
	}
	switch _, err := q.OpenCustomRuleConfirmation(ctx, org, p.RuleID); {
	case err == nil:
		return ErrAlreadyConfirmed
	case !db.IsNoRows(err):
		return err
	}
	change, err := q.PendingCustomRuleConfirmationOf(ctx, org, p.RuleID)
	if db.IsNoRows(err) {
		return protect.ErrNotFound
	} else if err != nil {
		return err
	}
	cf, err := q.InsertCustomRuleConfirmation(ctx, dbq.InsertCustomRuleConfirmationParams{
		OrgID: org, ID: ids.NewV7(), RuleID: row.RuleID, Version: row.Version, ContentDigest: row.ContentDigest,
		ProtectedChangeID: change, RequestedBy: author.Principal.String(),
	})
	if err != nil {
		return err
	}
	confirmer := tenancy.Caller{Subject: td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: publisher}}}
	return detectionAudit(ctx, tx, confirmer, "detection.custom_rule.confirmed", row, map[string]string{
		"confirmation": cf.ID.String(), "protected_change": change.String(), "requested_by": cf.RequestedBy, "reason": p.Reason,
	})
}

// confirmationState is what a confirmed re-run must still find: the rule's
// published version and content digest, so a new version, a disable or an
// edit in between voids the request.
func (s *Detections) confirmationState(ctx context.Context, tx db.TenantTx, payload []byte) ([]byte, error) {
	var p confirmPayload
	if err := json.Unmarshal(payload, &p); err != nil || p.RuleID == "" {
		return nil, protect.ErrInvalid
	}
	row, err := dbq.New(tx).PublishedCustomRule(ctx, tx.OrgID(), p.RuleID)
	if db.IsNoRows(err) {
		return []byte("none"), nil
	} else if err != nil {
		return nil, err
	}
	return []byte(itoa(int(row.Version)) + ":" + hex.EncodeToString(row.ContentDigest)), nil
}

// WithdrawCustomRuleConfirmation ends a rule's open confirmation at once:
// its alerts are INFERRED again (HR-666). It needs no edition, so a lapsed
// org can still take a confirmation away.
func (s *Detections) WithdrawCustomRuleConfirmation(ctx context.Context, ruleID, reason string) error {
	if err := validReason(reason); err != nil {
		return err
	}
	c, err := detectionManager(ctx)
	if err != nil {
		return err
	}
	return s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		by, why := c.Principal.String(), confirmationWithdrawn
		ended, err := q.EndCustomRuleConfirmations(ctx, dbq.EndCustomRuleConfirmationsParams{
			Reason: &why, EndedBy: &by, OrgID: c.Org, RuleID: ruleID, Versions: []int32{},
		})
		if err != nil {
			return err
		}
		if len(ended) == 0 {
			return ErrNotFound
		}
		cf := ended[0]
		return confirmationAudit(ctx, tx, c, "detection.custom_rule.confirmation_withdrawn", cf, map[string]string{
			"confirmation": cf.ID.String(), "reason": reason,
		})
	})
}

// endConfirmations ends the rule's open confirmation (of versions, or any)
// with why, and names it in the caller's audit details.
func endConfirmations(ctx context.Context, q *dbq.Queries, c tenancy.Caller, ruleID, why string, versions []int32,
	details map[string]string,
) error {
	if versions == nil {
		versions = []int32{}
	}
	by := c.Principal.String()
	ended, err := q.EndCustomRuleConfirmations(ctx, dbq.EndCustomRuleConfirmationsParams{
		Reason: &why, EndedBy: &by, OrgID: c.Org, RuleID: ruleID, Versions: versions,
	})
	if err != nil {
		return err
	}
	if len(ended) > 0 {
		details["confirmation_ended"] = ended[0].ID.String()
	}
	return nil
}

// applies reports whether cf confirms the published version row: open,
// same version, same content digest (HR-666).
func applies(cf *dbq.PcCustomDetectionRuleConfirmation, row dbq.PcCustomDetectionRule) bool {
	return cf != nil && cf.EndedAt == nil && row.State == "PUBLISHED" && cf.RuleID == row.RuleID && cf.Version == row.Version &&
		bytes.Equal(cf.ContentDigest, row.ContentDigest)
}

// intact reports whether a rule row's content still has its digest.
func intact(row dbq.PcCustomDetectionRule) bool {
	sum := sha256.Sum256([]byte(row.Content))
	return bytes.Equal(sum[:], row.ContentDigest)
}

func confirmationAudit(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name string,
	cf dbq.PcCustomDetectionRuleConfirmation, details map[string]string,
) error {
	details["version"] = itoa(int(cf.Version))
	details["content_digest"] = hex.EncodeToString(cf.ContentDigest)
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "detection_rule", ID: cf.RuleID},
		Details: details,
	})
	return err
}
