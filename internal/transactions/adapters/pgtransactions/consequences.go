// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgtransactions

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"fmt"
	"maps"
	"slices"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// Consequences of a confirmed action (G0 M8 W1c, HR-206, coordinator
// decision 2026-10-13). When the verifier of an action whose decision
// predicted consequences confirms it, the server opens a transaction for
// each consequence and environment: never dispatched, decided with the
// action (ALLOW, CONSEQUENCE), linked to it (consequence), and verified by
// a task of purpose consequence. The confirming read's captured fields fill
// the consequence's params (a merge's commit), with the environment.

// consequenceDelay is how long after the action's confirmation the
// consequence is first read: a deployment appears once its workflow runs.
const consequenceDelay = 5

// openConsequences opens the consequences of transaction parent, whose
// effect was just confirmed (by the verifier v of definition digest, with
// the fields of what it observed, or by a person, with those of the
// transaction's newest observation that holds them). A predicted
// consequence that cannot be verified is audited as such, never left
// silently (#349 review): nothing captured to find it by, no environment,
// no verifier that finds it. UNKNOWN consequences are audited apart, by
// auditUnknownConsequences.
func openConsequences(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, parent ids.UUID, digest string,
	v *defs.VerifierSpec, fields map[string]string, actor evdomain.Actor,
) error {
	if len(v.Capture) == 0 {
		return nil
	}
	rows, err := q.PredictedConsequences(ctx, org, parent)
	if err != nil || len(rows) == 0 {
		return err
	}
	captured := map[string]string{}
	for name, ptr := range v.Capture {
		val, ok := fields[ptr]
		if !ok || val == "" {
			for _, c := range rows {
				if err := notVerified(ctx, tx, parent, c.Operation, "NOTHING_CAPTURED", actor); err != nil {
					return err
				}
			}
			return nil
		}
		captured[name] = val
	}
	for _, c := range rows {
		sib, err := q.SiblingDefinitionWithDigest(ctx, org, digest, c.Operation)
		if db.IsNoRows(err) {
			if err := notVerified(ctx, tx, parent, c.Operation, "NO_DEFINITION", actor); err != nil {
				return err
			}
			continue
		} else if err != nil {
			return err
		}
		d, err := definitionOf(sib.Canonical)
		if err != nil {
			return err
		}
		cv := d.Verifier
		if cv == nil || !cv.Extended() || cv.Lookup == nil || len(cv.Lookup.Match) == 0 {
			if err := notVerified(ctx, tx, parent, c.Operation, "NO_VERIFIER", actor); err != nil {
				return err
			}
			continue
		}
		envs := c.Environments
		if _, ok := d.Params["environment"]; !ok {
			envs = []string{""}
		} else if len(envs) == 0 {
			if err := notVerified(ctx, tx, parent, c.Operation, "NO_ENVIRONMENT", actor); err != nil {
				return err
			}
			continue
		}
		for _, env := range envs {
			params := maps.Clone(captured)
			if env != "" {
				params["environment"] = env
			}
			if err := openConsequence(ctx, tx, q, org, parent, sib.Digest, d, actionir.Target{Type: c.TargetType, ID: c.TargetID},
				params, actor); err != nil {
				return err
			}
		}
	}
	return nil
}

// auditUnknownConsequences audits each consequence parent's decision could
// not rule out (UNKNOWN, such as the deployment of an approved merge whose
// facts were missing) as not verified (CONSEQUENCE_UNKNOWN) when parent is
// confirmed, by a verifier or by a person, with or without a verifier
// (G0 M8). It names no environment to look the consequence up by, so it is
// never opened, and never left silently either.
func auditUnknownConsequences(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, parent ids.UUID, actor evdomain.Actor) error {
	unknown, err := q.UnknownConsequences(ctx, org, parent)
	if err != nil {
		return err
	}
	for _, c := range unknown {
		if err := notVerified(ctx, tx, parent, c.Operation, "CONSEQUENCE_UNKNOWN", actor); err != nil {
			return err
		}
	}
	return nil
}

// notVerified audits a predicted consequence of parent that is not
// verified on its own, and why.
func notVerified(ctx context.Context, tx db.TenantTx, parent ids.UUID, operation, reason string, actor evdomain.Actor) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: "transaction.consequence_not_verified", Actor: actor, Outcome: audit.Failure, ReasonCode: reason,
		Object: &audit.Object{Type: "transaction", ID: parent.String()}, Details: map[string]string{"operation": operation},
	})
	return err
}

// capturedOf is the fields of transaction txn's newest observation that
// holds every field v captures, for a confirmation by a person.
func capturedOf(ctx context.Context, q *dbq.Queries, org ids.OrgID, txn ids.UUID, v *defs.VerifierSpec) (map[string]string, error) {
	rows, err := q.ObservationsOf(ctx, org, &txn, []ids.UUID{})
	if err != nil {
		return nil, err
	}
	for i := len(rows) - 1; i >= 0; i-- {
		var fields map[string]string
		if len(rows[i].Fields) == 0 || json.Unmarshal(rows[i].Fields, &fields) != nil {
			continue
		}
		all := true
		for _, ptr := range v.Capture {
			all = all && fields[ptr] != ""
		}
		if all {
			return fields, nil
		}
	}
	return nil, nil
}

// openConsequence opens one consequence transaction and its verification.
func openConsequence(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, parent ids.UUID, digest string,
	d *defs.Definition, target actionir.Target, params map[string]string, actor evdomain.Actor,
) error {
	canonical, err := json.Marshal(map[string]any{"operation": d.Operation, "target": target, "params": params, "consequence_of": parent},
		json.Deterministic(true))
	if err != nil {
		return err
	}
	hash := sha256.Sum256(canonical)
	id := ids.NewV7()
	level := string(d.Verifier.RequiredLevel())
	n, err := q.InsertConsequenceTransaction(ctx, dbq.InsertConsequenceTransactionParams{
		ID: id, ActionID: ids.NewV7(), ActionHash: hash[:], Operation: d.Operation, TargetType: &target.Type, TargetID: &target.ID,
		LevelRequired: &level, OrgID: org, Parent: parent,
	})
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("pgtransactions: consequence of %s: no parent", parent)
	}
	if _, err := q.InsertTransactionLink(ctx, dbq.InsertTransactionLinkParams{
		OrgID: org, FromTransactionID: parent, ToTransactionID: id, Kind: string(domain.LinkConsequence), CreatedBy: "verifier",
	}); err != nil {
		return err
	}
	req, err := json.Marshal(verifyRequest{Mode: "lookup", Target: target, Params: params}, json.Deterministic(true))
	if err != nil {
		return err
	}
	if err := q.ScheduleConsequenceVerification(ctx, dbq.ScheduleConsequenceVerificationParams{
		OrgID: org, ID: ids.NewV7(), TransactionID: &id, Operation: d.Verifier.Lookup.Operation, Request: req,
		DelaySeconds: consequenceDelay, WithinSeconds: float64(d.Verifier.WithinSeconds), DefinitionDigest: &digest,
	}); err != nil {
		return err
	}
	details := map[string]string{"consequence_of": parent.String(), "operation": d.Operation, "target": target.ID}
	for _, k := range slices.Sorted(maps.Keys(params)) {
		details["param_"+k] = params[k]
	}
	details["params"] = strconv.Itoa(len(params))
	_, err = audit.Record(ctx, tx, audit.Event{
		Name: "transaction.consequence_opened", Actor: actor, Outcome: audit.Success,
		Object: &audit.Object{Type: "transaction", ID: id.String()}, Details: details,
	})
	return err
}

// verifyRequest is the read a verification task names (as the gateway
// reads it).
type verifyRequest struct {
	Mode   string            `json:"mode"`
	Target actionir.Target   `json:"target"`
	Params map[string]string `json:"params"`
}

// definitionOf decodes a stored canonical definition.
func definitionOf(raw []byte) (*defs.Definition, error) {
	var d defs.Definition
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("pgtransactions: definition: %w", err)
	}
	return &d, nil
}
