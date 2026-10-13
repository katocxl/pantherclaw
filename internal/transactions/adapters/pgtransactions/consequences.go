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
// effect the verifier v of definition digest just confirmed with the
// captured fields.
func openConsequences(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, parent, conn ids.UUID, digest string,
	v *defs.VerifierSpec, fields map[string]string, gateway ids.UUID,
) error {
	if len(v.Capture) == 0 {
		return nil
	}
	captured := map[string]string{}
	for name, ptr := range v.Capture {
		val, ok := fields[ptr]
		if !ok || val == "" {
			return nil // nothing to find the consequence by
		}
		captured[name] = val
	}
	rows, err := q.PredictedConsequences(ctx, org, parent)
	if err != nil {
		return err
	}
	for _, c := range rows {
		sib, err := q.SiblingDefinitionWithDigest(ctx, org, digest, c.Operation)
		if db.IsNoRows(err) {
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
			continue // nothing finds it: it stays the parent's predicted consequence
		}
		envs := c.Environments
		if _, ok := d.Params["environment"]; !ok {
			envs = []string{""}
		}
		for _, env := range envs {
			params := maps.Clone(captured)
			if env != "" {
				params["environment"] = env
			}
			if err := openConsequence(ctx, tx, q, org, parent, conn, sib.Digest, d, actionir.Target{Type: c.TargetType, ID: c.TargetID},
				params, gateway); err != nil {
				return err
			}
		}
	}
	return nil
}

// openConsequence opens one consequence transaction and its verification.
func openConsequence(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, parent, conn ids.UUID, digest string,
	d *defs.Definition, target actionir.Target, params map[string]string, gateway ids.UUID,
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
		OrgID: org, ID: ids.NewV7(), TransactionID: &id, ConnectionID: conn, Operation: d.Verifier.Lookup.Operation, Request: req,
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
		Name: "transaction.consequence_opened", Actor: evdomain.Actor{Type: "gateway", ID: gateway.String()}, Outcome: audit.Success,
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
