// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package exposuretest

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Automation is an enabled automation with an ACTIVE ceiling (G0 M11 D37a).
type Automation struct {
	ID, ServiceAccount, Version, Ceiling ids.UUID
	Definition                           *autodomain.Definition
}

// Definition is a minimal valid version document whose ceiling covers ops
// (none: every operation) through agents.
func (o *Org) Definition(t *testing.T, name string, agents []ids.UUID, ops ...string) *autodomain.Definition {
	t.Helper()
	as := make([]string, 0, len(agents))
	for _, a := range agents {
		as = append(as, a.String())
	}
	bounds := "{}"
	if len(ops) > 0 {
		bounds = `{"operations": ["` + strings.Join(ops, `", "`) + `"]}`
	}
	doc := `{"apiVersion": "automations.pantherclaw.dev/v1", "kind": "Automation", "name": "` + name + `",
		"purpose": "Exposure test.", "work_kind": "AGENT_WORK", "owner": "` + o.User.String() + `", "review_by": "2099-01-01",
		"when": {"manual": {"params": {"ticket": {"type": "string", "pattern": "T-[0-9]{1,10}"}}},
			"dedupe": {"key": "{{params.ticket}}", "window": "24h"}},
		"authority": {"principal": "self", "ceiling": {"agents": ["` + strings.Join(as, `", "`) + `"], "bounds": ` + bounds + `,
			"per_grant": {"ttl": "1h"}, "per_day": {"grants": 5, "runs": 5}}},
		"do": [{"id": "launch", "step": "launch_run", "with": {"agent": "` + as[0] + `"}},
		       {"id": "wait", "step": "wait_run", "with": {"step": "launch"}, "timeout": "1h"}],
		"finish_when": [{"step": "wait", "condition": "RUN_ENDED"}]}`
	d, err := autodomain.Parse([]byte(doc))
	if err != nil {
		t.Fatalf("definition: %v", err)
	}
	return d
}

// Automation creates an ACTIVE, FULL automation named name with a published
// version and an ACTIVE ceiling over ops through agents, approved by the
// org's user.
func (o *Org) Automation(t *testing.T, name string, agents []ids.UUID, ops ...string) Automation {
	t.Helper()
	a := Automation{ID: ids.NewV7(), ServiceAccount: ids.NewV7(), Version: ids.NewV7(), Ceiling: ids.NewV7()}
	a.Definition = o.Definition(t, name, agents, ops...)
	canon, err := a.Definition.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canon)
	request := ids.NewV7()
	binding := sha256.Sum256([]byte(request.String()))
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		for _, s := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO pc.service_accounts (org_id, id, name, description, created_by, automation_id)
				VALUES ($1, $2, $3, 'test', 'test', $4)`, []any{o.Org, a.ServiceAccount, "automation-" + name, a.ID}},
			{`INSERT INTO pc.automations (org_id, id, name, purpose, kind, owner_user_id, service_account_id, created_by)
				VALUES ($1, $2, $3, 'test', 'AGENT_WORK', $4, $5, $4)`, []any{o.Org, a.ID, name, o.User, a.ServiceAccount}},
			{`INSERT INTO pc.automation_versions (org_id, id, automation_id, number, definition, digest, created_by)
				VALUES ($1, $2, $3, 1, $4, $5, $6)`, []any{o.Org, a.Version, a.ID, canon, digest[:], o.User}},
			{`UPDATE pc.automation_versions SET state = 'VALIDATED', validated_at = now() WHERE id = $1`, []any{a.Version}},
			{`INSERT INTO pc.change_requests (org_id, id, domain, kind, subject_id, content_digest, binding, summary, required,
				requested_by, expires_at) VALUES ($1, $2, 'automation', 'ENABLE', $3, $4, $5, '{}', 1, 'test',
				now() + interval '1 hour')`, []any{o.Org, request, a.ID, digest[:], binding[:]}},
			{`UPDATE pc.automation_versions SET state = 'PUBLISHED', change_request_id = $2 WHERE id = $1`, []any{a.Version, request}},
			{`UPDATE pc.automations SET state = 'ACTIVE', rollout = 'FULL', enabled_version_id = $2 WHERE id = $1`,
				[]any{a.ID, a.Version}},
			{`INSERT INTO pc.automation_ceilings (org_id, id, automation_id, version_id, digest, approved_by, change_request_id,
				review_by) VALUES ($1, $2, $3, $4, $5, ARRAY[$6::uuid], $7, now() + interval '30 days')`,
				[]any{o.Org, a.Ceiling, a.ID, a.Version, digest[:], o.User, request}},
		} {
			if _, err := tx.Exec(ctx, s.sql, s.args...); err != nil {
				t.Fatalf("%s: %v", s.sql, err)
			}
		}
		return nil
	})
	return a
}

// EndCeiling ends an automation's ceiling (SUPERSEDED, EXPIRED, VOID with
// a reason, or REVOKED).
func (o *Org) EndCeiling(t *testing.T, ceiling ids.UUID, state string) {
	t.Helper()
	var reason any
	if state == "VOID" {
		reason = "TEST"
	}
	o.Exec(t, `UPDATE pc.automation_ceilings SET state = $2, void_reason = $3 WHERE id = $1`, ceiling, state, reason)
}

// IssuedGrant issues agent a root grant under the automation's ceiling,
// granted by its execution identity, over ops for a day.
func (o *Org) IssuedGrant(t *testing.T, a Automation, agent ids.UUID, ops ...string) ids.UUID {
	t.Helper()
	grant := ids.NewV7()
	o.Exec(t, `INSERT INTO pc.grants (org_id, id, agent_id, principal_user_id, environment_id, depth, current_revision,
		grantor_kind, grantor_id, basis, ceiling_id) VALUES ($1, $2, $3, $4, $5, 0, 1, 'service_account', $6, 'automation test', $7)`,
		o.Org, grant, agent, o.User, o.Env, a.ServiceAccount, a.Ceiling)
	bounds := `{"operations":["` + strings.Join(ops, `","`) + `"]}`
	o.Exec(t, `INSERT INTO pc.grant_revisions (org_id, id, grant_id, revision, not_before, expires_at, bounds, requirements,
		limits, delegation_depth, max_children, min_attestation, widens, created_by) VALUES ($1, $2, $3, 1, now() - interval '1 hour',
		now() + interval '1 day', $4, '\x7b7d', '\x7b7d', 0, 0, 0, false, 'test')`,
		o.Org, ids.NewV7(), grant, []byte(bounds))
	o.Exec(t, `INSERT INTO pc.grant_lineage (org_id, grant_id, ancestor_id, distance) VALUES ($1, $2, $2, 0)`, o.Org, grant)
	return grant
}
