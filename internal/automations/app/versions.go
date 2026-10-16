// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/changes"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// VoidContentChanged voids pending requests of an automation whose
// version content changed.
const VoidContentChanged = "CONTENT_CHANGED"

// parseDefinition parses a definition strictly and returns its canonical
// JSON and digest.
func parseDefinition(raw []byte) ([]byte, []byte, error) {
	d, err := autodomain.Parse(raw)
	if err != nil {
		return nil, nil, pcerr.Wrap(err, pcerr.InvalidArgument, "DEFINITION_INVALID", strings.TrimPrefix(err.Error(), "automation: invalid definition: "))
	}
	c, err := d.Canonical()
	if err != nil {
		return nil, nil, err
	}
	digest, err := d.Digest()
	return c, digest, err
}

// CreateDraftVersion stores a definition as the automation's next DRAFT
// version.
func (s *Service) CreateDraftVersion(ctx context.Context, automation ids.UUID, raw []byte) (Version, error) {
	c, err := manager(ctx)
	if err != nil {
		return Version{}, err
	}
	canonical, digest, err := parseDefinition(raw)
	if err != nil {
		return Version{}, err
	}
	var out Version
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, err := loadAutomation(ctx, q, c.Org, automation, true)
		if err != nil {
			return err
		}
		if a.State == string(autodomain.StateRetired) {
			return ErrState
		}
		n, err := q.NextAutomationVersionNumber(ctx, c.Org, automation)
		if err != nil {
			return err
		}
		id := ids.NewV7()
		if err := q.InsertAutomationVersion(ctx, dbq.InsertAutomationVersionParams{
			OrgID: c.Org, ID: id, AutomationID: automation, Number: n, Definition: canonical, Digest: digest, CreatedBy: c.Principal.ID,
		}); err != nil {
			return err
		}
		v, err := loadVersion(ctx, q, c.Org, id, false)
		if err != nil {
			return err
		}
		out = versionView(v)
		return record(ctx, tx, c.Actor(), "automation.version_created", automation, map[string]string{
			"version": id.String(), "number": itoa(int(n)), "digest": hexDigest(digest),
		})
	})
	return out, err
}

// UpdateDraftVersion replaces the definition of a version that is not
// published, when it still has baseDigest; it returns to DRAFT and the
// automation's pending change requests are voided (new content).
func (s *Service) UpdateDraftVersion(ctx context.Context, version ids.UUID, raw, baseDigest []byte) (Version, error) {
	c, err := manager(ctx)
	if err != nil {
		return Version{}, err
	}
	canonical, digest, err := parseDefinition(raw)
	if err != nil {
		return Version{}, err
	}
	var out Version
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		v, err := loadVersion(ctx, q, c.Org, version, true)
		if err != nil {
			return err
		}
		if !slices.Contains([]string{"DRAFT", "VALIDATED", "TESTED"}, v.State) {
			return ErrVersionState
		}
		if !bytes.Equal(v.Digest, baseDigest) {
			return ErrRevisionChanged
		}
		if err := oneRow(q.UpdateDraftAutomationVersion(ctx, dbq.UpdateDraftAutomationVersionParams{
			Definition: canonical, Digest: digest, OrgID: c.Org, ID: version, BaseDigest: baseDigest,
		})); err != nil {
			return ErrRevisionChanged
		}
		if s.Changes != nil {
			if _, err := s.Changes.Void(ctx, tx, c, changes.DomainAutomation, v.AutomationID, VoidContentChanged); err != nil {
				return err
			}
		}
		if v, err = loadVersion(ctx, q, c.Org, version, false); err != nil {
			return err
		}
		out = versionView(v)
		return record(ctx, tx, c.Actor(), "automation.version_updated", v.AutomationID, map[string]string{
			"version": version.String(), "digest": hexDigest(digest),
		})
	})
	return out, err
}

// ValidateVersion validates a version against the org's current state
// (D4): with no error finding it becomes VALIDATED and its plain-language
// summary is stored; otherwise it stays DRAFT with the findings.
func (s *Service) ValidateVersion(ctx context.Context, version ids.UUID) (Version, bool, error) {
	c, err := manager(ctx)
	if err != nil {
		return Version{}, false, err
	}
	var out Version
	var valid bool
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		v, err := loadVersion(ctx, q, c.Org, version, true)
		if err != nil {
			return err
		}
		if !slices.Contains([]string{"DRAFT", "VALIDATED", "TESTED"}, v.State) {
			return ErrVersionState
		}
		d, err := definitionOf(v)
		if err != nil {
			return err
		}
		a, err := loadAutomation(ctx, q, c.Org, v.AutomationID, false)
		if err != nil {
			return err
		}
		env := &validationEnv{s: s, tx: tx, q: q, org: c.Org, owner: a.OwnerUserID, now: s.now(), ctx: ctx}
		findings := autodomain.Validate(ctx, d, env)
		valid = !autodomain.HasErrors(findings)
		raw, err := json.Marshal(findingsOrEmpty(findings))
		if err != nil {
			return err
		}
		summary := ""
		if valid {
			summary = autodomain.Summary(d, s.names(ctx, q, c.Org, d))
		}
		if err := oneRow(q.RecordAutomationValidation(ctx, dbq.RecordAutomationValidationParams{
			Passed: valid, Summary: summary, Findings: raw, OrgID: c.Org, ID: version, Digest: v.Digest,
		})); err != nil {
			return ErrRevisionChanged
		}
		if v, err = loadVersion(ctx, q, c.Org, version, false); err != nil {
			return err
		}
		out = versionView(v)
		return record(ctx, tx, c.Actor(), "automation.version_validated", v.AutomationID, map[string]string{
			"version": version.String(), "valid": boolString(valid), "findings": itoa(len(findings)),
		})
	})
	return out, valid, err
}

func findingsOrEmpty(f []autodomain.Finding) []autodomain.Finding {
	if f == nil {
		return []autodomain.Finding{}
	}
	return f
}

// names resolves the agent ids the summary shows.
func (s *Service) names(ctx context.Context, q *dbq.Queries, org ids.OrgID, d *autodomain.Definition) autodomain.Names {
	out := autodomain.Names{}
	agents := d.CeilingAgents()
	if len(agents) == 0 {
		return out
	}
	rows, err := q.AutomationAgentNames(ctx, org, agents)
	if err != nil {
		return out
	}
	for _, r := range rows {
		out[r.ID.String()] = r.Name
	}
	return out
}

// GetVersion returns a version with its definition.
func (s *Service) GetVersion(ctx context.Context, version ids.UUID) (Version, error) {
	c, err := reader(ctx)
	if err != nil {
		return Version{}, err
	}
	var out Version
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		v, err := loadVersion(ctx, dbq.New(tx), c.Org, version, false)
		out = versionView(v)
		return err
	}, db.ReadOnly())
	return out, err
}

// ListVersions lists an automation's versions before number (0: all),
// newest first, without their definitions.
func (s *Service) ListVersions(ctx context.Context, automation ids.UUID, before, limit int) ([]Version, error) {
	c, err := reader(ctx)
	if err != nil {
		return nil, err
	}
	if before <= 0 {
		before = 1 << 30
	}
	var out []Version
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := loadAutomation(ctx, q, c.Org, automation, false); err != nil {
			return err
		}
		rows, err := q.ListAutomationVersions(ctx, dbq.ListAutomationVersionsParams{
			OrgID: c.Org, AutomationID: automation, BeforeNumber: int32(before), MaxRows: int32(min(max(limit, 1), 200)), //nolint:gosec // bounded
		})
		if err != nil {
			return err
		}
		for _, r := range rows {
			out = append(out, Version{
				ID: r.ID, Automation: r.AutomationID, Number: int(r.Number), State: autodomain.VersionState(r.State),
				Digest: r.Digest, Summary: r.Summary, CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt,
				ValidatedAt: r.ValidatedAt, TestedAt: r.TestedAt, PublishedAt: r.PublishedAt,
				TestedRun: deref(r.TestedRunID), ChangeRequest: deref(r.ChangeRequestID),
			})
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// GetVersionGraph returns a version as nodes and edges (F663).
func (s *Service) GetVersionGraph(ctx context.Context, version ids.UUID) ([]autodomain.GraphNode, []autodomain.GraphEdge, error) {
	v, err := s.GetVersion(ctx, version)
	if err != nil {
		return nil, nil, err
	}
	d, err := autodomain.Parse(v.Definition)
	if err != nil {
		return nil, nil, ErrDefinition
	}
	nodes, edges := autodomain.Graph(d)
	return nodes, edges, nil
}

// validationEnv answers Validate's lookups in the caller's transaction.
type validationEnv struct {
	s     *Service
	tx    db.TenantTx
	q     *dbq.Queries
	org   ids.OrgID
	owner ids.UUID
	now   time.Time
	ctx   context.Context //nolint:containedctx // per-validation helper
}

func (e *validationEnv) Now() time.Time { return e.now }

// Owner is the automation row's owner (D68).
func (e *validationEnv) Owner() ids.UUID { return e.owner }

func (e *validationEnv) OwnerActivePerson(ctx context.Context, user ids.UUID) (bool, error) {
	ok, err := e.q.SubjectUserActive(ctx, e.org, user)
	if db.IsNoRows(err) {
		return false, nil
	}
	return ok, err
}

func (e *validationEnv) AgentGrantable(ctx context.Context, agent ids.UUID) (bool, error) {
	if e.s.Grants == nil || e.s.Grants.Store == nil {
		return false, errors.New("agents cannot be checked here")
	}
	a, err := e.s.Grants.Store.AgentInTx(ctx, e.tx, e.org, agent)
	if err != nil {
		return false, nil //nolint:nilerr // unknown agent: not grantable
	}
	return slices.Contains([]string{"CLAIMED", "VERIFIED", "OBSERVED", "PARTIALLY_PROTECTED", "PROTECTED"}, a.State), nil
}

func (e *validationEnv) Operation(ctx context.Context, op string) (autodomain.OperationInfo, error) {
	if strings.HasSuffix(op, ".*") {
		// A prefix may cover any operation: treat it as irreversible and
		// spending, so the version must reconcile and budget it.
		return autodomain.OperationInfo{Known: true, Irreversible: true, ConsumesBudget: true}, nil
	}
	if e.s.Operations == nil {
		return autodomain.OperationInfo{}, errors.New("operations cannot be checked here")
	}
	d, err := e.s.Operations.Active(ctx, e.org, op)
	if err != nil || d == nil {
		return autodomain.OperationInfo{}, err
	}
	return OperationInfo(d), nil
}

// OperationInfo describes a definition for validation: irreversible when
// its reversibility says so, spending when a parameter is money.
func OperationInfo(d *defs.Definition) autodomain.OperationInfo {
	out := autodomain.OperationInfo{Known: true, Irreversible: d.Reversibility == defs.Irreversible}
	for _, p := range d.Params {
		if p.Type == defs.TypeMoney {
			out.ConsumesBudget = true
		}
	}
	return out
}

func (e *validationEnv) DestinationActive(ctx context.Context, destination ids.UUID, purpose string) (bool, error) {
	if e.s.Destinations == nil {
		return false, nil
	}
	return e.s.Destinations.Active(ctx, e.tx.Pgx(), e.org, destination, purpose)
}

func (e *validationEnv) EligibleApprovers(ctx context.Context, g autodomain.GateWith, owner ids.UUID) (int, error) {
	people, err := e.q.OrgUsersWithRoles(ctx, e.org, rolesWith(td.PermAutomationApprove))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, p := range people {
		if len(g.Approvers.Users) > 0 && !slices.Contains(g.Approvers.Users, autodomain.RefID(p)) {
			continue
		}
		exclude := g.Exclude
		if len(exclude) == 0 {
			exclude = []string{autodomain.ExcludeOwner}
		}
		if p == owner && slices.Contains(exclude, autodomain.ExcludeOwner) {
			continue
		}
		n++
	}
	return n, nil
}

func (e *validationEnv) Edition(x autodomain.Edition) bool {
	ctx := e.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return e.s.entitled(ctx, x)
}

// rolesWith lists the default roles holding p.
func rolesWith(p td.Permission) []string {
	var out []string
	for _, r := range td.Roles() {
		if r.Has(p) {
			out = append(out, string(r.Name))
		}
	}
	return out
}

func deref(p *ids.UUID) ids.UUID {
	if p == nil {
		return ids.UUID{}
	}
	return *p
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
