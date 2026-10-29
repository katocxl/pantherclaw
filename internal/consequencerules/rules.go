// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package consequencerules holds an org's customer consequence rules (G0
// M17 D106–D108, F405, HR-453, HR-454): reviewed rules outside signed
// packages that the decision pipeline evaluates after the package rules
// and only adds to. A person holding consequence_rule.manage proposes a
// rule; it is ACTIVE only once a second person holding it confirms the
// protected change with a security key, in every protect mode and never
// as an emergency. Retiring a rule is a protected change too.
package consequencerules

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"fmt"
	"slices"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/actionir"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/protect"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Rule states (00207).
const (
	StateProposed = "PROPOSED"
	StateActive   = "ACTIVE"
	StateRetired  = "RETIRED"
)

// MaxActive is how many ACTIVE rules an org has at most (D106).
const MaxActive = 256

// maxBody bounds a rule's canonical JSON (00207).
const maxBody = 16 << 10

// Errors.
var (
	ErrEdition   = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "customer consequence rules need the Team edition")
	ErrHumanOnly = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person signed in as themselves changes consequence rules")
	ErrInvalid   = pcerr.New(pcerr.InvalidArgument, "CONSEQUENCE_RULE_INVALID", "the consequence rule is not valid")
	ErrNotFound  = pcerr.New(pcerr.NotFound, "CONSEQUENCE_RULE_NOT_FOUND", "consequence rule not found")
	ErrNotActive = pcerr.New(pcerr.FailedPrecondition, "CONSEQUENCE_RULE_NOT_ACTIVE", "the consequence rule has no ACTIVE version")
	ErrLimit     = pcerr.New(pcerr.FailedPrecondition, "CONSEQUENCE_RULE_LIMIT", "an org has at most 256 ACTIVE consequence rules")
	ErrState     = pcerr.New(pcerr.FailedPrecondition, "CONSEQUENCE_RULE_STATE", "the consequence rule version is not in a state that allows this")
)

// Editions reads the org's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// Definitions finds the org's ACTIVE definition of an operation, with the
// package version that holds it (definitions' pgstore.Store).
type Definitions interface {
	ActiveInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, op string) (*defs.Package, *defs.Definition, error)
}

// Service proposes, retires and lists customer consequence rules.
type Service struct {
	Pool        *db.Pool
	Gate        *protect.Gate
	Editions    Editions
	Definitions Definitions
}

// Version is one stored version of a rule, with its decoded body.
type Version struct {
	dbq.PcCustomerConsequenceRule
	Rule defs.ConsequenceRule
}

// Encode is a rule's canonical JSON and its SHA-256 digest.
func Encode(r defs.ConsequenceRule) ([]byte, [32]byte, error) {
	b, err := json.Marshal(r, json.Deterministic(true))
	if err != nil {
		return nil, [32]byte{}, err
	}
	return b, sha256.Sum256(b), nil
}

// Decode is the rule of a stored body, which must be its canonical JSON.
func Decode(body []byte) (defs.ConsequenceRule, error) {
	var r defs.ConsequenceRule
	if err := json.Unmarshal(body, &r, json.RejectUnknownMembers(true)); err != nil {
		return r, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return r, nil
}

// Opened is a stored version as the pipeline evaluates it: the rule, its
// version and digest, and the definition of its consequence operation
// with the pin of the package version that holds it (nil when the org no
// longer has an ACTIVE one, which the pipeline cannot evaluate).
type Opened struct {
	Rule       defs.ConsequenceRule
	Version    int
	Digest     [32]byte
	Definition *defs.Definition
	Pin        actionir.Definition
}

// Active opens the org's ACTIVE rules in tx, in rule id order (D108). A
// rule whose body does not decode is an error: the pipeline then cannot
// authorize, never decides without it.
func Active(ctx context.Context, tx db.TenantTx, org ids.OrgID, d Definitions) ([]Opened, error) {
	rows, err := dbq.New(tx).ActiveCustomerConsequenceRules(ctx, org)
	if err != nil {
		return nil, err
	}
	out := make([]Opened, 0, len(rows))
	for _, row := range rows {
		o, err := open(ctx, tx, org, d, row)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, nil
}

// OpenVersion opens one stored version by rule id and version, as a
// recorded evaluation names it, and checks its digest.
func OpenVersion(ctx context.Context, tx db.TenantTx, org ids.OrgID, d Definitions, ruleID string, version int, digest [32]byte) (Opened, error) {
	row, err := dbq.New(tx).GetCustomerConsequenceRuleVersion(ctx, org, ruleID, int32(version)) //nolint:gosec // ≤ 100000
	if db.IsNoRows(err) {
		return Opened{}, ErrNotFound
	} else if err != nil {
		return Opened{}, err
	}
	if len(row.Digest) != len(digest) || [32]byte(row.Digest) != digest {
		return Opened{}, fmt.Errorf("%w: %s version %d is not the recorded one", ErrInvalid, ruleID, version)
	}
	return open(ctx, tx, org, d, row)
}

func open(ctx context.Context, tx db.TenantTx, org ids.OrgID, d Definitions, row dbq.PcCustomerConsequenceRule) (Opened, error) {
	r, err := Decode(row.Body)
	if err != nil {
		return Opened{}, err
	}
	if len(row.Digest) != sha256.Size || sha256.Sum256(row.Body) != [32]byte(row.Digest) {
		return Opened{}, fmt.Errorf("%w: %s version %d does not match its digest", ErrInvalid, row.RuleID, row.Version)
	}
	o := Opened{Rule: r, Version: int(row.Version), Digest: [32]byte(row.Digest)}
	p, def, err := d.ActiveInTx(ctx, tx, org, r.Consequence.Operation)
	if err != nil {
		return Opened{}, err
	}
	if def != nil {
		o.Definition, o.Pin = def, actionir.Definition{Package: p.Name, Version: p.Version, Digest: def.Digest}
	}
	return o, nil
}

// manager is the caller, who must be a person signed in as themselves
// holding consequence_rule.manage at org scope, in a Team org.
func (s *Service) manager(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if !c.Human() || c.Credential == tenancy.CredAPIKey {
		return c, ErrHumanOnly
	}
	if err := c.Require(td.PermConsequenceRuleManage, td.OrgPath(c.Org)); err != nil {
		return c, err
	}
	return c, s.team(ctx)
}

func (s *Service) team(ctx context.Context) error {
	if s.Editions == nil {
		return ErrEdition
	}
	e, err := s.Editions.Current(ctx)
	if err != nil {
		return err
	}
	if !e.CustomConsequenceRules() {
		return ErrEdition
	}
	return nil
}

// validate checks r against the org's ACTIVE definitions of its operation
// and its consequence operation (D106).
func (s *Service) validate(ctx context.Context, tx db.TenantTx, org ids.OrgID, r defs.ConsequenceRule) error {
	if s.Definitions == nil {
		return protect.ErrUnavailable
	}
	ops := map[string]*defs.Definition{}
	for _, op := range []string{r.Operation, r.Consequence.Operation} {
		if !actionir.ValidOperation(op) {
			continue
		}
		_, d, err := s.Definitions.ActiveInTx(ctx, tx, org, op)
		if err != nil {
			return err
		}
		if d != nil {
			ops[op] = d
		}
	}
	if err := r.ValidateCustomer(ops); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return nil
}

// change is a protected change's payload: activate a proposed version, or
// retire a rule's ACTIVE one.
type change struct {
	Action string   `json:"action"`
	ID     ids.UUID `json:"id,omitzero"`
	RuleID string   `json:"rule_id"`
}

const (
	actionActivate = "ACTIVATE"
	actionRetire   = "RETIRE"
)

// WithProtect holds every rule change for a second person (D107) and
// registers their re-runs with g.
func (s *Service) WithProtect(g *protect.Gate) *Service {
	s.Gate = g
	if g != nil {
		g.Register(protect.SurfaceConsequenceRule, s.ApplyProtected, s.ProtectedState)
	}
	return s
}

// Propose stores r as the next version of its rule, PROPOSED, and opens
// the protected change that activates it once a second person confirms
// it (HR-453). It returns the version and the pending change.
func (s *Service) Propose(ctx context.Context, r defs.ConsequenceRule) (Version, *protect.PendingError, error) {
	var out Version
	c, err := s.manager(ctx)
	if err != nil {
		return out, nil, err
	}
	body, digest, err := Encode(r)
	if err != nil {
		return out, nil, err
	}
	if len(body) > maxBody {
		return out, nil, fmt.Errorf("%w: the rule is larger than 16 KiB", ErrInvalid)
	}
	var held *protect.PendingError
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		if err := s.validate(ctx, tx, c.Org, r); err != nil {
			return err
		}
		row, err := dbq.New(tx).InsertCustomerConsequenceRule(ctx, dbq.InsertCustomerConsequenceRuleParams{
			OrgID: c.Org, ID: ids.NewV7(), RuleID: r.ID, Body: body, Digest: digest[:], ProposedBy: c.Principal.ID,
		})
		if err != nil {
			return err
		}
		out = Version{PcCustomerConsequenceRule: row, Rule: r}
		if err := record(ctx, tx, c, "consequence_rule.proposed", row); err != nil {
			return err
		}
		held, err = s.hold(ctx, tx, c, change{Action: actionActivate, ID: row.ID, RuleID: r.ID}, map[string]string{
			"rule": r.ID, "version": strconv.Itoa(int(row.Version)), "operation": r.Operation,
			"consequence": r.Consequence.Operation, "digest": fmt.Sprintf("%x", digest), "to": StateActive,
		})
		return err
	})
	return out, held, err
}

// Retire opens the protected change that retires a rule's ACTIVE version
// once a second person confirms it: retiring takes requirements away
// (HR-453).
func (s *Service) Retire(ctx context.Context, ruleID string) (*protect.PendingError, error) {
	c, err := s.manager(ctx)
	if err != nil {
		return nil, err
	}
	if !defs.CustomerRuleIDRe.MatchString(ruleID) {
		return nil, ErrNotFound
	}
	var held *protect.PendingError
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		active, err := activeVersion(ctx, tx, ruleID)
		if err != nil {
			return err
		}
		if active == 0 {
			return ErrNotActive
		}
		held, err = s.hold(ctx, tx, c, change{Action: actionRetire, RuleID: ruleID}, map[string]string{
			"rule": ruleID, "version": strconv.Itoa(active), "to": StateRetired,
		})
		return err
	})
	return held, err
}

// hold stores ch as a protected change: it never applies here, since the
// surface always waits for a second person (protect.AlwaysProtected).
func (s *Service) hold(ctx context.Context, tx db.TenantTx, c tenancy.Caller, ch change, summary map[string]string) (*protect.PendingError, error) {
	if s.Gate == nil {
		return nil, protect.ErrUnavailable
	}
	held, err := s.Gate.Hold(ctx, tx, c, protect.Change{
		Category: protect.ConsequenceRules, Surface: protect.SurfaceConsequenceRule, Subject: ch.RuleID,
		Summary: summary, Widening: []string{"consequence_rule"}, Payload: ch,
	}, func(context.Context) error { return protect.ErrUnavailable })
	if err == nil && held == nil {
		return nil, protect.ErrUnavailable // never applied without a second person
	}
	return held, err
}

// ApplyProtected re-runs a confirmed rule change in the confirming
// transaction (a protect.Applier): it activates the proposed version,
// approved by the person who confirmed it, retiring the version it
// replaces, or retires the rule's ACTIVE version.
func (s *Service) ApplyProtected(ctx context.Context, tx db.TenantTx, author tenancy.Caller, payload []byte) error {
	var ch change
	if err := json.Unmarshal(payload, &ch); err != nil {
		return ErrInvalid
	}
	publisher, ok := protect.Publisher(ctx)
	if !ok || publisher == author.Principal.ID {
		return ErrState
	}
	q := dbq.New(tx)
	org := tx.OrgID()
	if err := q.LockCustomerConsequenceRules(ctx, org.UUID()); err != nil {
		return err
	}
	switch ch.Action {
	case actionActivate:
		if err := s.team(ctx); err != nil {
			return err
		}
		row, err := q.GetCustomerConsequenceRule(ctx, org, ch.ID)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if row.State != StateProposed || row.RuleID != ch.RuleID {
			return ErrState
		}
		r, err := Decode(row.Body)
		if err != nil {
			return err
		}
		// The definitions may have changed since it was proposed.
		if err := s.validate(ctx, tx, org, r); err != nil {
			return err
		}
		n, err := q.CountActiveCustomerConsequenceRules(ctx, org, row.RuleID)
		if err != nil {
			return err
		}
		if n >= MaxActive {
			return ErrLimit
		}
		if _, err := q.RetireActiveCustomerConsequenceRule(ctx, org, row.RuleID); err != nil {
			return err
		}
		p := publisher
		if n, err := q.ActivateCustomerConsequenceRule(ctx, &p, org, row.ID); err != nil {
			return err
		} else if n != 1 {
			return ErrState
		}
		row.State, row.ApprovedBy = StateActive, &p
		return record(ctx, tx, author, "consequence_rule.activated", row)
	case actionRetire:
		rows, err := q.RetireActiveCustomerConsequenceRule(ctx, org, ch.RuleID)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return ErrNotActive
		}
		row, err := q.GetCustomerConsequenceRule(ctx, org, rows[0].ID)
		if err != nil {
			return err
		}
		return record(ctx, tx, author, "consequence_rule.retired", row)
	}
	return ErrInvalid
}

// ProtectedState is the state a confirmed re-run must still find (a
// protect.State): the proposed version's state and the rule's ACTIVE
// version, so that a change in between voids the request.
func (s *Service) ProtectedState(ctx context.Context, tx db.TenantTx, payload []byte) ([]byte, error) {
	var ch change
	if err := json.Unmarshal(payload, &ch); err != nil {
		return nil, ErrInvalid
	}
	active, err := activeVersion(ctx, tx, ch.RuleID)
	if err != nil {
		return nil, err
	}
	state := "none"
	if !ch.ID.IsZero() {
		row, err := dbq.New(tx).GetCustomerConsequenceRule(ctx, tx.OrgID(), ch.ID)
		if err != nil && !db.IsNoRows(err) {
			return nil, err
		}
		state = row.State
	}
	return fmt.Appendf(nil, "%s/%s/%d", ch.Action, state, active), nil
}

// activeVersion is the rule's ACTIVE version, or 0.
func activeVersion(ctx context.Context, tx db.TenantTx, ruleID string) (int, error) {
	rows, err := dbq.New(tx).ListCustomerConsequenceRules(ctx, tx.OrgID(), ruleID)
	if err != nil {
		return 0, err
	}
	if i := slices.IndexFunc(rows, func(r dbq.PcCustomerConsequenceRule) bool { return r.State == StateActive }); i >= 0 {
		return int(rows[i].Version), nil
	}
	return 0, nil
}

// List lists every version of the org's rules (or of one rule), by rule,
// newest first; the caller holds package.read at org scope.
func (s *Service) List(ctx context.Context, ruleID string) ([]Version, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.Require(td.PermPackageRead, td.OrgPath(c.Org)); err != nil {
		return nil, err
	}
	var out []Version
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListCustomerConsequenceRules(ctx, c.Org, ruleID)
		if err != nil {
			return err
		}
		for _, row := range rows {
			r, err := Decode(row.Body)
			if err != nil {
				return err
			}
			out = append(out, Version{PcCustomerConsequenceRule: row, Rule: r})
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// Get is every version of one rule, newest first.
func (s *Service) Get(ctx context.Context, ruleID string) ([]Version, error) {
	if !defs.CustomerRuleIDRe.MatchString(ruleID) {
		return nil, ErrNotFound
	}
	out, err := s.List(ctx, ruleID)
	if err == nil && len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, err
}

// record audits a rule change, without its body.
func record(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name string, row dbq.PcCustomerConsequenceRule) error {
	details := map[string]string{
		"rule": row.RuleID, "version": strconv.Itoa(int(row.Version)), "digest": fmt.Sprintf("%x", row.Digest), "state": row.State,
	}
	if row.ApprovedBy != nil {
		details["approved_by"] = row.ApprovedBy.String()
	}
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "consequence_rule", ID: row.ID.String()},
		Details: details,
	})
	return err
}
