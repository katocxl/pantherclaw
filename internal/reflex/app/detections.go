// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"time"

	"github.com/katocxl/pantherclaw/internal/detection/engine"
	"github.com/katocxl/pantherclaw/internal/detection/rules"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// MaxPublishedCustomRules bounds an org's published custom rules (D13).
const MaxPublishedCustomRules = 100

// Errors of the detection use cases.
var (
	ErrRuleInvalid   = pcerr.New(pcerr.InvalidArgument, "RULE_INVALID", "the rule does not parse or validate")
	ErrTestsFailed   = pcerr.New(pcerr.FailedPrecondition, "RULE_TESTS_FAILED", "the rule needs a passing firing and non-firing test")
	ErrTooManyRules  = pcerr.New(pcerr.ResourceExhausted, "TOO_MANY_RULES", "at most 100 published custom rules")
	ErrRuleNotLoaded = pcerr.New(pcerr.FailedPrecondition, "DETECTIONS_OFF", "detections are off: the built-in pack failed its integrity check")
)

// Detections serves the detection rules.
type Detections struct {
	Pool        *db.Pool
	Builtin     []*engine.Compiled
	PackVersion string
	PackErr     error
	Env         *celenv.Env
	Ents        Entitlements
}

// Rule is one rule as the org runs it.
type Rule struct {
	Rule     *rules.Rule
	Digest   string
	Builtin  bool
	Licensed bool
	Custom   *dbq.PcCustomDetectionRule
	State    *dbq.DetectionRuleStatesRow
}

// RuleList is the org's rules and the pack's state.
type RuleList struct {
	Rules       []Rule
	PackVersion string
	Verified    bool
}

func detectionReader(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	return c, c.Require(td.PermDetectionRead, td.OrgPath(c.Org))
}

func detectionManager(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if err := c.Require(td.PermDetectionManage, td.OrgPath(c.Org)); err != nil {
		return c, err
	}
	if !c.Human() || c.Credential == tenancy.CredAPIKey {
		return c, ErrHumanOnly
	}
	return c, nil
}

func (s *Detections) custom(ctx context.Context) error {
	if s.Ents == nil {
		return ErrEdition
	}
	e, err := s.Ents.Current(ctx)
	if err != nil || !e.CustomDetections() {
		return ErrEdition
	}
	return nil
}

// ListRules lists the built-in rules and the org's custom rule versions.
func (s *Detections) ListRules(ctx context.Context) (RuleList, error) {
	c, err := detectionReader(ctx)
	if err != nil {
		return RuleList{}, err
	}
	advanced := false
	if s.Ents != nil {
		if e, err := s.Ents.Current(ctx); err == nil {
			advanced = e.AdvancedDetections()
		}
	}
	out := RuleList{PackVersion: s.PackVersion, Verified: s.PackErr == nil && s.Builtin != nil}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		states, err := q.DetectionRuleStates(ctx, c.Org)
		if err != nil {
			return err
		}
		byID := map[string]*dbq.DetectionRuleStatesRow{}
		for i := range states {
			byID[states[i].RuleID] = &states[i]
		}
		for _, b := range s.Builtin {
			out.Rules = append(out.Rules, Rule{
				Rule: b.Rule, Digest: b.Digest, Builtin: true, State: byID[b.Rule.ID],
				Licensed: b.Rule.Edition == rules.EditionCommunity || advanced,
			})
		}
		custom, err := q.ListCustomRules(ctx, c.Org, ids.UUID{}, 500)
		if err != nil {
			return err
		}
		licensed := s.custom(ctx) == nil
		for i := range custom {
			r, err := rules.Parse([]byte(custom[i].Content))
			if err != nil {
				continue
			}
			out.Rules = append(out.Rules, Rule{
				Rule: r, Digest: hex.EncodeToString(custom[i].ContentDigest), Custom: &custom[i], State: byID[r.ID],
				Licensed: licensed,
			})
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// Status is how far detection has read the org's feed.
type Status struct {
	Cursor, Head int64
	Updated      *time.Time
	Running      bool
}

// GetStatus returns the org's detection cursor and feed head.
func (s *Detections) GetStatus(ctx context.Context) (Status, error) {
	c, err := detectionReader(ctx)
	if err != nil {
		return Status{}, err
	}
	out := Status{Running: s.PackErr == nil && s.Builtin != nil}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		cur, err := q.GetDetectionCursor(ctx, c.Org)
		switch {
		case err == nil:
			out.Cursor, out.Updated = cur.Seq, &cur.UpdatedAt
		case !db.IsNoRows(err):
			return err
		}
		out.Head, err = feed.Reader{}.Head(ctx, tx)
		return err
	}, db.ReadOnly())
	return out, err
}

// compile parses, validates and compiles custom rule content.
func (s *Detections) compile(content string) (*engine.Compiled, error) {
	if s.Env == nil {
		return nil, ErrRuleNotLoaded
	}
	sum := sha256.Sum256([]byte(content))
	r, err := rules.Parse([]byte(content))
	if err != nil {
		return nil, invalidRule(err.Error())
	}
	if r.Builtin() {
		return nil, invalidRule("a custom rule id starts with org.")
	}
	c, err := engine.Compile(s.Env, r, hex.EncodeToString(sum[:]), "")
	if err != nil {
		return nil, invalidRule(err.Error())
	}
	return c, nil
}

// CreateCustomRule stores a DRAFT version of a custom rule (Business).
func (s *Detections) CreateCustomRule(ctx context.Context, content string) (Rule, error) {
	c, err := detectionManager(ctx)
	if err != nil {
		return Rule{}, err
	}
	if err := s.custom(ctx); err != nil {
		return Rule{}, err
	}
	cr, err := s.compile(content)
	if err != nil {
		return Rule{}, err
	}
	sum := sha256.Sum256([]byte(content))
	var out Rule
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.InsertCustomRule(ctx, dbq.InsertCustomRuleParams{
			OrgID: c.Org, ID: ids.NewV7(), RuleID: cr.Rule.ID, Content: content, ContentDigest: sum[:], CreatedBy: c.Principal.ID,
		})
		if err != nil {
			return err
		}
		out = Rule{Rule: cr.Rule, Digest: cr.Digest, Custom: &row, Licensed: true}
		return detectionAudit(ctx, tx, c, "detection.rule_created", row, nil)
	})
	return out, err
}

// TestCustomRule runs a version's tests and records the run.
func (s *Detections) TestCustomRule(ctx context.Context, id ids.UUID) ([]engine.TestResult, bool, error) {
	c, err := detectionManager(ctx)
	if err != nil {
		return nil, false, err
	}
	var results []engine.TestResult
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.GetCustomRule(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		cr, err := s.compile(row.Content)
		if err != nil {
			return err
		}
		results = engine.RunTests(ctx, cr)
		return recordTests(ctx, q, c, row.ID, results)
	})
	return results, err == nil && engine.AllPass(results), err
}

func recordTests(ctx context.Context, q *dbq.Queries, c tenancy.Caller, rule ids.UUID, rs []engine.TestResult) error {
	firing, quiet := 0, 0
	for _, r := range rs {
		if r.Fires {
			firing++
		} else {
			quiet++
		}
	}
	raw, err := json.Marshal(rs)
	if err != nil {
		return err
	}
	return q.InsertCustomRuleTest(ctx, dbq.InsertCustomRuleTestParams{
		OrgID: c.Org, ID: ids.NewV7(), Rule: rule, Passed: engine.AllPass(rs), Firing: int32(firing), //nolint:gosec // ≤ 32
		NonFiring: int32(quiet), Results: raw, RunBy: c.Principal.ID, //nolint:gosec // ≤ 32
	})
}

// PublishCustomRule re-runs the tests in the call and publishes the
// version when at least one firing and one non-firing test pass (D13,
// HR-241). The publication's audit entry records the content digest in the
// ledger; the engine runs the rule only while its stored digest equals it.
func (s *Detections) PublishCustomRule(ctx context.Context, id ids.UUID) (Rule, []engine.TestResult, error) {
	c, err := detectionManager(ctx)
	if err != nil {
		return Rule{}, nil, err
	}
	if err := s.custom(ctx); err != nil {
		return Rule{}, nil, err
	}
	var out Rule
	var results []engine.TestResult
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.LockCustomRule(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if row.State != "DRAFT" {
			return ErrState
		}
		sum := sha256.Sum256([]byte(row.Content))
		if hex.EncodeToString(sum[:]) != hex.EncodeToString(row.ContentDigest) {
			return ErrState
		}
		cr, err := s.compile(row.Content)
		if err != nil {
			return err
		}
		results = engine.RunTests(ctx, cr)
		if !engine.AllPass(results) {
			return errTests{results}
		}
		superseded, err := q.DisablePublishedCustomRule(ctx, &c.Principal.ID, c.Org, row.RuleID)
		if err != nil {
			return err
		}
		n, err := q.CountPublishedCustomRules(ctx, c.Org)
		if err != nil {
			return err
		}
		if n >= MaxPublishedCustomRules {
			return ErrTooManyRules
		}
		details := map[string]string{"content_digest": hex.EncodeToString(sum[:]), "version": itoa(int(row.Version))}
		if len(superseded) > 0 {
			details["superseded"] = superseded[0].String()
		}
		entry, err := audit.Record(ctx, tx, audit.Event{
			Name: "detection.rule_published", Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "detection_rule", ID: row.RuleID}, Details: details,
		})
		if err != nil {
			return err
		}
		if err := one(q.PublishCustomRule(ctx, dbq.PublishCustomRuleParams{
			PublishedBy: &c.Principal.ID, LedgerEntryID: &entry.ID, OrgID: c.Org, ID: id,
		})); err != nil {
			return err
		}
		if err := recordTests(ctx, q, c, row.ID, results); err != nil {
			return err
		}
		row, err = q.GetCustomRule(ctx, c.Org, id)
		out = Rule{Rule: cr.Rule, Digest: cr.Digest, Custom: &row, Licensed: true}
		return err
	})
	var te errTests
	if errors.As(err, &te) {
		return Rule{}, te.results, ErrTestsFailed
	}
	return out, results, err
}

type errTests struct{ results []engine.TestResult }

func (errTests) Error() string { return "rule tests failed" }

// DisableCustomRule disables a custom rule version.
func (s *Detections) DisableCustomRule(ctx context.Context, id ids.UUID, reason string) (Rule, error) {
	c, err := detectionManager(ctx)
	if err != nil {
		return Rule{}, err
	}
	var out Rule
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		n, err := q.DisableCustomRule(ctx, dbq.DisableCustomRuleParams{DisabledBy: &c.Principal.ID, Reason: &reason, OrgID: c.Org, ID: id})
		if err != nil {
			return err
		}
		row, err := q.GetCustomRule(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if n == 0 {
			return ErrState
		}
		r, _ := rules.Parse([]byte(row.Content))
		out = Rule{Rule: r, Digest: hex.EncodeToString(row.ContentDigest), Custom: &row}
		return detectionAudit(ctx, tx, c, "detection.rule_disabled", row, nil)
	})
	return out, err
}

// EnableRule turns a rule the engine disabled back on.
func (s *Detections) EnableRule(ctx context.Context, ruleID string) (bool, error) {
	c, err := detectionManager(ctx)
	if err != nil {
		return false, err
	}
	enabled := false
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		n, err := dbq.New(tx).EnableDetectionRule(ctx, c.Org, ruleID)
		if err != nil || n == 0 {
			return err
		}
		enabled = true
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "detection.rule_enabled", Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "detection_rule", ID: ruleID},
		})
		return err
	})
	return enabled, err
}

func detectionAudit(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name string, row dbq.PcCustomDetectionRule,
	details map[string]string,
) error {
	if details == nil {
		details = map[string]string{}
	}
	details["version"] = itoa(int(row.Version))
	details["content_digest"] = hex.EncodeToString(row.ContentDigest)
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "detection_rule", ID: row.RuleID},
		Details: details,
	})
	return err
}

// invalidRule explains to the rule's author why it does not validate.
func invalidRule(msg string) error {
	if len(msg) > 1000 {
		msg = msg[:1000]
	}
	return pcerr.Wrap(ErrRuleInvalid, pcerr.InvalidArgument, "RULE_INVALID", msg)
}
