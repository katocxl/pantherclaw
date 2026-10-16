// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package promotiontest is test setup, not product: it promotes an agent
// for production operations the way a person does (G0 M11 part 2, D39,
// D53, HR-290). Record writes the evidence the checks read that a fixture
// does not have yet (a published scenario test of each operation and a
// coverage snapshot of each operation on a connection, as a reassessment
// that saw the scope's changes records it); Promote then calls the real
// PromoteAgent as a person holding fleet_manager with a fresh step-up of
// their own security key, and fails the test unless every operation's
// checks pass. PromoteNew promotes a new agent provisionally (D80): it
// records only the scenario tests, as no traffic has been seen yet.
// Nothing here skips a check. Product code never imports it.
package promotiontest

import (
	"context"
	"encoding/json/v2"
	"slices"
	"strings"
	"testing"
	"time"

	defpg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/promotions"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Scope is an agent in a production environment and the connection that
// serves its operations.
type Scope struct {
	Pool       *db.Pool
	Org        ids.OrgID
	Agent      ids.UUID
	Env        ids.UUID
	Connection ids.UUID
	// Publish publishes a policy for the test: policytest.Publish, which only
	// test files may import (HR-230), so the caller passes it.
	Publish func(ctx context.Context, t testing.TB, pool *db.Pool, org ids.OrgID, b *pdomain.Bundle) ids.UUID
}

func (s Scope) exec(t testing.TB, sql string, args ...any) {
	t.Helper()
	if err := s.Pool.InTenantTx(context.Background(), s.Org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("promotiontest: %v", err)
	}
}

// Record writes what the TESTS and COVERAGE checks read for each operation
// that is not there yet: the published policy gains a scenario test of the
// operation in the environment (RecordTests), and the connection gets a
// PARTIAL coverage snapshot of the operation that has seen every pending
// change of the scope.
func Record(t testing.TB, s Scope, ops ...string) {
	t.Helper()
	RecordTests(t, s, ops...)
	recordCoverage(t, s, ops...)
}

// RecordTests adds a scenario test of each operation in the environment to
// the published policy where it has none (republished through
// Scope.Publish, its rules unchanged).
func RecordTests(t testing.TB, s Scope, ops ...string) {
	t.Helper()
	ctx := context.Background()
	var b pdomain.Bundle
	err := s.Pool.InTenantTx(ctx, s.Org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).GetPublishedPolicy(ctx, s.Org)
		if db.IsNoRows(err) {
			// A bundle has at least one rule: one that only labels.
			b = pdomain.Bundle{ID: "promotion-fixture", Version: 1, Rules: []pdomain.Rule{{
				ID: "promotion-fixture", Kind: pdomain.Annotate, Summary: "label production work", Operations: slices.Clone(ops),
				When: "true", Reason: "PRODUCTION_WORK", Labels: map[string]string{"environment": "production"},
			}}}
			return nil
		} else if err != nil {
			return err
		}
		return json.Unmarshal(row.Bundle, &b)
	})
	if err != nil {
		t.Fatalf("promotiontest: %v", err)
	}
	added := false
	for _, op := range ops {
		if slices.ContainsFunc(b.Tests, func(tc pdomain.TestCase) bool {
			return tc.Action.Operation == op && (tc.Action.Environment == "" || tc.Action.Environment == s.Env.String())
		}) {
			continue
		}
		b.Tests = append(b.Tests, pdomain.TestCase{
			ID:      "promote-" + strings.NewReplacer(".", "-", "_", "-", "*", "all").Replace(op),
			Summary: "the agent's production operation is decided (promotion fixture)",
			Action:  pdomain.TestAction{Operation: op, Environment: s.Env.String(), Params: []byte(`{}`)},
			Expect:  pdomain.TestExpect{Decision: "DENY", Reason: "NO_GRANT"},
		})
		added = true
	}
	if added {
		if s.Publish == nil {
			t.Fatal("promotiontest: Scope.Publish is not set (pass policytest.Publish)")
		}
		b.Version = 1
		s.Publish(ctx, t, s.Pool, s.Org, &b)
	}
}

// recordCoverage records a PARTIAL coverage snapshot of each operation on
// the connection, as a reassessment that saw the scope's changes would.
func recordCoverage(t testing.TB, s Scope, ops ...string) {
	t.Helper()
	Route(t, s)
	ctx := context.Background()
	var pending []string
	if err := s.Pool.InTenantTx(ctx, s.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).CoverageChangesPending(ctx, s.Org, s.Connection, &s.Agent)
		for _, r := range rows {
			pending = append(pending, r.ID.String())
		}
		return err
	}); err != nil {
		t.Fatalf("promotiontest: %v", err)
	}
	body, err := json.Marshal(map[string]any{"v": 1, "state": "PARTIAL", "seen": pending})
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range ops {
		entry := ids.NewV7()
		s.exec(t, `INSERT INTO pc.ledger_entries (org_id, id, kind, actor_type, actor_id, body)
			VALUES ($1, $2, 'coverage.test', 'test', 'promotiontest', '\x7b7d')`, s.Org, entry)
		s.exec(t, `INSERT INTO pc.coverage_snapshots (org_id, id, agent_id, connection_id, operation, state, reasons,
			body, body_sha256, ledger_entry_id) VALUES ($1, $2, $3, $4, $5, 'PARTIAL', '{agent_held}', $6, $7, $8)`,
			s.Org, ids.NewV7(), s.Agent, s.Connection, op, body, make([]byte, 32), entry)
	}
}

// Promoter is a person holding fleet_manager at the org, with an ACTIVE
// security key.
type Promoter struct {
	User, Key ids.UUID
	Ctx       context.Context
}

// NewPromoter adds a person holding fleet_manager with a security key.
func NewPromoter(t testing.TB, s Scope) Promoter {
	t.Helper()
	p := Promoter{User: ids.NewV7(), Key: ids.NewV7()}
	secret := make([]byte, 32)
	copy(secret, p.Key[:])
	s.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", s.Org, p.User, "promoter-"+p.User.String())
	s.exec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible, backup_state,
		attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`, s.Org, p.Key, p.User, secret[:16], secret)
	s.exec(t, `INSERT INTO pc.role_bindings (org_id, id, user_id, role, scope_type, created_by)
		VALUES ($1, $2, $3, 'fleet_manager', 'ORG', 'promotiontest')`, s.Org, ids.NewV7(), p.User)
	p.Ctx = tapp.WithCaller(context.Background(), tapp.Caller{
		Subject: td.Subject{
			Org: s.Org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: p.User},
			Bindings: []td.Binding{{Role: td.RoleFleetManager, Scope: td.Scope{Type: td.ScopeOrg, ID: s.Org.UUID()}}},
		},
		Credential: tapp.CredBrowserSession, Session: ids.NewV7(),
	})
	return p
}

// StepUp is a step-up the person made with their key just now.
func (p Promoter) StepUp() *stepup.StepUp {
	return &stepup.StepUp{Credential: p.Key, At: time.Now()}
}

// Promote records what the checks read for each exact operation of ops
// and of every operation a prefix in ops covers (Record) and promotes the
// agent for ops, FAIL_CLOSED, through PromoteAgent; it fails the test
// unless every operation's checks passed and it was promoted.
func Promote(t testing.TB, s Scope, ops ...string) []promotions.Promotion {
	t.Helper()
	Route(t, s)
	pk := &defpg.Store{Pool: s.Pool}
	var exact []string
	for _, op := range ops {
		if !strings.HasSuffix(op, ".*") {
			exact = append(exact, op)
			continue
		}
		if err := s.Pool.InTenantTx(context.Background(), s.Org, func(ctx context.Context, tx db.TenantTx) error {
			known, err := promotions.KnownUnder(ctx, tx, pk, s.Agent, op)
			exact = append(exact, known...)
			return err
		}); err != nil {
			t.Fatalf("promotiontest: %v", err)
		}
	}
	if len(exact) > 0 {
		Record(t, s, exact...)
	}
	return promote(t, s, promotions.StateActive, ops...)
}

// PromoteNew promotes a new agent, one with no traffic yet, as a person
// does: only its scenario tests are recorded (RecordTests), so the
// promotion is PROVISIONAL for 7 days (D80, F7) and grants under it end
// with it. It fails the test unless every operation is promoted
// provisionally.
func PromoteNew(t testing.TB, s Scope, ops ...string) []promotions.Promotion {
	t.Helper()
	RecordTests(t, s, ops...)
	return promote(t, s, promotions.StateProvisional, ops...)
}

func promote(t testing.TB, s Scope, state string, ops ...string) []promotions.Promotion {
	t.Helper()
	pk := &defpg.Store{Pool: s.Pool}
	p := NewPromoter(t, s)
	res, err := (&promotions.Service{Pool: s.Pool, Packages: pk}).PromoteAgent(p.Ctx, promotions.PromoteInput{
		Agent: s.Agent, Environment: s.Env, Operations: ops, FailureBehavior: promotions.FailClosed,
	}, p.StepUp())
	if err != nil {
		t.Fatalf("promotiontest: PromoteAgent: %v", err)
	}
	for _, r := range res.Readiness {
		if r.Promotion == nil || r.Promotion.State != state {
			t.Fatalf("promotiontest: %s not promoted %s: %+v %+v", r.Operation, state, r.Promotion, r.Checks)
		}
	}
	return slices.Concat(res.Promoted, res.Already)
}

// Route records that the agent's traffic goes through the scope's
// connection (an observed gateway channel route), which makes it one of
// the agent's connections: it serves the operations its package declares,
// and COVERAGE needs a passing record on it (D93 L2, V4).
func Route(t testing.TB, s Scope) {
	t.Helper()
	s.exec(t, `INSERT INTO pc.coverage_routes (org_id, id, agent_id, connection_id, kind, channel, observation, source, mode)
		VALUES ($1, $2, $3, $4, 'channel', 'http', 'observed', 'gateway', 'enforce') ON CONFLICT DO NOTHING`,
		s.Org, ids.NewV7(), s.Agent, s.Connection)
}
