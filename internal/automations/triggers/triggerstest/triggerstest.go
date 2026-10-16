// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package triggerstest builds the database fixtures of the trigger tests:
// an org with a person and a security key, automations with enabled
// versions, and a fake engine Starter.
package triggerstest

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Fixture is one test database with an org.
type Fixture struct {
	DB       *dbtest.DB
	Pool     *db.Pool
	Org      ids.OrgID
	User     ids.UUID
	Cred     ids.UUID
	Envelope *pccrypto.Envelope
}

// New creates the database, the org, a person and their security key.
func New(t *testing.T) *Fixture {
	t.Helper()
	d := dbtest.New(t)
	f := &Fixture{DB: d, Pool: d.AppPool(t), Org: ids.New[ids.Org](), User: ids.NewV7(), Cred: ids.NewV7()}
	kek := filepath.Join(t.TempDir(), "kek")
	if err := keys.GenerateKEKFile(kek); err != nil {
		t.Fatal(err)
	}
	kp, err := keys.NewFileProvider([]string{kek})
	if err != nil {
		t.Fatal(err)
	}
	f.Envelope = pccrypto.NewEnvelope(keystore.NewCurrentCache(keystore.NewDEKStore(f.Pool, kp), time.Minute, clock.System{}))
	f.Exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'automations')", f.Org)
	f.Exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", f.Org, f.User)
	f.Exec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		f.Org, f.Cred, f.User, bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 32))
	return f
}

// Exec runs one statement in the org's tenant transaction.
func (f *Fixture) Exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := f.Pool.InTenantTx(context.Background(), f.Org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// Tx runs fn in the org's tenant transaction.
func (f *Fixture) Tx(t *testing.T, fn func(ctx context.Context, tx db.TenantTx) error) {
	t.Helper()
	if err := f.Pool.InTenantTx(context.Background(), f.Org, fn); err != nil {
		t.Fatal(err)
	}
}

// As returns a context for the fixture's person (or kind) with roles at
// the org.
func (f *Fixture) As(kind td.PrincipalKind, roles ...td.RoleName) context.Context {
	bs := make([]td.Binding, 0, len(roles))
	for _, r := range roles {
		bs = append(bs, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: f.Org.UUID()}})
	}
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{Org: f.Org, Principal: td.PrincipalRef{Kind: kind, ID: f.User}, Bindings: bs},
	})
}

// Definition returns a minimal definition document (JSON) whose `when` is
// the given JSON object member list, e.g. `"manual":{}`; extra is merged
// at the top level (e.g. `"paused_triggers":"QUEUE"`). Name and owner live
// on the automation row (D68).
func (f *Fixture) Definition(when, extra string) string {
	doc := `{"apiVersion":"` + autodomain.APIVersion + `","kind":"Automation",` +
		`"purpose":"test","work_kind":"AGENT_WORK","when":{` + when +
		`},"authority":{"principal":"self"},"do":[],"finish_when":[]`
	if extra != "" {
		doc += "," + extra
	}
	return doc + "}"
}

// Automation is a created automation.
type Automation struct {
	ID, Version, ServiceAccount ids.UUID
}

// Automation creates an automation with its identity and a PUBLISHED
// version of def, and enables it with rollout (state ACTIVE).
func (f *Fixture) Automation(t *testing.T, name, def string, rollout autodomain.Rollout) Automation {
	t.Helper()
	d, err := autodomain.Parse([]byte(def))
	if err != nil {
		t.Fatalf("definition: %v", err)
	}
	canon, err := d.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	dig, err := d.Digest()
	if err != nil {
		t.Fatal(err)
	}
	a := Automation{ID: ids.NewV7(), Version: ids.NewV7(), ServiceAccount: ids.NewV7()}
	f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.InsertAutomationServiceAccount(ctx, dbq.InsertAutomationServiceAccountParams{
			OrgID: f.Org, ID: a.ServiceAccount, Name: "automation-" + name, Description: "Execution identity of automation " + name,
			CreatedBy: f.User.String(), AutomationID: &a.ID,
		}); err != nil {
			return err
		}
		if err := q.InsertAutomation(ctx, dbq.InsertAutomationParams{
			OrgID: f.Org, ID: a.ID, Name: name, Purpose: "test", Kind: "AGENT_WORK", OwnerUserID: f.User,
			ServiceAccountID: a.ServiceAccount, CreatedBy: f.User,
		}); err != nil {
			return err
		}
		if err := q.InsertAutomationVersion(ctx, dbq.InsertAutomationVersionParams{
			OrgID: f.Org, ID: a.Version, AutomationID: a.ID, Number: 1, Definition: canon, Digest: dig, CreatedBy: f.User,
		}); err != nil {
			return err
		}
		for _, sql := range []string{
			"UPDATE pc.automation_versions SET state = 'VALIDATED', validated_at = now() WHERE org_id = $1 AND id = $2",
			"UPDATE pc.automation_versions SET state = 'PUBLISHED' WHERE org_id = $1 AND id = $2",
		} {
			if _, err := tx.Exec(ctx, sql, f.Org, a.Version); err != nil {
				return err
			}
		}
		var cohort []ids.UUID
		if rollout == autodomain.RolloutCohort {
			cohort = []ids.UUID{ids.NewV7()}
		}
		_, err := q.EnableAutomation(ctx, dbq.EnableAutomationParams{
			VersionID: &a.Version, Rollout: ptr(string(rollout)), CohortAgents: cohort, OrgID: f.Org, ID: a.ID,
		})
		return err
	})
	return a
}

// NewVersion publishes a second version of a and enables it.
func (f *Fixture) NewVersion(t *testing.T, a Automation, def string) ids.UUID {
	t.Helper()
	d, err := autodomain.Parse([]byte(def))
	if err != nil {
		t.Fatal(err)
	}
	canon, _ := d.Canonical()
	dig, _ := d.Digest()
	v := ids.NewV7()
	f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.InsertAutomationVersion(ctx, dbq.InsertAutomationVersionParams{
			OrgID: f.Org, ID: v, AutomationID: a.ID, Number: 2, Definition: canon, Digest: dig, CreatedBy: f.User,
		}); err != nil {
			return err
		}
		for _, sql := range []string{
			"UPDATE pc.automation_versions SET state = 'SUPERSEDED' WHERE org_id = $1 AND automation_id = $3 AND state = 'PUBLISHED' AND id <> $2",
			"UPDATE pc.automation_versions SET state = 'VALIDATED', validated_at = now() WHERE org_id = $1 AND id = $2 AND $3::uuid IS NOT NULL",
			"UPDATE pc.automation_versions SET state = 'PUBLISHED' WHERE org_id = $1 AND id = $2 AND $3::uuid IS NOT NULL",
			"UPDATE pc.automations SET enabled_version_id = $2 WHERE org_id = $1 AND id = $3",
		} {
			if _, err := tx.Exec(ctx, sql, f.Org, v, a.ID); err != nil {
				return err
			}
		}
		return nil
	})
	return v
}

// Pause pauses a as core would (without the activator).
func (f *Fixture) Pause(t *testing.T, a Automation) {
	t.Helper()
	f.Exec(t, "UPDATE pc.automations SET state = 'PAUSED', pause_reason = 'USER', paused_at = now() WHERE org_id = $1 AND id = $2", f.Org, a.ID)
}

// Unpause makes a ACTIVE again as core would before Resume.
func (f *Fixture) Unpause(t *testing.T, a Automation) {
	t.Helper()
	f.Exec(t, "UPDATE pc.automations SET state = 'ACTIVE', pause_reason = NULL, paused_at = NULL WHERE org_id = $1 AND id = $2", f.Org, a.ID)
}

// Count returns one integer from sql (args after the org).
func (f *Fixture) Count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, append([]any{f.Org}, args...)...).Scan(&n)
	})
	return n
}

// States returns the trigger states of automation a, oldest first.
func (f *Fixture) States(t *testing.T, a Automation) []string {
	t.Helper()
	var out []string
	f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := tx.Query(ctx, "SELECT state FROM pc.automation_triggers WHERE org_id = $1 AND automation_id = $2 ORDER BY received_at, id", f.Org, a.ID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	return out
}

// Starter is a fake engine Starter: it records each start and inserts a
// PENDING execution for it (the trigger log names its execution, 00142),
// or returns Err when set. The row is a TEST execution whatever the
// trigger's mode: a LIVE one needs an approved ceiling, which these tests
// do not exercise.
type Starter struct {
	mu     sync.Mutex
	Starts []autodomain.TriggerRef
	Err    error
}

// Start implements autoports.Starter.
func (s *Starter) Start(ctx context.Context, tx pgx.Tx, t autodomain.TriggerRef) (ids.UUID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Err != nil {
		return ids.UUID{}, s.Err
	}
	id := ids.NewV7()
	tag, err := tx.Exec(ctx, `INSERT INTO pc.automation_executions (org_id, id, automation_id, version_id, trigger_id, mode,
		service_account_id, principal_sa_id, trigger_kind, occurred_at, root_trigger_id, ancestry, depth, deadline_at)
	SELECT a.org_id, $2, a.id, $4, $5, $6, a.service_account_id, a.service_account_id, $7, $8, $9, $10, $11,
		now() + interval '1 hour'
	FROM pc.automations a WHERE a.org_id = $1 AND a.id = $3`,
		t.Org, id, t.Automation, t.Version, t.ID, string(autodomain.ModeTest), string(t.Kind), t.OccurredAt, t.Root, ancestry(t.Ancestry), t.Depth)
	if err != nil {
		return ids.UUID{}, err
	}
	if tag.RowsAffected() != 1 {
		return ids.UUID{}, errors.New("triggerstest: no such automation")
	}
	s.Starts = append(s.Starts, t)
	return id, nil
}

// Count returns the number of starts.
func (s *Starter) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.Starts)
}

// Editions is a fixed licence.
type Editions struct{ Edition billing.Edition }

// Current implements the editions port.
func (e Editions) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: e.Edition}, nil
}

// Team is a Team licence.
var Team = Editions{Edition: billing.Team}

// Slug returns a lowercase slug of the test's name, for unique names.
func Slug(t *testing.T) string {
	s := strings.ToLower(t.Name())
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) > 40 {
		out = out[len(out)-40:]
	}
	return "a" + out
}

func ptr[T any](v T) *T { return &v }

func ancestry(a []ids.UUID) []ids.UUID {
	if a == nil {
		return []ids.UUID{}
	}
	return a
}
