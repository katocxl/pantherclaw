// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package stepup_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR259_ActivationNeedsAFreshStepUpWithOwnActiveKey: only a person
// whose step-up is at most five minutes old, made with one of their own
// active keys, passes (the activation of destinations and transmitters).
func TestHR259_ActivationNeedsAFreshStepUpWithOwnActiveKey(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	ctx := context.Background()
	org, alice, bob := ids.New[ids.Org](), ids.NewV7(), ids.NewV7()
	aliceKey, bobKey, suspended := ids.NewV7(), ids.NewV7(), ids.NewV7()
	exec := func(sql string, args ...any) {
		t.Helper()
		if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		}); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'stepup')", org)
	for i, u := range []ids.UUID{alice, bob} {
		exec("INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", org, u, string(rune('a'+i)))
	}
	key := func(id, user ids.UUID, n byte, state string) {
		exec(`INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
			backup_state, attestation_fmt, name, state, state_reason, changed_at) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key', $6,
			CASE WHEN $6 = 'SUSPENDED' THEN 'CLONE_SUSPECTED' END, CASE WHEN $6 = 'SUSPENDED' THEN now() END)`,
			org, id, user, bytes.Repeat([]byte{n}, 16), bytes.Repeat([]byte{n}, 32), state)
	}
	key(aliceKey, alice, 1, "ACTIVE")
	key(bobKey, bob, 2, "ACTIVE")
	key(suspended, alice, 3, "SUSPENDED")

	person := tenancy.Caller{Subject: td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: alice}}}
	service := tenancy.Caller{Subject: td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: alice}}}
	now := time.Now()
	cases := []struct {
		name string
		c    tenancy.Caller
		su   stepup.StepUp
		ok   bool
	}{
		{"fresh, own active key", person, stepup.StepUp{Credential: aliceKey, At: now.Add(-time.Minute)}, true},
		{"stale", person, stepup.StepUp{Credential: aliceKey, At: now.Add(-6 * time.Minute)}, false},
		{"from the future", person, stepup.StepUp{Credential: aliceKey, At: now.Add(2 * time.Minute)}, false},
		{"another person's key", person, stepup.StepUp{Credential: bobKey, At: now}, false},
		{"suspended key", person, stepup.StepUp{Credential: suspended, At: now}, false},
		{"no step-up", person, stepup.StepUp{}, false},
		{"not a person", service, stepup.StepUp{Credential: aliceKey, At: now}, false},
	}
	for _, c := range cases {
		err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			return stepup.Check(ctx, tx, c.c, c.su, now)
		})
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, stepup.ErrStepUp)) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}
