// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestT102_ExceptionsShareTheGatesChangeRequests (D11, D23): the exception
// service creates its requests through the policy gate's change requests,
// the ones the policy changes page confirms, and EXCEPTION is registered
// there, so an approved request runs the exception's apply callback.
func TestT102_ExceptionsShareTheGatesChangeRequests(t *testing.T) {
	pool := dbtest.New(t).AppPool(t)
	org, user := ids.New[ids.Org](), ids.NewV7()
	if err := pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'exc')", org); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", org, user)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	rs, err := rpc.NewServer(rpc.Options{Authenticate: rpcauth.New(denyAll{}, procedurePermissions, nil)})
	if err != nil {
		t.Fatal(err)
	}
	d := apiDeps{pool: pool, publicURL: "https://pc.test"}
	registerPolicyGate(rs, d)
	svc := registerPolicyExceptions(rs, d)
	gateChanges.Lock()
	gate := gateChanges.by[pool]
	gateChanges.Unlock()
	if got, ok := svc.Changes.(*policyapp.Changes); !ok || got != gate || gate == nil {
		t.Fatalf("the exception service's change requests %T are not the gate's", svc.Changes)
	}
	// Request refuses a kind without an apply callback (GATE_UNAVAILABLE);
	// an EXCEPTION request is created, so the callback is registered.
	ctx := tapp.WithCaller(context.Background(), tapp.Caller{
		Subject:    td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user}},
		Credential: tapp.CredAccessToken,
	})
	req, err := gate.Request(ctx, policyapp.ChangeException, ids.NewV7(), ids.UUID{}, [32]byte{7}, map[string]string{"kind": "EXCEPTION"})
	if err != nil || req.Kind != policyapp.ChangeException || req.State != policyapp.ChangePending {
		t.Fatalf("an EXCEPTION change request: %+v (%v)", req, err)
	}
}
