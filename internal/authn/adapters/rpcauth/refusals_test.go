// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rpcauth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// stalledPool never finishes a transaction; it waits for its context.
type stalledPool struct {
	calls    int
	deadline time.Duration
	err      error
}

func (p *stalledPool) InTenantTx(ctx context.Context, _ ids.OrgID, _ func(context.Context, db.TenantTx) error, _ ...db.TxOption) error {
	p.calls++
	if d, ok := ctx.Deadline(); ok {
		p.deadline = time.Until(d)
	}
	<-ctx.Done()
	p.err = ctx.Err()
	return p.err
}

// A stalled database must not hang the refused call: the audit write gives
// up after RefusalAuditTimeout, even when the request context was already
// canceled (G0 M10 D75).
func TestAuditRefusals_AStalledDatabaseTimesOutTheAuditWrite(t *testing.T) {
	pool := &stalledPool{}
	r := &rpcauth.AuditRefusals{Pool: pool}
	org := ids.New[ids.Org]()
	c := tapp.Caller{Subject: td.Subject{
		Org: org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: ids.NewV7()},
	}, Credential: tapp.CredAPIKey}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	start := time.Now()
	go func() {
		r.HumanOnlyRefused(ctx, c, "/pantherclaw.v1.GrantService/IssueGrant", td.Permission("grant.issue"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(4 * rpcauth.RefusalAuditTimeout):
		t.Fatal("HumanOnlyRefused hung on a stalled database")
	}
	if pool.calls != 1 {
		t.Fatalf("audit writes = %d, want 1", pool.calls)
	}
	if pool.deadline <= 0 || pool.deadline > rpcauth.RefusalAuditTimeout {
		t.Fatalf("audit write deadline = %v, want within %v", pool.deadline, rpcauth.RefusalAuditTimeout)
	}
	if !errors.Is(pool.err, context.DeadlineExceeded) {
		t.Fatalf("audit write ended with %v, want the timeout (not the request's cancellation)", pool.err)
	}
	if took := time.Since(start); took < rpcauth.RefusalAuditTimeout/2 {
		t.Fatalf("audit write ended after %v; the request's cancellation leaked into it", took)
	}
}
