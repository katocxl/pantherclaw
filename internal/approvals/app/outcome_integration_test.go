// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"slices"
	"sync"
	"testing"

	approvals "github.com/katocxl/pantherclaw/internal/approvals/app"
	notifapp "github.com/katocxl/pantherclaw/internal/notifications/app"
	notifdomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// notes renders each message from its template, as the real service does,
// records it, and drops a second one with the same dedupe key.
type notes struct {
	mu   sync.Mutex
	sent []notifapp.Message
}

func (n *notes) Enqueue(_ context.Context, _ db.TenantTx, m notifapp.Message) (notifapp.Enqueued, error) {
	if _, err := notifdomain.Render(m.Type, m.Params); err != nil {
		return notifapp.Enqueued{}, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if slices.ContainsFunc(n.sent, func(s notifapp.Message) bool { return s.DedupeKey == m.DedupeKey }) {
		return notifapp.Enqueued{Duplicate: true}, nil
	}
	n.sent = append(n.sent, m)
	return notifapp.Enqueued{Notification: ids.NewV7()}, nil
}

// of returns the messages of type typ.
func (n *notes) of(typ string) []notifapp.Message {
	var out []notifapp.Message
	for _, m := range n.sent {
		if m.Type == typ {
			out = append(out, m)
		}
	}
	return out
}

// TestHR173_TheOutcomeIsToldOnce: the person who asked (the run's
// launcher) hears that a request was decided, expired or no longer
// applies, once, with codes only; a completed multi-person approval is
// told to the org's admins.
func TestHR173_TheOutcomeIsToldOnce(t *testing.T) {
	f := newFx(t, 2)
	n := &notes{}
	f.svc.Notify = n
	f.exec(`INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, 'org_admin', $3, 'ORG', 'test')`,
		f.org, ids.NewV7(), f.carol.id)

	declined := f.request(1)
	if _, err := f.svc.Decline(f.as(f.bob), declined, "TOO_RISKY", "", "no"); err != nil {
		t.Fatal(err)
	}
	d := n.of("approval.decided")
	if len(d) != 1 || d[0].Params["outcome"] != "APPROVAL_DECLINED" || !slices.Equal(d[0].Personal, []ids.UUID{f.alice.id}) ||
		d[0].Params["request"] != declined.String() {
		t.Fatalf("decline notice %+v", d)
	}

	expired := f.request(1)
	f.d.AdminExec(t, `UPDATE pc.approval_requests SET created_at = now() - interval '2 hours', deadline_at = date_trunc('second', now()) - interval '1 minute'
		WHERE id = $1`, expired)
	if _, err := approvals.SweepOrg(context.Background(), f.p, n, f.org); err != nil {
		t.Fatal(err)
	}
	if e := n.of("approval.expired"); len(e) != 1 || e[0].Params["request"] != expired.String() {
		t.Fatalf("expiry notice %+v", e)
	}
	if _, err := approvals.SweepOrg(context.Background(), f.p, n, f.org); err != nil || len(n.of("approval.expired")) != 1 {
		t.Fatalf("a second sweep told again: %v", err)
	}

	two := f.request(2)
	if _, err := f.approve(f.bob, two); err != nil {
		t.Fatal(err)
	}
	if len(n.of("approval.decided")) != 1 {
		t.Fatal("a first of two approvals decided nothing yet")
	}
	if _, err := f.approve(f.dave, two); err != nil {
		t.Fatal(err)
	}
	d = n.of("approval.decided")
	if len(d) != 2 || d[1].Params["outcome"] != "APPROVED" {
		t.Fatalf("approval notice %+v", d)
	}
	if m := n.of("approval.multi_person_completed"); len(m) != 1 || !slices.Equal(m[0].Personal, []ids.UUID{f.carol.id}) {
		t.Fatalf("multi-person notice %+v", m)
	}
}
