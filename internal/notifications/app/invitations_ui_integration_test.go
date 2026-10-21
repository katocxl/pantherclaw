// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"

	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

type recordingMailer struct {
	mu   sync.Mutex
	sent []napp.Mail
}

func (m *recordingMailer) Send(_ context.Context, mail napp.Mail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, mail)
	return nil
}

// TestHR157_InvitationEmailsGoOnlyToTheInvitationsOwnAddress (G0 UI D8):
// the widened rule sends an invitation link to the pending invitation's
// own email and to no one else, never for a revoked or expired one, and
// keeps the link out of every stored record.
func TestHR157_InvitationEmailsGoOnlyToTheInvitationsOwnAddress(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.svc.SendInvitation(ctx, e.org, ids.NewV7(), "https://pc.example.test/invite/x"); err != nil {
		t.Errorf("without email configured it sends nothing: %v", err)
	}
	m := &recordingMailer{}
	e.svc.SetMailer(m)
	invite := func(email, state, expires string) ids.UUID {
		id := ids.NewV7()
		e.exec(t, `INSERT INTO pc.invitations (org_id, id, email, roles, token_hash, state, created_by, expires_at, revoked_at)
			VALUES ($1, $2, $3, '{}', $4, $5, 'test', now() + $6::interval, CASE WHEN $5 = 'REVOKED' THEN now() END)`,
			e.org, id, email, func() []byte { h := sha256.Sum256([]byte(id.String())); return h[:] }(), state, expires)
		return id
	}
	link := "https://pc.example.test/invite/pci_secret"
	ok := invite("dana@example.test", "PENDING", "1 day")
	if err := e.svc.SendInvitation(ctx, e.org, ok, link); err != nil {
		t.Fatal(err)
	}
	if len(m.sent) != 1 || m.sent[0].To != "dana@example.test" || !strings.Contains(m.sent[0].Body, link) {
		t.Fatalf("sent = %+v", m.sent)
	}
	for name, id := range map[string]ids.UUID{
		"revoked": invite("erin@example.test", "REVOKED", "1 day"),
		"expired": invite("fay@example.test", "PENDING", "-1 minute"),
		"unknown": ids.NewV7(),
	} {
		if err := e.svc.SendInvitation(ctx, e.org, id, link); !errors.Is(err, napp.ErrNoInvitationRecipient) {
			t.Errorf("%s invitation: %v", name, err)
		}
	}
	if len(m.sent) != 1 {
		t.Errorf("%d emails sent, want 1", len(m.sent))
	}
	if n := e.count(t, "SELECT count(*)::int FROM pc.ledger_entries WHERE org_id = $1 AND body::text LIKE '%pci_secret%'", e.org); n != 0 {
		t.Error("the invitation link was stored in the ledger")
	}
	if n := e.count(t, "SELECT count(*)::int FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.notifications.invitation_sent'", e.org); n != 1 {
		t.Errorf("invitation_sent records = %d", n)
	}
}
