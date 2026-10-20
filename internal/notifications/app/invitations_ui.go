// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// ErrNoInvitationRecipient: the invitation is not pending, expired or has
// no email, so no invitation email may be sent.
var ErrNoInvitationRecipient = errors.New("notifications: the invitation has no pending recipient")

// invitationMailTimeout bounds one invitation email.
const invitationMailTimeout = 20 * time.Second

// SendInvitation emails an invitation link (G0 UI D8). It widens HR-157 for
// invitations only: the one recipient is the pending invitation's own
// email address, read from the invitation, never an address a caller
// passes. The link (which carries the single-use token) is sent once and
// stored nowhere; the send is recorded without it. Without email
// configured it sends nothing.
func (s *Service) SendInvitation(ctx context.Context, org ids.OrgID, invitation ids.UUID, link string) error {
	if s.mailer == nil {
		return nil
	}
	var inv dbq.PendingInvitationForMailRow
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		inv, err = dbq.New(tx).PendingInvitationForMail(ctx, org, invitation)
		if db.IsNoRows(err) {
			return ErrNoInvitationRecipient
		}
		return err
	}, db.ReadOnly())
	if err != nil {
		return err
	}
	body := "You were invited to join the organization \"" + inv.OrgName + "\" on PantherClaw.\n\n" +
		"Open this link to accept, and sign in with the account your identity provider verified for " + inv.Email + ":\n" +
		link + "\n\n" +
		"The link works once and expires on " + inv.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC") + ". " +
		"If you did not expect this invitation, ignore this email.\n\n" +
		"This message was sent by PantherClaw. It never asks you to approve anything by email.\n"
	sendCtx, cancel := context.WithTimeout(ctx, invitationMailTimeout)
	defer cancel()
	sendErr := s.mailer.Send(sendCtx, Mail{
		To: inv.Email, Subject: "Your invitation to " + inv.OrgName + " on PantherClaw", Body: body,
		MessageID: invitation.String(),
	})
	outcome := audit.Success
	if sendErr != nil {
		outcome = audit.Failure
		s.log.WarnContext(ctx, "notifications.invitation_mail_failed", pclog.Err(sendErr))
	}
	return errors.Join(sendErr, s.pool.InTenantTx(context.WithoutCancel(ctx), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := audit.Record(ctx, tx, audit.Event{
			Name: "notifications.invitation_sent", Actor: evdomain.Actor{Type: "system", ID: "notifications"}, Outcome: outcome,
			Object: &audit.Object{Type: "invitation", ID: invitation.String()},
		})
		return err
	}))
}
