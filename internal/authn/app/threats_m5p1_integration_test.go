// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/webauthntest"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// p1tWAEnv is newWAEnv with the real notification service as the security
// notifier, so every change to a key queues an email to its owner.
func p1tWAEnv(t *testing.T) *waEnv {
	t.Helper()
	b := newBrowserEnv(t)
	jc, err := jobs.NewClient(b.pool, nil, jobs.Config{})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := napp.New(b.pool, jc, nil, napp.Config{PublicURL: browserIssuer}, clock.System{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wa, err := authnapp.NewWebAuthn(b.pool, authnapp.WebAuthnConfig{RPID: rpID, PublicURL: browserIssuer}, svc, clock.System{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &waEnv{browserEnv: b, wa: wa}
}

// p1tEmails counts the personal emails of one notice type queued for alice.
func p1tEmails(t *testing.T, e *waEnv, typ string) int {
	t.Helper()
	return e.count(t, `SELECT count(*) FROM pc.deliveries d JOIN pc.notifications n ON n.id = d.notification_id
		WHERE d.kind = 'email' AND d.channel_id IS NULL AND d.state = 'PENDING' AND d.recipient_user_id = $1 AND n.type = $2`, e.user, typ)
}

// TestT052_StolenSessionsAndClonedKeysGainNoKeys: T-052 — Mallory holds a
// stolen cookie of one of alice's sessions, signed in without a recent
// provider sign-in. She cannot register her own key, finish a registration
// that alice's fresh session began, or remove alice's key; a step-up she
// relays to alice through a phishing origin, or alice's own assertion
// replayed into Mallory's ceremony, fails; and alice's step-up on her own
// session does nothing for Mallory's. A copy of alice's key is suspended at
// its first stale counter, for both copies. Alice is emailed about each
// change to her keys. TestHR153_* to TestHR156_* cover each check alone.
func TestT052_StolenSessionsAndClonedKeysGainNoKeys(t *testing.T) {
	t.Run("stolen session", func(t *testing.T) {
		e := p1tWAEnv(t)
		ctx := context.Background()
		alice, _ := e.session(t, true)
		key := e.authenticator(t, webauthntest.ES256)
		desk, err := e.register(t, alice, key, "Desk key")
		if err != nil {
			t.Fatal(err)
		}
		stolen, stolenSecret := e.session(t, false)
		mallory := e.authenticator(t, webauthntest.ES256)

		if _, err := e.wa.BeginRegistration(ctx, stolen); !errors.Is(err, authnapp.ErrRecentAuthRequired) {
			t.Errorf("registration from the stolen session: %v", err)
		}
		c, err := e.wa.BeginRegistration(ctx, alice)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := mallory.Register(c.Options)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.wa.FinishRegistration(ctx, stolen, c.ID, "Backup", resp); !errors.Is(err, authnapp.ErrCeremonyInvalid) {
			t.Errorf("alice's registration finished from the stolen session: %v", err)
		}
		if err := e.wa.RemoveCredential(ctx, stolen, desk.ID); !errors.Is(err, authnapp.ErrRecentAuthRequired) {
			t.Errorf("removal from the stolen session: %v", err)
		}

		// Mallory relays her step-up challenge to alice on a look-alike site.
		c, err = e.wa.BeginStepUp(ctx, stolen)
		if err != nil {
			t.Fatal(err)
		}
		key.Origin = "https://pc-example.test"
		resp, err = key.Assert(c.Options)
		key.Origin = browserIssuer
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.wa.FinishStepUp(ctx, stolen, c.ID, resp); !errors.Is(err, authnapp.ErrWebAuthnFailed) {
			t.Errorf("assertion relayed from a phishing origin: %v", err)
		}

		// Alice steps up on her own session; Mallory captures the assertion.
		mine, err := e.wa.BeginStepUp(ctx, alice)
		if err != nil {
			t.Fatal(err)
		}
		captured, err := key.Assert(mine.Options)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.wa.FinishStepUp(ctx, stolen, mine.ID, captured); !errors.Is(err, authnapp.ErrCeremonyInvalid) {
			t.Errorf("alice's ceremony finished from the stolen session: %v", err)
		}
		up, err := e.wa.FinishStepUp(ctx, alice, mine.ID, captured)
		if err != nil {
			t.Fatal(err)
		}
		theirs, err := e.wa.BeginStepUp(ctx, stolen)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.wa.FinishStepUp(ctx, stolen, theirs.ID, captured); !errors.Is(err, authnapp.ErrWebAuthnFailed) {
			t.Errorf("alice's assertion replayed into Mallory's ceremony: %v", err)
		}
		stolen = e.reauth(t, stolenSecret)
		if stolen.SteppedUpWithin(authnapp.StepUpLifetime) {
			t.Fatal("alice's step-up carried over to the stolen session")
		}
		if _, err := e.wa.BeginRegistration(ctx, stolen); !errors.Is(err, authnapp.ErrRecentAuthRequired) {
			t.Errorf("registration after alice's step-up: %v", err)
		}
		if err := e.wa.RemoveCredential(ctx, stolen, desk.ID); !errors.Is(err, authnapp.ErrRecentAuthRequired) {
			t.Errorf("removal after alice's step-up: %v", err)
		}

		keys, err := e.wa.ListCredentials(ctx, e.reauth(t, up.Rotated))
		if err != nil || len(keys) != 1 || keys[0].ID != desk.ID || keys[0].State != "ACTIVE" {
			t.Fatalf("alice's keys %+v %v", keys, err)
		}
		if n := p1tEmails(t, e, "security.credential_registered"); n != 1 {
			t.Errorf("%d emails about an added key, want 1 (alice's own)", n)
		}
		if n := p1tEmails(t, e, "security.credential_removed"); n != 0 {
			t.Errorf("%d emails about a removed key, want 0", n)
		}
	})

	t.Run("cloned key", func(t *testing.T) {
		e := p1tWAEnv(t)
		ctx := context.Background()
		alice, _ := e.session(t, true)
		key := e.authenticator(t, webauthntest.ES256)
		if _, err := e.register(t, alice, key, "Desk key"); err != nil {
			t.Fatal(err)
		}
		if _, err := e.stepUp(t, alice, key); err != nil {
			t.Fatal(err)
		}
		clone := *key // Mallory copies the key, signature counter and all
		if _, err := e.stepUp(t, alice, key); err != nil {
			t.Fatal(err)
		}
		stolen, _ := e.session(t, false)
		if _, err := e.stepUp(t, stolen, &clone); !errors.Is(err, authnapp.ErrCredentialSuspended) {
			t.Fatalf("step-up with the copy: %v", err)
		}
		// The key is suspended for both copies: no step-up can even start.
		for name, s := range map[string]authnapp.BrowserSession{"the stolen session": stolen, "alice's session": alice} {
			if _, err := e.wa.BeginStepUp(ctx, s); !errors.Is(err, authnapp.ErrNoCredentials) {
				t.Errorf("step-up on %s after the suspension: %v", name, err)
			}
		}
		if n := p1tEmails(t, e, "security.credential_suspended"); n != 1 {
			t.Errorf("%d emails about the suspension, want 1", n)
		}
		if n := e.count(t, "SELECT count(*) FROM pc.notifications WHERE type = 'security.credential_suspended' AND severity = 'CRITICAL'"); n != 1 {
			t.Errorf("%d critical suspension notices, want 1", n)
		}
		if n := e.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.authn.webauthn_suspended'"); n != 1 {
			t.Errorf("%d suspension audit events, want 1", n)
		}
	})
}
