// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"slices"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// purposeBinding is the approval ceremony (G0 M5 part 2): its challenge is
// the binding of an approval request, or the hash of a batch.
const purposeBinding = "BINDING"

// BindingSubject is what a BINDING ceremony signs: one approval request,
// one batch, or (G0 M7 slice A11) the release of one reconciliation.
type BindingSubject struct {
	Request        ids.UUID
	Batch          ids.UUID
	Reconciliation ids.UUID
}

func (b BindingSubject) params() (request, batch, reconciliation *ids.UUID) {
	if !b.Request.IsZero() {
		r := b.Request
		request = &r
	}
	if !b.Batch.IsZero() {
		x := b.Batch
		batch = &x
	}
	if !b.Reconciliation.IsZero() {
		k := b.Reconciliation
		reconciliation = &k
	}
	return request, batch, reconciliation
}

// one reports whether the subject names exactly one thing.
func (b BindingSubject) one() bool {
	n := 0
	for _, id := range []ids.UUID{b.Request, b.Batch, b.Reconciliation} {
		if !id.IsZero() {
			n++
		}
	}
	return n == 1
}

// BeginBinding starts the approval ceremony (HR-033, design decision 12):
// a WebAuthn assertion whose challenge is exactly the binding (or batch
// hash) the approvals use case gave, with user verification required,
// over one of the person's active keys, bound to this browser session, the
// user and the request or batch for 5 minutes. A release (G0 M7 design
// decision 3) uses the same ceremony over the release's binding, bound to
// the reconciliation. A person's open ceremony for the same subject is
// replaced, so a reload starts afresh.
func (w *WebAuthn) BeginBinding(ctx context.Context, s BrowserSession, subject BindingSubject, challenge [32]byte) (Ceremony, error) {
	if !subject.one() {
		return Ceremony{}, ErrCeremonyInvalid
	}
	request, batch, reconciliation := subject.params()
	var out Ceremony
	err := w.pool.InTenantTx(ctx, s.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		u, err := loadUser(ctx, q, s.Org, s.User())
		if err != nil {
			return err
		}
		if len(u.credentials) == 0 {
			return ErrNoCredentials
		}
		assertion, sd, err := w.wa.BeginLogin(u, webauthn.WithChallenge(challenge[:]),
			webauthn.WithAllowedCredentials(descriptors(u.credentials)), webauthn.WithUserVerification(protocol.VerificationRequired))
		if err != nil {
			return err
		}
		raw, err := decodeChallenge(sd.Challenge)
		if err != nil || !bytes.Equal(raw, challenge[:]) {
			return errors.Join(err, errors.New("authn: the ceremony's challenge is not the binding"))
		}
		opts, err := json.Marshal(assertion)
		if err != nil {
			return err
		}
		if err := q.DeleteOpenBindingCeremonies(ctx, dbq.DeleteOpenBindingCeremoniesParams{
			OrgID: s.Org, UserID: s.User(), ApprovalRequestID: request, BatchID: batch, ReconciliationID: reconciliation,
		}); err != nil {
			return err
		}
		out.ID, out.Options = ids.NewV7(), opts
		return q.InsertBindingCeremony(ctx, dbq.InsertBindingCeremonyParams{
			OrgID: s.Org, ID: out.ID, SessionID: s.ID, UserID: s.User(), Challenge: raw,
			AllowedCredentials: sd.AllowedCredentialIDs, ApprovalRequestID: request, BatchID: batch,
			ReconciliationID: reconciliation, TtlSeconds: int32(CeremonyTTL / time.Second),
		})
	})
	return out, err
}

// BindingAssertion is an assertion VerifyBinding verified: the ceremony
// (still open; the approvals use case consumes it in the transaction that
// records the response), what it signed, and the parts kept for M6
// (HR-038).
type BindingAssertion struct {
	Ceremony          ids.UUID
	Subject           BindingSubject
	Challenge         [32]byte
	Credential        ids.UUID
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte
}

// VerifyBinding verifies an assertion over an open BINDING ceremony of this
// browser session and user (HR-033, HR-153, HR-154): origin, RP ID, the
// challenge, user verification, a known active key and a counter that
// moves forward. Any failure spends the ceremony, so a response is never
// tried twice; a counter that does not move forward suspends the key.
func (w *WebAuthn) VerifyBinding(ctx context.Context, s BrowserSession, ceremony ids.UUID, response []byte) (BindingAssertion, error) {
	fail := func(reason string, err error) (BindingAssertion, error) {
		_, _ = w.consume(ctx, s, ceremony, purposeBinding)
		return BindingAssertion{}, w.verifyFailed(ctx, s, reason, err)
	}
	if len(response) > maxResponseBytes {
		return fail("assertion_size", nil)
	}
	parsed, perr := protocol.ParseCredentialRequestResponseBytes(response)
	var out BindingAssertion
	var suspended bool
	err := w.pool.InTenantTx(ctx, s.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.GetOpenBindingCeremony(ctx, dbq.GetOpenBindingCeremonyParams{OrgID: s.Org, ID: ceremony, SessionID: s.ID, UserID: s.User()})
		if err != nil {
			return notFoundAs(err, ErrCeremonyInvalid)
		}
		if perr != nil {
			return errAssertion
		}
		u, err := loadUser(ctx, q, s.Org, s.User())
		if err != nil {
			return err
		}
		user := s.User()
		sd := webauthn.SessionData{
			Challenge: base64.RawURLEncoding.EncodeToString(row.Challenge), RelyingPartyID: w.wa.Config.RPID,
			UserID: user[:], AllowedCredentialIDs: row.AllowedCredentials, Expires: row.ExpiresAt,
			UserVerification: protocol.VerificationRequired,
		}
		c, err := w.wa.ValidateLogin(u, sd, parsed)
		if err != nil || !c.Flags.UserVerified {
			return errAssertion
		}
		i := slices.IndexFunc(u.credentials, func(x webauthn.Credential) bool { return bytes.Equal(x.ID, c.ID) })
		if i < 0 {
			return errAssertion
		}
		id, received := u.rowIDs[i], parsed.Response.AuthenticatorData.Counter
		if !CounterOK(u.counts[i], received) {
			return w.suspend(ctx, tx, q, s, id, u.counts[i], received, &suspended)
		}
		n, err := q.RecordAssertion(ctx, dbq.RecordAssertionParams{OrgID: s.Org, ID: id, SignCount: int64(received), BackupState: c.Flags.BackupState})
		if err != nil {
			return err
		}
		if n == 0 {
			return w.suspend(ctx, tx, q, s, id, u.counts[i], received, &suspended)
		}
		out = BindingAssertion{
			Ceremony: ceremony, Credential: id, AuthenticatorData: parsed.Raw.AssertionResponse.AuthenticatorData,
			ClientDataJSON: parsed.Raw.AssertionResponse.ClientDataJSON, Signature: parsed.Raw.AssertionResponse.Signature,
		}
		copy(out.Challenge[:], row.Challenge)
		if row.ApprovalRequestID != nil {
			out.Subject.Request = *row.ApprovalRequestID
		}
		if row.BatchID != nil {
			out.Subject.Batch = *row.BatchID
		}
		if row.ReconciliationID != nil {
			out.Subject.Reconciliation = *row.ReconciliationID
		}
		return nil
	})
	switch {
	case errors.Is(err, errAssertion):
		return fail("binding_verify", perr)
	case err != nil && !errors.Is(err, ErrCeremonyInvalid):
		return fail("binding_error", err)
	case err != nil:
		return BindingAssertion{}, err
	case suspended:
		_, _ = w.consume(ctx, s, ceremony, purposeBinding)
		return BindingAssertion{}, ErrCredentialSuspended
	}
	return out, nil
}

// errAssertion marks an assertion that did not verify.
var errAssertion = errors.New("authn: the assertion did not verify")

// SpendBinding consumes an open BINDING ceremony without recording
// anything, after the approvals use case refused the response.
func (w *WebAuthn) SpendBinding(ctx context.Context, s BrowserSession, ceremony ids.UUID) {
	_, _ = w.consume(ctx, s, ceremony, purposeBinding)
}
