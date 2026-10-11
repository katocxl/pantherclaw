// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"time"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	"github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// The release of an unknown outcome (G0 M7 slice A11, design decision 3,
// HR-192): "it did not happen" frees the held budget only when a person who
// holds transaction.reconcile where the run's agent lives, and who is not
// the run's launcher, its represented principal, or the agent's owner or
// backup owner, confirms it on /reconciliations/{id}. They write a basis
// and sign the release binding with a security key in M5 part 2's BINDING
// ceremony. Never an API key, a service account or a CLI session.

// Errors of the release.
var (
	ErrBrowserSession = pcerr.New(pcerr.PermissionDenied, "BROWSER_SESSION_REQUIRED",
		"only a person signed in on the reconciliation page releases an unknown outcome")
	ErrNotIndependent = pcerr.New(pcerr.PermissionDenied, "NOT_INDEPENDENT",
		"the run's launcher, its represented principal and the agent's owner and backup owner cannot release its unknown outcome")
	ErrNotReleasable = pcerr.New(pcerr.FailedPrecondition, "NOT_RELEASABLE",
		"only an open unknown outcome is released; a conflicting effect's budget stays committed")
	ErrReleaseExpired = pcerr.New(pcerr.FailedPrecondition, "RELEASE_EXPIRED", "the release expired; start it again")
	// ErrReleaseAssertion refuses an assertion that is not over this
	// release: another basis, other evidence or another expiry, or a
	// ceremony of another person, session or reconciliation, used or
	// expired.
	ErrReleaseAssertion = pcerr.New(pcerr.InvalidArgument, "RELEASE_ASSERTION_INVALID",
		"the security key did not sign this release; start it again")
)

// ReleaseRequest is a release as the person writes it on the page: the
// reconciliation, their basis (untrusted text, at most 2,000 characters)
// and the observations the page showed them.
type ReleaseRequest struct {
	Reconciliation ids.UUID
	Basis          string
	Evidence       []ids.UUID
}

// ReleaseOffer is what the person's key signs: the release document and
// its binding, SHA-256(JCS(document)), the ceremony's challenge.
type ReleaseOffer struct {
	Release domain.Release
	Binding [32]byte
}

// Assertion is a WebAuthn assertion over a release binding, verified by
// the page (origin, RP ID, challenge, user verification, a known active key
// and its counter: authn/app.VerifyBinding). It is kept whole with the
// release.
type Assertion struct {
	Ceremony          ids.UUID
	Credential        ids.UUID
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte
}

// ReleaseView is what the reconciliation page shows: the reconciliation,
// everything recorded about its transaction (the observations are the
// evidence a release names), and whether the caller may release it now,
// else why not (a stable code).
type ReleaseView struct {
	Reconciliation Reconciliation
	Evidence       Evidence
	MayRelease     bool
	Refusal        string
	Now            time.Time
}

// ReleaseStore is the port of the release. Each method runs in one tenant
// transaction.
type ReleaseStore interface {
	// Releasable reports why c may not release the reconciliation now (""
	// when they may), and the database clock.
	Releasable(ctx context.Context, c tenancy.Caller, reconciliation ids.UUID) (string, time.Time, error)
	// BeginRelease checks that c may release the reconciliation now and that
	// the evidence names only its transaction's observations, and returns
	// the release document bound at the database clock.
	BeginRelease(ctx context.Context, c tenancy.Caller, r ReleaseRequest) (domain.Release, error)
	// Release checks everything again and, in one transaction, consumes c's
	// ceremony over the release binding, records the release with the
	// assertion, releases the reservations and the dedupe claim, appends a
	// NONE_CONFIRMED effect receipt whose basis is the person, writes
	// transaction.reconciliation_released, closes the waitlist entry and
	// notifies org admins.
	Release(ctx context.Context, c tenancy.Caller, r ReleaseRequest, expiresAt time.Time, a Assertion, sign Sign) (Reconciliation, error)
	// SpendRelease spends c's open ceremony for the reconciliation, after a
	// refused release.
	SpendRelease(ctx context.Context, c tenancy.Caller, reconciliation, ceremony ids.UUID)
}

// Releases serves the release page's use cases.
type Releases struct {
	Store    ReleaseStore
	Explorer *Explorer
	// Effects signs effect receipts (the verification service's signer).
	Effects *Service
}

// releaser returns the caller, who must be a person signed in on a page
// (HR-156: browser sessions belong to users only).
func releaser(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if !c.Human() || c.Credential != tenancy.CredBrowserSession || c.Session.IsZero() {
		return c, ErrBrowserSession
	}
	return c, nil
}

// View returns what the reconciliation page shows. A caller who may not
// read the reconciliation (evidence.read where the run's agent lives) gets
// "not found" (T-037).
func (r *Releases) View(ctx context.Context, id ids.UUID) (ReleaseView, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return ReleaseView{}, err
	}
	k, _, err := r.Explorer.Reconciliation(ctx, id)
	if pcerr.CodeOf(err) == pcerr.PermissionDenied {
		return ReleaseView{}, ErrReconciliationNotFound
	} else if err != nil {
		return ReleaseView{}, err
	}
	ev, err := r.Explorer.TransactionEvidence(ctx, k.Transaction)
	if pcerr.CodeOf(err) == pcerr.PermissionDenied {
		return ReleaseView{}, ErrReconciliationNotFound
	} else if err != nil {
		return ReleaseView{}, err
	}
	v := ReleaseView{Reconciliation: k, Evidence: ev}
	if _, err := releaser(ctx); err != nil {
		v.Refusal = Refusal(err)
		return v, nil
	}
	if v.Refusal, v.Now, err = r.Store.Releasable(ctx, c, id); err != nil {
		return ReleaseView{}, err
	}
	v.MayRelease = v.Refusal == ""
	return v, nil
}

// BeginRelease checks that the person may release the reconciliation with
// this basis and evidence, and returns what their key signs.
func (r *Releases) BeginRelease(ctx context.Context, req ReleaseRequest) (ReleaseOffer, error) {
	c, err := releaser(ctx)
	if err != nil {
		return ReleaseOffer{}, err
	}
	req.Evidence = domain.ShownEvidence(req.Evidence)
	if err := basis(c, req); err != nil {
		return ReleaseOffer{}, err
	}
	doc, err := r.Store.BeginRelease(ctx, c, req)
	if err != nil {
		return ReleaseOffer{}, translateRelease(err)
	}
	b, err := doc.Binding()
	return ReleaseOffer{Release: doc, Binding: b}, err
}

// Release records the person's release with their verified assertion over
// the release binding (HR-192). Any refusal spends the ceremony, so one
// assertion is never tried twice.
func (r *Releases) Release(ctx context.Context, req ReleaseRequest, expiresAt time.Time, a Assertion) (Reconciliation, error) {
	c, err := releaser(ctx)
	if err != nil {
		return Reconciliation{}, err
	}
	req.Evidence = domain.ShownEvidence(req.Evidence)
	err = basis(c, req)
	var out Reconciliation
	if err == nil {
		out, err = r.Store.Release(ctx, c, req, expiresAt, a, r.Effects.sign)
	}
	if err != nil {
		r.Store.SpendRelease(context.WithoutCancel(ctx), c, req.Reconciliation, a.Ceremony)
		return Reconciliation{}, translateRelease(err)
	}
	return out, nil
}

// EffectReason returns the reason an effect receipt states ("" for none),
// read from the receipt this server signed and stored.
func EffectReason(jws string) string {
	var claims struct {
		Pap struct {
			Reason string `json:"reason"`
		} `json:"pap"`
	}
	if !payload(jws, &claims) {
		return ""
	}
	return claims.Pap.Reason
}

// basis checks the person's basis and the size of their evidence.
func basis(c tenancy.Caller, req ReleaseRequest) error {
	switch err := domain.CheckResolver(true, c.Principal.ID, domain.Party{}, req.Basis, req.Evidence); {
	case errors.Is(err, domain.ErrTooMuchEvidence):
		return ErrEvidence
	case err != nil:
		return ErrBasis
	}
	return nil
}

// translateRelease gives the release's refusals their API errors.
func translateRelease(err error) error {
	switch {
	case errors.Is(err, domain.ErrNotIndependent):
		return ErrNotIndependent
	case errors.Is(err, domain.ErrNotReleasable):
		return ErrNotReleasable
	case errors.Is(err, domain.ErrReleaseExpired):
		return ErrReleaseExpired
	case errors.Is(err, domain.ErrReleaseMismatch):
		return ErrReleaseAssertion
	case errors.Is(err, domain.ErrBasisRequired), errors.Is(err, domain.ErrBasisTooLong):
		return ErrBasis
	}
	return translate(err)
}

// Refusal codes of ReleaseView: why the caller may not release now.
const (
	RefusalBrowserSession = "BROWSER_SESSION_REQUIRED"
	RefusalPermission     = "PERMISSION_DENIED"
	RefusalIndependence   = "NOT_INDEPENDENT"
	RefusalNotOpen        = "RECONCILIATION_NOT_OPEN"
	RefusalNotReleasable  = "NOT_RELEASABLE"
)

// Refusal is the refusal code of a release error, "" for none.
func Refusal(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrBrowserSession):
		return RefusalBrowserSession
	case errors.Is(err, domain.ErrNotIndependent), errors.Is(err, ErrNotIndependent):
		return RefusalIndependence
	case errors.Is(err, domain.ErrNotOpen), errors.Is(err, ErrNotOpen):
		return RefusalNotOpen
	case errors.Is(err, domain.ErrNotReleasable), errors.Is(err, ErrNotReleasable):
		return RefusalNotReleasable
	case pcerr.CodeOf(err) == pcerr.PermissionDenied:
		return RefusalPermission
	}
	return ""
}
