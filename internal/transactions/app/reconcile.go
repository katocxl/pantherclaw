// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	"github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// Errors of the reconciliation use cases.
var (
	ErrHumanOnly              = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can do this")
	ErrReconciliationNotFound = pcerr.New(pcerr.NotFound, "RECONCILIATION_NOT_FOUND", "reconciliation not found")
	ErrNotOpen                = pcerr.New(pcerr.FailedPrecondition, "RECONCILIATION_NOT_OPEN", "the reconciliation is no longer open")
	ErrBasis                  = pcerr.New(pcerr.InvalidArgument, "INVALID_BASIS", "a basis of 1 to 2000 characters is required")
	ErrEvidence               = pcerr.New(pcerr.InvalidArgument, "INVALID_EVIDENCE", "evidence names only the transaction's observations, the authoritative one among them")
	ErrNoVerifier             = pcerr.New(pcerr.FailedPrecondition, "NO_VERIFIER", "nothing verifies this transaction's effect")
	ErrLinkOrder              = pcerr.New(pcerr.FailedPrecondition, "LINK_ORDER", "the later transaction must be decided after the earlier one was dispatched")
	ErrLinkSelf               = pcerr.New(pcerr.InvalidArgument, "LINK_SELF", "a transaction cannot be linked to itself")
	ErrLinkExists             = pcerr.New(pcerr.AlreadyExists, "LINK_EXISTS", "these transactions are already linked")
)

// Resolution is a person's "occurred" (design decision 3).
type Resolution struct {
	Reconciliation ids.UUID
	// Basis is the person's untrusted text.
	Basis    string
	Evidence []ids.UUID
	// Authoritative is the observation the person relied on, one of
	// Evidence.
	Authoritative *ids.UUID
}

// LinkRequest links a later transaction to an earlier one (HR-193).
type LinkRequest struct {
	From, To ids.UUID
	Kind     domain.LinkKind
}

// ReconcileStore is the port of the people-facing reconciliation use
// cases. Each method runs in one tenant transaction and checks
// transaction.reconcile where the run's agent lives.
type ReconcileStore interface {
	// ResolveOccurred resolves an open reconciliation as occurred by c:
	// an unknown outcome's reservations are committed and its dedupe claim
	// succeeds; a person-based CONFIRMED effect receipt is appended unless
	// the effect is confirmed already.
	ResolveOccurred(ctx context.Context, c tenancy.Caller, r Resolution, sign Sign) (Reconciliation, error)
	// RequestVerification makes the transaction's open verification due
	// now, or opens a new one like its latest, and returns it.
	RequestVerification(ctx context.Context, c tenancy.Caller, txn ids.UUID) (ids.UUID, error)
	// Link links two transactions and, when the later one compensates the
	// earlier and both effects are confirmed, appends the earlier one's
	// COMPENSATED receipt.
	Link(ctx context.Context, c tenancy.Caller, l LinkRequest, sign Sign) (Link, error)
}

// Reconciler serves the people-facing reconciliation use cases. Releasing
// ("did not occur") is a page action with a security key, never here.
type Reconciler struct {
	Store ReconcileStore
	// Effects signs effect receipts (the verification service's signer).
	Effects *Service
}

// human returns the caller, who must be a person.
func human(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if !c.Human() {
		return c, ErrHumanOnly
	}
	return c, nil
}

// ResolveOccurred records, as a person with a basis, that an effect
// happened (HR-192).
func (r *Reconciler) ResolveOccurred(ctx context.Context, res Resolution) (Reconciliation, error) {
	c, err := human(ctx)
	if err != nil {
		return Reconciliation{}, err
	}
	switch err := domain.CheckOccurred(true, res.Basis, res.Evidence, res.Authoritative); {
	case errors.Is(err, domain.ErrNotEvidence), errors.Is(err, domain.ErrTooMuchEvidence):
		return Reconciliation{}, ErrEvidence
	case err != nil:
		return Reconciliation{}, ErrBasis
	}
	out, err := r.Store.ResolveOccurred(ctx, c, res, r.Effects.sign)
	return out, translate(err)
}

// RequestVerification asks for the transaction's effect to be read again
// now.
func (r *Reconciler) RequestVerification(ctx context.Context, txn ids.UUID) (ids.UUID, error) {
	c, err := human(ctx)
	if err != nil {
		return ids.UUID{}, err
	}
	return r.Store.RequestVerification(ctx, c, txn)
}

// Link links a later, separately authorized transaction to an earlier one.
func (r *Reconciler) Link(ctx context.Context, l LinkRequest) (Link, error) {
	c, err := human(ctx)
	if err != nil {
		return Link{}, err
	}
	if l.Kind != domain.LinkCompensates && l.Kind != domain.LinkRecovers {
		return Link{}, pcerr.New(pcerr.InvalidArgument, "INVALID_LINK_KIND", "a link compensates or recovers")
	}
	out, err := r.Store.Link(ctx, c, l, r.Effects.sign)
	return out, translate(err)
}

// translate gives the domain's refusals their API errors.
func translate(err error) error {
	switch {
	case errors.Is(err, domain.ErrNotOpen):
		return ErrNotOpen
	case errors.Is(err, domain.ErrNotEvidence):
		return ErrEvidence
	case errors.Is(err, domain.ErrLinkOrder):
		return ErrLinkOrder
	case errors.Is(err, domain.ErrLinkSelf):
		return ErrLinkSelf
	}
	return err
}
