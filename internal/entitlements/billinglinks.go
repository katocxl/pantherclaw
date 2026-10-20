// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package entitlements

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Billing link errors (extension.ErrNotFound, extension.ErrConflict).
var (
	ErrLinkNotFound = pcerr.New(pcerr.NotFound, "BILLING_LINK_NOT_FOUND", "unknown billing reference")
	ErrLinkConflict = pcerr.New(pcerr.Aborted, "BILLING_LINK_CONFLICT", "the billing reference conflicts with a recorded one")
	ErrInvalidLink  = pcerr.New(pcerr.InvalidArgument, "INVALID_BILLING_LINK", "invalid billing reference")
	// ErrLinkDuplicate: the subscription was kept as a duplicate of the
	// org's current one (D52); it is a kind of ErrLinkConflict.
	ErrLinkDuplicate = fmt.Errorf("%w: duplicate subscription", ErrLinkConflict)
)

const stateDuplicate = "DUPLICATE"

// MaxCheckoutTTL bounds a recorded checkout's life (the table allows 7 days).
const MaxCheckoutTTL = 7 * 24 * time.Hour

const (
	kindCheckout     = "CHECKOUT"
	kindSubscription = "SUBSCRIPTION"
)

var providerPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

func validRef(r string) bool { return r != "" && len(r) <= 255 }

// Links binds billing subscriptions to orgs only through checkouts the
// server recorded (G0 UI D36, D37, D45, D46; extension.BillingLinks). A
// ref is unique per provider and kind across orgs and never moves to
// another org; an org has at most one current subscription per provider.
type Links struct {
	pool  *db.Pool
	clock interface{ Now() time.Time }
}

// NewLinks returns the billing links over pool.
func (s *Service) NewLinks() *Links { return &Links{pool: s.pool, clock: s.clock} }

// orgOf finds the org of (provider, kind, ref) through the audited lister.
func orgOf(ctx context.Context, tx db.DBTX, provider, kind, ref string) (ids.OrgID, ids.UUID, bool, error) {
	refs, err := db.CrossOrgListIn(ctx, tx, db.ListBillingLink, 2, db.ListerParams{
		BillingProvider: provider, BillingKind: kind, BillingRef: ref,
	})
	if err != nil || len(refs) == 0 {
		return ids.OrgID{}, ids.UUID{}, false, err
	}
	return refs[0].Org, refs[0].ID, true, nil
}

// lookup finds the org of a ref in its own global transaction.
func (l *Links) lookup(ctx context.Context, provider, kind, ref string) (ids.OrgID, bool, error) {
	var org ids.OrgID
	var found bool
	err := l.pool.InGlobalTx(ctx, db.GlobalCrossOrgList, func(ctx context.Context, tx db.GlobalTx) error {
		var err error
		org, _, found, err = orgOf(ctx, tx, provider, kind, ref)
		return err
	})
	return org, found, err
}

func parseOrg(s string) (ids.OrgID, error) {
	org, err := ids.Parse[ids.Org](s)
	if err != nil || org == ids.PlatformOrg {
		return ids.OrgID{}, ErrUnknownOrg
	}
	return org, nil
}

// RecordCheckout records a checkout the server created for org (D45). A
// pending checkout of the org and provider is superseded (marked expired)
// and its ref returned; recording the same pending ref again changes
// nothing. It is refused (ErrLinkConflict) when the org has a current
// subscription with the provider or the ref is recorded otherwise.
func (l *Links) RecordCheckout(ctx context.Context, orgID, provider, checkoutRef string, expiresAt time.Time) (string, error) {
	org, err := parseOrg(orgID)
	if err != nil {
		return "", err
	}
	now := l.clock.Now()
	if !providerPattern.MatchString(provider) || !validRef(checkoutRef) || !expiresAt.After(now) ||
		expiresAt.Sub(now) > MaxCheckoutTTL-time.Minute {
		return "", ErrInvalidLink
	}
	var superseded string
	err = l.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if state, err := q.OrgState(ctx, org); db.IsNoRows(err) || (err == nil && state != "ACTIVE") {
			return ErrUnknownOrg
		} else if err != nil {
			return err
		}
		if err := q.LockBillingOrg(ctx, org.UUID()); err != nil {
			return err
		}
		if err := q.LockBillingRef(ctx, provider, kindCheckout, checkoutRef); err != nil {
			return err
		}
		owner, _, found, err := orgOf(ctx, tx, provider, kindCheckout, checkoutRef)
		if err != nil {
			return err
		}
		if found {
			if owner != org {
				return ErrLinkConflict
			}
			cur, err := q.BillingLinkByRef(ctx, dbq.BillingLinkByRefParams{OrgID: org, Provider: provider, Kind: kindCheckout, Ref: checkoutRef})
			if err != nil {
				return err
			}
			if cur.State == "PENDING" {
				return nil // the same pending checkout again
			}
			return ErrLinkConflict
		}
		if _, err := q.CurrentSubscription(ctx, org, provider); err == nil {
			return ErrLinkConflict
		} else if !db.IsNoRows(err) {
			return err
		}
		if old, err := q.PendingCheckout(ctx, org, provider); err == nil {
			if _, err := q.SetBillingLinkState(ctx, dbq.SetBillingLinkStateParams{
				State: "EXPIRED", OrgID: org, ID: old.ID, FromState: "PENDING",
			}); err != nil {
				return err
			}
			superseded = old.Ref
		} else if !db.IsNoRows(err) {
			return err
		}
		exp := expiresAt.UTC()
		id := ids.NewV7()
		if err := q.InsertBillingLink(ctx, dbq.InsertBillingLinkParams{
			OrgID: org, ID: id, Provider: provider, Kind: kindCheckout, Ref: checkoutRef, State: "PENDING", ExpiresAt: &exp,
		}); err != nil {
			return err
		}
		details := map[string]string{"provider": provider, "kind": "checkout", "expires_at": exp.Format(time.RFC3339)}
		if superseded != "" {
			details["superseded"] = "true"
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "billing.checkout_recorded", Actor: billingActor, Outcome: audit.Success,
			Object: &audit.Object{Type: "billing_link", ID: id.String()}, Details: details,
		})
		return err
	})
	return superseded, err
}

// BindSubscription binds a subscription to the org of the server-recorded
// checkout it was bought through, and consumes the checkout (D37, D46). An
// expired or superseded checkout still binds when the org has no current
// subscription; the same checkout and subscription again returns the org.
// It is refused (ErrLinkConflict) when the checkout was consumed by
// another subscription, the org has a different current subscription, or
// the subscription is recorded otherwise; an unknown checkout is
// ErrLinkNotFound.
func (l *Links) BindSubscription(ctx context.Context, provider, checkoutRef, subscriptionRef, customerRef string) (string, error) {
	if !providerPattern.MatchString(provider) || !validRef(checkoutRef) || !validRef(subscriptionRef) || len(customerRef) > 255 {
		return "", ErrInvalidLink
	}
	org, found, err := l.lookup(ctx, provider, kindCheckout, checkoutRef)
	if err != nil {
		return "", err
	}
	if !found {
		return "", ErrLinkNotFound
	}
	var duplicate bool
	bind := func(ctx context.Context, tx db.TenantTx) error {
		duplicate = false
		q := dbq.New(tx)
		if err := q.LockBillingOrg(ctx, org.UUID()); err != nil {
			return err
		}
		if err := q.LockBillingRef(ctx, provider, kindSubscription, subscriptionRef); err != nil {
			return err
		}
		co, err := q.BillingLinkByRef(ctx, dbq.BillingLinkByRefParams{OrgID: org, Provider: provider, Kind: kindCheckout, Ref: checkoutRef})
		if db.IsNoRows(err) {
			return ErrLinkNotFound
		} else if err != nil {
			return err
		}
		if sub, err := q.SubscriptionByCheckout(ctx, org, &co.ID); err == nil {
			switch {
			case sub.Ref != subscriptionRef:
				return ErrLinkConflict
			case sub.State == stateDuplicate:
				duplicate = true
			}
			return nil // the same binding again
		} else if !db.IsNoRows(err) {
			return err
		}
		if _, _, taken, err := orgOf(ctx, tx, provider, kindSubscription, subscriptionRef); err != nil {
			return err
		} else if taken {
			return ErrLinkConflict
		}
		state := "CURRENT"
		if _, err := q.CurrentSubscription(ctx, org, provider); err == nil {
			// D52: a second subscription of the org is kept, ended, for
			// the adapter to cancel and refund.
			state, duplicate = stateDuplicate, true
		} else if !db.IsNoRows(err) {
			return err
		}
		if n, err := q.SetBillingLinkState(ctx, dbq.SetBillingLinkStateParams{
			State: "CONSUMED", OrgID: org, ID: co.ID, FromState: co.State,
		}); err != nil {
			return err
		} else if n == 0 {
			return db.ErrLostRace
		}
		id := ids.NewV7()
		if err := q.InsertBillingLink(ctx, dbq.InsertBillingLinkParams{
			OrgID: org, ID: id, Provider: provider, Kind: kindSubscription, Ref: subscriptionRef, CustomerRef: customerRef,
			State: state, CheckoutID: &co.ID,
		}); err != nil {
			return err
		}
		name, outcome := "billing.subscription_bound", audit.Success
		if duplicate {
			name, outcome = "billing.subscription_duplicate", audit.Denied
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: name, Actor: billingActor, Outcome: outcome,
			Object:  &audit.Object{Type: "billing_link", ID: id.String()},
			Details: map[string]string{"provider": provider, "checkout_link": co.ID.String(), "checkout_state": co.State},
		})
		return err
	}
	// Both locks serialize binds of one org and of one subscription, so a
	// unique clash means a concurrent writer got in first some other way:
	// decide again from what it stored (D55), never surface the clash.
	for attempt := 0; ; attempt++ {
		err = l.pool.InTenantTx(ctx, org, bind)
		if (db.IsUniqueViolation(err) || errors.Is(err, db.ErrLostRace)) && attempt == 0 {
			continue
		}
		break
	}
	if db.IsUniqueViolation(err) {
		err = ErrLinkConflict
	}
	if err != nil {
		return "", err
	}
	if duplicate {
		return org.String(), ErrLinkDuplicate
	}
	return org.String(), nil
}

// SubscriptionOrg returns the org a subscription is bound to and whether
// it is current (not ended); ErrLinkNotFound when it is unknown.
func (l *Links) SubscriptionOrg(ctx context.Context, provider, subscriptionRef string) (string, bool, error) {
	if !providerPattern.MatchString(provider) || !validRef(subscriptionRef) {
		return "", false, ErrInvalidLink
	}
	org, found, err := l.lookup(ctx, provider, kindSubscription, subscriptionRef)
	if err != nil {
		return "", false, err
	}
	if !found {
		return "", false, ErrLinkNotFound
	}
	var current bool
	err = l.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).BillingLinkByRef(ctx, dbq.BillingLinkByRefParams{
			OrgID: org, Provider: provider, Kind: kindSubscription, Ref: subscriptionRef,
		})
		if db.IsNoRows(err) {
			return ErrLinkNotFound
		} else if err != nil {
			return err
		}
		current = r.State == "CURRENT"
		return nil
	})
	if err != nil {
		return "", false, err
	}
	return org.String(), current, nil
}

// EndSubscription ends a subscription (canceled for good, refunded or
// charged back, D38). Ending an ended one changes nothing.
func (l *Links) EndSubscription(ctx context.Context, provider, subscriptionRef string) error {
	if !providerPattern.MatchString(provider) || !validRef(subscriptionRef) {
		return ErrInvalidLink
	}
	org, found, err := l.lookup(ctx, provider, kindSubscription, subscriptionRef)
	if err != nil {
		return err
	}
	if !found {
		return ErrLinkNotFound
	}
	return l.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.BillingLinkByRef(ctx, dbq.BillingLinkByRefParams{OrgID: org, Provider: provider, Kind: kindSubscription, Ref: subscriptionRef})
		if db.IsNoRows(err) {
			return ErrLinkNotFound
		} else if err != nil {
			return err
		}
		if r.State != "CURRENT" {
			return nil
		}
		if _, err := q.SetBillingLinkState(ctx, dbq.SetBillingLinkStateParams{
			State: "ENDED", OrgID: org, ID: r.ID, FromState: "CURRENT",
		}); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "billing.subscription_ended", Actor: billingActor, Outcome: audit.Success,
			Object: &audit.Object{Type: "billing_link", ID: r.ID.String()}, Details: map[string]string{"provider": provider},
		})
		return err
	})
}

// CurrentSubscription returns org's current subscription with provider.
func (l *Links) CurrentSubscription(ctx context.Context, orgID, provider string) (string, bool, error) {
	org, err := parseOrg(orgID)
	if err != nil {
		return "", false, err
	}
	if !providerPattern.MatchString(provider) {
		return "", false, ErrInvalidLink
	}
	var ref string
	err = l.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).CurrentSubscription(ctx, org, provider)
		if db.IsNoRows(err) {
			return nil
		} else if err != nil {
			return err
		}
		ref = r.Ref
		return nil
	}, db.ReadOnly())
	return ref, ref != "", err
}

// IsLinkNotFound and IsLinkConflict classify Links errors for adapters.
func IsLinkNotFound(err error) bool { return errors.Is(err, ErrLinkNotFound) }

// IsLinkConflict reports a refused binding.
func IsLinkConflict(err error) bool { return errors.Is(err, ErrLinkConflict) }
