// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package accounts

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evd "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var (
	ErrDeletionPending = pcerr.New(pcerr.FailedPrecondition, "ACCOUNT_DELETION_PENDING", "account deletion is in progress")
	ErrLastAdmin       = pcerr.New(pcerr.FailedPrecondition, "LAST_ORG_ADMIN", "assign another organization administrator before deleting this account")
	ErrReauth          = pcerr.New(pcerr.FailedPrecondition, "REAUTH_REQUIRED", "confirm account deletion on the server after a fresh sign-in")
)

// DeletedAccountRecorder writes the platform security event. A DONE journal
// remains retryable until this callback has succeeded; the sink is idempotent.
type DeletedAccountRecorder func(context.Context, ids.UUID, string, evd.Actor) error

// Deletion uses a global journal and independently committed tenant steps.
// No transaction changes tenant context or claims cross-tenant atomicity.
type Deletion struct {
	store          *Store
	record, intent DeletedAccountRecorder
}

// NewDeletion builds the resumable account eraser. intent must return nil
// only after the exact intent has a verified external-copy acknowledgement
// (F19). Retryable errors keep the identity blocked and personal data intact.
func NewDeletion(s *Store, record, intent DeletedAccountRecorder) *Deletion {
	return &Deletion{store: s, record: record, intent: intent}
}

// DeleteAccount advertises the hosted feature to the RPC adapter. Starting
// deletion always goes through the single-use canonical page ceremony.
func (*Deletion) DeleteAccount(context.Context) error { return ErrReauth }

// Confirm consumes proof of the account-bound forced sign-in. A recent
// ordinary session or an RPC caller's asserted timestamp is insufficient.
func (d *Deletion) Confirm(ctx context.Context, account, session ids.UUID) error {
	err := d.store.pool.InGlobalTx(ctx, db.GlobalAccounts, func(ctx context.Context, tx db.GlobalTx) error {
		n, err := dbq.New(tx).ConsumeDeletionReauthentication(ctx, session, account)
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrReauth
		}
		return nil
	})
	if err != nil {
		return err
	}
	return d.Begin(ctx, account)
}

// Begin is called only by the canonical freshly reauthenticated page.
func (d *Deletion) Begin(ctx context.Context, account ids.UUID) error {
	a, err := d.store.Get(ctx, account)
	if err != nil {
		return err
	}
	err = d.store.pool.InGlobalTx(ctx, db.GlobalAccounts, func(ctx context.Context, tx db.GlobalTx) error {
		q := dbq.New(tx)
		if err := q.AccountIdentityExclusive(ctx, a.Issuer, a.Subject); err != nil {
			return err
		}
		// Active journals already installed the guard atomically. Do not
		// relock them while holding the identity lock: a tenant mutation may
		// hold their share lock while waiting for its organization's lock.
		existing, e := q.AccountDeletion(ctx, account)
		if e == nil && existing.State != "REFUSED" {
			return nil
		}
		if e != nil && !db.IsNoRows(e) {
			return e
		}
		if e == nil {
			if _, e = q.LockAccountDeletion(ctx, account); e != nil {
				return e
			}
		}
		locked, err := q.LockAccount(ctx, account)
		if err != nil {
			return err
		}
		if locked.DeletedAt != nil {
			return nil
		}
		if locked.Issuer != a.Issuer || locked.Subject != a.Subject {
			return ErrDeletionPending
		}
		if err := q.StartAccountDeletion(ctx, account); err != nil {
			return err
		}
		j, err := q.AccountDeletion(ctx, account)
		if err != nil {
			return err
		}
		if j.State == "DONE" {
			return nil
		}
		return q.BlockAccountIdentity(ctx, a.Issuer, a.Subject, "PREPARING")
	})
	if err != nil {
		return err
	}
	return d.Resume(ctx, account)
}

func (d *Deletion) journal(ctx context.Context, account ids.UUID) (dbq.PcAccountDeletion, error) {
	var out dbq.PcAccountDeletion
	err := d.store.pool.InGlobalTx(ctx, db.GlobalAccounts, func(ctx context.Context, tx db.GlobalTx) error {
		var err error
		out, err = dbq.New(tx).AccountDeletion(ctx, account)
		return err
	})
	return out, err
}

func (d *Deletion) transition(ctx context.Context, account ids.UUID, from, to string) error {
	return d.store.pool.InGlobalTx(ctx, db.GlobalAccounts, func(ctx context.Context, tx db.GlobalTx) error {
		return dbq.New(tx).SetAccountDeletionState(ctx, to, account, from)
	})
}

func (d *Deletion) refs(ctx context.Context, account ids.UUID) ([]db.OrgRef, error) {
	r, err := d.store.pool.CrossOrgListWith(ctx, db.ListAccountUsers, 10000, db.ListerParams{AccountID: account})
	if err != nil {
		return nil, err
	}
	if len(r) == 10000 {
		return nil, fmt.Errorf("account deletion enumeration reached safety cap")
	}
	slices.SortFunc(r, func(a, b db.OrgRef) int { return strings.Compare(a.Org.String(), b.Org.String()) })
	return r, nil
}

// Resume is duplicate-safe, including overlapping workers and a crash after
// any commit. A shared journal lock fences every tenant mutation against a
// competing transition into rollback or completion.
func (d *Deletion) Resume(ctx context.Context, account ids.UUID) error {
	for {
		j, err := d.journal(ctx, account)
		if err != nil {
			return err
		}
		a, err := d.store.Get(ctx, account)
		if err != nil {
			return err
		}
		if j.State == "REFUSED" {
			return ErrLastAdmin
		}
		if j.State == "DONE" {
			return d.emit(ctx, j)
		}
		refs, err := d.refs(ctx, account)
		if err != nil {
			return err
		}
		switch j.State {
		case "PREPARING":
			refused := false
			for _, r := range refs {
				err = d.tenant(ctx, account, r, "PREPARING", func(ctx context.Context, tx db.TenantTx, q *dbq.Queries) error {
					if _, e := q.AccountUserDeletionStep(ctx, r.Org, account); e == nil {
						return nil
					} else if !db.IsNoRows(e) {
						return e
					}
					u, e := q.GetUser(ctx, r.Org, r.ID)
					if e != nil {
						return e
					}
					o, e := q.OrgSummary(ctx, r.Org)
					if e != nil {
						return e
					}
					if u.State == "ACTIVE" && o.State == "ACTIVE" {
						admin, e := q.AccountUserIsOrgAdmin(ctx, r.Org, &r.ID)
						if e != nil {
							return e
						}
						if admin {
							n, e := q.CountActiveOrgAdmins(ctx, r.Org)
							if e != nil {
								return e
							}
							if n <= 1 {
								return ErrLastAdmin
							}
						}
					}
					return q.ReserveAccountUser(ctx, r.Org, account, r.ID)
				})
				if errors.Is(err, ErrLastAdmin) {
					refused = true
					break
				}
				if err != nil {
					return err
				}
			}
			if refused {
				err = d.transition(ctx, account, "PREPARING", "ROLLING_BACK")
			} else {
				err = d.transition(ctx, account, "PREPARING", "INTENT_PENDING")
			}
		case "INTENT_PENDING":
			if d.intent == nil {
				return fmt.Errorf("account deletion intent recorder unavailable")
			}
			h := sha256.Sum256([]byte("account.deletion_started:v1:" + account.String() + ":" + j.JournalID.String()))
			if err = d.intent(ctx, account, hex.EncodeToString(h[:]), evd.Actor{Type: "account", ID: account.String()}); err != nil {
				return err
			}
			err = d.transition(ctx, account, "INTENT_PENDING", "DELETING")
		case "ROLLING_BACK":
			for _, r := range refs {
				if err = d.tenant(ctx, account, r, "ROLLING_BACK", func(ctx context.Context, _ db.TenantTx, q *dbq.Queries) error {
					return q.RemoveAccountUserReservation(ctx, r.Org, account)
				}); err != nil {
					return err
				}
			}
			err = d.store.pool.InGlobalTx(ctx, db.GlobalAccounts, func(ctx context.Context, tx db.GlobalTx) error {
				q := dbq.New(tx)
				locked, e := q.LockAccountDeletion(ctx, account)
				if e != nil {
					return e
				}
				if locked.State != "ROLLING_BACK" {
					return nil
				}
				if e := q.UnblockAccountIdentity(ctx, a.Issuer, a.Subject); e != nil {
					return e
				}
				return q.SetAccountDeletionState(ctx, "REFUSED", account, "ROLLING_BACK")
			})
		case "DELETING":
			for _, r := range refs {
				if err = d.scrub(ctx, account, r); err != nil {
					return err
				}
			}
			err = d.finish(ctx, account, a)
		default:
			return fmt.Errorf("unknown account deletion state")
		}
		if err != nil {
			return err
		}
	}
}

func (d *Deletion) tenant(ctx context.Context, account ids.UUID, r db.OrgRef, state string, fn func(context.Context, db.TenantTx, *dbq.Queries) error) error {
	return d.store.pool.InTenantTx(ctx, r.Org, func(ctx context.Context, tx db.TenantTx) error {
		if err := db.SetAccountContext(ctx, tx, account); err != nil {
			return err
		}
		q := dbq.New(tx)
		got, err := q.ShareAccountDeletion(ctx, account)
		if err != nil {
			return err
		}
		if got != state {
			return nil
		}
		// The deletion freezer takes this barrier before the organization
		// row. Keep the same order rather than holding the admin row while
		// waiting for the freezer's exclusive write barrier.
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock_shared(hashtextextended('pc.org.write/' || $1::text, 0))", r.Org.String()); err != nil {
			return err
		}
		if err := q.LockOrgAdmins(ctx, r.Org); err != nil {
			return err
		}
		return fn(ctx, tx, q)
	})
}

func (d *Deletion) scrub(ctx context.Context, account ids.UUID, r db.OrgRef) error {
	return d.tenant(ctx, account, r, "DELETING", func(ctx context.Context, tx db.TenantTx, q *dbq.Queries) error {
		s, err := q.AccountUserDeletionStep(ctx, r.Org, account)
		if err != nil {
			return err
		}
		if s.State == "DELETED" {
			return nil
		}
		if err := q.DisableDeletingAccountUser(ctx, account, r.Org, r.ID); err != nil {
			return err
		}
		if err := q.PseudonymiseAccountUser(ctx, tombstone(), r.Org, r.ID); err != nil {
			return err
		}
		if _, err := q.RevokeUserSessions(ctx, ptrString("USER_DISABLED"), r.Org, r.ID); err != nil {
			return err
		}
		if _, err := q.EndAllUserBrowserSessions(ctx, ptrString("REVOKED"), r.Org, r.ID); err != nil {
			return err
		}
		if err := q.MarkAccountUserDeleted(ctx, r.Org, account); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{Name: "account.user_deleted", Actor: evd.Actor{Type: "account", ID: account.String()}, Outcome: audit.Success, Object: &audit.Object{Type: "user", ID: r.ID.String()}})
		return err
	})
}

func ptrString(v string) *string { return &v }

func tombstone() string {
	var u ids.UUID
	_, _ = rand.Read(u[:])
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	return u.String()
}

func (d *Deletion) finish(ctx context.Context, account ids.UUID, a Account) error {
	return d.store.pool.InGlobalTx(ctx, db.GlobalAccounts, func(ctx context.Context, tx db.GlobalTx) error {
		q := dbq.New(tx)
		// The exclusive journal lock waits for every in-flight tenant step.
		j, err := q.LockAccountDeletion(ctx, account)
		if err != nil {
			return err
		}
		if j.State != "DELETING" {
			return nil
		}
		if j.RecordDigest != "" {
			return nil
		}
		if err := q.EndDeletedAccountSessions(ctx, account); err != nil {
			return err
		}
		if err := q.ScrubDeletedAccountEvents(ctx, account); err != nil {
			return err
		}
		if err := q.TombstoneAccount(ctx, tombstone(), account); err != nil {
			return err
		}
		if err := q.UnblockAccountIdentity(ctx, a.Issuer, a.Subject); err != nil {
			return err
		}
		h := sha256.Sum256([]byte("account.deleted:v1:" + account.String()))
		if err := q.SetAccountDeletionDigest(ctx, hex.EncodeToString(h[:]), account); err != nil {
			return err
		}
		if err := q.InsertAccountEvent(ctx, dbq.InsertAccountEventParams{AccountID: account, Kind: "ACCOUNT_DELETED"}); err != nil {
			return err
		}
		return q.SetAccountDeletionState(ctx, "DONE", account, "DELETING")
	})
}

func (d *Deletion) emit(ctx context.Context, j dbq.PcAccountDeletion) error {
	if j.EventRecorded {
		return nil
	}
	if d.record == nil {
		return fmt.Errorf("account deletion security-event recorder unavailable")
	}
	if err := d.record(ctx, j.AccountID, j.RecordDigest, evd.Actor{Type: "account", ID: j.AccountID.String()}); err != nil {
		return err
	}
	return d.store.pool.InGlobalTx(ctx, db.GlobalAccounts, func(ctx context.Context, tx db.GlobalTx) error {
		return dbq.New(tx).AccountDeletionEventRecorded(ctx, j.AccountID)
	})
}

// ResumePending is the bounded periodic worker entry point.
func (d *Deletion) ResumePending(ctx context.Context) error {
	var pending []ids.UUID
	err := d.store.pool.InGlobalTx(ctx, db.GlobalAccounts, func(ctx context.Context, tx db.GlobalTx) error {
		var err error
		pending, err = dbq.New(tx).PendingAccountDeletions(ctx)
		return err
	})
	if err != nil {
		return err
	}
	var errs []error
	for _, account := range pending {
		if err := d.Resume(ctx, account); err != nil && !errors.Is(err, ErrLastAdmin) && pcerr.ReasonOf(err) != "DELETION_AWAITING_SECURITY_COPY" {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Reapply resumes account erasure under the restore maintenance hold. The
// caller validates the closed event schema before invoking this callback.
// Missing account provenance fails closed: an ID alone cannot safely locate
// legacy users in a dump from before the account itself existed.
func (d *Deletion) Reapply(ctx context.Context, account ids.UUID, sourceDigest string, actor evd.Actor) error {
	decoded, err := hex.DecodeString(sourceDigest)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != sourceDigest || actor.Type != "operator" || actor.ID == "" {
		return fmt.Errorf("accounts: invalid deletion replay provenance")
	}
	if err := d.Begin(ctx, account); err != nil {
		return err
	}
	return d.store.pool.InTenantTx(ctx, ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
		_, err := audit.Record(ctx, tx, audit.Event{Name: "restore.account_reapplied", Actor: actor, Outcome: audit.Success, Object: &audit.Object{Type: "account", ID: account.String()}, Details: map[string]string{"source_digest": sourceDigest}})
		return err
	})
}
