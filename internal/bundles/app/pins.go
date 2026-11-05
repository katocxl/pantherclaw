// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/ed25519"
	"net/url"
	"slices"
	"strings"
	"time"

	bdomain "github.com/katocxl/pantherclaw/internal/bundles/domain"
	"github.com/katocxl/pantherclaw/internal/bundles/format"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
)

// NewPin describes a publisher key to pin.
type NewPin struct {
	Publisher      string
	PublicKey      []byte
	AllowedKinds   []string
	RevocationsURL string
	// ExpectedFingerprint, when set, must equal the fingerprint the server
	// computes from PublicKey (D1084b).
	ExpectedFingerprint string
}

// Pin is a pinned publisher key.
type Pin struct {
	ID             ids.UUID
	Publisher      string
	KID            string
	PublicKey      []byte
	Fingerprint    string
	AllowedKinds   []string
	RevocationsURL string
	State          string
	RevokeReason   string
	CreatedBy      string
	CreatedAt      time.Time
	ActivatedBy    *ids.UUID
	ActivatedAt    *time.Time
	RevokedAt      *time.Time
}

// checkRevocationsURL allows an absolute https URL without credentials or
// fragment. Where it resolves is checked at every fetch by the egress
// client (public addresses only, no redirects).
func checkRevocationsURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || len(raw) > 2048 {
		return bdomain.ErrPinInvalid
	}
	return nil
}

// PinKey records a PENDING pin (D1081): a person holding publisher.manage.
// A key revoked as compromised, or by its publisher, is never pinned again.
func (s *Service) PinKey(ctx context.Context, in NewPin) (Pin, error) {
	c, err := person(ctx, bdomain.PermPublisherManage)
	if err != nil {
		return Pin{}, err
	}
	if !format.ValidPublisher(in.Publisher) || len(in.PublicKey) != ed25519.PublicKeySize || checkRevocationsURL(in.RevocationsURL) != nil {
		return Pin{}, bdomain.ErrPinInvalid
	}
	kinds := []string{}
	for _, k := range in.AllowedKinds {
		if !format.Kind(k).Valid() || slices.Contains(kinds, k) {
			return Pin{}, bdomain.ErrPinInvalid
		}
		kinds = append(kinds, k)
	}
	pub := ed25519.PublicKey(slices.Clone(in.PublicKey))
	if in.ExpectedFingerprint != "" && in.ExpectedFingerprint != format.Fingerprint(pub) {
		return Pin{}, bdomain.ErrFingerprint
	}
	kid := format.KID(in.Publisher, pub)
	var revURL *string
	if in.RevocationsURL != "" {
		revURL = &in.RevocationsURL
	}
	id := ids.NewV7()
	var out Pin
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		withdrawn, err := q.KidWithdrawn(ctx, c.Org, kid)
		if err != nil {
			return err
		}
		if withdrawn {
			return bdomain.ErrKeyWithdrawn
		}
		err = q.InsertPublisherPin(ctx, dbq.InsertPublisherPinParams{
			OrgID: c.Org, ID: id, Publisher: in.Publisher, Kid: kid, PublicKey: pub, Fingerprint: format.Fingerprint(pub),
			AllowedKinds: kinds, RevocationsUrl: revURL, CreatedBy: c.Principal.ID.String(),
		})
		if db.IsUniqueViolation(err) {
			return bdomain.ErrPinExists
		} else if err != nil {
			return err
		}
		if err := record(ctx, tx, c.Actor(), audit.Success, auditkind.PublisherPinCreated, "publisher_pin", id.String(), map[string]string{
			"publisher": in.Publisher, "kid": kid, "fingerprint": format.Fingerprint(pub), "allowed_kinds": strings.Join(kinds, ","),
		}); err != nil {
			return err
		}
		out, err = getPin(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

// ActivatePin makes a PENDING pin ACTIVE (HR-795): a person holding
// publisher.manage, with a fresh step-up made with their own active key;
// su is nil over the API, which refuses.
func (s *Service) ActivatePin(ctx context.Context, id ids.UUID, su *stepup.StepUp) (Pin, error) {
	c, err := person(ctx, bdomain.PermPublisherManage)
	if err != nil {
		return Pin{}, err
	}
	if su == nil {
		return Pin{}, stepup.ErrStepUp
	}
	var out Pin
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if err := stepup.Check(ctx, tx, c, *su, now); err != nil {
			return err
		}
		p, err := getPin(ctx, q, c.Org, id)
		if err != nil {
			return err
		}
		if p.State != bdomain.PinPending {
			return bdomain.ErrPinState
		}
		// A statement may have withdrawn the key since it was pinned.
		if withdrawn, err := q.KidWithdrawn(ctx, c.Org, p.KID); err != nil {
			return err
		} else if withdrawn {
			return bdomain.ErrKeyWithdrawn
		}
		n, err := q.ActivatePublisherPin(ctx, dbq.ActivatePublisherPinParams{
			ActivatedBy: &c.Principal.ID, ActivatedCredential: &su.Credential, OrgID: c.Org, ID: id,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return bdomain.ErrPinState
		}
		if err := record(ctx, tx, c.Actor(), audit.Success, auditkind.PublisherPinActivated, "publisher_pin", id.String(), map[string]string{
			"publisher": p.Publisher, "kid": p.KID, "fingerprint": p.Fingerprint, "security_key": su.Credential.String(),
		}); err != nil {
			return err
		}
		out, err = getPin(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

// RevokePin revokes a pin (a person holding publisher.manage). UNPINNED
// stops new installs with the key; COMPROMISED also revokes, in the same
// transaction, every install the key signed (D1083).
func (s *Service) RevokePin(ctx context.Context, id ids.UUID, reason string) (Pin, []ids.UUID, error) {
	c, err := person(ctx, bdomain.PermPublisherManage)
	if err != nil {
		return Pin{}, nil, err
	}
	if reason != bdomain.ReasonUnpinned && reason != bdomain.ReasonCompromised {
		return Pin{}, nil, bdomain.ErrReason
	}
	var out Pin
	var revoked []ids.UUID
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		p, err := getPin(ctx, q, c.Org, id)
		if err != nil {
			return err
		}
		n, err := q.RevokePublisherPin(ctx, &reason, c.Org, id)
		if err != nil {
			return err
		}
		if n == 0 {
			return bdomain.ErrPinState
		}
		if err := record(ctx, tx, c.Actor(), audit.Success, auditkind.PublisherPinRevoked, "publisher_pin", id.String(), map[string]string{
			"publisher": p.Publisher, "kid": p.KID, "from": p.State, "reason": reason,
		}); err != nil {
			return err
		}
		if reason == bdomain.ReasonCompromised {
			kid := p.KID
			if _, err := q.InsertBundleRevocation(ctx, dbq.InsertBundleRevocationParams{
				OrgID: c.Org, ID: ids.NewV7(), Publisher: p.Publisher, Scope: format.ScopeKey, Kid: &kid, Source: bdomain.SourceAdmin,
			}); err != nil {
				return err
			}
			if revoked, err = s.revokeKidTx(ctx, tx, c.Actor(), kid, bdomain.SourceAdmin); err != nil {
				return err
			}
		}
		out, err = getPin(ctx, q, c.Org, id)
		return err
	})
	return out, revoked, err
}

// GetPin returns one pin (bundle.read).
func (s *Service) GetPin(ctx context.Context, id ids.UUID) (Pin, error) {
	c, err := reader(ctx)
	if err != nil {
		return Pin{}, err
	}
	var out Pin
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = getPin(ctx, dbq.New(tx), c.Org, id)
		return err
	}, db.ReadOnly())
	return out, err
}

// ListPins returns one page of pins by id (bundle.read).
func (s *Service) ListPins(ctx context.Context, size int32, token string) ([]Pin, string, error) {
	c, err := reader(ctx)
	if err != nil {
		return nil, "", err
	}
	pr, err := page.Parse(size, token)
	if err != nil {
		return nil, "", err
	}
	var after *ids.UUID
	if !pr.After.IsZero() {
		after = &pr.After
	}
	var out []Pin
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListPublisherPins(ctx, c.Org, after, pr.Limit())
		if err != nil {
			return err
		}
		for _, r := range rows {
			out = append(out, pinOf(dbq.GetPublisherPinRow(r)))
		}
		return nil
	}, db.ReadOnly())
	if err != nil {
		return nil, "", err
	}
	out, next := page.Finish(pr, out, func(p Pin) ids.UUID { return p.ID })
	return out, next, nil
}

func getPin(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID) (Pin, error) {
	r, err := q.GetPublisherPin(ctx, org, id)
	if db.IsNoRows(err) {
		return Pin{}, bdomain.ErrPinNotFound
	} else if err != nil {
		return Pin{}, err
	}
	return pinOf(r), nil
}

func pinOf(r dbq.GetPublisherPinRow) Pin {
	p := Pin{
		ID: r.ID, Publisher: r.Publisher, KID: r.Kid, PublicKey: r.PublicKey, Fingerprint: r.Fingerprint, AllowedKinds: r.AllowedKinds,
		State: r.State, CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, ActivatedBy: r.ActivatedBy, ActivatedAt: r.ActivatedAt,
		RevokedAt: r.RevokedAt,
	}
	if r.RevocationsUrl != nil {
		p.RevocationsURL = *r.RevocationsUrl
	}
	if r.RevokeReason != nil {
		p.RevokeReason = *r.RevokeReason
	}
	return p
}
