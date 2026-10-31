// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package endpoints

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// CheckURL applies the destination URL rule (D22: the SIEM rule): https,
// no credentials or fragment, the egress guard's reading of the host, a
// metadata service always refused, private and loopback addresses only
// for an internal destination.
func CheckURL(raw, ownHost string, internal bool, allowed []netip.Prefix) error {
	u, err := url.Parse(raw)
	if err != nil {
		return ErrURL
	}
	if httpx.MetadataHost(u.Hostname()) {
		return ErrMetadata
	}
	if a, ok := httpx.HostAddr(u.Hostname()); ok && httpx.MetadataAddr(a) {
		return ErrMetadata
	}
	if internal {
		allowed = append(slices.Clone(allowed), internalPrefixes...)
	}
	if err := ndomain.CheckWebhookURL(raw, ownHost, func(h string) bool { return httpx.DeniedHost(h, allowed) }); err != nil {
		return ErrURL
	}
	return nil
}

// NewDestination describes a destination to create.
type NewDestination struct {
	Name     string
	URL      string
	Internal bool
	Purposes []string
}

// Destination is an automation destination.
type Destination struct {
	ID                  ids.UUID
	Name                string
	URL                 string
	Internal            bool
	Purposes            []string
	State               string
	CreatedBy           ids.UUID
	CreatedAt           time.Time
	ActivatedBy         *ids.UUID
	ActivatedCredential *ids.UUID
	ActivatedAt         *time.Time
	DisabledAt          *time.Time
	// RotationEndsAt is when the previous secret stops signing.
	RotationEndsAt *time.Time
	// SignatureScheme is hmac (the default) or hmac+ed25519 (G0 M20 D251).
	SignatureScheme string
}

// CreatedDestination is a new destination; Secret is shown once.
type CreatedDestination struct {
	Destination Destination
	Secret      string
}

var purposes = []string{string(autodomain.DeliveryLaunch), string(autodomain.DeliveryDigest), string(autodomain.DeliveryNotice)}

func validPurposes(ps []string) bool {
	if len(ps) == 0 || len(ps) > len(purposes) {
		return false
	}
	seen := map[string]bool{}
	for _, p := range ps {
		if !slices.Contains(purposes, p) || seen[p] {
			return false
		}
		seen[p] = true
	}
	return true
}

func destinationOf(r dbq.GetAutomationDestinationRow) Destination {
	return Destination{
		ID: r.ID, Name: r.Name, URL: r.Url, Internal: r.Internal, Purposes: r.Purposes, State: r.State,
		CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, ActivatedBy: r.ActivatedBy, ActivatedCredential: r.ActivatedCredential,
		ActivatedAt: r.ActivatedAt, DisabledAt: r.DisabledAt, RotationEndsAt: r.PrevUntil,
		SignatureScheme: r.SignatureScheme,
	}
}

func getDestination(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID) (Destination, error) {
	r, err := q.GetAutomationDestination(ctx, org, id)
	if db.IsNoRows(err) {
		return Destination{}, ErrNotFound
	} else if err != nil {
		return Destination{}, err
	}
	return destinationOf(r), nil
}

// CreateDestination stores a PENDING destination and returns its signing
// secret once. Nothing is sent to it until a person activates it.
func (s *Service) CreateDestination(ctx context.Context, in NewDestination) (CreatedDestination, error) {
	c, err := s.manager(ctx, true)
	if err != nil {
		return CreatedDestination{}, err
	}
	in.Purposes = slices.Clone(in.Purposes)
	slices.Sort(in.Purposes)
	if !ndomain.ValidChannelName(in.Name) || !validPurposes(in.Purposes) {
		return CreatedDestination{}, ErrInvalidDestination
	}
	if err := CheckURL(in.URL, s.ownHost, in.Internal, s.cfg.AllowedPrivateRanges); err != nil {
		return CreatedDestination{}, err
	}
	secret, err := ndomain.NewSigningSecret()
	if err != nil {
		return CreatedDestination{}, err
	}
	id := ids.NewV7()
	var out CreatedDestination
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		blob, err := s.envelope.Encrypt(ctx, field(c.Org, destinationsTable, id, secretColumn), SecretPurpose, secret)
		if err != nil {
			return fmt.Errorf("endpoints: encrypt secret: %w", err)
		}
		q := dbq.New(tx)
		err = q.InsertAutomationDestination(ctx, dbq.InsertAutomationDestinationParams{
			OrgID: c.Org, ID: id, Name: in.Name, Url: in.URL, Internal: in.Internal, Purposes: in.Purposes,
			Secret: blob, CreatedBy: c.Principal.ID,
		})
		if db.IsUniqueViolation(err) {
			return ErrExists
		} else if err != nil {
			return err
		}
		if err := s.audit(ctx, tx, c, "automation.destination_created", "automation_destination", id, map[string]string{
			"name": in.Name, "host": hostOf(in.URL), "internal": fmt.Sprint(in.Internal), "purposes": strings.Join(in.Purposes, ","),
		}); err != nil {
			return err
		}
		out.Destination, err = getDestination(ctx, q, c.Org, id)
		return err
	})
	if err != nil {
		return CreatedDestination{}, err
	}
	out.Secret = ndomain.FormatSecret(secret)
	return out, nil
}

// ActivateDestination makes a PENDING destination ACTIVE (D22): a person
// holding automation.endpoints.manage, with a fresh step-up of their own
// key. su is nil over the API, which refuses (D53).
func (s *Service) ActivateDestination(ctx context.Context, id ids.UUID, su *stepup.StepUp) (Destination, error) {
	c, err := s.manager(ctx, true)
	if err != nil {
		return Destination{}, err
	}
	if su == nil {
		return Destination{}, stepup.ErrStepUp
	}
	var out Destination
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if err := stepup.Check(ctx, tx, c, *su, now); err != nil {
			return err
		}
		d, err := getDestination(ctx, q, c.Org, id)
		if err != nil {
			return err
		}
		if d.State != StatePending {
			return ErrState
		}
		// The rules may have changed since the destination was created.
		if err := CheckURL(d.URL, s.ownHost, d.Internal, s.cfg.AllowedPrivateRanges); err != nil {
			return err
		}
		n, err := q.ActivateAutomationDestination(ctx, dbq.ActivateAutomationDestinationParams{
			ActivatedBy: &c.Principal.ID, ActivatedCredential: &su.Credential, OrgID: c.Org, ID: id,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrState
		}
		if err := s.audit(ctx, tx, c, "automation.destination_activated", "automation_destination", id, map[string]string{
			"host": hostOf(d.URL), "internal": fmt.Sprint(d.Internal), "security_key": su.Credential.String(),
		}); err != nil {
			return err
		}
		out, err = getDestination(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

// RotateDestinationSecret replaces a destination's signing secret with a
// step-up (D22, D53) and returns the new one once; the old one keeps
// signing for 24 hours, and a second rotation waits for that overlap.
func (s *Service) RotateDestinationSecret(ctx context.Context, id ids.UUID, su *stepup.StepUp) (string, error) {
	c, err := s.manager(ctx, true)
	if err != nil {
		return "", err
	}
	if su == nil {
		return "", stepup.ErrStepUp
	}
	secret, err := ndomain.NewSigningSecret()
	if err != nil {
		return "", err
	}
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if err := stepup.Check(ctx, tx, c, *su, now); err != nil {
			return err
		}
		row, err := q.LoadAutomationDestinationSecrets(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if row.State != StateActive && row.State != StatePaused {
			return ErrState
		}
		if row.PrevUntil != nil && row.PrevUntil.After(now) {
			return ErrRotating
		}
		cur, prev, err := s.rotate(ctx, c.Org, destinationsTable, id, row.Secret, secret)
		if err != nil {
			return err
		}
		n, err := q.RotateAutomationDestinationSecret(ctx, dbq.RotateAutomationDestinationSecretParams{
			Secret: cur, PrevSecret: prev, OrgID: c.Org, ID: id,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrRotating
		}
		return s.audit(ctx, tx, c, "automation.destination_secret_rotated", "automation_destination", id,
			map[string]string{"security_key": su.Credential.String()})
	})
	if err != nil {
		return "", err
	}
	return ndomain.FormatSecret(secret), nil
}

// rotate seals the new secret and re-seals the current one for the
// previous-secret column (the AAD binds the column).
func (s *Service) rotate(ctx context.Context, org ids.OrgID, table string, id ids.UUID, sealed, secret []byte) (cur, prev []byte, err error) {
	old, err := s.envelope.Decrypt(ctx, field(org, table, id, secretColumn), SecretPurpose, sealed)
	if err != nil {
		return nil, nil, fmt.Errorf("endpoints: decrypt secret: %w", err)
	}
	if prev, err = s.envelope.Encrypt(ctx, field(org, table, id, prevSecretColumn), SecretPurpose, old); err != nil {
		return nil, nil, err
	}
	if cur, err = s.envelope.Encrypt(ctx, field(org, table, id, secretColumn), SecretPurpose, secret); err != nil {
		return nil, nil, err
	}
	return cur, prev, nil
}

// SetDestinationState pauses, resumes or disables a destination. Resuming
// needs the licence; DISABLED is final.
func (s *Service) SetDestinationState(ctx context.Context, id ids.UUID, state string) (Destination, error) {
	c, err := s.manager(ctx, state == StateActive)
	if err != nil {
		return Destination{}, err
	}
	var from []string
	switch state {
	case StatePaused:
		from = []string{StateActive}
	case StateActive:
		from = []string{StatePaused}
	case StateDisabled:
		from = []string{StatePending, StateActive, StatePaused}
	default:
		return Destination{}, ErrInvalidDestination
	}
	var out Destination
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		d, err := getDestination(ctx, q, c.Org, id)
		if err != nil {
			return err
		}
		if !slices.Contains(from, d.State) {
			return ErrState
		}
		n, err := q.SetAutomationDestinationState(ctx, dbq.SetAutomationDestinationStateParams{
			State: state, By: &c.Principal.ID, OrgID: c.Org, ID: id, Expected: d.State,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrState
		}
		if err := s.audit(ctx, tx, c, "automation.destination_state_changed", "automation_destination", id,
			map[string]string{"from": d.State, "to": state}); err != nil {
			return err
		}
		out, err = getDestination(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

// GetDestination returns one destination (automation.read).
func (s *Service) GetDestination(ctx context.Context, id ids.UUID) (Destination, error) {
	c, err := s.reader(ctx)
	if err != nil {
		return Destination{}, err
	}
	var out Destination
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = getDestination(ctx, dbq.New(tx), c.Org, id)
		return err
	}, db.ReadOnly())
	return shown(c, out), err
}

// ListDestinations lists the org's destinations (automation.read).
func (s *Service) ListDestinations(ctx context.Context) ([]Destination, error) {
	c, err := s.reader(ctx)
	if err != nil {
		return nil, err
	}
	var out []Destination
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListAutomationDestinations(ctx, c.Org)
		if err != nil {
			return err
		}
		out = make([]Destination, 0, len(rows))
		for _, r := range rows {
			out = append(out, shown(c, destinationOf(dbq.GetAutomationDestinationRow(r))))
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// shown is a destination as caller may see it (D87 P4): its URL in full
// only for people who manage endpoints, else scheme and host — a webhook
// URL's path or query often carries its credential.
func shown(c tenancy.Caller, d Destination) Destination {
	if c.Require(td.PermAutomationEndpointsManage, td.OrgPath(c.Org)) == nil {
		return d
	}
	d.URL = RedactURL(d.URL)
	return d
}

// RedactURL keeps a URL's scheme and host.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
