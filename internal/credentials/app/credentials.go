// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app holds the credential custody use cases (G0 M6 design
// decision 8, HR-060, HR-061, HR-182). A person holding credential.seal
// asks for the sealing key of a connection, seals the credential locally
// (pclaw seal) and uploads the sealed bytes. The server checks the blob's
// format, the broker key, the version and the binding, stores the bytes and
// supersedes the previous version. Nothing here ever returns sealed bytes;
// only the gateway configuration sends them, to the gateway that owns the
// broker key. Replacing a credential weakens enforcement and is notified;
// revoking one strengthens it and raises the containment epoch (HR-183).
package app

import (
	"context"
	"slices"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors.
var (
	ErrConnectionNotFound = pcerr.New(pcerr.NotFound, "CONNECTION_NOT_FOUND", "connection not found")
	ErrCredentialNotFound = pcerr.New(pcerr.NotFound, "CREDENTIAL_NOT_FOUND", "no such credential version, or it is already revoked")
	ErrNotHeld            = pcerr.New(pcerr.FailedPrecondition, "CONNECTION_NOT_HELD",
		"only an active connection whose access mode is pantherclaw_held takes a credential")
	ErrNoBrokerKey = pcerr.New(pcerr.FailedPrecondition, "NO_BROKER_KEY", "the connection's gateway has not registered a broker key")
	ErrStaleKey    = pcerr.New(pcerr.FailedPrecondition, "BROKER_KEY_CHANGED", "the gateway's broker key changed since the sealing key was read; seal again")
	ErrStale       = pcerr.New(pcerr.FailedPrecondition, "CREDENTIAL_VERSION_STALE", "another credential was stored since the sealing key was read; seal again")
	ErrBinding     = pcerr.New(pcerr.FailedPrecondition, "CREDENTIAL_BINDING_CHANGED",
		"the connection's hosts, header or scheme changed since the sealing key was read; seal again")
	ErrFormat = pcerr.New(pcerr.InvalidArgument, "SEALED_FORMAT", "the upload is not a sealed credential")
	ErrKind   = pcerr.New(pcerr.InvalidArgument, "CREDENTIAL_KIND",
		"a credential is static or github_app, and a GitHub App credential is placed as Authorization: Bearer")
	ErrInstallation = pcerr.New(pcerr.InvalidArgument, "GITHUB_INSTALLATION",
		"a GitHub App credential names its App, installation and account (lowercase), and a static one names none")
)

// Notifier queues a notification in the caller's transaction (M5).
type Notifier interface {
	Enqueue(ctx context.Context, tx db.TenantTx, m napp.Message) (napp.Enqueued, error)
}

// Service serves credential custody.
type Service struct {
	pool   *db.Pool
	notify Notifier
}

// New returns the credential use cases; n may be nil.
func New(pool *db.Pool, n Notifier) *Service { return &Service{pool: pool, notify: n} }

// SealingKey is what pclaw seals to and binds.
type SealingKey struct {
	Binding     domain.Binding
	PublicKey   []byte
	Fingerprint string
	Gateway     ids.UUID
}

// PutInput is a sealed credential to store, with the binding it was sealed
// for.
type PutInput struct {
	Connection, BrokerKey ids.UUID
	Version               int32
	Sealed                []byte
	AllowedHosts          []string
	Header, Scheme        string
	// Kind is domain.KindStatic (or empty) or domain.KindGitHubApp.
	Kind string
	// GitHub is the installation a GitHub App credential was sealed for;
	// nil for a static credential.
	GitHub *domain.Installation
}

// Metadata describes a stored credential; it never carries sealed bytes.
type Metadata = dbq.ListCredentialMetadataRow

func (s *Service) caller(ctx context.Context, p td.Permission) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	return c, c.Require(p, td.OrgPath(c.Org))
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// held returns a connection that can take a credential.
func held(conn dbq.PcConnection, err error) (dbq.PcConnection, error) {
	if db.IsNoRows(err) {
		return conn, ErrConnectionNotFound
	} else if err != nil {
		return conn, err
	}
	if conn.State == "RETIRED" || conn.AccessMode != "pantherclaw_held" || conn.CredentialHeader == nil {
		return conn, ErrNotHeld
	}
	return conn, nil
}

func binding(org ids.OrgID, conn dbq.PcConnection, version int32, key ids.UUID) domain.Binding {
	return domain.Binding{
		Org: org.String(), Connection: conn.ID.String(), Version: version, AllowedHosts: conn.AllowedHosts, BrokerKey: key.String(),
		Header: deref(conn.CredentialHeader), Scheme: deref(conn.CredentialScheme),
	}
}

// GetSealingKey returns the active broker key of the connection's gateway
// and the binding the next credential version gets (credential.seal).
func (s *Service) GetSealingKey(ctx context.Context, connection ids.UUID) (SealingKey, error) {
	c, err := s.caller(ctx, td.PermCredentialSeal)
	if err != nil {
		return SealingKey{}, err
	}
	var out SealingKey
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		conn, err := held(q.GetConnection(ctx, c.Org, connection))
		if err != nil {
			return err
		}
		key, err := q.GetActiveBrokerKey(ctx, c.Org, conn.GatewayID)
		if db.IsNoRows(err) {
			return ErrNoBrokerKey
		} else if err != nil {
			return err
		}
		version, err := q.NextCredentialVersion(ctx, c.Org, conn.ID)
		if err != nil {
			return err
		}
		out = SealingKey{Binding: binding(c.Org, conn, version, key.ID), PublicKey: key.PublicKey, Fingerprint: key.Fingerprint, Gateway: conn.GatewayID}
		return nil
	})
	return out, err
}

// PutCredential stores a sealed credential as the connection's next
// version and supersedes the active one (credential.seal). The upload must
// name the gateway's current broker key and the next version, and the
// binding it was sealed for must still be the connection's.
func (s *Service) PutCredential(ctx context.Context, in PutInput) (Metadata, error) {
	c, err := s.caller(ctx, td.PermCredentialSeal)
	if err != nil {
		return Metadata{}, err
	}
	if domain.CheckFormat(in.Sealed) != nil {
		return Metadata{}, ErrFormat
	}
	if in.Kind == "" {
		in.Kind = domain.KindStatic
	}
	if !domain.ValidKind(in.Kind) || (in.Kind == domain.KindGitHubApp && (in.Header != domain.GitHubAppHeader || in.Scheme != domain.GitHubAppScheme)) {
		return Metadata{}, ErrKind
	}
	if (in.Kind == domain.KindGitHubApp) != (in.GitHub != nil) || (in.GitHub != nil && in.GitHub.Validate() != nil) {
		return Metadata{}, ErrInstallation
	}
	var out Metadata
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		conn, err := held(q.LockConnection(ctx, c.Org, in.Connection))
		if err != nil {
			return err
		}
		key, err := q.GetActiveBrokerKey(ctx, c.Org, conn.GatewayID)
		if db.IsNoRows(err) {
			return ErrNoBrokerKey
		} else if err != nil {
			return err
		}
		if key.ID != in.BrokerKey {
			return ErrStaleKey
		}
		next, err := q.NextCredentialVersion(ctx, c.Org, conn.ID)
		if err != nil {
			return err
		}
		if in.Version != next {
			return ErrStale
		}
		want, got := slices.Sorted(slices.Values(conn.AllowedHosts)), slices.Sorted(slices.Values(in.AllowedHosts))
		if !slices.Equal(want, got) || in.Header != deref(conn.CredentialHeader) || in.Scheme != deref(conn.CredentialScheme) {
			return ErrBinding
		}
		replaced, err := q.SupersedeCredentials(ctx, c.Org, conn.ID)
		if err != nil {
			return err
		}
		var scheme *string
		if in.Scheme != "" {
			scheme = &in.Scheme
		}
		row, err := q.InsertSealedCredential(ctx, dbq.InsertSealedCredentialParams{
			OrgID: c.Org, ID: ids.NewV7(), ConnectionID: conn.ID, Version: in.Version, BrokerKeyID: key.ID, Sealed: in.Sealed,
			AllowedHosts: conn.AllowedHosts, Header: in.Header, Scheme: scheme, CreatedBy: c.Principal.String(), Kind: in.Kind,
		})
		if err != nil {
			return err
		}
		details := map[string]string{
			"version": strconv.Itoa(int(in.Version)), "broker_key_id": key.ID.String(), "broker_key_fingerprint": key.Fingerprint,
			"allowed_hosts": strings.Join(conn.AllowedHosts, ","), "replaced": strconv.FormatInt(replaced, 10), "kind": in.Kind,
		}
		if gh := in.GitHub; gh != nil {
			// The installation is configuration, not a secret: the gateway
			// refuses another account's repository with it (ADR-0021).
			if err := q.UpsertConnectionGitHub(ctx, dbq.UpsertConnectionGitHubParams{
				OrgID: c.Org, ConnectionID: conn.ID, AppClientID: gh.AppClientID, InstallationID: gh.ID, AccountLogin: gh.Account,
				UpdatedBy: c.Principal.String(),
			}); err != nil {
				return err
			}
			details["github_app"], details["github_installation"], details["github_account"] = gh.AppClientID, strconv.FormatInt(gh.ID, 10), gh.Account
		}
		if _, err := q.BumpGatewayConfig(ctx, c.Org, conn.GatewayID); err != nil {
			return err
		}
		if replaced > 0 {
			details["weakening"] = "sealed_replaced"
		}
		if err := record(ctx, tx, c, "connection.sealed_stored", conn.ID, details); err != nil {
			return err
		}
		if replaced > 0 && s.notify != nil {
			if _, err := s.notify.Enqueue(ctx, tx, napp.Message{Org: c.Org, Type: "security.connection_weakened", Params: map[string]string{
				"connection": conn.Name, "user": c.Principal.String(), "change": "credential replaced",
			}}); err != nil {
				return err
			}
		}
		out = Metadata{
			ID: row.ID, ConnectionID: conn.ID, Version: row.Version, BrokerKeyID: key.ID, BrokerKeyFingerprint: key.Fingerprint,
			AllowedHosts: conn.AllowedHosts, Header: in.Header, Scheme: scheme, State: row.State, CreatedBy: c.Principal.String(),
			CreatedAt: row.CreatedAt, Kind: in.Kind,
		}
		return nil
	})
	return out, err
}

// ListCredentials lists a connection's credentials, newest first, as
// metadata only (connection.read).
func (s *Service) ListCredentials(ctx context.Context, connection ids.UUID) ([]Metadata, error) {
	c, err := s.caller(ctx, td.PermConnectionRead)
	if err != nil {
		return nil, err
	}
	var out []Metadata
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := q.GetConnection(ctx, c.Org, connection); db.IsNoRows(err) {
			return ErrConnectionNotFound
		} else if err != nil {
			return err
		}
		out, err = q.ListCredentialMetadata(ctx, c.Org, connection)
		return err
	})
	return out, err
}

// RevokeCredential revokes one version (connection.manage). It strengthens
// enforcement, so it raises the containment epoch in the same transaction.
func (s *Service) RevokeCredential(ctx context.Context, connection ids.UUID, version int32) error {
	c, err := s.caller(ctx, td.PermConnectionManage)
	if err != nil {
		return err
	}
	return s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		conn, err := q.LockConnection(ctx, c.Org, connection)
		if db.IsNoRows(err) {
			return ErrConnectionNotFound
		} else if err != nil {
			return err
		}
		by := c.Principal.String()
		n, err := q.RevokeCredentialVersion(ctx, dbq.RevokeCredentialVersionParams{RevokedBy: &by, OrgID: c.Org, ConnectionID: conn.ID, Version: version})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrCredentialNotFound
		}
		if err := q.InsertContainment(ctx, c.Org); err != nil {
			return err
		}
		if _, err := q.BumpEpoch(ctx, c.Org); err != nil {
			return err
		}
		if _, err := q.BumpGatewayConfig(ctx, c.Org, conn.GatewayID); err != nil {
			return err
		}
		return record(ctx, tx, c, "connection.sealed_revoked", conn.ID, map[string]string{"version": strconv.Itoa(int(version))})
	})
}

func record(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name string, conn ids.UUID, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "connection", ID: conn.String()}, Details: details,
	})
	return err
}
