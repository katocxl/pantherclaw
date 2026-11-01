// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app holds the ticket sync use cases (G0 M20 D255; F545, HR-527,
// HR-528, T-227): sync configurations with their webhook secrets, links
// between cases or incidents and tickets, field ownership, and inbound
// ticket changes. Ticket sync needs the Business edition.
//
// Inbound changes run as system:ticketsync, which holds no permission on
// the response, restoration, approvals or kill-switch services, and this
// package does not import them (TestHR527_TicketSyncImportsNoAuthority).
// An inbound change can only add a note or an EXTERNAL entry to a case,
// add a note to an incident, and be audited: a ticket status never
// restores authority or lifts containment.
package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	casesdomain "github.com/katocxl/pantherclaw/internal/cases/domain"
	casesstore "github.com/katocxl/pantherclaw/internal/cases/store"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/platform/tenantctx"
	"github.com/katocxl/pantherclaw/internal/protect"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/ticketsync/domain"
)

// SecretPurpose is the DEK purpose of webhook secrets (HR-062).
const SecretPurpose = "ticket_sync_secrets" //nolint:gosec // G101: a DEK purpose name, not a credential

const (
	configsTable     = "ticket_sync_configs"
	secretColumn     = "webhook_secret"
	prevSecretColumn = "prev_webhook_secret" //nolint:gosec // G101: a column name, not a credential
)

// Config states.
const (
	StateActive = "ACTIVE"
	StatePaused = "PAUSED"
)

// Inbound outcomes (migration 00243).
const (
	OutcomeApplied  = "APPLIED"
	OutcomeIgnored  = "IGNORED"
	OutcomeNoted    = "NOTED"
	OutcomeStale    = "STALE"
	OutcomeUnlinked = "UNLINKED"
)

// Errors of the ticket sync use cases.
var (
	ErrEdition   = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "ticket sync needs the Business edition or above")
	ErrHumanOnly = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can change ticket sync")
	ErrNotFound  = pcerr.New(pcerr.NotFound, "TICKET_SYNC_NOT_FOUND", "ticket sync configuration not found")
	ErrInvalid   = pcerr.New(pcerr.InvalidArgument, "INVALID_TICKET_SYNC",
		"a ticket sync names a connection, a project key, and issue keys of that project")
	ErrLinked      = pcerr.New(pcerr.AlreadyExists, "TICKET_ALREADY_LINKED", "the case, incident or ticket is already linked")
	ErrLockedField = pcerr.New(pcerr.FailedPrecondition, "TICKET_FIELD_LOCKED",
		"PantherClaw always owns containment and restoration")
	ErrSignature = pcerr.New(pcerr.Unauthenticated, "TICKET_WEBHOOK_SIGNATURE", "the ticket webhook signature does not verify")
	ErrWebhook   = pcerr.New(pcerr.InvalidArgument, "TICKET_WEBHOOK_INVALID", "the ticket webhook is not an issue or comment event")
)

// Editions reports the licence's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// Service serves the ticket sync use cases as pc_app.
type Service struct {
	Pool     *db.Pool
	Envelope *pccrypto.Envelope
	Editions Editions
	// Gate holds giving a field to the ticket system (D264); nil applies
	// every change directly.
	Gate *protect.Gate
	// Refusals bounds the audit entries of refused webhooks, per
	// configuration; nil audits each one.
	Refusals *httpx.Limiter
	// Now is the clock (nil: time.Now).
	Now func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// business fails closed: without entitlements, or below Business, no
// ticket sync (F545).
func (s *Service) business(ctx context.Context) error {
	if s.Editions == nil {
		return ErrEdition
	}
	e, err := s.Editions.Current(ctx)
	if err != nil {
		return err
	}
	if e.Edition != billing.Business && e.Edition != billing.Enterprise {
		return ErrEdition
	}
	return nil
}

// person returns the caller when it is a person (not an API key) holding
// perm at the org.
func person(ctx context.Context, perm td.Permission) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if err := c.Require(perm, td.OrgPath(c.Org)); err != nil {
		return c, err
	}
	if !c.Human() || c.Credential == tenancy.CredAPIKey {
		return c, ErrHumanOnly
	}
	return c, nil
}

func (s *Service) field(org ids.OrgID, id ids.UUID, column string) pccrypto.FieldContext {
	return pccrypto.FieldContext{Org: org, Table: configsTable, Column: column, RowID: id.String()}
}

// newSecret returns a fresh webhook secret: 32 random bytes, hex encoded,
// as the ticket system is given it.
func newSecret() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return []byte(hex.EncodeToString(b))
}

// Config is a sync configuration without its secrets.
type Config struct {
	ID, Connection ids.UUID
	System         domain.System
	ProjectKey     string
	State          string
	Created        time.Time
}

func configOf(r dbq.PcTicketSyncConfig) Config {
	return Config{ID: r.ID, Connection: r.ConnectionID, System: domain.System(r.System), ProjectKey: r.ProjectKey, State: r.State, Created: r.CreatedAt}
}

// CreateConfig binds a project behind a connection (connection.manage, a
// person). The webhook secret is returned once, to be given to the ticket
// system; PantherClaw keeps it only encrypted.
//
// permission: connection.manage
func (s *Service) CreateConfig(ctx context.Context, connection ids.UUID, projectKey string) (Config, []byte, error) {
	c, err := person(ctx, td.PermConnectionManage)
	if err != nil {
		return Config{}, nil, err
	}
	if err := s.business(ctx); err != nil {
		return Config{}, nil, err
	}
	if connection.IsZero() || !domain.ProjectKeyPattern.MatchString(projectKey) {
		return Config{}, nil, ErrInvalid
	}
	id, secret := ids.NewV7(), newSecret()
	blob, err := s.Envelope.Encrypt(ctx, s.field(c.Org, id, secretColumn), SecretPurpose, secret)
	if err != nil {
		return Config{}, nil, err
	}
	var out Config
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).InsertTicketSyncConfig(ctx, dbq.InsertTicketSyncConfigParams{
			OrgID: c.Org, ID: id, System: string(domain.SystemJira), ConnectionID: connection, ProjectKey: projectKey,
			WebhookSecret: blob, CreatedBy: c.Principal.String(),
		})
		switch {
		case db.IsForeignKeyViolation(err):
			return ErrInvalid
		case db.IsUniqueViolation(err):
			return ErrLinked
		case err != nil:
			return err
		}
		out = configOf(row)
		return s.audit(ctx, tx, c.Actor(), "ticket.sync_configured", "ticket_sync_config", id, map[string]string{
			"connection": connection.String(), "project": projectKey,
		})
	})
	if err != nil {
		return Config{}, nil, err
	}
	return out, secret, nil
}

// RotateSecret replaces a configuration's webhook secret; the previous one
// verifies for 24 hours. The new secret is returned once.
//
// permission: connection.manage
func (s *Service) RotateSecret(ctx context.Context, id ids.UUID) ([]byte, error) {
	c, err := person(ctx, td.PermConnectionManage)
	if err != nil {
		return nil, err
	}
	if err := s.business(ctx); err != nil {
		return nil, err
	}
	fresh := newSecret()
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		cur, err := q.GetTicketSyncConfig(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		old, err := s.Envelope.Decrypt(ctx, s.field(c.Org, id, secretColumn), SecretPurpose, cur.WebhookSecret)
		if err != nil {
			return err
		}
		prev, err := s.Envelope.Encrypt(ctx, s.field(c.Org, id, prevSecretColumn), SecretPurpose, old)
		if err != nil {
			return err
		}
		blob, err := s.Envelope.Encrypt(ctx, s.field(c.Org, id, secretColumn), SecretPurpose, fresh)
		if err != nil {
			return err
		}
		if _, err := q.RotateTicketSyncSecret(ctx, dbq.RotateTicketSyncSecretParams{
			PrevWebhookSecret: prev, WebhookSecret: blob, OrgID: c.Org, ID: id,
		}); err != nil {
			return err
		}
		return s.audit(ctx, tx, c.Actor(), "ticket.sync_secret_rotated", "ticket_sync_config", id, nil)
	})
	if err != nil {
		return nil, err
	}
	return fresh, nil
}

// SetPaused pauses or resumes a configuration: a paused one refuses
// inbound webhooks and starts no outbound call.
//
// permission: connection.manage
func (s *Service) SetPaused(ctx context.Context, id ids.UUID, paused bool) error {
	c, err := person(ctx, td.PermConnectionManage)
	if err != nil {
		return err
	}
	state := StateActive
	if paused {
		state = StatePaused
	}
	return s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := q.GetTicketSyncConfig(ctx, c.Org, id); db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		n, err := q.SetTicketSyncConfigState(ctx, state, c.Org, id)
		if err != nil || n == 0 {
			return err
		}
		return s.audit(ctx, tx, c.Actor(), "ticket.sync_state_changed", "ticket_sync_config", id, map[string]string{"state": state})
	})
}

// Configs lists the organization's configurations.
//
// permission: connection.read
func (s *Service) Configs(ctx context.Context) ([]Config, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.Require(td.PermConnectionRead, td.OrgPath(c.Org)); err != nil {
		return nil, err
	}
	var out []Config
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListTicketSyncConfigs(ctx, c.Org)
		for _, r := range rows {
			out = append(out, configOf(r))
		}
		return err
	}, db.ReadOnly())
	return out, err
}

// Ref is a link between a case or an incident and a ticket.
type Ref struct {
	ID, Connection  ids.UUID
	Case, Incident  *ids.UUID
	System          domain.System
	Key             string
	RemoteUpdatedAt *time.Time
}

func refOf(r dbq.PcExternalRef) Ref {
	return Ref{
		ID: r.ID, Connection: r.ConnectionID, Case: r.CaseID, Incident: r.IncidentID, System: domain.System(r.System),
		Key: r.ExternalKey, RemoteUpdatedAt: r.RemoteUpdatedAt,
	}
}

// LinkCase links case c to ticket key of the configuration's project.
//
// permission: case.manage
func (s *Service) LinkCase(ctx context.Context, c, config ids.UUID, key string) (Ref, error) {
	return s.link(ctx, td.PermCaseManage, &c, nil, config, key)
}

// LinkIncident links incident i to ticket key of the configuration's
// project.
//
// permission: incident.manage
func (s *Service) LinkIncident(ctx context.Context, i, config ids.UUID, key string) (Ref, error) {
	return s.link(ctx, td.PermIncidentManage, nil, &i, config, key)
}

func (s *Service) link(ctx context.Context, perm td.Permission, kase, incident *ids.UUID, config ids.UUID, key string) (Ref, error) {
	c, err := person(ctx, perm)
	if err != nil {
		return Ref{}, err
	}
	if err := s.business(ctx); err != nil {
		return Ref{}, err
	}
	if !domain.ValidIssueKey(key) {
		return Ref{}, ErrInvalid
	}
	var out Ref
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		cfg, err := q.GetTicketSyncConfig(ctx, c.Org, config)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if !strings.HasPrefix(key, cfg.ProjectKey+"-") {
			return ErrInvalid
		}
		row, err := q.InsertExternalRef(ctx, dbq.InsertExternalRefParams{
			OrgID: c.Org, ID: ids.NewV7(), CaseID: kase, IncidentID: incident, System: cfg.System, ConnectionID: cfg.ConnectionID,
			ExternalKey: key, CreatedBy: c.Principal.String(),
		})
		switch {
		case db.IsForeignKeyViolation(err):
			return ErrNotFound
		case db.IsUniqueViolation(err):
			return ErrLinked
		case err != nil:
			return err
		}
		out = refOf(row)
		return s.audit(ctx, tx, c.Actor(), "ticket.linked", "external_ref", row.ID, map[string]string{"key": key, "system": cfg.System})
	})
	return out, err
}

// FieldOwners returns the organization's owner of every field.
//
// permission: case.read
func (s *Service) FieldOwners(ctx context.Context) (domain.Owners, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.Require(td.PermCaseRead, td.OrgPath(c.Org)); err != nil {
		return nil, err
	}
	var out domain.Owners
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = owners(ctx, dbq.New(tx), c.Org)
		return err
	}, db.ReadOnly())
	return out, err
}

// owners returns every field's owner, defaults filled in.
func owners(ctx context.Context, q *dbq.Queries, org ids.OrgID) (domain.Owners, error) {
	rows, err := q.TicketFieldOwners(ctx, org)
	if err != nil {
		return nil, err
	}
	stored := domain.Owners{}
	for _, r := range rows {
		stored[domain.Field(r.Field)] = domain.Owner(r.Owner)
	}
	out := domain.Owners{}
	for _, f := range domain.Fields {
		out[f] = stored.Of(f)
	}
	return out, nil
}

func (s *Service) audit(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, name, objType string, id ids.UUID, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: actor, Outcome: audit.Success, Object: &audit.Object{Type: objType, ID: id.String()}, Details: details,
	})
	return err
}

// Inbound handles one webhook delivery for configuration config of org:
// it verifies the signature with the configuration's secret (or the
// previous one within its 24 hours), drops a delivery it has seen before,
// and applies the event as system:ticketsync. It returns the outcome
// recorded for the delivery ("" for a replay, which changes nothing).
func (s *Service) Inbound(ctx context.Context, org ids.OrgID, config ids.UUID, delivery, signature string, body []byte) (string, error) {
	if len(body) > domain.MaxWebhookBytes || !domain.ValidDeliveryID(delivery) {
		return "", ErrWebhook
	}
	// A webhook has no caller: the org names the edition on a hosted server.
	if err := s.business(tenantctx.WithOrg(ctx, org)); err != nil {
		return "", err
	}
	outcome := ""
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		cfg, err := q.GetTicketSyncConfig(ctx, org, config)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if cfg.State != StateActive {
			return ErrNotFound
		}
		secrets, err := s.secrets(ctx, org, cfg)
		if err != nil {
			return err
		}
		if !domain.VerifyJiraSignature(signature, body, secrets...) {
			return ErrSignature
		}
		seen, err := q.TicketInboundDeliverySeen(ctx, org, config, delivery)
		if err != nil || seen {
			return err // a replayed delivery changes nothing
		}
		ev, err := domain.ParseJiraWebhook(body)
		if err != nil {
			return ErrWebhook
		}
		outcome, err = s.apply(ctx, tx, q, org, cfg, ev)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		key := ev.IssueKey
		n, err := q.InsertTicketInboundEvent(ctx, dbq.InsertTicketInboundEventParams{
			OrgID: org, ID: ids.NewV7(), ConfigID: config, DeliveryID: delivery, BodySha256: sum[:], IssueKey: &key, Outcome: outcome,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			outcome = ""
			return errReplayRace
		}
		return nil
	})
	if errors.Is(err, errReplayRace) {
		return "", nil // a concurrent delivery of the same id won; this one rolled back
	}
	if errors.Is(err, ErrSignature) {
		s.refused(ctx, org, config)
	}
	return outcome, err
}

var errReplayRace = pcerr.New(pcerr.Aborted, "TICKET_WEBHOOK_REPLAY", "the delivery was already recorded")

// refused audits a webhook whose signature did not verify, in its own
// transaction (the delivery's rolled back), at most Refusals allows.
func (s *Service) refused(ctx context.Context, org ids.OrgID, config ids.UUID) {
	if s.Refusals != nil && !s.Refusals.Allow(config.String()) {
		return
	}
	_ = s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := audit.Record(ctx, tx, audit.Event{
			Name: "ticket.webhook_refused", Actor: domain.Actor, Outcome: audit.Denied, ReasonCode: "BAD_SIGNATURE",
			Object: &audit.Object{Type: "ticket_sync_config", ID: config.String()},
		})
		return err
	})
}

// secrets opens the configuration's current secret and, within its 24
// hours, the previous one.
func (s *Service) secrets(ctx context.Context, org ids.OrgID, cfg dbq.PcTicketSyncConfig) ([][]byte, error) {
	cur, err := s.Envelope.Decrypt(ctx, s.field(org, cfg.ID, secretColumn), SecretPurpose, cfg.WebhookSecret)
	if err != nil {
		return nil, err
	}
	out := [][]byte{cur}
	if cfg.PrevWebhookSecret != nil && cfg.PrevSecretExpiresAt != nil && s.now().Before(*cfg.PrevSecretExpiresAt) {
		prev, err := s.Envelope.Decrypt(ctx, s.field(org, cfg.ID, prevSecretColumn), SecretPurpose, cfg.PrevWebhookSecret)
		if err == nil {
			out = append(out, prev)
		}
	}
	return out, nil
}

// apply writes what an authentic, new event becomes. It only appends case
// entries (NOTE, EXTERNAL), incident NOTE events and audit records, and
// moves the ref's change time forward; nothing else.
func (s *Service) apply(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, cfg dbq.PcTicketSyncConfig, ev domain.Event) (string, error) {
	ref, err := q.ExternalRefByTicket(ctx, dbq.ExternalRefByTicketParams{
		OrgID: org, System: cfg.System, ConnectionID: cfg.ConnectionID, ExternalKey: ev.IssueKey,
	})
	if db.IsNoRows(err) {
		return OutcomeUnlinked, nil
	} else if err != nil {
		return "", err
	}
	if ref.RemoteUpdatedAt != nil && !ev.At.After(*ref.RemoteUpdatedAt) {
		return OutcomeStale, nil
	}
	own, err := owners(ctx, q, org)
	if err != nil {
		return "", err
	}
	outcome := OutcomeApplied
	for _, v := range domain.Decide(own, ev.IssueKey, ev.Changes, ev.Comment) {
		if err := s.record(ctx, tx, q, org, ref, v); err != nil {
			return "", err
		}
		switch v.Action {
		case domain.ActionIgnore:
			outcome = OutcomeIgnored
			if err := s.ignored(ctx, tx, ref, v); err != nil {
				return "", err
			}
		case domain.ActionNote:
			if outcome != OutcomeIgnored {
				outcome = OutcomeNoted
			}
			if err := s.ignored(ctx, tx, ref, v); err != nil {
				return "", err
			}
		case domain.ActionMirror:
		}
	}
	at := ev.At
	if _, err := q.AdvanceExternalRef(ctx, &at, org, ref.ID); err != nil {
		return "", err
	}
	return outcome, nil
}

// ignored audits a dropped change to a PantherClaw-owned field (HR-528).
func (s *Service) ignored(ctx context.Context, tx db.TenantTx, ref dbq.PcExternalRef, v domain.Verdict) error {
	return s.audit(ctx, tx, domain.Actor, "ticket.owned_field_ignored", "external_ref", ref.ID, map[string]string{
		"key": ref.ExternalKey, "system": ref.System, "field": string(v.Field), "action": string(v.Action),
	})
}

// caseAuthor is the sync actor as a case entry author.
var caseAuthor = casesdomain.Author{Type: domain.ActorType, ID: domain.ActorID}

// record writes v on the ref's case (a NOTE for a mirrored change, an
// EXTERNAL entry otherwise) or incident (a NOTE event).
func (s *Service) record(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, ref dbq.PcExternalRef, v domain.Verdict) error {
	if ref.CaseID != nil {
		kind := casesdomain.KindExternal
		if v.Action == domain.ActionMirror {
			kind = casesdomain.KindNote
		}
		_, err := casesstore.Append(ctx, tx, *ref.CaseID, caseAuthor, casesdomain.Draft{Kind: kind, Text: domain.Clean(v.Text, casesdomain.MaxText)})
		return err
	}
	if ref.IncidentID == nil {
		return nil
	}
	note := domain.Clean(v.Text, 2000)
	return q.InsertIncidentEvent(ctx, dbq.InsertIncidentEventParams{
		OrgID: org, ID: ids.NewV7(), IncidentID: *ref.IncidentID, Kind: "NOTE", ActorType: domain.ActorType, ActorID: domain.ActorID, Note: &note,
	})
}

// RefsOfCase lists the tickets linked to a case (G0 M22 D7, F833).
//
// permission: case.read
func (s *Service) RefsOfCase(ctx context.Context, id ids.UUID) ([]Ref, error) {
	return s.refs(ctx, td.PermCaseRead, func(ctx context.Context, q *dbq.Queries, org ids.OrgID) ([]dbq.PcExternalRef, error) {
		return q.ExternalRefsOfCase(ctx, org, &id)
	})
}

// RefsOfIncident lists the tickets linked to an incident (G0 M22 D7, F833).
//
// permission: incident.read
func (s *Service) RefsOfIncident(ctx context.Context, id ids.UUID) ([]Ref, error) {
	return s.refs(ctx, td.PermIncidentRead, func(ctx context.Context, q *dbq.Queries, org ids.OrgID) ([]dbq.PcExternalRef, error) {
		return q.ExternalRefsOfIncident(ctx, org, &id)
	})
}

func (s *Service) refs(ctx context.Context, perm td.Permission, list func(context.Context, *dbq.Queries, ids.OrgID) ([]dbq.PcExternalRef, error)) ([]Ref, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.Require(perm, td.OrgPath(c.Org)); err != nil {
		return nil, err
	}
	if err := s.business(ctx); err != nil {
		return nil, err
	}
	var out []Ref
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := list(ctx, dbq.New(tx), c.Org)
		for _, r := range rows {
			out = append(out, refOf(r))
		}
		return err
	}, db.ReadOnly())
	return out, err
}

// SyncEvent is one entry of a configuration's sync log. Bodies and secrets
// are not stored here; empty fields do not apply to its direction.
type SyncEvent = dbq.ListTicketSyncEventsRow

// SyncEvents returns a page of a configuration's sync log, newest first
// (G0 M22 D7, F833). An unknown configuration is not found.
//
// permission: connection.read
func (s *Service) SyncEvents(ctx context.Context, config ids.UUID, pr page.Request) ([]SyncEvent, string, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, "", err
	}
	if err := c.Require(td.PermConnectionRead, td.OrgPath(c.Org)); err != nil {
		return nil, "", err
	}
	if err := s.business(ctx); err != nil {
		return nil, "", err
	}
	var after *ids.UUID
	if !pr.After.IsZero() {
		after = &pr.After
	}
	var out []SyncEvent
	var next string
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := q.GetTicketSyncConfig(ctx, c.Org, config); db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		rows, err := q.ListTicketSyncEvents(ctx, dbq.ListTicketSyncEventsParams{OrgID: c.Org, ConfigID: config, After: after, PageLimit: pr.Limit()})
		if err != nil {
			return err
		}
		out, next = page.Finish(pr, rows, func(r SyncEvent) ids.UUID { return r.ID })
		return nil
	}, db.ReadOnly())
	return out, next, err
}
