// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app holds the publisher pin, bundle install and revocation use
// cases (G0 M37 D1081–D1083; FQ37-1..3; HR-795..800; every edition, each
// item kind keeps its own edition gate through its use case):
//
//   - a publisher key is pinned PENDING by a person holding
//     publisher.manage and trusted only once a person activates it on its
//     page with a fresh WebAuthn step-up (pins.go);
//   - a bundle installs only when it verifies against an ACTIVE pin of its
//     publisher that allows its item kinds, is not older than (ROLLBACK) or
//     different at (EQUIVOCATION) the version installed, and is not
//     revoked; each item goes to its kind's DRAFT path in one transaction
//     and nothing is activated (install.go);
//   - a revocation stops every affected install in one transaction: its
//     package versions withdrawn as the org-key COMPROMISED quarantine does,
//     its custom rules disabled, its automations paused, an audit event per
//     install and a notification to Org Admins and Security Admins
//     (revoke.go). Statements are accepted only from keys the org pinned
//     for that publisher; a daily job fetches them (jobs.go).
package app

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	autoapp "github.com/katocxl/pantherclaw/internal/automations/app"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	bdomain "github.com/katocxl/pantherclaw/internal/bundles/domain"
	ddomain "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Rules is the custom detection rule use case (reflex/app.Detections).
type Rules interface {
	CreateBundleRuleTx(ctx context.Context, tx db.TenantTx, content, publisher string) (ids.UUID, error)
	DisableCustomRuleTx(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, id ids.UUID, reason string) (bool, error)
}

// Automations is the automation use case (automations/app.Service).
type Automations interface {
	CreateDraftTx(ctx context.Context, tx db.TenantTx, in autoapp.Draft) (autoapp.Automation, autoapp.Version, error)
	Pause(ctx context.Context, tx pgx.Tx, org ids.OrgID, sel autodomain.PauseSelector, reason autodomain.PauseReason) ([]ids.UUID, error)
}

// Versions moves package versions (definitions/adapters/pgstore.Store),
// the quarantine org-key COMPROMISED and MCP catalog revoke use.
type Versions interface {
	TransitionTx(ctx context.Context, tx db.TenantTx, pkg, version string, from, to ddomain.State, ev *audit.Event) error
}

// Notifier enqueues notifications (notifications/app.Service).
type Notifier interface {
	Enqueue(ctx context.Context, tx db.TenantTx, m napp.Message) (napp.Enqueued, error)
}

// Config is the deployment configuration.
type Config struct {
	// PublicURL is PantherClaw's own URL, under which the pin pages live.
	PublicURL string
}

// Deps are the use cases install and revocation route into. A nil one
// refuses its item kind (install fails closed) and, for a revocation,
// is a wiring error.
type Deps struct {
	Rules       Rules
	Automations Automations
	Versions    Versions
	Notify      Notifier
}

// Service implements the use cases.
type Service struct {
	pool  *db.Pool
	deps  Deps
	cfg   Config
	clock clock.Clock
	log   *slog.Logger
	// http fetches revocation statements through the egress client.
	http *http.Client
}

// FetchTimeout bounds one revocation statement fetch.
const FetchTimeout = 10 * time.Second

// New returns the service.
func New(pool *db.Pool, deps Deps, cfg Config, clk clock.Clock, log *slog.Logger) *Service {
	if log == nil {
		log = pclog.Discard()
	}
	return &Service{
		pool: pool, deps: deps, cfg: cfg, clock: clk, log: log,
		http: httpx.NewEgressClient(httpx.EgressConfig{Timeout: FetchTimeout}),
	}
}

// systemActor is the actor of a revocation no person made (a fetched or
// submitted statement's effects).
var systemActor = evdomain.Actor{Type: "system", ID: "bundles"}

// ConfirmPath is where the pin activation pages live.
const ConfirmPath = "/integrations/publisher-pins"

// ConfirmURL is a pin's activation page.
func (s *Service) ConfirmURL(id ids.UUID) string {
	return strings.TrimSuffix(s.cfg.PublicURL, "/") + ConfirmPath + "/" + id.String() + "/confirm"
}

// person returns the caller if it holds perm and is a person signed in as
// themselves: not an API key, a service account or a support session.
func person(ctx context.Context, perm td.Permission) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if err := c.Require(perm, td.OrgPath(c.Org)); err != nil {
		return c, err
	}
	if !c.Human() || c.Credential == tenancy.CredAPIKey || c.Credential == tenancy.CredSupportSession {
		return c, bdomain.ErrHuman
	}
	return c, nil
}

// reader returns the caller if it holds bundle.read.
func reader(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	return c, c.Require(bdomain.PermBundleRead, td.OrgPath(c.Org))
}

func record(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, outcome audit.Outcome, name, objType, id string,
	details map[string]string,
) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: actor, Outcome: outcome, Object: &audit.Object{Type: objType, ID: id}, Details: details,
	})
	return err
}
