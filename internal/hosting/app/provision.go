// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/hosting/domain"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// The provisioner (G0 M19 D203): hosting.provision runs every
// ProvisionInterval and fans out, through the audited lister (HR-054,
// purpose hosting_due), to one hosting.provision_org job per org that has
// a hosted gateway to act on (ids only, HR-056).
const ProvisionInterval = 30 * time.Second

// enrollmentTTL is the enrollment token's lifetime, as for every gateway
// (G0 M6 design decision 1): the provisioner issues a fresh one when the
// host agent did not pull it within 10 minutes (lister hosting_due).
const enrollmentTTL = 15 * time.Minute

// tokenField is where the sealed token lives (HR-062).
func tokenField(org ids.OrgID, id ids.UUID) pccrypto.FieldContext {
	return pccrypto.FieldContext{Org: org, Table: "hosted_gateways", Column: "token_sealed", RowID: id.String()}
}

// tokenPurpose is the DEK purpose of sealed hosting tokens.
const tokenPurpose = "hosting_token"

// ProvisionArgs fans the provisioner out to every due org.
type ProvisionArgs struct{}

// Kind implements river.JobArgs.
func (ProvisionArgs) Kind() string { return "hosting.provision" }

// ProvisionOrgArgs provisions one org's hosted gateway.
type ProvisionOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (ProvisionOrgArgs) Kind() string { return "hosting.provision_org" }

// InsertOpts keeps one queued job per org.
func (ProvisionOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

type provisionWorker struct {
	river.WorkerDefaults[ProvisionArgs]
	pool *db.Pool
}

func (w *provisionWorker) Work(ctx context.Context, _ *river.Job[ProvisionArgs]) error {
	return w.pool.CrossOrgPages(ctx, listDue, db.ListerPageSize, func(page []db.OrgRef) error {
		client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
		if err != nil {
			return fmt.Errorf("hosting provisioner: %w", err)
		}
		params := make([]river.InsertManyParams, 0, len(page))
		for _, r := range page {
			params = append(params, river.InsertManyParams{Args: ProvisionOrgArgs{Org: r.Org}})
		}
		_, err = client.InsertMany(ctx, params)
		return err
	})
}

type provisionOrgWorker struct {
	river.WorkerDefaults[ProvisionOrgArgs]
	svc *Service
	log *slog.Logger
}

func (w *provisionOrgWorker) Work(ctx context.Context, job *river.Job[ProvisionOrgArgs]) error {
	n, err := w.svc.ProvisionOrg(ctx, job.Args.Org)
	if n > 0 {
		w.log.InfoContext(ctx, "hosting.provisioned", slog.String("org", job.Args.Org.String()), slog.Int("hosted_gateways", n))
	}
	if errors.Is(err, domain.ErrNoCapacity) {
		w.log.WarnContext(ctx, "hosting.no_capacity", slog.String("org", job.Args.Org.String()))
		return nil // the next run tries again
	}
	return err
}

// RegisterJobs adds the provisioner to reg.
func (s *Service) RegisterJobs(reg *jobs.Registry, log *slog.Logger) error {
	if log == nil {
		log = pclog.Discard()
	}
	if err := jobs.Register[ProvisionArgs](reg, &provisionWorker{pool: s.pool}); err != nil {
		return err
	}
	return jobs.Register[ProvisionOrgArgs](reg, &provisionOrgWorker{svc: s, log: log})
}

// PeriodicJobs returns the provisioner's schedule.
func PeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(ProvisionInterval),
			func() (river.JobArgs, *river.InsertOpts) { return ProvisionArgs{}, nil }, nil),
	}
}

// ProvisionOrg acts on the org's due hosted gateways: a requested one gets
// its gateway, a single-use enrollment token sealed until its host agent
// pulls it, and a host; a token not pulled in time is replaced. It returns
// how many it provisioned.
func (s *Service) ProvisionOrg(ctx context.Context, org ids.OrgID) (int, error) {
	var requested []dbq.PcHostedGateway
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if state, err := q.OrgState(ctx, org); err != nil || state != "ACTIVE" {
			return err // a deleted org gets nothing (HR-392)
		}
		due, err := q.ListDueHostedGateways(ctx, org)
		if err != nil {
			return err
		}
		for _, h := range due {
			switch h.State {
			case domain.StateRequested:
				requested = append(requested, h)
			case domain.StateProvisioned:
				if err := s.reissue(ctx, tx, q, h); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, h := range requested {
		done, err := s.placeAndProvision(ctx, h)
		if err != nil {
			return n, err
		}
		if done {
			n++
		}
	}
	return n, nil
}

// placeAndProvision places a requested hosted gateway on a host and
// provisions it there. It reports false if another worker got there first.
func (s *Service) placeAndProvision(ctx context.Context, h dbq.PcHostedGateway) (bool, error) {
	done := false
	err := s.place(ctx, h.Slug, func(host dbq.PcHostingHost) error {
		return s.pool.InTenantTx(ctx, h.OrgID, func(ctx context.Context, tx db.TenantTx) error {
			q := dbq.New(tx)
			if state, err := q.OrgState(ctx, h.OrgID); err != nil || state != "ACTIVE" {
				return err
			}
			cur, err := q.LockHostedGateway(ctx, h.OrgID, h.ID)
			if err != nil || cur.State != domain.StateRequested {
				return err
			}
			done = true
			return s.provision(ctx, tx, q, cur, host)
		})
	})
	return done, err
}

// hostedGatewayName is the gateway record's name: "hosted-" and the slug,
// within the gateway name's 63 characters.
func hostedGatewayName(slug string) string {
	n := "hosted-" + slug
	if len(n) > 63 {
		n = n[:63]
	}
	for len(n) > 0 && n[len(n)-1] == '-' {
		n = n[:len(n)-1]
	}
	return n
}

func (s *Service) provision(ctx context.Context, tx db.TenantTx, q *dbq.Queries, h dbq.PcHostedGateway, host dbq.PcHostingHost) error {
	g, err := q.InsertGateway(ctx, dbq.InsertGatewayParams{OrgID: h.OrgID, ID: ids.NewV7(), Name: hostedGatewayName(h.Slug), CreatedBy: "system:hosting"})
	if err != nil {
		return err // a name taken by a customer gateway retries until renamed
	}
	sealed, enrollment, err := s.mint(ctx, q, h, g.ID)
	if err != nil {
		return err
	}
	if n, err := q.ProvisionHostedGateway(ctx, dbq.ProvisionHostedGatewayParams{
		GatewayID: &g.ID, HostID: &host.ID, TokenSealed: sealed, EnrollmentID: &enrollment, OrgID: h.OrgID, ID: h.ID,
	}); err != nil {
		return err
	} else if n != 1 {
		return db.ErrLostRace
	}
	return record(ctx, tx, systemActor, "hosted_gateway.provisioned", h.ID, map[string]string{
		"gateway_id": g.ID.String(), "host_id": host.ID.String(), "enrollment_id": enrollment.String(),
	})
}

func (s *Service) reissue(ctx context.Context, tx db.TenantTx, q *dbq.Queries, h dbq.PcHostedGateway) error {
	if h.GatewayID == nil {
		return nil
	}
	if h.EnrollmentID != nil { // the token it replaces ends now, not at its TTL
		if err := q.ExpireHostedEnrollmentToken(ctx, h.OrgID, *h.EnrollmentID); err != nil {
			return err
		}
	}
	sealed, enrollment, err := s.mint(ctx, q, h, *h.GatewayID)
	if err != nil {
		return err
	}
	if n, err := q.ReissueHostedToken(ctx, dbq.ReissueHostedTokenParams{
		TokenSealed: sealed, EnrollmentID: &enrollment, OrgID: h.OrgID, ID: h.ID,
	}); err != nil || n != 1 {
		return err
	}
	return record(ctx, tx, systemActor, "hosted_gateway.token_reissued", h.ID, map[string]string{"enrollment_id": enrollment.String()})
}

// mint creates a single-use enrollment token for the gateway, stored as
// its SHA-256 like every enrollment token (HR-180), and returns it sealed
// with the org's DEK for the host agent to pull once (HR-502).
func (s *Service) mint(ctx context.Context, q *dbq.Queries, h dbq.PcHostedGateway, gateway ids.UUID) ([]byte, ids.UUID, error) {
	tok, err := credential.New(credential.GatewayEnrollmentToken, "", h.OrgID)
	if err != nil {
		return nil, ids.UUID{}, err
	}
	r, err := q.InsertGatewayEnrollmentToken(ctx, dbq.InsertGatewayEnrollmentTokenParams{
		OrgID: h.OrgID, ID: ids.NewV7(), GatewayID: gateway, TokenHash: tok.Hash(), CreatedBy: "system:hosting",
		TtlMinutes: int32(enrollmentTTL / time.Minute),
	})
	if err != nil {
		return nil, ids.UUID{}, err
	}
	sealed, err := s.env.Encrypt(ctx, tokenField(h.OrgID, h.ID), tokenPurpose, []byte(tok.Reveal()))
	return sealed, r.ID, err
}

// place picks the active host with the fewest hosted gateways below its
// capacity (T-218) that runs none with the same slug, so that
// <slug>.gw.<host domain> names one process, and runs fn while it holds that
// host's row: the checks repeat under the lock, so two placements on one
// host are one after the other (G0 M19 D219). Both are counted across orgs
// through the audited lister.
func (s *Service) place(ctx context.Context, slug string, fn func(dbq.PcHostingHost) error) error {
	var hosts []dbq.PcHostingHost
	if err := s.pool.InGlobalTx(ctx, db.GlobalHosting, func(ctx context.Context, tx db.GlobalTx) error {
		var err error
		hosts, err = dbq.New(tx).ListActiveHostingHosts(ctx)
		return err
	}); err != nil {
		return err
	}
	type load struct {
		host dbq.PcHostingHost
		n    int
	}
	var room []load
	for _, h := range hosts {
		n, ok, err := s.fits(ctx, h, slug)
		if err != nil {
			return err
		}
		if ok {
			room = append(room, load{h, n})
		}
	}
	slices.SortStableFunc(room, func(a, b load) int { return a.n - b.n })
	for _, r := range room {
		placed := false
		err := s.pool.InGlobalTx(ctx, db.GlobalHosting, func(gctx context.Context, tx db.GlobalTx) error {
			host, err := dbq.New(tx).LockActiveHostingHost(gctx, r.host.ID)
			if db.IsNoRows(err) {
				return nil
			} else if err != nil {
				return err
			}
			if _, ok, err := s.fits(ctx, host, slug); err != nil || !ok {
				return err
			}
			placed = true
			return fn(host)
		})
		if err != nil || placed {
			return err
		}
	}
	return domain.ErrNoCapacity
}

// fits counts the host's hosted gateways and reports whether it can take
// one more with this slug.
func (s *Service) fits(ctx context.Context, h dbq.PcHostingHost, slug string) (int, bool, error) {
	refs, err := s.assigned(ctx, h.ID, "")
	if err != nil || len(refs) >= int(h.Capacity) {
		return len(refs), false, err
	}
	same, err := s.assigned(ctx, h.ID, slug)
	return len(refs), err == nil && len(same) == 0, err
}

// through the audited lister.

// maxPerHost bounds a host's assignments the lister returns: above every
// host capacity (migration 00228).
const maxPerHost = 1000

// assigned lists the (org, hosted gateway) pairs placed on one host, only
// those with slug when it is set (lister hosting_assigned, its own audited
// global transaction).
func (s *Service) assigned(ctx context.Context, host ids.UUID, slug string) ([]db.OrgRef, error) {
	var out []db.OrgRef
	err := s.pool.InGlobalTx(ctx, db.GlobalCrossOrgList, func(ctx context.Context, tx db.GlobalTx) error {
		// The slug narrows the purpose for placement only; it is set for
		// this transaction alone, like the host (ListerParams.HostID).
		if _, err := tx.Exec(ctx, "SELECT set_config('app.hosting_slug', $1::text, true)", slug); err != nil {
			return err
		}
		var err error
		out, err = db.CrossOrgListIn(ctx, tx, listAssigned, maxPerHost, db.ListerParams{HostID: host})
		return err
	})
	return out, err
}
