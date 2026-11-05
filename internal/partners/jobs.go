// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package partners

import (
	"context"
	"time"

	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// expiryActor is the sweep's audit actor.
var expiryActor = evdomain.Actor{Type: "system", ID: "partner_expiry"}

type ended struct {
	id, partner ids.UUID
	name        string
	objType     string
}

// Expire ends org's links whose window ended or whose request went
// undecided for seven days, ends their partner sessions, and expires
// proposals nobody decided within 30 days (D1100, D1102). Expiry is also
// enforced at every authentication and decision, whenever the sweep runs;
// the sweep records it in both orgs.
func (s *Service) Expire(ctx context.Context, org ids.OrgID) error {
	var done []ended
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		links, err := q.ExpirePartnerLinks(ctx, org.UUID())
		if err != nil {
			return err
		}
		for _, l := range links {
			if _, err := q.EndPartnerSessionsOfLink(ctx, org, l.ID); err != nil {
				return err
			}
			d := map[string]string{"partner_org": l.PartnerOrg.String(), "customer_org": org.String()}
			if err := record(ctx, tx, expiryActor, auditkind.PartnerLinkExpired, "partner_link", l.ID, d); err != nil {
				return err
			}
			done = append(done, ended{l.ID, l.PartnerOrg, auditkind.PartnerLinkExpired, "partner_link"})
		}
		props, err := q.ExpirePartnerProposals(ctx, org.UUID())
		if err != nil {
			return err
		}
		for _, p := range props {
			d := map[string]string{"partner_org": p.PartnerOrg.String(), "customer_org": org.String()}
			if err := record(ctx, tx, expiryActor, auditkind.PartnerProposalExpired, "partner_proposal", p.ID, d); err != nil {
				return err
			}
			done = append(done, ended{p.ID, p.PartnerOrg, auditkind.PartnerProposalExpired, "partner_proposal"})
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, e := range done {
		d := map[string]string{"partner_org": e.partner.String(), "customer_org": org.String()}
		if err := s.mirror(ctx, e.partner, expiryActor, e.name, e.objType, e.id, d); err != nil {
			return err
		}
	}
	return nil
}

type expirySweepArgs struct{}

func (expirySweepArgs) Kind() string { return "partners.expiry_sweep" }

type expirySweepWorker struct {
	river.WorkerDefaults[expirySweepArgs]
	s *Service
}

func (w *expirySweepWorker) Work(ctx context.Context, _ *river.Job[expirySweepArgs]) error {
	return w.s.pool.CrossOrgPages(ctx, db.ListActiveOrgs, db.ListerPageSize, func(page []db.OrgRef) error {
		for _, r := range page {
			if err := w.s.Expire(ctx, r.Org); err != nil {
				return err
			}
		}
		return nil
	})
}

// Register adds the expiry worker.
func (s *Service) Register(reg *jobs.Registry) error {
	return jobs.Register[expirySweepArgs](reg, &expirySweepWorker{s: s})
}

// PeriodicJobs schedules the expiry sweep every five minutes.
func PeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{river.NewPeriodicJob(river.PeriodicInterval(5*time.Minute),
		func() (river.JobArgs, *river.InsertOpts) { return expirySweepArgs{}, nil }, nil)}
}
