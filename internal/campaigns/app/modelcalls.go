// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"time"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Limits of the model route (D313).
const (
	// MaxModelBytes is the most one request or answer may carry.
	MaxModelBytes = 8 << 20
	// RunModelTotal is the most one run may send and receive together.
	RunModelTotal = 256 << 20
	// MaxCampaignAge closes the route on a campaign that was never finished,
	// also before the abandon sweep reaches it.
	MaxCampaignAge = 24 * time.Hour
)

// ErrModelRoute refuses a model call. It never says which rule failed, so it
// cannot be used to learn about campaigns.
var ErrModelRoute = pcerr.New(pcerr.FailedPrecondition, "MODEL_ROUTE_CLOSED",
	"the model route is open only to a range agent's run, during its open campaign, through its relay, to its model host")

// RelayRef is a connection as the model route needs it.
type RelayRef struct {
	Gateway    ids.UUID
	Simulated  bool
	ModelRelay bool
	Active     bool
}

// ModelTx is what the model route needs of a tenant transaction.
type ModelTx interface {
	RelayConnection(ctx context.Context, id ids.UUID) (RelayRef, bool, error)
	// AddModelRequest counts one request of a run, within the total; false
	// when it would pass it.
	AddModelRequest(ctx context.Context, campaign, run ids.UUID, host string, bytes, total int64) (bool, error)
	AddModelAnswer(ctx context.Context, campaign, run ids.UUID, bytes int64) (bool, error)
}

// ModelCall is one model request as the gateway describes it.
type ModelCall struct {
	Gateway, Connection, Run ids.UUID
	ModelHost                string
	BytesToModel             int64
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// AuthorizeModelCall decides one model request and counts it (D313, HR-613).
// The gateway asks for every request, so the route is off the moment the
// campaign closes. Every refusal is ErrModelRoute. It returns the campaign.
func (s *Service) AuthorizeModelCall(ctx context.Context, org ids.OrgID, in ModelCall) (ids.UUID, error) {
	if in.BytesToModel < 0 || in.BytesToModel > MaxModelBytes {
		return ids.UUID{}, ErrModelRoute
	}
	var campaign ids.UUID
	err := s.Store.InTx(ctx, org, false, func(ctx context.Context, tx Tx) error {
		relay, ok, err := tx.RelayConnection(ctx, in.Connection)
		if err != nil {
			return err
		}
		if !ok || relay.Gateway != in.Gateway || !relay.Simulated || !relay.ModelRelay || !relay.Active {
			return ErrModelRoute
		}
		run, ok, err := tx.Run(ctx, in.Run)
		if err != nil {
			return err
		}
		if !ok {
			return ErrModelRoute
		}
		agent, err := tx.Agent(ctx, run.Agent)
		if err != nil || !agent.RangeAgent {
			return ErrModelRoute
		}
		c, open, err := tx.OpenOf(ctx, agent.ID)
		if err != nil {
			return err
		}
		if !open || c.Relay != in.Connection || c.ModelHost != in.ModelHost ||
			s.now().Sub(c.Started) >= MaxCampaignAge || !run.Belongs(agent.ID, c.Started) {
			return ErrModelRoute
		}
		added, err := tx.AddModelRequest(ctx, c.ID, in.Run, in.ModelHost, in.BytesToModel, RunModelTotal)
		if err != nil {
			return err
		}
		if !added {
			return ErrModelRoute
		}
		campaign = c.ID
		return nil
	})
	return campaign, err
}

// ReportModelUsage adds one answer's size to the run's count. Only the
// gateway that serves the campaign's relay may report it. A campaign that has
// since closed still takes the count of a call it allowed.
func (s *Service) ReportModelUsage(ctx context.Context, org ids.OrgID, gateway, campaign, run ids.UUID, bytes int64) error {
	if bytes < 0 || bytes > MaxModelBytes {
		return ErrModelRoute
	}
	return s.Store.InTx(ctx, org, false, func(ctx context.Context, tx Tx) error {
		c, err := tx.Campaign(ctx, campaign, false)
		if err != nil {
			return ErrModelRoute
		}
		relay, ok, err := tx.RelayConnection(ctx, c.Relay)
		if err != nil {
			return err
		}
		if !ok || relay.Gateway != gateway {
			return ErrModelRoute
		}
		added, err := tx.AddModelAnswer(ctx, campaign, run, bytes)
		if err != nil {
			return err
		}
		if !added {
			return ErrModelRoute
		}
		return nil
	})
}
