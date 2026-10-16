// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package triggers

import (
	"context"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// InboundEvent is one verified inbound event (D21): its signature,
// timestamp, replay and type were checked by the receiver.
type InboundEvent struct {
	Source    ids.UUID
	Type      string
	WebhookID string
	// Secret is which secret verified it: "current" or "previous".
	Secret string
	Body   []byte
	// SentAt is the sender's timestamp (kept as a detail); ReceivedAt is
	// when it arrived, the trigger's occurrence time (D87 L9).
	SentAt     time.Time
	ReceivedAt time.Time
}

// FireInbound fires every INBOUND trigger listening to the event's source
// and type (ACTIVE or PAUSED automations): parameters come only from the
// declared JSON Pointers (HR-276); a failed extraction refuses that
// automation's trigger alone. The body is never stored.
func (s *Service) FireInbound(ctx context.Context, tx db.TenantTx, ev InboundEvent) ([]Outcome, error) {
	q := dbq.New(tx)
	org := tx.OrgID()
	rows, err := q.InboundAutomations(ctx, org, ev.Source.String(), ev.Type)
	if err != nil {
		return nil, err
	}
	var out []Outcome
	for _, r := range rows {
		a, err := automationOf(r.ID, r.Name, r.State, r.Rollout, r.ServiceAccountID, r.OwnerUserID, r.VersionID, r.Definition)
		if err != nil || a.Def.When.Inbound == nil {
			continue
		}
		params, perr := ExtractInbound(a.Def.When.Inbound.Params, ev.Body)
		o, ok := s.FireInSavepoint(ctx, tx, Candidate{
			Automation: a, Kind: autodomain.TriggerInbound, Authenticity: autodomain.AuthSignedSource,
			Detail: map[string]string{
				"source": ev.Source.String(), "generation": ev.Secret, "webhook_id": truncate(ev.WebhookID, 256), "type": ev.Type,
				"sent_at": ev.SentAt.UTC().Format(time.RFC3339),
			},
			SourceRef: truncate("inbound:"+ev.Source.String()+":"+ev.Type, 256), Params: params, ParamErr: perr,
			BaseKey: InboundKey(ev.Source, ev.WebhookID), OccurredAt: ev.ReceivedAt, QueueOK: true,
		})
		if ok {
			out = append(out, o)
		}
	}
	return out, nil
}
