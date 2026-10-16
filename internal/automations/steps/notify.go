// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package steps

import (
	"context"
	"encoding/json/v2"
	"slices"
	"strconv"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// revokeGrant revokes grants within its declared scope (D25): the
// execution's own grants, the trigger's grant, or the ceiling agents'
// grants, always through RevokeForAutomationTx (D9). Narrowing only.
type revokeGrant struct{ d Deps }

func (*revokeGrant) Kind() string { return autodomain.KindRevokeGrant }

func (s *revokeGrant) revoke(sc autodomain.StepContext) (GrantRevoke, string) {
	w, ok := sc.With.(*autodomain.RevokeGrantWith)
	if !ok || len([]rune(w.Reason)) > 1000 {
		return GrantRevoke{}, ReasonBadWith
	}
	switch w.Scope {
	case autodomain.RevokeExecution, autodomain.RevokeTriggerGrant, autodomain.RevokeCeilingAgents:
	default:
		return GrantRevoke{}, ReasonBadWith
	}
	if !inScope(sc.Def, autodomain.KindRevokeGrant, w.Scope) {
		return GrantRevoke{}, ReasonOutsideScope
	}
	in := GrantRevoke{Org: sc.Org, Execution: sc.Execution.ID, Scope: w.Scope, Reason: w.Reason}
	if w.Scope == autodomain.RevokeTriggerGrant {
		for _, sub := range sc.Execution.Trigger.Subjects {
			if sub.Type == reflexdomain.SubjectGrant {
				if id, ok := parseID(sub.ID); ok {
					in.Grant = &id
					break
				}
			}
		}
		if in.Grant == nil {
			return GrantRevoke{}, ReasonBadWith
		}
	}
	return in, ""
}

func (s *revokeGrant) Run(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	if s.d.Grants == nil {
		return unwired()
	}
	in, reason := s.revoke(sc)
	if reason != "" {
		return failed(reason)
	}
	revoked, err := s.d.Grants.RevokeForAutomation(ctx, tx, in)
	if err != nil {
		if r, ok := refusal(err); ok {
			return failed(r)
		}
		return autodomain.StepResult{}, err
	}
	effect := autodomain.EffectUnchanged
	refs := make([]reflexdomain.EvidenceRef, 0, len(revoked))
	for _, g := range revoked {
		refs = append(refs, ref(RefGrant, g))
	}
	if len(revoked) > 0 {
		effect = autodomain.EffectChanged
	}
	return autodomain.StepResult{
		State: autodomain.StepDone, Effect: effect, Refs: refs,
		Output: map[string]string{"revoked": strconv.Itoa(len(revoked))},
	}, nil
}

func (s *revokeGrant) Poll(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	return s.Run(ctx, tx, sc)
}

func (s *revokeGrant) Preview(_ context.Context, _ pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	in, reason := s.revoke(sc)
	if reason != "" {
		return autodomain.StepResult{
			State: autodomain.StepFailed, Reason: reason,
			Output: map[string]string{"shadow": "true", "decision": "REFUSED"},
		}, nil
	}
	return shadowed(map[string]string{"shadow": "true", "scope": in.Scope})
}

// Notice bounds (D25).
const (
	MaxNoticeTitle = 120
	MaxNoticeBody  = 1000
)

// notify sends a notice to the people its declared scopes name, or to a
// declared destination (D25). In SHADOW and TEST modes only the owner is
// told, and the notice says it is a shadow (HR-288).
type notify struct{ d Deps }

func (*notify) Kind() string { return autodomain.KindNotify }

func (s *notify) check(sc autodomain.StepContext) (*autodomain.NotifyWith, string) {
	w, ok := sc.With.(*autodomain.NotifyWith)
	if !ok || w.Message.Title == "" || utf8.RuneCountInString(w.Message.Title) > MaxNoticeTitle ||
		utf8.RuneCountInString(w.Message.Body) > MaxNoticeBody || len(w.To) == 0 && w.Destination == nil {
		return nil, ReasonBadWith
	}
	for _, to := range w.To {
		if !inScope(sc.Def, autodomain.KindNotify, to) {
			return nil, ReasonOutsideScope
		}
	}
	if w.Destination != nil && (!slices.Contains(sc.Def.Authority.Destinations, *w.Destination) ||
		!inScope(sc.Def, autodomain.KindNotify, w.Destination.String())) {
		return nil, ReasonOutsideScope
	}
	return w, ""
}

func (s *notify) Run(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	w, reason := s.check(sc)
	if reason != "" {
		return failed(reason)
	}
	out := map[string]string{}
	var refs []reflexdomain.EvidenceRef
	if len(w.To) > 0 {
		if s.d.Notifier == nil || s.d.Recipients == nil {
			return unwired()
		}
		var people []ids.UUID
		for _, to := range w.To {
			ps, err := s.d.Recipients.Resolve(ctx, tx, sc, to)
			if err != nil {
				return autodomain.StepResult{}, err
			}
			people = append(people, ps...)
		}
		slices.SortFunc(people, compareUUID)
		people = slices.Compact(people)
		id, err := s.d.Notifier.Notify(ctx, tx, Notice{
			Org: sc.Org, Automation: sc.Execution.Automation, Execution: sc.Execution.ID, StepID: sc.Spec.ID,
			People: people, Title: w.Message.Title, Body: w.Message.Body,
		})
		if err != nil {
			return autodomain.StepResult{}, err
		}
		out["notification_id"], out["recipients"] = id.String(), strconv.Itoa(len(people))
		refs = append(refs, ref(RefNotification, id))
	}
	if w.Destination != nil {
		if s.d.Deliverer == nil {
			return unwired()
		}
		body, err := json.Marshal(map[string]string{
			"type": "automation.notice", "execution": sc.Execution.ID.String(), "title": w.Message.Title, "body": w.Message.Body,
		}, json.Deterministic(true))
		if err != nil {
			return autodomain.StepResult{}, err
		}
		id, err := s.d.Deliverer.Deliver(ctx, tx, autodomain.Delivery{
			Org: sc.Org, Destination: w.Destination.UUID(), Execution: sc.Execution.ID, Kind: autodomain.DeliveryNotice, Body: body,
		})
		if err != nil {
			if r, ok := refusal(err); ok {
				return failed(r)
			}
			return autodomain.StepResult{}, err
		}
		out[OutDelivery] = id.String()
		refs = append(refs, ref(RefDelivery, id))
	}
	return autodomain.StepResult{State: autodomain.StepDone, Effect: autodomain.EffectChanged, Output: out, Refs: refs}, nil
}

func (s *notify) Poll(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	return s.Run(ctx, tx, sc)
}

// Preview tells the owner only, marked as a shadow (HR-288).
func (s *notify) Preview(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	w, reason := s.check(sc)
	if reason != "" {
		return autodomain.StepResult{
			State: autodomain.StepFailed, Reason: reason,
			Output: map[string]string{"shadow": "true", "decision": "REFUSED"},
		}, nil
	}
	out := map[string]string{"shadow": "true"}
	if s.d.Notifier != nil && sc.Mode == autodomain.ModeShadow && !sc.Execution.Owner.IsZero() {
		id, err := s.d.Notifier.Notify(ctx, tx, Notice{
			Org: sc.Org, Automation: sc.Execution.Automation, Execution: sc.Execution.ID, StepID: sc.Spec.ID,
			People: []ids.UUID{sc.Execution.Owner}, Title: w.Message.Title, Body: w.Message.Body, Shadow: true,
		})
		if err != nil {
			return autodomain.StepResult{}, err
		}
		out["notification_id"] = id.String()
	}
	return shadowed(out)
}

// deliver sends a build_digest step's report to a declared destination
// and waits until it is delivered (D25, DELIVERY_CONFIRMED).
type deliver struct{ d Deps }

func (*deliver) Kind() string { return autodomain.KindDeliver }

func (s *deliver) check(sc autodomain.StepContext) (*autodomain.DeliverWith, map[string]string, string) {
	w, ok := sc.With.(*autodomain.DeliverWith)
	if !ok || w.Destination.IsZero() || w.From == "" {
		return nil, nil, ReasonBadWith
	}
	if !slices.Contains(sc.Def.Authority.Destinations, w.Destination) ||
		!inScope(sc.Def, autodomain.KindDeliver, w.Destination.String()) {
		return nil, nil, ReasonOutsideScope
	}
	from, ok := stepOutput(sc, w.From)
	if !ok || from["pack_id"] == "" {
		return nil, nil, ReasonBadWith
	}
	return w, from, ""
}

func (s *deliver) Run(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	if s.d.Deliverer == nil {
		return unwired()
	}
	w, from, reason := s.check(sc)
	if reason != "" {
		return failed(reason)
	}
	body, err := json.Marshal(map[string]string{
		"type": "automation.digest", "execution": sc.Execution.ID.String(), "pack_id": from["pack_id"],
		"report_digest": from["report_digest"],
	}, json.Deterministic(true))
	if err != nil {
		return autodomain.StepResult{}, err
	}
	id, err := s.d.Deliverer.Deliver(ctx, tx, autodomain.Delivery{
		Org: sc.Org, Destination: w.Destination.UUID(), Execution: sc.Execution.ID, Kind: autodomain.DeliveryDigest, Body: body,
	})
	if err != nil {
		if r, ok := refusal(err); ok {
			return failed(r)
		}
		return autodomain.StepResult{}, err
	}
	return autodomain.StepResult{
		State: autodomain.StepWaiting, Effect: autodomain.EffectChanged,
		Output: map[string]string{OutDelivery: id.String()}, WakeAt: sc.Now.Add(engine.PollInterval),
	}, nil
}

func (s *deliver) Poll(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	if s.d.Deliverer == nil {
		return unwired()
	}
	o := own(sc)
	id, ok := parseID(o[OutDelivery])
	if !ok {
		return failed(ReasonBadWith)
	}
	st, err := s.d.Deliverer.Status(ctx, tx, id)
	if err != nil {
		return autodomain.StepResult{}, err
	}
	refs := []reflexdomain.EvidenceRef{ref(RefDelivery, id)}
	switch st.State {
	case autodomain.DeliveryDelivered:
		return autodomain.StepResult{State: autodomain.StepDone, Effect: autodomain.EffectChanged, Output: o, Refs: refs}, nil
	case autodomain.DeliveryFailed:
		return autodomain.StepResult{
			State: autodomain.StepFailed, Reason: ReasonDelivery, Effect: autodomain.EffectUnknown,
			Output: o, Refs: refs,
		}, nil
	case autodomain.DeliveryPending:
	}
	return autodomain.StepResult{
		State: autodomain.StepWaiting, Effect: autodomain.EffectChanged, Output: o,
		WakeAt: sc.Now.Add(engine.PollInterval),
	}, nil
}

func (s *deliver) Preview(_ context.Context, _ pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	_, _, reason := s.check(sc)
	if reason != "" && reason != ReasonBadWith {
		return autodomain.StepResult{
			State: autodomain.StepFailed, Reason: reason,
			Output: map[string]string{"shadow": "true", "decision": "REFUSED"},
		}, nil
	}
	return shadowed(map[string]string{"shadow": "true"})
}
