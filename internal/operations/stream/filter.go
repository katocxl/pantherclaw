// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package stream

import (
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// focusKinds are the feed kinds the stream sends (D32): live signals
// (first sensitive use, significant writes, new or expanded authority,
// unexpected denials), alerts, incidents and containment. Routine reads
// and everything else stay searchable but are not streamed.
var focusKinds = map[string]bool{
	"reflex.live":     true,
	"reflex.alert":    true,
	"reflex.incident": true,
	"response.action": true,
	"response.path":   true,
}

// focusPrefixes are kind prefixes the stream sends: kill switch and
// containment audit records.
var focusPrefixes = []string{"audit.containment."}

// Focus reports whether e belongs on the live stream.
func Focus(e Event) bool {
	if focusKinds[e.Kind] {
		return true
	}
	for _, p := range focusPrefixes {
		if strings.HasPrefix(e.Kind, p) {
			return true
		}
	}
	return false
}

// agentsOf returns the agents e names, and false when a subject id is
// malformed (the event is then treated as unscoped).
func agentsOf(e Event) ([]ids.UUID, bool) {
	var out []ids.UUID
	for _, s := range e.Subjects {
		if s.Type != "agent" {
			continue
		}
		id, err := ids.ParseUUID(s.ID)
		if err != nil {
			return nil, false
		}
		out = append(out, id)
	}
	return out, true
}

// Visible reports whether the viewer c may see e (D8, HR-256). An event
// naming agents is visible only when every one of them is in the viewer's
// scope; an event naming no agent (org-wide, such as the kill switch) only
// to a viewer holding perm at the org. Nothing else in the event widens
// what the viewer sees.
func Visible(c tenancy.Caller, perm td.Permission, sc Scope, e Event) bool {
	if e.Org != c.Org {
		return false
	}
	agents, ok := agentsOf(e)
	if !ok || len(agents) == 0 {
		return c.Can(perm, td.OrgPath(c.Org))
	}
	if sc.All {
		return true
	}
	for _, a := range agents {
		if !sc.Agents[a] {
			return false
		}
	}
	return true
}

// grouped is an event standing for Count retries of one transaction.
type grouped struct {
	Event
	Count int
	First time.Time
}

// retryKey is what makes events retries of each other: the same kind about
// the same transaction (its idempotency).
func retryKey(e Event) string {
	for _, s := range e.Subjects {
		if s.Type == "transaction" {
			return e.Kind + "/" + s.ID
		}
	}
	return ""
}

// group folds retries of one transaction within evs into one event: the
// latest, with the count and the first time. Order follows each group's
// latest event.
func group(evs []Event) []grouped {
	out := make([]grouped, 0, len(evs))
	at := map[string]int{}
	for _, e := range evs {
		k := retryKey(e)
		if i, ok := at[k]; ok && k != "" {
			g := out[i]
			out = append(out[:i], out[i+1:]...)
			for key, j := range at {
				if j > i {
					at[key] = j - 1
				}
			}
			g.Event, g.Count = e, g.Count+1
			at[k] = len(out)
			out = append(out, g)
			continue
		}
		if k != "" {
			at[k] = len(out)
		}
		out = append(out, grouped{Event: e, Count: 1, First: e.OccurredAt})
	}
	return out
}

// wire is an event as sent: ids, codes and times only (D2 never carries
// payloads or secrets).
type wire struct {
	Seq              int64             `json:"seq"`
	ID               string            `json:"id"`
	Kind             string            `json:"kind"`
	OccurredAt       time.Time         `json:"occurred_at"`
	FirstAt          time.Time         `json:"first_at,omitzero"`
	Count            int               `json:"count"`
	ActorType        string            `json:"actor_type,omitzero"`
	ActorID          string            `json:"actor_id,omitzero"`
	Subjects         []Subject         `json:"subjects,omitzero"`
	Decision         string            `json:"decision,omitzero"`
	Reason           string            `json:"reason,omitzero"`
	Operation        string            `json:"operation,omitzero"`
	Mode             string            `json:"mode,omitzero"`
	Outcome          string            `json:"outcome,omitzero"`
	Environment      string            `json:"environment,omitzero"`
	DestinationClass string            `json:"destination_class,omitzero"`
	Test             bool              `json:"test,omitzero"`
	Attrs            map[string]string `json:"attrs,omitzero"`
}

func wireOf(g grouped) wire {
	w := wire{
		Seq: g.Seq, ID: g.ID.String(), Kind: g.Kind, OccurredAt: g.OccurredAt.UTC(), Count: g.Count,
		ActorType: g.ActorType, ActorID: g.ActorID, Subjects: g.Subjects, Decision: g.Decision, Reason: g.Reason,
		Operation: g.Operation, Mode: g.Mode, Outcome: g.Outcome, Environment: g.Environment,
		DestinationClass: g.DestinationClass, Test: g.Test, Attrs: g.Attrs,
	}
	if g.Count > 1 {
		w.FirstAt = g.First.UTC()
	}
	return w
}
