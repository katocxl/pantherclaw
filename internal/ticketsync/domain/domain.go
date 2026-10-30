// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the ticket sync model (G0 M20 D255; F545, HR-527,
// HR-528, T-227): which side owns each field, what an inbound ticket
// change becomes, and the sync actor.
//
// A ticket status never restores authority. PantherClaw always owns
// containment and restoration (D264); state and severity are PantherClaw's
// unless the organization gives them to the ticket system, and assignee,
// labels, the ticket's own priority and comments are the ticket system's
// unless it takes them back. An inbound change to a field PantherClaw owns
// is dropped and recorded (an EXTERNAL case entry and the audit event
// ticket.owned_field_ignored), and a ticket moved to Done is only noted.
// A change to a field the ticket system owns is mirrored as a note: even
// a ticket-owned state never moves a case, an incident or a control. Nothing here can reach a
// containment control, a restoration plan, an approval or a kill switch:
// the sync actor holds no permission on those services and its packages do
// not import them.
package domain

import (
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
)

// The sync actor (D255): PantherClaw's ticket sync acting by itself.
const (
	ActorType = "system"
	ActorID   = "ticketsync"
	// Principal is the actor as a "type:id" string.
	Principal = ActorType + ":" + ActorID
)

// Actor is the sync actor as a ledger actor.
var Actor = evdomain.Actor{Type: ActorType, ID: ActorID}

// System is a ticket system. Jira is the first (G15).
type System string

// Systems.
const SystemJira System = "jira"

// Field is a field of a case or incident and its ticket.
type Field string

// Fields.
const (
	FieldState       Field = "state"
	FieldSeverity    Field = "severity"
	FieldContainment Field = "containment"
	FieldRestoration Field = "restoration"
	FieldAssignee    Field = "assignee"
	FieldLabels      Field = "labels"
	FieldPriority    Field = "priority"
	FieldComments    Field = "comments"
)

// Fields lists every field in a stable order.
var Fields = []Field{
	FieldState, FieldSeverity, FieldContainment, FieldRestoration, FieldAssignee, FieldLabels, FieldPriority, FieldComments,
}

// Valid reports whether f is a known field.
func (f Field) Valid() bool { return slices.Contains(Fields, f) }

// Locked reports whether PantherClaw always owns f: containment and
// restoration never move to the ticket system (HR-527, D264; migration
// 00242).
func (f Field) Locked() bool { return f == FieldContainment || f == FieldRestoration }

// Movable reports whether an organization may choose f's owner (D264).
func (f Field) Movable() bool { return f.Valid() && !f.Locked() }

// Owner is the side that owns a field.
type Owner string

// Owners.
const (
	OwnerPantherClaw Owner = "PANTHERCLAW"
	OwnerTicket      Owner = "TICKET"
)

// Valid reports whether o is a known owner.
func (o Owner) Valid() bool { return o == OwnerPantherClaw || o == OwnerTicket }

// DefaultOwner is f's owner when the organization set none: PantherClaw
// for state, severity and the locked fields, the ticket system for the
// rest (D255).
func DefaultOwner(f Field) Owner {
	if f.Locked() || !f.Valid() || f == FieldState || f == FieldSeverity {
		return OwnerPantherClaw
	}
	return OwnerTicket
}

// Owners are an organization's stored owners.
type Owners map[Field]Owner

// Of returns f's owner: always PantherClaw for a locked or unknown field,
// whatever is stored.
func (o Owners) Of(f Field) Owner {
	if f.Locked() || !f.Valid() {
		return OwnerPantherClaw
	}
	if v, ok := o[f]; ok && v.Valid() {
		return v
	}
	return DefaultOwner(f)
}

// Change is one field change an inbound ticket event reports. From and To
// are the ticket system's display values: untrusted text.
type Change struct {
	Field    Field
	From, To string
	// Done marks a status change into the ticket system's done category.
	Done bool
}

// Comment is a comment an inbound ticket event adds; untrusted text.
type Comment struct {
	ID, Author, Body string
}

// Action is what PantherClaw does with one inbound change.
type Action string

// Actions.
const (
	// ActionMirror writes a ticket-owned change as a NOTE.
	ActionMirror Action = "MIRROR"
	// ActionIgnore drops a change to a PantherClaw-owned field and records
	// it as an EXTERNAL entry and ticket.owned_field_ignored (HR-528).
	ActionIgnore Action = "IGNORE"
	// ActionNote records a status moved to Done; nothing changes (HR-527).
	ActionNote Action = "NOTE"
)

// Verdict is the decision on one change or comment, with the entry text.
type Verdict struct {
	Field  Field
	Action Action
	Text   string
}

// MaxValue bounds one ticket value quoted in an entry.
const MaxValue = 200

// MaxComment bounds a mirrored comment.
const MaxComment = 3000

// Decide returns what each change and the comment of an inbound event
// become, for the ticket key. It never returns anything that changes a
// case's or incident's state, severity, containment or restoration: the
// only actions are a note, a mirror note and an ignored change.
func Decide(owners Owners, key string, changes []Change, comment *Comment) []Verdict {
	var out []Verdict
	for _, c := range changes {
		if !c.Field.Valid() {
			continue
		}
		val := Clean(c.To, MaxValue)
		switch {
		case owners.Of(c.Field) == OwnerTicket:
			text := string(SystemJira) + " " + key + ": " + string(c.Field) + " changed to " + quote(val)
			if c.Field == FieldState {
				// A ticket-owned state is mirrored as a note only (HR-527).
				text += "; a ticket status never restores authority or lifts containment"
			}
			out = append(out, Verdict{Field: c.Field, Action: ActionMirror, Text: text})
		case c.Field == FieldState && c.Done:
			out = append(out, Verdict{Field: c.Field, Action: ActionNote,
				Text: string(SystemJira) + " " + key + ": status moved to " + quote(val) +
					"; a ticket status never restores authority or lifts containment, so nothing changed here"})
		default:
			out = append(out, Verdict{Field: c.Field, Action: ActionIgnore,
				Text: string(SystemJira) + " " + key + ": " + string(c.Field) + " changed to " + quote(val) +
					"; PantherClaw owns " + string(c.Field) + ", so the change was ignored"})
		}
	}
	if comment != nil && strings.TrimSpace(comment.Body) != "" {
		who := Clean(comment.Author, MaxValue)
		if who == "" {
			who = "someone"
		}
		body := Clean(comment.Body, MaxComment)
		if owners.Of(FieldComments) == OwnerTicket {
			out = append(out, Verdict{Field: FieldComments, Action: ActionMirror,
				Text: string(SystemJira) + " " + key + ": comment by " + who + ": " + body})
		} else {
			out = append(out, Verdict{Field: FieldComments, Action: ActionIgnore,
				Text: string(SystemJira) + " " + key + ": comment by " + who + " not mirrored; PantherClaw owns comments"})
		}
	}
	return out
}

func quote(s string) string { return "“" + s + "”" }

// Clean makes untrusted ticket text safe to store: control and format
// characters become spaces, runs of space collapse, and it is cut to at
// most maxRunes runes (with an ellipsis).
func Clean(s string, maxRunes int) string {
	var b strings.Builder
	space := false
	for _, r := range strings.ToValidUTF8(s, "�") {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.IsSpace(r) {
			if !space && b.Len() > 0 {
				b.WriteByte(' ')
			}
			space = true
			continue
		}
		space = false
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	if utf8.RuneCountInString(out) > maxRunes {
		out = string([]rune(out)[:maxRunes-1]) + "…"
	}
	return out
}
