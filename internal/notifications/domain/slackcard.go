// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Slack approval cards (G0 M14 D23, HR-313, HR-314). A card tells a
// channel that a decision is waiting and links to the authenticated
// approval page, where the decision is made: it carries fixed labels, ids
// and times, never parameters, amounts, the principal, untrusted text or
// who decided. Its one interactive element is a link button; Slack can
// never decide anything, and PantherClaw has no Slack inbound endpoint.

// CardEvent is what a notification does to a card.
type CardEvent string

// Card events.
const (
	// CardPost posts the open card (a new request).
	CardPost CardEvent = "post"
	// CardClose updates the card to the request's final state.
	CardClose CardEvent = "close"
	// CardEscalate adds a thread reply to the card.
	CardEscalate CardEvent = "escalate"
	// CardTest posts the channel test message.
	CardTest CardEvent = "test"
	// CardNone: the notification has no card (it is skipped).
	CardNone CardEvent = ""
)

// CardEventOf maps a notification type to its card event: the approval
// and automation-gate notices of a request; everything else has none.
func CardEventOf(notificationType string) CardEvent {
	if notificationType == "channel.test" {
		return CardTest
	}
	rest, ok := strings.CutPrefix(notificationType, "approval.")
	if !ok {
		if rest, ok = strings.CutPrefix(notificationType, "automation.gate_"); !ok {
			return CardNone
		}
	}
	switch rest {
	case "requested":
		return CardPost
	case "decided", "expired", "invalidated":
		return CardClose
	case "escalated":
		return CardEscalate
	}
	return CardNone
}

// Card states stored with a card.
const (
	CardOpen   = "OPEN"
	CardClosed = "CLOSED"
)

// CardFacts are the facts a card shows, read by the server when it is sent.
// Kind, Consequence and State are fixed vocabulary; the summary strings are
// configuration (the approval template's title, the agent's and the
// environment's names) and are cleaned before use.
type CardFacts struct {
	// Level is SlackMinimal or SlackSummary.
	Level string
	// Kind is the request's subject kind (ACTION, RESTORATION,
	// AUTOMATION_GATE).
	Kind string
	// Consequence is the definition's reversibility (reversible,
	// compensatable, irreversible; "" when not stated).
	Consequence string
	// State is the request's state.
	State     string
	ExpiresAt time.Time
	// RequestID is the request's id; the card shows its first 8 characters.
	RequestID string
	// Link is the approval page's deep link.
	Link      string
	Simulated bool
	// Summary level only.
	Title, Agent, Environment string
}

// SlackCard is a chat.postMessage or chat.update body without channel and
// ts: the plain-text fallback and the Block Kit blocks.
type SlackCard struct {
	Text   string       `json:"text"`
	Blocks []SlackBlock `json:"blocks,omitzero"`
}

// SlackBlock is one Block Kit block (header, section, context, actions).
type SlackBlock struct {
	Type     string         `json:"type"`
	Text     *BlockText     `json:"text,omitzero"`
	Fields   []BlockText    `json:"fields,omitzero"`
	Elements []SlackElement `json:"elements,omitzero"`
}

// BlockText is a Block Kit text object; cards use plain_text only, so
// nothing in them can form a link, a mention or formatting.
type BlockText struct {
	Type  string `json:"type"`
	Text  string `json:"text"`
	Emoji bool   `json:"emoji,omitzero"`
}

// SlackElement is a context text or the card's one link button.
type SlackElement struct {
	Type string `json:"type"`
	// Text is the context text (a string) or the button label (*BlockText).
	Text     any    `json:"text,omitzero"`
	URL      string `json:"url,omitzero"`
	ActionID string `json:"action_id,omitzero"`
}

// Card text limits (Block Kit: header 150, field 2000; ours are smaller).
const (
	maxCardValue = 80
	shortID      = 8
)

func plain(s string) BlockText { return BlockText{Type: "plain_text", Text: s} }

// kindLabels and consequenceLabels are the fixed labels a card shows.
var (
	kindLabels = map[string]string{
		"ACTION": "Agent action", "RESTORATION": "Restoration", "AUTOMATION_GATE": "Automation gate",
	}
	consequenceLabels = map[string]string{
		"reversible": "Reversible", "compensatable": "Can be compensated", "irreversible": "Irreversible",
	}
	closedLabels = map[string]string{
		"APPROVED": "Approved", "CONSUMED": "Approved", "DECLINED": "Declined", "EXPIRED": "Expired",
		"INVALIDATED": "No longer applies", "SUPERSEDED": "No longer applies", "CANCELLED": "Cancelled", //nolint:misspell // a state name
	}
)

// CardIsClosed reports whether a request in state is final for its card:
// decided, expired or no longer applying. A request that is PENDING or
// EVIDENCE_REQUESTED keeps an open card.
func CardIsClosed(state string) bool {
	_, ok := closedLabels[state]
	return ok
}

// CardValue cleans a configured string for a card: control and format
// characters removed, cut to 80 characters; "" when nothing is left.
func CardValue(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range strings.TrimSpace(s) {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029 {
			continue
		}
		if n == maxCardValue {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

func label(m map[string]string, k, fallback string) string {
	if v, ok := m[k]; ok {
		return v
	}
	return fallback
}

// short is the card's request reference.
func short(id string) string {
	if len(id) > shortID {
		return id[:shortID]
	}
	return id
}

func (f CardFacts) heading(h string) string {
	if f.Simulated {
		return strings.TrimSpace(SimulatedPrefix) + " " + h
	}
	return h
}

// fields are the card's facts by data level (D23).
func (f CardFacts) fields(open bool) []BlockText {
	out := []BlockText{
		plain("Request: " + label(kindLabels, f.Kind, "Approval")),
		plain("Consequence: " + label(consequenceLabels, f.Consequence, "Not stated")),
	}
	if open {
		out = append(out, plain("Expires: "+f.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC")))
	}
	out = append(out, plain("Reference: "+short(f.RequestID)))
	if f.Level == SlackSummary {
		for _, kv := range [][2]string{{"Approval", f.Title}, {"Agent", f.Agent}, {"Environment", f.Environment}} {
			if v := CardValue(kv[1]); v != "" {
				out = append(out, plain(kv[0]+": "+v))
			}
		}
	}
	return out
}

// OpenCard is the card of a waiting request: the facts and one link button
// to the approval page, with the link in the fallback text too.
func OpenCard(f CardFacts) SlackCard {
	h := f.heading("Approval needed")
	return SlackCard{
		Text: SlackEscape(h+" (reference "+short(f.RequestID)+"). Decide on the approval page: ") + "<" + SlackEscape(f.Link) + ">",
		Blocks: []SlackBlock{
			{Type: "header", Text: &BlockText{Type: "plain_text", Text: h}},
			{Type: "section", Fields: f.fields(true)},
			{Type: "context", Elements: []SlackElement{{
				Type: "plain_text", Text: "Decisions are made only on the PantherClaw approval page. Reactions and replies here never count.",
			}}},
			{Type: "actions", Elements: []SlackElement{{
				Type: "button", Text: &BlockText{Type: "plain_text", Text: "Open in PantherClaw"}, URL: f.Link, ActionID: "open_approval",
			}}},
		},
	}
}

// ClosedCard is the card of a request that is final: its outcome label and
// facts, no button and no link, and no names.
func ClosedCard(f CardFacts) SlackCard {
	h := f.heading(label(closedLabels, f.State, "Closed"))
	return SlackCard{
		Text: SlackEscape(h + " (reference " + short(f.RequestID) + ")."),
		Blocks: []SlackBlock{
			{Type: "header", Text: &BlockText{Type: "plain_text", Text: h}},
			{Type: "section", Fields: f.fields(false)},
		},
	}
}

// EscalationReply is the thread reply of escalation step n.
func EscalationReply(n int) SlackCard {
	return SlackCard{Text: "Escalated (step " + strconv.Itoa(max(n, 1)) + ")"}
}

// TestCard is a channel test's message.
func TestCard(simulated bool) SlackCard {
	f := CardFacts{Simulated: simulated}
	return SlackCard{Text: SlackEscape(f.heading("Test notification from PantherClaw. No action is needed."))}
}
