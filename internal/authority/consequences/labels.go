// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package consequences

// Label is what a consequence is, shown apart from what was authorized
// and what was confirmed (G0 M17 D111, F410). It is derived where it is
// shown, never stored: a decision says what may happen, its consequence
// transaction what was accepted, and that transaction's verified effect
// what happened.
type Label string

// Labels.
const (
	// LabelMayCause: the rule predicts the consequence; nothing permitted
	// the action (or the decision was observe-only).
	LabelMayCause Label = "MAY_CAUSE"
	// LabelAuthorized: the consequence is predicted and the decision
	// permitted the action, the consequence with it.
	LabelAuthorized Label = "AUTHORIZED"
	// LabelUnknown: the consequence could not be ruled out.
	LabelUnknown Label = "UNKNOWN"
	// LabelNotTriggered: the rule's facts rule the consequence out.
	LabelNotTriggered Label = "NOT_TRIGGERED"
	// LabelAccepted: the consequence's own transaction was opened once the
	// action's effect was confirmed.
	LabelAccepted Label = "ACCEPTED"
	// LabelConfirmed: that transaction's effect is CONFIRMED.
	LabelConfirmed Label = "CONFIRMED"
)

// LabelOf is the label of a consequence of state (PREDICTED, UNKNOWN or
// NOT_TRIGGERED) whose decision permitted the action (permits, an
// enforced permit only), whose consequence transaction was opened
// (accepted) and whose effect was confirmed (confirmed). Only a predicted
// consequence is ever accepted or confirmed.
func LabelOf(state State, permits, accepted, confirmed bool) Label {
	switch {
	case state == Unknown:
		return LabelUnknown
	case state != Predicted:
		return LabelNotTriggered
	case confirmed:
		return LabelConfirmed
	case accepted:
		return LabelAccepted
	case permits:
		return LabelAuthorized
	}
	return LabelMayCause
}

// RuleChain is the ids of the rules from the action to consequence i of
// cs, in chain order (F411): each consequence's parent comes before it.
func RuleChain(cs []Consequence, i int) []string {
	var out []string
	for i >= 0 && i < len(cs) {
		out = append(out, cs[i].Rule)
		depth, parent, chained, _ := cs[i].Chain()
		if !chained || parent >= i || depth <= 1 {
			break
		}
		i = parent
	}
	for l, r := 0, len(out)-1; l < r; l, r = l+1, r-1 {
		out[l], out[r] = out[r], out[l]
	}
	return out
}
