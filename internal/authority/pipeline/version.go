// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

// Version is the version of steps 1–8 as decision replay sees them (G0 M7
// design decision 11): every evaluation's recorded inputs carry it, and a
// replay of inputs recorded by another version is incomplete (F507). Raise
// it with any change that could decide the same recorded reads differently,
// or that reads something the recording does not hold.
//
// 2: step 8 applies the policy's verify obligation and checks that the
// connection can make the verifier's reads (Connection.Reads, F497).
//
// 3: step 6 evaluates the consequence rules of the action's package version
// (Pinned.Consequences), and steps 4, 7 and 8 decide each predicted or
// unknown consequence with the action (G0 M8, HR-206).
//
// 4: step 6 also checks the definition's fact bindings (Prerequisite.Binds,
// HR-205): from the same recorded reads, a merge whose sha differs from its
// fact's is CANNOT_AUTHORIZE HEAD_MOVED, which version 3 did not decide.
//
// 5: step 6 reads the identity-risk facts a policy using `principal` needs,
// and step 7 asks the org's active external policy checks (G0 M16 D81,
// D82), whose answers a recording does not hold. Step 7 also reads the run
// tree's sensitive reads for the data-flow hold (D73, D76).
//
// 6: step 6 follows consequence chains down rules that apply deeper than
// the action itself, reading the facts about each consequence's target
// (G0 M17 D109), an expired rule's consequence is UNKNOWN (D110), and the
// org's customer rules join the package's (D106, D108).
//
// 7: step 6 reads the org's content signal mode and the run tree's flags,
// and step 7 holds on them (G0 M27 D507, D512), which a recording before it
// does not hold.
//
// 8: step 7 reads the org's owned accounts and holds an action that
// shares to the public or to an account the org does not own (G0 M30 D935,
// D935a), which a recording before it does not hold.
//
// 9: step 7 reads the org's browser sites and holds a pc.browser action on
// a site not listed, and every takeover (G0 M33 D977), which a recording
// before it does not hold.
//
// 10: step 7 reads the org's shared intel consume mode and the indicators
// the action's upstream server and tool match, and holds (HOLD) or notes
// (ALERT_ONLY) a match, including a shared injection_text match from the
// content scan, which no longer counts as a content flag (G0 M38 D1104), a
// read a recording before it does not hold.
//
// 11: step 7 decides a payment-class action (G0 M39 D1124, D1124d): the
// server verifies its mandate with no snapshot open, reads the mandate's
// earlier uses and the merchant's ACTIVE cap, and holds every payment for
// a person unless the cap allows it. A recording does not hold the
// mandate's verification, so a replay of a payment is CANNOT_AUTHORIZE.
const Version = 11

// Replays reports whether this code replays inputs recorded by pipeline
// version v (G0 M16 D95, G0 M17 D133, D134): this version, and versions 4
// to 10, each in its own mode (Pipeline.ReplayOf), so a recording decides
// as it did. Others are incomplete (F507).
func Replays(v int) bool { return (v >= 4 && v <= 10) || v == Version }

// at reports whether the evaluation runs at least version v: always, except
// when it replays a recording made under an earlier one.
func (p *Pipeline) at(v int) bool { return p.ReplayOf == 0 || p.ReplayOf >= v }

// direct reports whether the evaluation decides consequences as the
// versions before 6 did: the rules for the action's operation only,
// without chains, expiry or customer rules.
func (p *Pipeline) direct() bool { return !p.at(6) }
