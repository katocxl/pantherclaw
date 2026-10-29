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
// 5 is M16's (G0 M17 D134).
//
// 6: step 6 follows consequence chains down rules that apply deeper than
// the action itself, reading the facts about each consequence's target
// (G0 M17 D109), an expired rule's consequence is UNKNOWN (D110), and the
// org's customer rules join the package's (D106, D108).
const Version = 6

// Replays reports whether this server replays inputs recorded by pipeline
// version v (G0 M17 D133, D134): this version, and version 4, which it
// decides as version 4 did (Pipeline.Replaying). Others are incomplete
// (F507).
func Replays(v int) bool { return v == 4 || v == Version }

// direct reports whether the evaluation decides consequences as the
// versions before 6 did: the rules for the action's operation only,
// without chains, expiry or customer rules.
func (p *Pipeline) direct() bool { return p.Replaying != 0 && p.Replaying < 6 }
