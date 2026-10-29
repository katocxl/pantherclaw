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
// D82), whose answers a recording does not hold.
const Version = 5

// Replays reports whether this code replays inputs recorded by pipeline
// version v (G0 M16 D95): the current version, and version 4 in its own
// mode, which makes none of version 5's reads (Pipeline.ReplayOf), so a
// version 4 recording decides as it did.
func Replays(v int) bool { return v == 4 || v == Version }

// at reports whether the evaluation runs at least version v: always, except
// when it replays a recording made under an earlier one.
func (p *Pipeline) at(v int) bool { return p.ReplayOf == 0 || p.ReplayOf >= v }
