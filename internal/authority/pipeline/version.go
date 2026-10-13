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
const Version = 4
