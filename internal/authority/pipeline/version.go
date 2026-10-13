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
const Version = 2
