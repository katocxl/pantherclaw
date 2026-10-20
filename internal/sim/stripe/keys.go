// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package stripe

// FakeKey returns a made-up key shaped like a Stripe API key: kind is sk
// (secret), rk (restricted) or pk (publishable), mode test or live, and
// body the characters after them. Tests build their keys with it so that
// no key-shaped literal sits in the source for secret scanners to flag;
// none of them is valid anywhere but in the simulator.
func FakeKey(kind, mode, body string) string {
	return kind + "_" + mode + "_" + body
}
