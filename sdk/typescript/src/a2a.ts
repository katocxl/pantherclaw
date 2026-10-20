// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// The receiving side of a PantherClaw peer agent call (G0 M14 D33,
// HR-325): an enrolled agent that serves A2A takes a message only when the
// gateway sent it for a requester whose grant allows it, and then acts in
// the delegated run PantherClaw created for it.
//
// Every message the gateway sends carries a PAP-Action token minted for
// exactly that request (its body, operation a2a.message.send, target type
// a2a.agent) with the claim pc_peer_run naming the child run. peerRun
// verifies the token with the target verifier (signature, issuer,
// audience, lifetime, body, single use) and returns the run id, which the
// agent then sends as its PAP-Run-Id. A message without a valid token,
// one sent directly to the agent, is refused.

import { HEADER_ACTION } from "./pap.ts";
import type { Verifier } from "./verifier.ts";

export const PEER_OPERATION = "a2a.message.send";
export const PEER_TARGET_TYPE = "a2a.agent";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** A verified token that names no peer run: the connection has no peer agent. */
export class PeerRunMissing extends Error {
  readonly code = "peer_run_missing";
  readonly status = 403;
  constructor() {
    super("action token refused: peer_run_missing: the action token names no peer run");
  }
}

/** Headers as node:http, fetch or a plain object carries them. */
export type PeerHeaders = Headers | Record<string, string | string[] | undefined>;

function header(h: PeerHeaders, name: string): string | undefined {
  if (h instanceof Headers) return h.get(name) ?? undefined;
  for (const [k, v] of Object.entries(h)) {
    if (k.toLowerCase() === name.toLowerCase()) return Array.isArray(v) ? undefined : v;
  }
  return undefined;
}

/**
 * Verifies the PAP-Action token of an A2A request (its headers and exact
 * body), spends it, and returns the peer run it names. Throws the
 * verifier's Refusal, or PeerRunMissing.
 */
export async function peerRun(headers: PeerHeaders, body: Uint8Array | string, verifier: Verifier): Promise<string> {
  const claims = await verifier.verify(header(headers, HEADER_ACTION), body, (c) => c.pap.op === PEER_OPERATION && c.pap.target?.type === PEER_TARGET_TYPE);
  const run = (claims as unknown as Record<string, unknown>).pc_peer_run;
  if (typeof run !== "string" || !UUID.test(run)) throw new PeerRunMissing();
  return run;
}
