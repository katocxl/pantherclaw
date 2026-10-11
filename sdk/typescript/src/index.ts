// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// @pantherclaw/sdk: the PantherClaw Authority Protocol (PAP/1) for
// TypeScript. See docs/protocol/PAP-1.md in the PantherClaw repository.

export { ActionError, type ParsedAction, parseAction } from "./action.ts";
export { checkProof, type ProofRequest } from "./check.ts";
export {
  type Answer,
  type CallClass,
  Client,
  type ClientConfig,
  classify,
  type Dispatch,
  evaluate,
  type HookAnswer,
  type HookResult,
  MAX_CALL_BODY,
  newActionId,
  next,
  type Outbound,
  type Outcome,
  outboundRequest,
  parseWaitResponse,
  readStream,
  type Result,
  retry,
  type ShellCall,
  type ToolCall,
  type WaitState,
} from "./client.ts";
export { canonicalize, JCSError, type JSONValue, parseJSON, serialize } from "./jcs.ts";
export * from "./pap.ts";
export {
  type ActionClaims,
  actionTokenKid,
  DEFAULT_MAX_BODY,
  MemoryStore,
  middleware,
  Refusal,
  type RefusalCode,
  type ReplayStore,
  type Spend,
  Verifier,
  type VerifierConfig,
} from "./verifier.ts";
